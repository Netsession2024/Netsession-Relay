package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
)

// ---- games ----

// SeedResult reports what SyncSeed changed.
type SeedResult struct {
	Added, Updated, Pending int
}

// SyncSeed brings the seed database into the store: new games are added, unchanged seed games are updated,
// locally modified games keep their state and get seed_pending set (UI shows "seed differs").
func (s *Store) SyncSeed(ctx context.Context, seed *gamedb.DB) (SeedResult, error) {
	var res SeedResult
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, g := range seed.Games {
			h := gamedb.GameHash(g)
			data, _ := json.Marshal(g)
			var origin, cur string
			var modified bool
			err := tx.QueryRowContext(ctx, `SELECT origin, seed_hash, locally_modified FROM game WHERE id = ?`, g.ID).Scan(&origin, &cur, &modified)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				_, err = tx.ExecContext(ctx, `INSERT INTO game(id, name, category, relay_needed, default_enabled, confidence, origin, seed_hash, data)
					VALUES (?,?,?,?,?,?,'seed',?,?)`, g.ID, g.Name, g.Category, g.RelayNeeded, g.DefaultEnabled, g.Confidence, h, string(data))
				res.Added++
			case err != nil:
				return err
			case origin != "seed" || cur == h:
				continue
			case modified:
				_, err = tx.ExecContext(ctx, `UPDATE game SET seed_pending = ? WHERE id = ?`, h, g.ID)
				res.Pending++
			default:
				_, err = tx.ExecContext(ctx, `UPDATE game SET name=?, category=?, relay_needed=?, default_enabled=?, confidence=?, seed_hash=?, seed_pending='', data=? WHERE id=?`,
					g.Name, g.Category, g.RelayNeeded, g.DefaultEnabled, g.Confidence, h, string(data), g.ID)
				res.Updated++
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

// GameRow is a game with its store metadata and its state in the active event.
type GameRow struct {
	gamedb.Game
	Origin          string
	LocallyModified bool
	SeedPending     bool
	Enabled         bool // switched on in the active event
}

// Games returns all games sorted by name.
func (s *Store) Games(ctx context.Context) ([]GameRow, error) {
	ev, _ := s.activeEventID(ctx)
	rows, err := s.DB.QueryContext(ctx, `SELECT g.data, g.origin, g.locally_modified, g.seed_pending != '',
		EXISTS(SELECT 1 FROM event_game eg WHERE eg.event_id = ? AND eg.game_id = g.id) FROM game g`, ev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GameRow
	for rows.Next() {
		var r GameRow
		var data string
		if err := rows.Scan(&data, &r.Origin, &r.LocallyModified, &r.SeedPending, &r.Enabled); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &r.Game); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, rows.Err()
}

// GameDB returns all stored games as a validated database for the compiler.
func (s *Store) GameDB(ctx context.Context) (*gamedb.DB, error) {
	rows, err := s.Games(ctx)
	if err != nil {
		return nil, err
	}
	list := make([]gamedb.Game, len(rows))
	for i, r := range rows {
		list[i] = r.Game
	}
	return gamedb.New(list)
}

// ---- events ----

func (s *Store) activeEventID(ctx context.Context) (int64, error) {
	var id int64
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM event WHERE is_active = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: no active event (run `nsrelay admin init`)", ErrNotFound)
	}
	return id, err
}

// ActiveEvent returns the name of the active event.
func (s *Store) ActiveEvent(ctx context.Context) (string, error) {
	var name string
	err := s.DB.QueryRowContext(ctx, `SELECT name FROM event WHERE is_active = 1`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: no active event", ErrNotFound)
	}
	return name, err
}

// SetGameEnabled switches a game on or off in the active event.
func (s *Store) SetGameEnabled(ctx context.Context, user, gameID string, on bool) error {
	ev, err := s.activeEventID(ctx)
	if err != nil {
		return err
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM game WHERE id = ?`, gameID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("%w: game %q", ErrNotFound, gameID)
	}
	if on {
		_, err = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO event_game(event_id, game_id) VALUES (?, ?)`, ev, gameID)
	} else {
		_, err = s.DB.ExecContext(ctx, `DELETE FROM event_game WHERE event_id = ? AND game_id = ?`, ev, gameID)
	}
	if err != nil {
		return err
	}
	action := "game.disable"
	if on {
		action = "game.enable"
	}
	return s.Audit(ctx, user, action, gameID, "", "")
}

// SetMode stores the engine mode for the next apply.
func (s *Store) SetMode(ctx context.Context, user, mode string) error {
	switch mode {
	case compile.ModeActive, compile.ModeObserve, compile.ModePaused:
	default:
		return fmt.Errorf("mode %q invalid (active|observe|paused)", mode)
	}
	old, _ := s.Setting(ctx, SettingMode, compile.ModeActive)
	if err := s.SetSetting(ctx, SettingMode, mode); err != nil {
		return err
	}
	return s.Audit(ctx, user, "mode.set", "engine", old, mode)
}

// ---- configuration export / import (backup, rollback) ----

// VLANConfig is one VLAN in the configuration export.
type VLANConfig struct {
	VID     int    `json:"vid" yaml:"vid"`
	Name    string `json:"name" yaml:"name"`
	Group   string `json:"group" yaml:"group"`
	CIDR    string `json:"cidr" yaml:"cidr"`
	RelayIP string `json:"relay_ip,omitempty" yaml:"relay_ip,omitempty"`
	Attach  string `json:"attach" yaml:"attach"`
	Parent  string `json:"parent,omitempty" yaml:"parent,omitempty"`
	Device  string `json:"device,omitempty" yaml:"device,omitempty"`
	RatePPS int    `json:"rate_pps,omitempty" yaml:"rate_pps,omitempty"`
	Burst   int    `json:"rate_burst,omitempty" yaml:"rate_burst,omitempty"`
	Enabled bool   `json:"enabled" yaml:"enabled"` // in the active event
}

// ProfileConfig is a flow profile.
type ProfileConfig struct {
	Name    string         `json:"name" yaml:"name"`
	Default bool           `json:"default,omitempty" yaml:"default,omitempty"`
	Edges   []compile.Edge `json:"edges" yaml:"edges"`
}

// EventGameConfig is a game in the active event.
type EventGameConfig struct {
	ID          string           `json:"id" yaml:"id"`
	FlowProfile string           `json:"flow_profile,omitempty" yaml:"flow_profile,omitempty"`
	Override    compile.Override `json:"override,omitempty" yaml:"override,omitempty"`
}

// Config is the complete configuration of the active event (backup export, revision content).
type Config struct {
	Version  int               `json:"version" yaml:"version"`
	Event    string            `json:"event" yaml:"event"`
	Mode     string            `json:"mode" yaml:"mode"`
	VLANs    []VLANConfig      `json:"vlans" yaml:"vlans"`
	Profiles []ProfileConfig   `json:"profiles" yaml:"profiles"`
	Games    []EventGameConfig `json:"games" yaml:"games"`
}

// ExportConfig reads the active configuration.
func (s *Store) ExportConfig(ctx context.Context) (Config, error) {
	c := Config{Version: 1}
	ev, err := s.activeEventID(ctx)
	if err != nil {
		return c, err
	}
	if c.Event, err = s.ActiveEvent(ctx); err != nil {
		return c, err
	}
	if c.Mode, err = s.Setting(ctx, SettingMode, compile.ModeActive); err != nil {
		return c, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT v.vid, v.name, v.grp, v.cidr, v.relay_ip, v.attach, v.parent, v.device, v.rate_pps, v.rate_burst,
		COALESCE(ev.enabled, 0) FROM vlan v LEFT JOIN event_vlan ev ON ev.vid = v.vid AND ev.event_id = ? ORDER BY v.vid`, ev)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var v VLANConfig
		if err := rows.Scan(&v.VID, &v.Name, &v.Group, &v.CIDR, &v.RelayIP, &v.Attach, &v.Parent, &v.Device, &v.RatePPS, &v.Burst, &v.Enabled); err != nil {
			rows.Close()
			return c, err
		}
		c.VLANs = append(c.VLANs, v)
	}
	rows.Close()
	prows, err := s.DB.QueryContext(ctx, `SELECT name, is_default FROM flow_profile ORDER BY name`)
	if err != nil {
		return c, err
	}
	for prows.Next() {
		var p ProfileConfig
		if err := prows.Scan(&p.Name, &p.Default); err != nil {
			prows.Close()
			return c, err
		}
		c.Profiles = append(c.Profiles, p)
	}
	prows.Close()
	for i := range c.Profiles {
		erows, err := s.DB.QueryContext(ctx, `SELECT src, dst FROM flow_profile_edge WHERE profile = ? ORDER BY src, dst`, c.Profiles[i].Name)
		if err != nil {
			return c, err
		}
		for erows.Next() {
			var e compile.Edge
			if err := erows.Scan(&e.Src, &e.Dst); err != nil {
				erows.Close()
				return c, err
			}
			c.Profiles[i].Edges = append(c.Profiles[i].Edges, e)
		}
		erows.Close()
	}
	grows, err := s.DB.QueryContext(ctx, `SELECT game_id, flow_profile, override FROM event_game WHERE event_id = ? ORDER BY game_id`, ev)
	if err != nil {
		return c, err
	}
	defer grows.Close()
	for grows.Next() {
		var g EventGameConfig
		var ov string
		if err := grows.Scan(&g.ID, &g.FlowProfile, &ov); err != nil {
			return c, err
		}
		_ = json.Unmarshal([]byte(ov), &g.Override)
		c.Games = append(c.Games, g)
	}
	return c, grows.Err()
}

// ImportConfig replaces mode, VLANs, profiles and the active event's VLANs and games with c (one
// transaction). The event is created if it does not exist and becomes the active one. Games referenced
// by c must exist in the game table.
func (s *Store) ImportConfig(ctx context.Context, user string, c Config) error {
	before, _ := s.ExportConfig(ctx)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if c.Mode != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO setting(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, SettingMode, c.Mode); err != nil {
				return err
			}
		}
		for _, stmt := range []string{`DELETE FROM flow_profile_edge`, `DELETE FROM flow_profile`, `DELETE FROM event_vlan`, `DELETE FROM vlan`} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		for _, v := range c.VLANs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vlan(vid, name, grp, cidr, relay_ip, attach, parent, device, rate_pps, rate_burst) VALUES (?,?,?,?,?,?,?,?,?,?)`,
				v.VID, v.Name, v.Group, v.CIDR, v.RelayIP, v.Attach, v.Parent, v.Device, v.RatePPS, v.Burst); err != nil {
				return fmt.Errorf("VLAN %d: %w", v.VID, err)
			}
		}
		for _, p := range c.Profiles {
			if _, err := tx.ExecContext(ctx, `INSERT INTO flow_profile(name, is_default) VALUES (?, ?)`, p.Name, p.Default); err != nil {
				return err
			}
			for _, e := range p.Edges {
				if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO flow_profile_edge(profile, src, dst) VALUES (?,?,?)`, p.Name, e.Src, e.Dst); err != nil {
					return err
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE event SET is_active = 0`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO event(name, is_active, created) VALUES (?, 1, ?) ON CONFLICT(name) DO UPDATE SET is_active = 1`,
			c.Event, s.ts()); err != nil {
			return err
		}
		var ev int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM event WHERE name = ?`, c.Event).Scan(&ev); err != nil {
			return err
		}
		for _, v := range c.VLANs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO event_vlan(event_id, vid, enabled) VALUES (?,?,?)`, ev, v.VID, v.Enabled); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM event_game WHERE event_id = ?`, ev); err != nil {
			return err
		}
		for _, g := range c.Games {
			ov, _ := json.Marshal(g.Override)
			if _, err := tx.ExecContext(ctx, `INSERT INTO event_game(event_id, game_id, flow_profile, override) VALUES (?,?,?,?)`,
				ev, g.ID, g.FlowProfile, string(ov)); err != nil {
				return fmt.Errorf("game %q: %w", g.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(c)
	return s.Audit(ctx, user, "config.import", c.Event, string(b), string(a))
}

// BuildInput turns the active configuration into compiler input.
func (s *Store) BuildInput(ctx context.Context) (compile.Input, error) {
	var in compile.Input
	c, err := s.ExportConfig(ctx)
	if err != nil {
		return in, err
	}
	if in.DB, err = s.GameDB(ctx); err != nil {
		return in, err
	}
	in.Mode = c.Mode
	for _, v := range c.VLANs {
		cv := compile.VLAN{VID: v.VID, Name: v.Name, Group: v.Group, Attach: v.Attach, Parent: v.Parent, Device: v.Device,
			Enabled: v.Enabled, RatePPS: v.RatePPS, Burst: v.Burst}
		if v.CIDR != "" {
			if cv.CIDR, err = netip.ParsePrefix(v.CIDR); err != nil {
				return in, fmt.Errorf("VLAN %d: %w", v.VID, err)
			}
		}
		if v.RelayIP != "" {
			if cv.RelayIP, err = netip.ParseAddr(v.RelayIP); err != nil {
				return in, fmt.Errorf("VLAN %d: %w", v.VID, err)
			}
		}
		in.VLANs = append(in.VLANs, cv)
	}
	for _, p := range c.Profiles {
		in.Profiles = append(in.Profiles, compile.FlowProfile{Name: p.Name, Edges: p.Edges})
		if p.Default {
			in.DefaultProfile = p.Name
		}
	}
	for _, g := range c.Games {
		in.Games = append(in.Games, compile.Selection{GameID: g.ID, FlowProfile: g.FlowProfile, Override: g.Override})
	}
	return in, nil
}

// ---- revisions ----

// Revision is one applied (or attempted) configuration state.
type Revision struct {
	ID            int64
	TS, User      string
	Note          string
	Hash          string
	Snapshot      string // JSON
	Config        string // JSON (Config)
	Warnings      []string
	AppliedOK     bool
	EngineMessage string
}

// AddRevision stores a revision and returns its ID.
func (s *Store) AddRevision(ctx context.Context, r Revision) (int64, error) {
	w, _ := json.Marshal(r.Warnings)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO config_revision(ts, user, note, hash, snapshot, config, warnings, applied_ok, engine_message) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ts(), r.User, r.Note, r.Hash, r.Snapshot, r.Config, string(w), r.AppliedOK, r.EngineMessage)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Revisions returns the newest revisions (without snapshot/config bodies).
func (s *Store) Revisions(ctx context.Context, limit int) ([]Revision, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, user, note, hash, warnings, applied_ok, engine_message FROM config_revision ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var r Revision
		var w string
		if err := rows.Scan(&r.ID, &r.TS, &r.User, &r.Note, &r.Hash, &w, &r.AppliedOK, &r.EngineMessage); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(w), &r.Warnings)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevisionByID returns a revision with snapshot and config.
func (s *Store) RevisionByID(ctx context.Context, id int64) (Revision, error) {
	var r Revision
	var w string
	err := s.DB.QueryRowContext(ctx, `SELECT id, ts, user, note, hash, snapshot, config, warnings, applied_ok, engine_message FROM config_revision WHERE id = ?`, id).
		Scan(&r.ID, &r.TS, &r.User, &r.Note, &r.Hash, &r.Snapshot, &r.Config, &w, &r.AppliedOK, &r.EngineMessage)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("%w: revision %d", ErrNotFound, id)
	}
	_ = json.Unmarshal([]byte(w), &r.Warnings)
	return r, err
}

// SetVLANEnabled switches a VLAN on or off in the active event (number of tables changes per event).
func (s *Store) SetVLANEnabled(ctx context.Context, user string, vid int, on bool) error {
	ev, err := s.activeEventID(ctx)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE event_vlan SET enabled = ? WHERE event_id = ? AND vid = ?`, on, ev, vid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: VLAN %d", ErrNotFound, vid)
	}
	action := "vlan.disable"
	if on {
		action = "vlan.enable"
	}
	return s.Audit(ctx, user, action, fmt.Sprint(vid), "", "")
}

// ErrExists is returned when a new game would replace an existing one.
var ErrExists = errors.New("exists")

// AddGame stores a new game (origin "custom" or "sniffer"); existing IDs are never overwritten.
func (s *Store) AddGame(ctx context.Context, user, origin string, g gamedb.Game) error {
	if err := gamedb.Validate([]gamedb.Game{g}); err != nil {
		return err
	}
	data, _ := json.Marshal(g)
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM game WHERE id = ?`, g.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: game %q", ErrExists, g.ID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO game(id, name, category, relay_needed, default_enabled, confidence, origin, data)
			VALUES (?,?,?,?,?,?,?,?)`, g.ID, g.Name, g.Category, g.RelayNeeded, g.DefaultEnabled, g.Confidence, origin, string(data)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_log(ts, user, action, object, before, after) VALUES (?,?,?,?,?,?)`,
			s.ts(), user, "game.create", g.ID, "", string(data))
		return err
	})
}
