package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Monitoring targets: where alarms and audit entries are pushed (syslog, OTLP, SNMP traps). Not part of the
// event configuration: no revisions, no rollback, no YAML export.

// Target kinds.
const (
	TargetSyslog   = "syslog"
	TargetOTLP     = "otlp"
	TargetSNMPTrap = "snmptrap"
)

// MaxTargets limits the number of targets (memory: one queue each).
const MaxTargets = 20

// Target is one push destination. Config holds the non-secret fields of its kind, Secret the secret ones
// (community, passwords, headers); both are JSON objects.
type Target struct {
	ID       int64
	Kind     string
	Name     string
	Enabled  bool
	Endpoint string
	Events   []string // subset of "alarm", "audit"
	Config   map[string]any
	Secret   map[string]string
	Created  string
	Updated  string
}

// SecretDelete as a secret value in SaveTarget removes that secret (empty keeps it).
const SecretDelete = "\x00delete"

// Wants reports whether the target takes events of this type ("test" always).
func (t Target) Wants(typ string) bool { return typ == "test" || slices.Contains(t.Events, typ) }

// Targets returns all targets sorted by kind and name.
func (s *Store) Targets(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, kind, name, enabled, endpoint, events, config, secret, created_ts, updated_ts
		FROM monitor_target ORDER BY kind, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		var events, cfg, sec string
		if err := rows.Scan(&t.ID, &t.Kind, &t.Name, &t.Enabled, &t.Endpoint, &events, &cfg, &sec, &t.Created, &t.Updated); err != nil {
			return nil, err
		}
		for _, e := range strings.Split(events, ",") {
			if e = strings.TrimSpace(e); e != "" {
				t.Events = append(t.Events, e)
			}
		}
		_ = json.Unmarshal([]byte(cfg), &t.Config)
		_ = json.Unmarshal([]byte(sec), &t.Secret)
		if t.Config == nil {
			t.Config = map[string]any{}
		}
		if t.Secret == nil {
			t.Secret = map[string]string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Target returns one target.
func (s *Store) Target(ctx context.Context, id int64) (Target, error) {
	all, err := s.Targets(ctx)
	if err != nil {
		return Target{}, err
	}
	for _, t := range all {
		if t.ID == id {
			return t, nil
		}
	}
	return Target{}, fmt.Errorf("%w: target %d", ErrNotFound, id)
}

// auditTarget is what the audit log sees of a target: never the secret.
func auditTarget(t Target) string {
	b, _ := json.Marshal(map[string]any{"kind": t.Kind, "name": t.Name, "endpoint": t.Endpoint, "enabled": t.Enabled,
		"events": t.Events, "config": t.Config})
	return string(b)
}

// SaveTarget creates (ID 0) or updates a target. Secret values that are empty keep the stored value, so the
// UI never has to show them.
func (s *Store) SaveTarget(ctx context.Context, user string, t Target) (int64, error) {
	t.Name, t.Endpoint = strings.TrimSpace(t.Name), strings.TrimSpace(t.Endpoint)
	switch {
	case !slices.Contains([]string{TargetSyslog, TargetOTLP, TargetSNMPTrap}, t.Kind):
		return 0, fmt.Errorf("%w: kind %q", ErrInvalid, t.Kind)
	case t.Name == "" || len(t.Name) > 60:
		return 0, fmt.Errorf("%w: name", ErrInvalid)
	case t.Endpoint == "" || len(t.Endpoint) > 300:
		return 0, fmt.Errorf("%w: endpoint", ErrInvalid)
	}
	for _, e := range t.Events {
		if e != "alarm" && e != "audit" {
			return 0, fmt.Errorf("%w: event %q", ErrInvalid, e)
		}
	}
	var before Target
	if t.ID != 0 {
		var err error
		if before, err = s.Target(ctx, t.ID); err != nil {
			return 0, err
		}
		merged := map[string]string{}
		for k, v := range before.Secret {
			merged[k] = v
		}
		for k, v := range t.Secret {
			switch v {
			case "":
			case SecretDelete:
				delete(merged, k)
			default:
				merged[k] = v
			}
		}
		t.Secret = merged
	}
	if t.Config == nil {
		t.Config = map[string]any{}
	}
	if t.Secret == nil {
		t.Secret = map[string]string{}
	}
	cfg, _ := json.Marshal(t.Config)
	sec, _ := json.Marshal(t.Secret)
	events := strings.Join(t.Events, ",")
	now := s.ts()
	id := t.ID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if t.ID == 0 {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM monitor_target`).Scan(&n); err != nil {
				return err
			}
			if n >= MaxTargets {
				return fmt.Errorf("%w: at most %d targets", ErrInvalid, MaxTargets)
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO monitor_target(kind, name, enabled, endpoint, events, config, secret, created_ts, updated_ts)
				VALUES (?,?,?,?,?,?,?,?,?)`, t.Kind, t.Name, t.Enabled, t.Endpoint, events, string(cfg), string(sec), now, now)
			if err != nil {
				return err
			}
			id, _ = res.LastInsertId()
			return nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE monitor_target SET kind=?, name=?, enabled=?, endpoint=?, events=?, config=?, secret=?, updated_ts=? WHERE id=?`,
			t.Kind, t.Name, t.Enabled, t.Endpoint, events, string(cfg), string(sec), now, t.ID)
		return err
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("%w: target %q", ErrExists, t.Name)
		}
		return 0, err
	}
	t.ID = id
	action, b := "monitor.target.create", ""
	if before.ID != 0 {
		action, b = "monitor.target.update", auditTarget(before)
	}
	return id, s.Audit(ctx, user, action, t.Name, b, auditTarget(t))
}

// DeleteTarget removes a target.
func (s *Store) DeleteTarget(ctx context.Context, user string, id int64) error {
	t, err := s.Target(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM monitor_target WHERE id = ?`, id); err != nil {
		return err
	}
	return s.Audit(ctx, user, "monitor.target.delete", t.Name, auditTarget(t), "")
}

// ---- alarm instances reported as open ----

// AlarmKey identifies one alarm instance.
type AlarmKey struct{ Kind, Key string }

// OpenAlarms returns the alarm instances reported as open.
func (s *Store) OpenAlarms(ctx context.Context) (map[AlarmKey]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT kind, key, opened_ts FROM monitor_alarm_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[AlarmKey]string{}
	for rows.Next() {
		var k AlarmKey
		var ts string
		if err := rows.Scan(&k.Kind, &k.Key, &ts); err != nil {
			return nil, err
		}
		out[k] = ts
	}
	return out, rows.Err()
}

// SetAlarmOpen records (open) or forgets (!open) an alarm instance.
func (s *Store) SetAlarmOpen(ctx context.Context, k AlarmKey, open bool) error {
	if open {
		_, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO monitor_alarm_state(kind, key, opened_ts) VALUES (?,?,?)`, k.Kind, k.Key, s.ts())
		return err
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM monitor_alarm_state WHERE kind = ? AND key = ?`, k.Kind, k.Key)
	return err
}
