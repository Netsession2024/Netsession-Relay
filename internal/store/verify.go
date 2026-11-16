package store

import (
	"context"
	"fmt"
	"strings"
)

// Verification is one "tested at event X" record of a game.
type Verification struct {
	ID      int64
	GameID  string
	Event   string
	Result  string // works | fails | partial
	Variant string // e.g. Steam, GOG
	Note    string
	User    string
	TS      string
}

// Verification results.
const (
	ResultWorks   = "works"
	ResultFails   = "fails"
	ResultPartial = "partial"
)

// AddVerification stores a record for the active event.
func (s *Store) AddVerification(ctx context.Context, user string, v Verification) error {
	switch v.Result {
	case ResultWorks, ResultFails, ResultPartial:
	default:
		return fmt.Errorf("%w: result %q", ErrInvalid, v.Result)
	}
	if _, err := s.Game(ctx, v.GameID); err != nil {
		return err
	}
	ev, err := s.ActiveEvent(ctx)
	if err != nil {
		return err
	}
	v.Variant, v.Note = strings.TrimSpace(v.Variant), strings.TrimSpace(v.Note)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO verification(game_id, event, result, variant, note, user, ts) VALUES (?,?,?,?,?,?,?)`,
		v.GameID, ev, v.Result, v.Variant, v.Note, user, s.ts()); err != nil {
		return err
	}
	return s.Audit(ctx, user, "game.verify", v.GameID, "", v.Result+" "+v.Variant)
}

// Verifications returns the records of one game ("" = all games), newest first.
func (s *Store) Verifications(ctx context.Context, gameID string) ([]Verification, error) {
	q := `SELECT id, game_id, event, result, variant, note, user, ts FROM verification`
	var args []any
	if gameID != "" {
		q += ` WHERE game_id = ?`
		args = append(args, gameID)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Verification
	for rows.Next() {
		var v Verification
		if err := rows.Scan(&v.ID, &v.GameID, &v.Event, &v.Result, &v.Variant, &v.Note, &v.User, &v.TS); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestVerifications returns the newest record per game.
func (s *Store) LatestVerifications(ctx context.Context) (map[string]Verification, error) {
	all, err := s.Verifications(ctx, "")
	if err != nil {
		return nil, err
	}
	m := map[string]Verification{}
	for _, v := range all { // newest first
		if _, ok := m[v.GameID]; !ok {
			m[v.GameID] = v
		}
	}
	return m, nil
}

// DeleteVerification removes a record (typo, wrong game).
func (s *Store) DeleteVerification(ctx context.Context, user string, id int64) error {
	var game string
	if err := s.DB.QueryRowContext(ctx, `SELECT game_id FROM verification WHERE id = ?`, id).Scan(&game); err != nil {
		return fmt.Errorf("%w: verification %d", ErrNotFound, id)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM verification WHERE id = ?`, id); err != nil {
		return err
	}
	return s.Audit(ctx, user, "game.verify_delete", game, fmt.Sprint(id), "")
}
