// Package store persists the relay configuration in SQLite: migrations, seed sync, VLANs, flow profiles,
// events, settings, revisions and the append-only audit log.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the configuration database.
type Store struct {
	DB  *sql.DB
	Now func() time.Time

	auditMu sync.Mutex
	onAudit func(AuditEntry)
}

// Open opens (and creates) the database file and applies pending migrations.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps transactions simple
	s := &Store{DB: db, Now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migration (name TEXT PRIMARY KEY, applied TEXT NOT NULL)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM schema_migration WHERE name = ?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			for _, stmt := range splitSQL(string(body)) {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("%s: %w\n%s", name, err, stmt)
				}
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migration(name, applied) VALUES (?, ?)`, name, s.ts())
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// splitSQL splits a migration into statements. Triggers (BEGIN ... END;) are kept together.
func splitSQL(body string) []string {
	var out []string
	var cur strings.Builder
	inTrigger := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "CREATE TRIGGER") {
			inTrigger = true
		}
		if strings.HasSuffix(trimmed, ";") && (!inTrigger || strings.HasSuffix(upper, "END;")) {
			out = append(out, cur.String())
			cur.Reset()
			inTrigger = false
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

func (s *Store) ts() string { return s.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ErrNotFound is returned for missing rows.
var ErrNotFound = errors.New("store: not found")

// Audit appends to the audit log.
func (s *Store) Audit(ctx context.Context, user, action, object, before, after string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_log(ts, user, action, object, before, after) VALUES (?,?,?,?,?,?)`,
		s.ts(), user, action, object, before, after)
	if err == nil {
		s.notifyAudit(AuditEntry{TS: s.ts(), User: user, Action: action, Object: object, Before: before, After: after})
	}
	return err
}

// SetOnAudit sets a function called after every audit entry (syslog). It must not block.
func (s *Store) SetOnAudit(fn func(AuditEntry)) {
	s.auditMu.Lock()
	s.onAudit = fn
	s.auditMu.Unlock()
}

func (s *Store) notifyAudit(e AuditEntry) {
	s.auditMu.Lock()
	fn := s.onAudit
	s.auditMu.Unlock()
	if fn != nil {
		fn(e)
	}
}

// AuditEntry is one audit log row.
type AuditEntry struct {
	ID                    int64
	TS, User, Action      string
	Object, Before, After string
}

// AuditLog returns the newest entries.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, user, action, object, before, after FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.User, &e.Action, &e.Object, &e.Before, &e.After); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Setting returns a setting or def.
func (s *Store) Setting(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM setting WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	return v, err
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO setting(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Setting keys.
const (
	SettingMode = "engine_mode" // active | observe | paused
)
