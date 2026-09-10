// Package store owns transactional local history and bounded retention.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"vigil/internal/event"
	"vigil/internal/process"
)

type Store struct {
	db                   *sql.DB
	maxEvents, maxAlerts int
}
type Record struct {
	Event  event.Event
	Node   *process.Node
	Alerts []event.Alert
}
type Query struct {
	Process string
	Type    string
	Limit   int
}
type Counts struct {
	Events    int `json:"events"`
	Processes int `json:"processes"`
	Alerts    int `json:"alerts"`
}

// OpenReadOnly never creates a database or performs migrations.
func OpenReadOnly(filename string) (*Store, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA busy_timeout=3000"); err != nil {
		db.Close()
		return nil, err
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version != 1 {
		db.Close()
		return nil, fmt.Errorf("unsupported database schema %d", version)
	}
	return &Store{db: db}, nil
}

func Open(filename string, maxEvents, maxAlerts int) (*Store, error) {
	if maxEvents < 1 || maxAlerts < 1 {
		return nil, errors.New("retention limits must be positive")
	}
	if filename != ":memory:" { // create privately before the SQLite driver opens it
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(filename); err == nil && !info.Mode().IsRegular() {
			return nil, errors.New("database path must be a regular file")
		}
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, maxEvents: maxEvents, maxAlerts: maxAlerts}
	if err = s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	for _, q := range []string{"PRAGMA busy_timeout=3000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA wal_autocheckpoint=1000", "PRAGMA journal_size_limit=16777216", "PRAGMA max_page_count=65536"} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 1 {
		return fmt.Errorf("database schema %d is newer than supported schema 1", version)
	}
	if version == 1 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, process_key TEXT NOT NULL, type TEXT NOT NULL, time_ns INTEGER NOT NULL, payload BLOB NOT NULL);
CREATE INDEX events_process ON events(process_key, seq);
CREATE INDEX events_type ON events(type, seq);
CREATE TABLE processes (key TEXT PRIMARY KEY, time_ns INTEGER NOT NULL, payload BLOB NOT NULL);
CREATE TABLE alerts (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, process_key TEXT NOT NULL, payload BLOB NOT NULL);
CREATE INDEX alerts_process ON alerts(process_key,seq);
PRAGMA user_version=1;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error { return s.db.Close() }

// Write commits event, current process state and evidence-bearing alerts together.
// A duplicate persisted ID never updates the graph snapshot or emits another alert.
func (s *Store) Write(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range records {
		if err := r.Event.Validate(); err != nil {
			return err
		}
		b, err := json.Marshal(r.Event)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, "INSERT INTO events(id,process_key,type,time_ns,payload) VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING", r.Event.ID, r.Event.Key(), r.Event.Type, r.Event.TimeNS, b)
		if err != nil {
			return err
		}
		changed, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if changed == 0 {
			continue
		}
		if r.Node != nil {
			b, err = json.Marshal(r.Node)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO processes(key,time_ns,payload) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET time_ns=excluded.time_ns,payload=excluded.payload WHERE excluded.time_ns>=processes.time_ns", r.Node.Key, r.Node.LastNS, b)
			if err != nil {
				return err
			}
		}
		for _, a := range r.Alerts {
			b, err = json.Marshal(a)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO alerts(id,process_key,payload) VALUES(?,?,?) ON CONFLICT(id) DO NOTHING", a.ID, a.ProcessKey, b)
			if err != nil {
				return err
			}
		}
	}
	// Keep most recent accepted records. Alert payloads retain their own evidence.
	if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE seq <= COALESCE((SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?),0)", s.maxEvents); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM alerts WHERE seq <= COALESCE((SELECT seq FROM alerts ORDER BY seq DESC LIMIT 1 OFFSET ?),0)", s.maxAlerts); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM processes WHERE key NOT IN (SELECT DISTINCT process_key FROM events)"); err != nil {
		return err
	}
	return tx.Commit()
}

func limit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 10000 {
		return 10000
	}
	return n
}

func (s *Store) Query(ctx context.Context, kind string, q Query) ([]json.RawMessage, error) {
	var stmt string
	var args []any
	switch kind {
	case "events", "alerts":
		stmt = "SELECT payload FROM " + kind + " WHERE 1=1"
		if q.Process != "" {
			stmt += " AND process_key=?"
			args = append(args, q.Process)
		}
		if q.Type != "" && kind == "events" {
			stmt += " AND type=?"
			args = append(args, q.Type)
		}
		stmt += " ORDER BY seq DESC LIMIT ?"
	case "processes":
		stmt = "SELECT payload FROM processes WHERE 1=1"
		if q.Process != "" {
			stmt += " AND key=?"
			args = append(args, q.Process)
		}
		stmt += " ORDER BY time_ns DESC LIMIT ?"
	default:
		return nil, fmt.Errorf("unknown query kind %q", kind)
	}
	args = append(args, limit(q.Limit))
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]json.RawMessage, 0)
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(b))
	}
	return out, rows.Err()
}

func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	err := s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM processes),(SELECT count(*) FROM alerts)").Scan(&c.Events, &c.Processes, &c.Alerts)
	return c, err
}
