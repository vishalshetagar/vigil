package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"vigil/internal/event"
	"vigil/internal/process"
)

func record(id string, ts uint64) Record {
	e := event.Event{Version: 1, ID: id, Host: "h", Boot: "b", Run: "r", TimeNS: ts, Type: event.Exec, Process: event.Identity{PID: 2, StartNS: 1}, Filename: "/tmp/a"}
	g := process.New(10)
	n := g.Apply(e)
	a := event.Alert{ID: id, Rule: "test", ProcessKey: e.Key(), Evidence: []event.Event{e}}
	return Record{e, n, []event.Alert{a}}
}

func TestPersistenceDedupRetentionEvidence(t *testing.T) {
	name := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(name, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []Record{record("a", 1), record("b", 2), record("c", 3), record("c", 3)} {
		if err = s.Write(ctx, []Record{r}); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.Counts(ctx)
	if err != nil || c.Events != 2 || c.Alerts != 3 {
		t.Fatal(c, err)
	}
	s.Close()
	s, err = Open(name, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Query(ctx, "alerts", Query{Limit: 10})
	if err != nil || len(rows) != 3 {
		t.Fatal(err, rows)
	}
	var a event.Alert
	if err = json.Unmarshal(rows[2], &a); err != nil || a.Evidence[0].ID != "a" {
		t.Fatal("evidence lost", err)
	}
	rows, err = s.Query(ctx, "events", Query{Process: "' OR 1=1 --"})
	if err != nil || len(rows) != 0 {
		t.Fatal("query injection", err)
	}
}

func TestAtomicRollback(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history.db"), 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bad := record("b", 2)
	bad.Event.Version = 99
	if err = s.Write(context.Background(), []Record{record("a", 1), bad}); err == nil {
		t.Fatal("accepted invalid batch")
	}
	c, _ := s.Counts(context.Background())
	if c.Events != 0 || c.Alerts != 0 {
		t.Fatal("partial transaction", c)
	}
}
