package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"vigil/internal/event"
	"vigil/internal/process"
	"vigil/internal/store"
)

func TestReplayAndReadOnlyHistory(t *testing.T) {
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "demo.db")
	var out, logs bytes.Buffer
	if err := Run(ctx, []string{"replay", "--input", "../../testdata/replay/demo.jsonl", "--db", db}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(out.Bytes(), []byte("\n")); lines != 4 {
		t.Fatalf("want 4 alerts, got %d: %s", lines, out.String())
	}
	seen := make(map[string]bool)
	for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
		var alert event.Alert
		if err := json.Unmarshal(line, &alert); err != nil {
			t.Fatal(err)
		}
		if seen[alert.Rule] {
			t.Fatalf("duplicate demo rule: %s", alert.Rule)
		}
		seen[alert.Rule] = true
		if alert.Rule == "VIGIL-003" {
			if alert.Severity != "medium" || alert.ProcessKey != "demo-host/demo-boot/101/200" || !strings.HasSuffix(alert.Summary, "(pending)") {
				t.Fatalf("documented connection alert changed: %+v", alert)
			}
			if len(alert.Evidence) != 2 || alert.Evidence[0].Type != event.Exec || alert.Evidence[1].Type != event.Connect || alert.Evidence[1].Network.Outcome() != "pending" {
				t.Fatalf("connection alert lacks the documented evidence: %+v", alert.Evidence)
			}
		}
	}
	for _, id := range []string{"VIGIL-001", "VIGIL-002", "VIGIL-003", "VIGIL-004"} {
		if !seen[id] {
			t.Fatalf("demo did not trigger %s", id)
		}
	}
	out.Reset()
	if err := Run(ctx, []string{"alerts", "--db", db}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 4 {
		t.Fatal(err, out.String())
	}
	out.Reset()
	if err := Run(ctx, []string{"timeline", "--db", db, "--process", "demo-host/demo-boot/103/400"}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatal(err, out.String())
	}
	var timeline []event.Event
	if err := json.Unmarshal(out.Bytes(), &timeline); err != nil {
		t.Fatal(err)
	}
	if timeline[0].Type != event.Exit || timeline[1].Type != event.Exec || timeline[0].TimeNS < timeline[1].TimeNS {
		t.Fatal("timeline must contain the exited process's events in newest-first order", timeline)
	}

	for _, command := range []string{"ps", "inspect"} {
		args := []string{command, "--db", db}
		want := 4
		if command == "inspect" {
			args = append(args, "--process", "demo-host/demo-boot/103/400")
			want = 1
		}
		out.Reset()
		if err := Run(ctx, args, &out, &logs); err != nil {
			t.Fatal(err)
		}
		var nodes []process.Node
		if err := json.Unmarshal(out.Bytes(), &nodes); err != nil || len(nodes) != want {
			t.Fatal(err, out.String())
		}
		if command == "inspect" && (!nodes[0].Exited || nodes[0].Filename != "/tmp/vigil-demo") {
			t.Fatal("inspect lost the exited process's executable", nodes[0])
		}
	}

	// Repeat the documented replay: evaluation repeats, persisted rows do not.
	out.Reset()
	if err := Run(ctx, []string{"replay", "--input", "../../testdata/replay/demo.jsonl", "--db", db}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(ctx, []string{"status", "--db", db}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	var counts store.Counts
	if err := json.Unmarshal(out.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts != (store.Counts{Events: 7, Processes: 4, Alerts: 4}) {
		t.Fatal("documented demo counts changed", counts)
	}

	out.Reset()
	if err := Run(ctx, []string{"events", "--db", db, "--type", "exec", "--limit", "2"}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	var filtered []event.Event
	if err := json.Unmarshal(out.Bytes(), &filtered); err != nil || len(filtered) != 2 {
		t.Fatal(err, out.String())
	}
	for _, ev := range filtered {
		if ev.Type != event.Exec {
			t.Fatal("event type filter ignored", ev)
		}
	}
}

func TestDocumentedRuleValidation(t *testing.T) {
	for _, args := range [][]string{{"rules", "validate"}, {"rules", "validate", "--rules", "../detect/default.yaml"}} {
		var out, logs bytes.Buffer
		if err := Run(context.Background(), args, &out, &logs); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Valid bool `json:"valid"`
			Rules int  `json:"rules"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Valid || result.Rules != 4 {
			t.Fatal("default rules did not validate", result)
		}
	}
}

func TestCLIRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"replay"}, {"inspect"}, {"events", "--limit", "-1"}, {"run", "--duration", "-1s"}, {"rules", "anything"}} {
		var out bytes.Buffer
		if err := Run(context.Background(), args, &out, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
