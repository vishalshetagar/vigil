package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
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
}

func TestCLIRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"replay"}, {"inspect"}, {"events", "--limit", "-1"}, {"run", "--duration", "-1s"}, {"rules", "anything"}} {
		var out bytes.Buffer
		if err := Run(context.Background(), args, &out, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
