package replay

import (
	"bytes"
	"os"
	"testing"

	"vigil/internal/detect"
	"vigil/internal/event"
)

// Benchmark the complete deterministic demo, including graph/rule initialization.
func BenchmarkReplayDemo(b *testing.B) {
	data, err := os.ReadFile("../../testdata/replay/demo.jsonl")
	if err != nil {
		b.Fatal(err)
	}
	set, err := detect.Load("")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		e, err := detect.New(set, 100, 100)
		if err != nil {
			b.Fatal(err)
		}
		if err := Read(bytes.NewReader(data), func(v event.Event) error { _, _, err := e.Process(v); return err }); err != nil {
			b.Fatal(err)
		}
		if e.Stats.Alerts != 4 {
			b.Fatal("unexpected replay result")
		}
	}
}
