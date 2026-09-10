package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictConfigAndBudgets(t *testing.T) {
	for _, content := range []string{"queue_size: 0\n", "unexpected: true\n", "flush_ms: -1\n", "database: ''\n", "queue_size: 2\n---\nqueue_size: 3\n"} {
		file := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(file); err == nil {
			t.Fatalf("accepted invalid config: %s", content)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}
