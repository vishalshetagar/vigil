//go:build linux

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vigil/internal/store"
)

func TestSocketPermissionsQueriesAndOwnership(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "vigil.sock")
	db, err := store.Open(filepath.Join(dir, "history.db"), 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := Start(socket, db, func() any { return map[string]string{"state": "running"} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions", info, err)
	}
	if other, err := Start(socket, db, func() any { return nil }); err == nil {
		other.Close()
		t.Fatal("replaced active socket")
	}
	if _, err := Get(context.Background(), socket, "status"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(context.Background(), socket, "events?limit=-1"); err == nil {
		t.Fatal("invalid limit accepted")
	}
	b, err := Get(context.Background(), socket, "events?limit=10")
	if err != nil || string(b) != "[]\n" {
		t.Fatal(string(b), err)
	}
	s.Close()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatal("socket left behind", err)
	}
}
