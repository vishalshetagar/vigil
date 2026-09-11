//go:build linux && amd64

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vigil/internal/api"
	"vigil/internal/config"
	"vigil/internal/detect"
	"vigil/internal/event"
	"vigil/internal/pipeline"
	"vigil/internal/probe"
	"vigil/internal/store"
)

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("VIGIL_INTEGRATION") != "1" {
		t.Skip("set VIGIL_INTEGRATION=1 and run privileged to load BPF")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration explicitly enabled but root privileges missing")
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "vigil-fixture")
	cmd := exec.Command("cc", "-Wall", "-Wextra", "-Werror", "-pthread", "../workloads/fixture.c", "-o", name)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v: %s", err, b)
	}
	return name
}

func TestKernelLifecycleAndNetwork(t *testing.T) {
	requireKernel(t)
	binary := fixture(t)
	c, err := probe.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	type result struct {
		events []event.Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		var events []event.Event
		for {
			b, err := c.Read()
			if err != nil {
				if probe.IsClosed(err) {
					err = nil
				}
				done <- result{events, err}
				return
			}
			e, err := event.Decode(b)
			if err != nil {
				done <- result{events, err}
				return
			}
			if len(events) < 100000 {
				events = append(events, e)
			}
		}
	}()
	type run struct {
		pid    uint32
		path   string
		mode   string
		result int
		child  uint32
		port   uint16
		family string
	}
	var runs []run
	execute := func(mode string, args ...string) run {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// Unique executable paths map namespace-local fixture PIDs to host PIDs.
		// WSL distributions can be nested PID namespaces of the same kernel.
		unique := filepath.Join(filepath.Dir(binary), fmt.Sprintf("fixture-%d", len(runs)))
		if err := os.Link(binary, unique); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, unique, append([]string{mode}, args...)...)
		var output strings.Builder
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		r := run{pid: uint32(cmd.Process.Pid), mode: mode, path: unique}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("fixture %s: %v: %s", mode, err, output.String())
		}
		if mode == "fork" {
			v, err := strconv.Atoi(strings.TrimSpace(output.String()))
			if err != nil {
				t.Fatal(err)
			}
			r.child = uint32(v)
		}
		if mode == "network" {
			v, err := strconv.Atoi(strings.TrimSpace(output.String()))
			if err != nil {
				t.Fatal(err)
			}
			r.result = v
			p, _ := strconv.Atoi(args[1])
			r.port = uint16(p)
			r.family = args[0]
		}
		return r
	}
	for _, mode := range []string{"fork", "failedexec", "threads", "threadexec"} {
		runs = append(runs, execute(mode))
	}
	for _, family := range []string{"4", "6"} {
		address := "127.0.0.1:0"
		if family == "6" {
			address = "[::1]:0"
		}
		l, err := net.Listen("tcp"+family, address)
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		for _, nonblock := range []string{"0", "1"} {
			runs = append(runs, execute("network", family, strconv.Itoa(port), nonblock))
		}
		l.Close()
		runs = append(runs, execute("network", family, strconv.Itoa(port), "0"))
	}
	if err := c.Drain(); err != nil {
		t.Fatal(err)
	}
	var captured result
	select {
	case captured = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not drain")
	}
	if captured.err != nil {
		t.Fatal(captured.err)
	}
	s, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel counters: %+v; decoded records: %d", s, len(captured.events))
	if s.RingLost != 0 || s.MapErrors != 0 || s.ReadErrors != 0 {
		t.Fatal("controlled fixture lost telemetry", s)
	}
	for _, r := range runs {
		foundExec := false
		for _, e := range captured.events {
			if e.Type == event.Exec && e.Filename == r.path {
				r.pid = e.Process.PID
				foundExec = true
				break
			}
		}
		if !foundExec {
			t.Fatalf("fixture exec missing for %s", r.path)
		}
		t.Run(fmt.Sprintf("%s-%d", r.mode, r.pid), func(t *testing.T) {
			var own []event.Event
			for _, e := range captured.events {
				if e.Process.PID == r.pid {
					own = append(own, e)
				}
			}
			var execs, exits, groupExits, connects int
			var start uint64
			for _, e := range own {
				if start == 0 {
					start = e.Process.StartNS
				}
				if e.Process.StartNS != start {
					t.Fatalf("birth identity changed across lifecycle: %+v", own)
				}
				switch e.Type {
				case event.Exec:
					execs++
					if strings.Contains(e.Filename, "does-not-exist") {
						t.Fatal("failed exec reported as success")
					}
				case event.Exit:
					exits++
					if e.GroupDead {
						groupExits++
					}
				case event.Connect:
					connects++
					if e.Network.Result != int64(r.result) || e.Network.Port != r.port {
						t.Fatalf("network outcome mismatch: %+v / %+v", r, e)
					}
					want := "127.0.0.1"
					if r.family == "6" {
						want = "::1"
					}
					if e.Network.Address != want {
						t.Fatal(e.Network)
					}
				}
			}
			if execs < 1 || groupExits != 1 {
				t.Fatalf("missing lifecycle exec=%d exits=%d last=%d events=%+v", execs, exits, groupExits, own)
			}
			if r.mode == "threads" && exits < 2 {
				t.Fatal("missing thread exit")
			}
			if r.mode == "threadexec" && execs != 2 {
				t.Fatal("non-leader exec missing", execs)
			}
			if r.mode == "network" && connects != 1 {
				t.Fatal("connect missing", connects)
			}
			if r.mode == "fork" {
				found := false
				for _, e := range captured.events {
					if e.Type == event.Fork && e.Parent.PID == r.pid && e.Parent.StartNS == start {
						found = true
					}
				}
				if !found {
					t.Fatal("child fork lineage missing")
				}
			}
		})
	}
}

func TestLivePipelineAndRestart(t *testing.T) {
	requireKernel(t)
	binary := fixture(t)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Database = filepath.Join(dir, "history.db")
	cfg.Socket = filepath.Join(dir, "vigil.sock")
	cfg.FlushMS = 20
	set, err := detect.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		type outcome struct {
			status pipeline.Status
			err    error
		}
		done := make(chan outcome, 1)
		go func() { s, err := pipeline.Live(ctx, cfg, set, nil); done <- outcome{s, err} }()
		ready := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			b, err := api.Get(context.Background(), cfg.Socket, "status")
			if err == nil {
				var s pipeline.Status
				if json.Unmarshal(b, &s) == nil && s.State == "running" {
					ready = true
					break
				}
			}
			select {
			case o := <-done:
				cancel()
				t.Fatalf("sensor stopped at startup: %v", o.err)
			default:
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			cancel()
			t.Fatal("sensor did not become ready")
		}
		if b, err := exec.Command(binary, "fork").CombinedOutput(); err != nil {
			cancel()
			t.Fatalf("workload: %v %s", err, b)
		}
		// Query while live, then cancel and require a finite, fully committed drain.
		if _, err := api.Get(context.Background(), cfg.Socket, "events?limit=10"); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		select {
		case o := <-done:
			if o.err != nil {
				t.Fatal(o.err)
			}
			if o.status.Persisted < 3 || o.status.QueueDrops != 0 || o.status.Malformed != 0 {
				t.Fatalf("bad final status: %+v", o.status)
			}
			t.Logf("run %d status: %+v", attempt, o.status)
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown hung")
		}
		if _, err := os.Stat(cfg.Socket); !os.IsNotExist(err) {
			t.Fatal("socket not removed after shutdown", err)
		}
	}
	s, err := store.OpenReadOnly(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Query(context.Background(), "alerts", store.Query{Limit: 100})
	if err != nil || len(rows) < 2 {
		t.Fatal("alerts not durable", err, len(rows))
	}
}

func TestRingPressureIsCountedAndDrains(t *testing.T) {
	requireKernel(t)
	c, err := probe.OpenWithRingSize(4096)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Intentionally leave the reader idle while a benign workload fills the ring.
	for i := 0; i < 30; i++ {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.RingLost == 0 {
		t.Fatal("pressure did not produce a loss counter")
	}
	t.Logf("pressure counters: %+v", s)
	if err = c.Drain(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for {
			b, err := c.Read()
			if probe.IsClosed(err) {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
			if _, err = event.Decode(b); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("full ring did not drain")
	}
}
