package detect

import (
	"fmt"
	"testing"

	"vigil/internal/event"
)

func ev(id int, pid uint32, start, sec uint64, filename string) event.Event {
	return event.Event{Version: 1, ID: fmt.Sprint(id), Host: "host", Boot: "boot", Run: "run", Type: event.Exec, TimeNS: sec * 1e9, Process: event.Identity{PID: pid, StartNS: start}, Filename: filename}
}

func engine(t *testing.T) *Engine {
	t.Helper()
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(s, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func feed(t *testing.T, e *Engine, v event.Event) []event.Alert {
	t.Helper()
	_, a, err := e.Process(v)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServerShellAndNegative(t *testing.T) {
	e := engine(t)
	p := ev(1, 10, 1, 1, "/usr/sbin/nginx")
	feed(t, e, p)
	c := ev(2, 11, 2, 2, "/bin/sh")
	c.Parent = p.Process
	a := feed(t, e, c)
	if len(a) != 1 || a[0].Rule != "VIGIL-001" || len(a[0].Evidence) != 2 {
		t.Fatalf("alerts: %+v", a)
	}
	if a := feed(t, e, c); len(a) != 0 || e.Stats.Duplicates != 1 {
		t.Fatal("duplicate alert")
	}
	n := ev(3, 12, 3, 3, "/usr/bin/true")
	n.Parent = p.Process
	if len(feed(t, e, n)) != 0 {
		t.Fatal("benign child alerted")
	}
}

func TestNetworkWindowPIDReuseAndUnknown(t *testing.T) {
	e := engine(t)
	p := ev(1, 10, 1, 1, "/bin/bash")
	feed(t, e, p)
	c := p
	c.ID = "2"
	c.Type = event.Connect
	c.TimeNS = 2e9
	c.Filename = ""
	c.Network = &event.Network{Address: "127.0.0.1", Port: 9, Result: -115}
	a := feed(t, e, c)
	if len(a) != 1 || a[0].Rule != "VIGIL-003" {
		t.Fatal(a)
	}
	c.ID = "3"
	c.TimeNS = 3e9
	c.Process.StartNS = 99
	if len(feed(t, e, c)) != 0 {
		t.Fatal("PID reuse matched old exec")
	}
	c.Process = p.Process
	c.ID = "4"
	c.TimeNS = 100e9
	if len(feed(t, e, c)) != 0 {
		t.Fatal("expired exec matched")
	}
}

func TestDownloadSequenceGapAndPathBoundary(t *testing.T) {
	e := engine(t)
	p := event.Identity{PID: 10, StartNS: 1}
	d := ev(1, 11, 2, 1, "/usr/bin/curl")
	d.Parent = p
	feed(t, e, d)
	x := ev(2, 12, 3, 2, "/tmp/payload")
	x.Parent = p
	if a := feed(t, e, x); len(a) != 2 {
		t.Fatalf("want temp+sequence, got %v", a)
	}
	gap := ev(3, 0, 0, 3, "")
	gap.Type = event.Gap
	gap.GapReason = "lost records"
	feed(t, e, gap)
	x = ev(4, 13, 4, 4, "/tmp/next")
	x.Parent = p
	if a := feed(t, e, x); len(a) != 1 || len(a[0].Coverage) == 0 {
		t.Fatal(a)
	}
	if a := feed(t, e, ev(5, 14, 5, 5, "/tmp-not/normal")); len(a) != 0 {
		t.Fatal("path prefix false positive")
	}
	x = ev(6, 15, 6, 6, "/tmp/truncated")
	x.FilenameTruncated = true
	if len(feed(t, e, x)) != 0 {
		t.Fatal("truncated path matched")
	}
}

func TestBoundedStateLateAndValidation(t *testing.T) {
	e := engine(t)
	e.maxState = 2
	for i := 1; i < 10; i++ {
		feed(t, e, ev(i, uint32(i), uint64(i), uint64(i), "/tmp/a"))
	}
	if len(e.cooldown) > 2 || len(e.recent) > 2 || e.Stats.StateDrops == 0 {
		t.Fatal("unbounded state")
	}
	feed(t, e, ev(20, 20, 20, 1, "/tmp/a"))
	if e.Stats.Late != 1 {
		t.Fatal("late not counted")
	}
	if _, err := Parse([]byte("version: 1\nunknown: true\nrules: []\n")); err == nil {
		t.Fatal("unknown fields accepted")
	}
	s, _ := Load("")
	s.Rules[0].Kind = "arbitrary-code"
	if s.Validate() == nil {
		t.Fatal("unknown rule accepted")
	}
}
