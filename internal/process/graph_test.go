package process

import (
	"testing"
	"vigil/internal/event"
)

func sample(pid uint32, start, time uint64, typ event.Type) event.Event {
	return event.Event{Version: 1, Host: "host", Boot: "boot", Run: "run", ID: "id", Process: event.Identity{PID: pid, StartNS: start}, TimeNS: time, Type: typ}
}

func TestPIDReuseAndThreadExit(t *testing.T) {
	g := New(10)
	e := sample(2, 1, 10, event.Exec)
	e.Filename = "/bin/one"
	g.Apply(e)
	e.Type = event.Exit
	e.TimeNS = 20
	g.Apply(e)
	if g.Get(e.Key()).Exited {
		t.Fatal("thread exit closed process")
	}
	e.GroupDead = true
	g.Apply(e)
	if !g.Get(e.Key()).Exited {
		t.Fatal("last-thread exit missed")
	}
	fresh := sample(2, 30, 40, event.Exec)
	g.Apply(fresh)
	if g.Len() != 2 || g.Get(fresh.Key()).Exited {
		t.Fatal("PID reused old state")
	}
}

func TestLateEventAndBoundedAncestry(t *testing.T) {
	g := New(2)
	p := sample(1, 1, 2, event.Exec)
	g.Apply(p)
	e := sample(2, 3, 4, event.Exec)
	e.Parent = p.Process
	e.Filename = "/bin/new"
	g.Apply(e)
	e.TimeNS = 3
	e.Filename = "/bin/old"
	g.Apply(e)
	if g.Get(e.Key()).Filename != "/bin/new" || len(g.Ancestors(e.Key(), 10)) != 1 {
		t.Fatal("history corrupted")
	}
	g.Apply(sample(3, 5, 6, event.Exec))
	if g.Len() != 2 || g.Evictions != 1 {
		t.Fatal("unbounded graph")
	}
}

func TestCreatorSurvivesReparenting(t *testing.T) {
	g := New(10)
	e := sample(3, 1, 10, event.Fork)
	e.Run = "r"
	e.Parent = event.Identity{PID: 2, StartNS: 1}
	g.Apply(e)
	e.Type = event.Exec
	e.TimeNS = 20
	e.Parent = event.Identity{PID: 1, StartNS: 1}
	n := g.Apply(e)
	if n.ParentKey != "host/boot/2/1" || n.Run != "r" {
		t.Fatal("creator/run changed", n)
	}
}
