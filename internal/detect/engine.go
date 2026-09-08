// Package detect evaluates a bounded set of explainable behavioral rules.
package detect

import (
	"container/list"
	"fmt"
	"path"
	"strings"

	"vigil/internal/event"
	"vigil/internal/process"
)

type temporal struct {
	evidence event.Event
	expires  uint64
}
type Stats struct {
	Events     uint64 `json:"events"`
	Alerts     uint64 `json:"alerts"`
	Duplicates uint64 `json:"duplicates"`
	Late       uint64 `json:"late"`
	StateDrops uint64 `json:"state_drops"`
	Gaps       uint64 `json:"gaps"`
}

type Engine struct {
	Graph     *process.Graph
	Rules     Ruleset
	Stats     Stats
	maxState  int
	clock     uint64
	scope     string
	recent    map[string]*list.Element
	order     *list.List
	cooldown  map[string]uint64
	downloads map[string]temporal
	degraded  bool
}

func New(set Ruleset, maxProcesses, maxState int) (*Engine, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	if maxState < 1 {
		return nil, fmt.Errorf("state capacity must be positive")
	}
	return &Engine{Graph: process.New(maxProcesses), Rules: set, maxState: maxState, recent: map[string]*list.Element{}, order: list.New(), cooldown: map[string]uint64{}, downloads: map[string]temporal{}}, nil
}

func matches(filename string, choices []string) bool {
	if !path.IsAbs(filename) {
		return false
	}
	for _, v := range choices {
		if filename == v || !strings.Contains(v, "/") && path.Base(filename) == v {
			return true
		}
	}
	return false
}

func under(filename string, dirs []string) bool {
	if !path.IsAbs(filename) {
		return false
	}
	filename = path.Clean(filename)
	for _, d := range dirs {
		if strings.HasPrefix(filename, path.Clean(d)+"/") {
			return true
		}
	}
	return false
}

func within(now, then, seconds uint64) bool { return now >= then && now-then <= seconds*1e9 }

// Process is deterministic and single-owner. Live and replay use this same path.
func (e *Engine) Process(ev event.Event) (*process.Node, []event.Alert, error) {
	if err := ev.Validate(); err != nil {
		return nil, nil, err
	}
	scope := ev.Host + "/" + ev.Boot + "/" + ev.Run
	if e.scope != "" && scope != e.scope {
		return nil, nil, fmt.Errorf("stream changes host, boot, or sensor run; replay each run separately")
	}
	e.scope = scope
	if _, ok := e.recent[ev.ID]; ok {
		e.Stats.Duplicates++
		return nil, nil, nil
	}
	if len(e.recent) >= e.maxState {
		front := e.order.Front()
		delete(e.recent, front.Value.(string))
		e.order.Remove(front)
	}
	e.recent[ev.ID] = e.order.PushBack(ev.ID)
	e.Stats.Events++
	if ev.TimeNS < e.clock {
		e.Stats.Late++
		return nil, nil, nil
	}
	e.clock = ev.TimeNS
	for k, v := range e.cooldown {
		if v <= e.clock {
			delete(e.cooldown, k)
		}
	}
	for k, v := range e.downloads {
		if v.expires < e.clock {
			delete(e.downloads, k)
		}
	}
	if ev.Type == event.Gap {
		e.Stats.Gaps++
		e.degraded = true
		clear(e.downloads)
		clear(e.cooldown)
		return nil, nil, nil
	}
	before := e.Graph.Evictions
	n := e.Graph.Apply(ev)
	if e.Graph.Evictions > before {
		e.degraded = true
	}
	var alerts []event.Alert
	for _, r := range e.Rules.Rules {
		var evidence []event.Event
		var summary string
		reliablePath := !ev.ReadError && !ev.FilenameTruncated
		switch r.Kind {
		case "server_shell":
			if ev.Type == event.Exec && reliablePath && matches(ev.Filename, r.Executables) {
				for _, a := range e.Graph.Ancestors(ev.Key(), 8) {
					if a.Exec != nil && !a.Exec.ReadError && !a.Exec.FilenameTruncated && matches(a.Filename, r.Ancestors) {
						evidence = []event.Event{*a.Exec, ev}
						summary = "Configured server ancestry launched a shell"
						break
					}
				}
			}
		case "temp_exec":
			if ev.Type == event.Exec && reliablePath && under(ev.Filename, r.Directories) {
				evidence = []event.Event{ev}
				summary = "Successful exec reported a filename in a configured temporary directory"
			}
		case "shell_connect":
			if ev.Type == event.Connect && n.Exec != nil && !n.Exec.ReadError && !n.Exec.FilenameTruncated && matches(n.Filename, r.Executables) && within(ev.TimeNS, n.Exec.TimeNS, r.WindowSeconds) {
				evidence = []event.Event{*n.Exec, ev}
				summary = "Shell or interpreter initiated an outbound connect (" + ev.Network.Outcome() + ")"
			}
		case "download_exec":
			if ev.Type != event.Exec || !reliablePath {
				break
			}
			// Scope to the immediate creator. Do not correlate all children of init.
			scope := n.ParentKey
			if ev.Parent.PID <= 1 || scope == "" {
				break
			}
			k := r.ID + ":" + scope
			if under(ev.Filename, r.Directories) {
				if d, ok := e.downloads[k]; ok && within(ev.TimeNS, d.evidence.TimeNS, r.WindowSeconds) {
					evidence = []event.Event{d.evidence, ev}
					summary = "Downloader execution preceded temporary-path execution under the same creator; file linkage is unproven"
				}
			}
			if matches(ev.Filename, r.Executables) {
				if _, ok := e.downloads[k]; ok || len(e.downloads) < e.maxState {
					e.downloads[k] = temporal{ev, ev.TimeNS + r.WindowSeconds*1e9}
				} else {
					e.Stats.StateDrops++
					e.degraded = true
				}
			}
		}
		if len(evidence) == 0 {
			continue
		}
		key := r.ID + ":" + ev.Key()
		if until := e.cooldown[key]; until > ev.TimeNS {
			continue
		}
		if len(e.cooldown) >= e.maxState {
			e.Stats.StateDrops++
			e.degraded = true
			continue
		}
		e.cooldown[key] = ev.TimeNS + r.CooldownSeconds*1e9
		a := event.Alert{ID: event.AlertID(r.ID, ev.ID), Rule: r.ID, RuleVersion: r.Version, Severity: r.Severity, ProcessKey: ev.Key(), TimeNS: ev.TimeNS, Summary: summary, Evidence: evidence}
		if n.Partial {
			a.Coverage = append(a.Coverage, "process creation was not observed")
		}
		if e.degraded {
			a.Coverage = append(a.Coverage, "stream contains an observation gap or state eviction")
		}
		alerts = append(alerts, a)
	}
	e.Stats.Alerts += uint64(len(alerts))
	return n, alerts, nil
}
