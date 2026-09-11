// Package pipeline connects capture, detection and transactional persistence.
package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vigil/internal/api"
	"vigil/internal/config"
	"vigil/internal/detect"
	"vigil/internal/event"
	"vigil/internal/probe"
	"vigil/internal/store"
)

type Status struct {
	State          string       `json:"state"`
	Run            string       `json:"run"`
	Started        time.Time    `json:"started"`
	Kernel         probe.Stats  `json:"kernel"`
	Engine         detect.Stats `json:"engine"`
	QueueDrops     uint64       `json:"queue_drops"`
	Malformed      uint64       `json:"malformed"`
	GraphEvictions uint64       `json:"graph_evictions"`
	Persisted      uint64       `json:"persisted"`
	Uncommitted    uint64       `json:"uncommitted"`
	Limitations    []string     `json:"limitations"`
}

type health struct {
	mu    sync.RWMutex
	value Status
}

func (h *health) get() any { h.mu.RLock(); defer h.mu.RUnlock(); return h.value }

func identifier(filename string) (string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
func newRun() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Live stops on persistence failure rather than falsely reporting durable history.
// onAlert is called only after the corresponding transaction commits.
func Live(ctx context.Context, cfg config.Config, set detect.Ruleset, onAlert func(event.Alert) error) (final Status, err error) {
	if err = cfg.Validate(); err != nil {
		return final, err
	}
	host, err := identifier("/etc/machine-id")
	if err != nil {
		return final, err
	}
	boot, err := identifier("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return final, err
	}
	run, err := newRun()
	if err != nil {
		return final, err
	}
	engine, err := detect.New(set, cfg.MaxProcesses, cfg.MaxRuleState)
	if err != nil {
		return final, err
	}
	db, err := store.Open(cfg.Database, cfg.MaxEvents, cfg.MaxAlerts)
	if err != nil {
		return final, err
	}
	defer db.Close()
	h := &health{value: Status{State: "starting", Run: run, Started: time.Now().UTC(), Limitations: []string{"successful exec only; no argv or pre-attachment history", "connect syscall outcomes, not complete network flows", "kernel filename may be relative or refer to a script", "only this run is held in the live process graph"}}}
	server, err := api.Start(cfg.Socket, db, h.get)
	if err != nil {
		return final, err
	}
	defer server.Close()
	collector, err := probe.OpenWithRingSize(cfg.RingBytes)
	if err != nil {
		return final, err
	}
	defer collector.Close()
	var queueDrops, malformed atomic.Uint64
	queue := make(chan event.Event, cfg.QueueSize)
	readDone := make(chan error, 1)
	go func() {
		defer close(queue)
		for {
			raw, err := collector.Read()
			if err != nil {
				if probe.IsClosed(err) {
					readDone <- nil
				} else {
					readDone <- err
				}
				return
			}
			ev, err := event.Decode(raw)
			if err != nil {
				malformed.Add(1)
				continue
			}
			select {
			case queue <- ev:
			default:
				queueDrops.Add(1)
			}
		}
	}()
	defer func() { collector.Stop(); <-readDone }()
	h.mu.Lock()
	h.value.State = "running"
	h.mu.Unlock()
	ticker := time.NewTicker(time.Duration(cfg.FlushMS) * time.Millisecond)
	defer ticker.Stop()
	healthTick := time.NewTicker(time.Second)
	defer healthTick.Stop()
	var sequence, lastNS uint64
	var lost uint64
	var batch []store.Record
	stamp := func(ev *event.Event) {
		sequence++
		ev.Host = host
		ev.Boot = boot
		ev.Run = run
		ev.Sequence = sequence
		ev.ID = run + "-" + fmt.Sprint(sequence)
		if ev.TimeNS > lastNS {
			lastNS = ev.TimeNS
		}
	}
	process := func(ev event.Event) error {
		stamp(&ev)
		n, alerts, err := engine.Process(ev)
		if err != nil {
			return err
		}
		// Snapshot the mutable graph node before adding it to an asynchronous batch.
		if n != nil {
			copy := *n
			n = &copy
		}
		batch = append(batch, store.Record{Event: ev, Node: n, Alerts: alerts})
		return nil
	}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// Loss counters can change before the next periodic gap record. Conservatively
		// annotate alerts at commit, rather than presenting them as complete evidence.
		s, statsErr := collector.Stats()
		if statsErr != nil {
			return statsErr
		}
		if s.RingLost+s.MapErrors+s.ReadErrors+queueDrops.Load()+malformed.Load() > 0 {
			for i := range batch {
				for j := range batch[i].Alerts {
					batch[i].Alerts[j].Coverage = append(batch[i].Alerts[j].Coverage, "collection counters indicate missing or incomplete telemetry")
				}
			}
		}
		commitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.Write(commitCtx, batch); err != nil {
			return fmt.Errorf("persistence failed; stopping capture: %w", err)
		}
		h.mu.Lock()
		h.value.Persisted += uint64(len(batch))
		h.mu.Unlock()
		for _, r := range batch {
			for _, a := range r.Alerts {
				if onAlert != nil {
					if err := onAlert(a); err != nil {
						return err
					}
				}
			}
		}
		batch = batch[:0]
		return nil
	}
	update := func() error {
		s, err := collector.Stats()
		if err != nil {
			return err
		}
		total := s.RingLost + s.MapErrors + s.ReadErrors + queueDrops.Load() + malformed.Load()
		if total > lost && lastNS > 0 {
			if err := process(event.Event{Version: 1, Type: event.Gap, TimeNS: lastNS, GapReason: fmt.Sprintf("collection counters increased by %d; affected events may be missing or incomplete", total-lost)}); err != nil {
				return err
			}
			lost = total
		}
		h.mu.Lock()
		h.value.Kernel = s
		h.value.Engine = engine.Stats
		h.value.QueueDrops = queueDrops.Load()
		h.value.Malformed = malformed.Load()
		h.value.GraphEvictions = engine.Graph.Evictions
		if lost > 0 || engine.Stats.Late > 0 || engine.Stats.StateDrops > 0 || engine.Graph.Evictions > 0 {
			h.value.State = "degraded"
		}
		h.mu.Unlock()
		return nil
	}
	defer func() {
		h.mu.Lock()
		h.value.Engine = engine.Stats
		h.value.QueueDrops = queueDrops.Load()
		h.value.Malformed = malformed.Load()
		h.value.GraphEvictions = engine.Graph.Evictions
		h.value.State = "stopped"
		h.value.Uncommitted = engine.Stats.Events - h.value.Persisted
		if err != nil {
			h.value.State = "failed"
		}
		final = h.value
		h.mu.Unlock()
	}()
	first := true
	for {
		select {
		case <-ctx.Done():
			if err = collector.Drain(); err != nil {
				return final, err
			}
			// Reader closure gives a finite queue to drain before the final commit.
			for ev := range queue {
				if first {
					first = false
					if err = process(event.Event{Version: 1, Type: event.Gap, TimeNS: ev.TimeNS, GapReason: "sensor start: history before attachment is unavailable"}); err != nil {
						return final, err
					}
				}
				if err = process(ev); err != nil {
					return final, err
				}
				if len(batch) >= cfg.BatchSize {
					if err = flush(); err != nil {
						return final, err
					}
				}
			}
			if err = update(); err != nil {
				return final, err
			}
			err = flush()
			return final, err
		case ev, ok := <-queue:
			if !ok {
				return final, fmt.Errorf("kernel event reader stopped unexpectedly")
			}
			if first {
				first = false
				if err = process(event.Event{Version: 1, Type: event.Gap, TimeNS: ev.TimeNS, GapReason: "sensor start: history before attachment is unavailable"}); err != nil {
					return final, err
				}
			}
			if err = process(ev); err != nil {
				return final, err
			}
			if len(batch) >= cfg.BatchSize {
				if err = flush(); err != nil {
					return final, err
				}
			}
		case <-ticker.C:
			if err = flush(); err != nil {
				return final, err
			}
		case <-healthTick.C:
			if err = update(); err != nil {
				return final, err
			}
		}
	}
}
