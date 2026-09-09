//go:build linux && amd64

package probe

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Collector struct {
	objects    sensorObjects
	links      []link.Link
	reader     *ringbuf.Reader
	once       sync.Once
	detachOnce sync.Once
}

func Open() (_ *Collector, err error) {
	c := &Collector{}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("BPF memory accounting: %w", err)
	}
	spec, err := loadSensor()
	if err != nil {
		return nil, err
	}
	if err = spec.LoadAndAssign(&c.objects, nil); err != nil {
		return nil, fmt.Errorf("load BPF programs (need BTF and BPF permissions): %w", err)
	}
	for _, p := range []struct {
		name    string
		program *ebpf.Program
	}{{"sched_process_fork", c.objects.OnFork}, {"sched_process_exec", c.objects.OnExec}, {"sched_process_exit", c.objects.OnExit}} {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: p.name, Program: p.program})
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", p.name, err)
		}
		c.links = append(c.links, l)
	}
	for _, p := range []struct {
		name    string
		program *ebpf.Program
	}{{"sys_enter_connect", c.objects.OnConnectEnter}, {"sys_exit_connect", c.objects.OnConnectExit}} {
		l, err := link.Tracepoint("syscalls", p.name, p.program, nil)
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", p.name, err)
		}
		c.links = append(c.links, l)
	}
	c.reader, err = ringbuf.NewReader(c.objects.Events)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Collector) Read() ([]byte, error) {
	r, err := c.reader.Read()
	if err != nil {
		return nil, err
	}
	return r.RawSample, nil
}

func (c *Collector) Stats() (Stats, error) {
	var values []sensorVigilStats
	if err := c.objects.Stats.Lookup(uint32(0), &values); err != nil {
		return Stats{}, err
	}
	var s Stats
	for _, v := range values {
		s.Emitted += v.Emitted
		s.RingLost += v.RingLost
		s.ReadErrors += v.ReadErrors
		s.MapErrors += v.MapErrors
	}
	return s, nil
}

// Stop unblocks Read. Close subsequently detaches programs and releases maps.
func (c *Collector) Stop() {
	if c.reader != nil {
		_ = c.reader.Close()
	}
}

// Drain detaches producers, then wakes the reader after all pending records.
func (c *Collector) Drain() error {
	c.detach()
	return c.reader.Flush()
}
func (c *Collector) detach() {
	c.detachOnce.Do(func() {
		for i := len(c.links) - 1; i >= 0; i-- {
			_ = c.links[i].Close()
		}
	})
}
func (c *Collector) Close() {
	c.once.Do(func() {
		c.detach()
		c.Stop()
		_ = c.objects.Close()
	})
}
func IsClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed)
}

func Doctor() []Check {
	checks := []Check{{"platform", true, "linux/amd64"}}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	checks = append(checks, check("kernel_btf", err))
	checks = append(checks, check("ring_buffer", features.HaveMapType(ebpf.RingBuf)), check("raw_tracepoint", features.HaveProgramType(ebpf.RawTracepoint)))
	// Actual load + attachment is the authoritative capability test and is cleaned up.
	c, err := Open()
	checks = append(checks, check("load_and_attach", err))
	if c != nil {
		c.Close()
	}
	return checks
}

func check(name string, err error) Check {
	if err == nil {
		return Check{name, true, "available"}
	}
	detail := err.Error()
	if !errors.Is(err, ebpf.ErrNotSupported) {
		detail = "failed or inconclusive (check privileges/configuration): " + detail
	}
	return Check{name, false, detail}
}
