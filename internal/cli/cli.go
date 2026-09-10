// Package cli implements the sensor's command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"

	"vigil/internal/api"
	"vigil/internal/config"
	"vigil/internal/detect"
	"vigil/internal/event"
	"vigil/internal/pipeline"
	"vigil/internal/probe"
	"vigil/internal/replay"
	"vigil/internal/store"
)

const Version = "0.1.0-dev"
const usage = `Vigil — Linux endpoint security sensor

Usage:
  vigil doctor
  vigil run [--config FILE] [--db FILE] [--socket PATH] [--rules FILE] [--duration 10s]
  vigil replay --input FILE [--db FILE] [--rules FILE]
  vigil rules validate [--rules FILE]
  vigil status [--socket PATH]
  vigil events|alerts|ps [--db FILE | --socket PATH] [--process KEY] [--limit N]
  vigil inspect|timeline --process KEY [--db FILE | --socket PATH]
  vigil version

Live capture requires Linux amd64 and privileges to load BPF programs.
Replay and offline queries work without kernel privileges. Output is JSON.
`

func flags(name string, errout io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(errout)
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return nil
}

func Run(ctx context.Context, args []string, out, errout io.Writer) error {
	if len(args) == 0 {
		_, err := io.WriteString(out, usage)
		return err
	}
	enc := json.NewEncoder(out)
	switch args[0] {
	case "help", "--help", "-h":
		_, err := io.WriteString(out, usage)
		return err
	case "version":
		_, err := fmt.Fprintln(out, Version)
		return err
	case "doctor":
		if len(args) != 1 {
			return errors.New("doctor takes no arguments")
		}
		checks := probe.Doctor()
		if err := enc.Encode(checks); err != nil {
			return err
		}
		for _, c := range checks {
			if !c.OK {
				return errors.New("capability checks failed; see diagnostic output")
			}
		}
		return nil
	case "run":
		return live(ctx, args[1:], out, errout)
	case "replay":
		return replayFile(ctx, args[1:], out, errout)
	case "rules":
		if len(args) < 2 || args[1] != "validate" {
			return errors.New("usage: vigil rules validate [--rules FILE]")
		}
		f := flags("rules validate", errout)
		filename := f.String("rules", "", "rules YAML; empty uses embedded defaults")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		set, err := detect.Load(*filename)
		if err != nil {
			return err
		}
		return enc.Encode(map[string]any{"valid": true, "rules": len(set.Rules)})
	case "status", "events", "alerts", "ps", "inspect", "timeline":
		return query(ctx, args, out, errout)
	default:
		return fmt.Errorf("unknown command %q; use vigil help", args[0])
	}
}

func live(ctx context.Context, args []string, out, errout io.Writer) error {
	f := flags("run", errout)
	file := f.String("config", "", "configuration YAML")
	db := f.String("db", "", "database override")
	socket := f.String("socket", "", "Unix socket override")
	rules := f.String("rules", "", "rules override")
	duration := f.Duration("duration", 0, "optional capture duration")
	if err := parse(f, args); err != nil {
		return err
	}
	if *duration < 0 {
		return errors.New("duration cannot be negative")
	}
	cfg, err := config.Load(*file)
	if err != nil {
		return err
	}
	if *db != "" {
		cfg.Database = *db
	}
	if *socket != "" {
		cfg.Socket = *socket
	}
	if *rules != "" {
		cfg.Rules = *rules
	}
	set, err := detect.Load(cfg.Rules)
	if err != nil {
		return err
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	enc := json.NewEncoder(out)
	status, err := pipeline.Live(ctx, cfg, set, func(a event.Alert) error { return enc.Encode(a) })
	_ = json.NewEncoder(errout).Encode(status)
	return err
}

func replayFile(ctx context.Context, args []string, out, errout io.Writer) error {
	f := flags("replay", errout)
	input := f.String("input", "", "normalized JSONL input (required)")
	dbfile := f.String("db", "", "optional SQLite output")
	rules := f.String("rules", "", "rules YAML")
	if err := parse(f, args); err != nil {
		return err
	}
	if *input == "" {
		return errors.New("replay requires --input FILE")
	}
	set, err := detect.Load(*rules)
	if err != nil {
		return err
	}
	engine, err := detect.New(set, 32768, 10000)
	if err != nil {
		return err
	}
	in, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer in.Close()
	var db *store.Store
	if *dbfile != "" {
		db, err = store.Open(*dbfile, 50000, 10000)
		if err != nil {
			return err
		}
		defer db.Close()
	}
	enc := json.NewEncoder(out)
	err = replay.Read(in, func(ev event.Event) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, a, err := engine.Process(ev)
		if err != nil {
			return err
		}
		if db != nil {
			if err = db.Write(ctx, []store.Record{{Event: ev, Node: n, Alerts: a}}); err != nil {
				return err
			}
		}
		for _, alert := range a {
			if err = enc.Encode(alert); err != nil {
				return err
			}
		}
		return nil
	})
	_ = json.NewEncoder(errout).Encode(engine.Stats)
	return err
}

func query(ctx context.Context, args []string, out, errout io.Writer) error {
	f := flags(args[0], errout)
	dbfile := f.String("db", "", "offline database (read-only)")
	socket := f.String("socket", config.Default().Socket, "live Unix socket")
	key := f.String("process", "", "stable process key")
	kind := f.String("type", "", "event type filter")
	count := f.Int("limit", 100, "result limit (1..10000)")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *count < 1 || *count > 10000 {
		return errors.New("limit must be 1..10000")
	}
	if (args[0] == "inspect" || args[0] == "timeline") && *key == "" {
		return errors.New("inspect and timeline require --process KEY")
	}
	resource := args[0]
	switch resource {
	case "ps", "inspect":
		resource = "processes"
	case "timeline":
		resource = "events"
	}
	if *dbfile != "" {
		s, err := store.OpenReadOnly(*dbfile)
		if err != nil {
			return err
		}
		defer s.Close()
		if resource == "status" {
			c, err := s.Counts(ctx)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(c)
		}
		rows, err := s.Query(ctx, resource, store.Query{Process: *key, Type: *kind, Limit: *count})
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(rows)
	}
	q := url.Values{"limit": {strconv.Itoa(*count)}, "process": {*key}, "type": {*kind}}
	b, err := api.Get(ctx, *socket, resource+"?"+q.Encode())
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(b)
}
