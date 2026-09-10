package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Database     string `yaml:"database"`
	Socket       string `yaml:"socket"`
	Rules        string `yaml:"rules"`
	QueueSize    int    `yaml:"queue_size"`
	BatchSize    int    `yaml:"batch_size"`
	FlushMS      int    `yaml:"flush_ms"`
	MaxProcesses int    `yaml:"max_processes"`
	MaxRuleState int    `yaml:"max_rule_state"`
	MaxEvents    int    `yaml:"max_events"`
	MaxAlerts    int    `yaml:"max_alerts"`
}

func Default() Config {
	return Config{Database: "/var/lib/vigil/history.db", Socket: "/run/vigil/vigil.sock", QueueSize: 8192, BatchSize: 256, FlushMS: 100, MaxProcesses: 32768, MaxRuleState: 10000, MaxEvents: 50000, MaxAlerts: 10000}
}
func Load(filename string) (Config, error) {
	c := Default()
	if filename == "" {
		return c, nil
	}
	b, err := os.ReadFile(filename)
	if err != nil {
		return c, err
	}
	if len(b) > 64<<10 {
		return c, fmt.Errorf("configuration exceeds 64 KiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, fmt.Errorf("expected a single configuration document")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Database == "" || c.Socket == "" {
		return fmt.Errorf("database and socket paths are required")
	}
	for _, v := range []struct {
		name            string
		value, min, max int
	}{{"queue_size", c.QueueSize, 1, 65536}, {"batch_size", c.BatchSize, 1, 1000}, {"flush_ms", c.FlushMS, 10, 5000}, {"max_processes", c.MaxProcesses, 1, 100000}, {"max_rule_state", c.MaxRuleState, 1, 100000}, {"max_events", c.MaxEvents, 1, 10000000}, {"max_alerts", c.MaxAlerts, 1, 100000}} {
		if v.value < v.min || v.value > v.max {
			return fmt.Errorf("%s must be %d..%d", v.name, v.min, v.max)
		}
	}
	return nil
}
