package detect

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"go.yaml.in/yaml/v3"
)

//go:embed default.yaml
var defaultRules []byte

type Ruleset struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

type Rule struct {
	ID              string   `yaml:"id" json:"id"`
	Version         int      `yaml:"version" json:"version"`
	Kind            string   `yaml:"kind" json:"kind"`
	Severity        string   `yaml:"severity" json:"severity"`
	Executables     []string `yaml:"executables" json:"executables,omitempty"`
	Ancestors       []string `yaml:"ancestors" json:"ancestors,omitempty"`
	Directories     []string `yaml:"directories" json:"directories,omitempty"`
	WindowSeconds   uint64   `yaml:"window_seconds" json:"window_seconds"`
	CooldownSeconds uint64   `yaml:"cooldown_seconds" json:"cooldown_seconds"`
}

func Load(filename string) (Ruleset, error) {
	b := defaultRules
	if filename != "" {
		var err error
		b, err = os.ReadFile(filename)
		if err != nil {
			return Ruleset{}, err
		}
	}
	return Parse(b)
}

func Parse(b []byte) (Ruleset, error) {
	var set Ruleset
	if len(b) > 1<<20 {
		return set, errors.New("rules file exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&set); err != nil {
		return set, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return set, errors.New("expected a single YAML document")
	}
	return set, set.Validate()
}

func (s Ruleset) Validate() error {
	if s.Version != 1 || len(s.Rules) == 0 || len(s.Rules) > 64 {
		return errors.New("ruleset requires version 1 and 1..64 rules")
	}
	seen := map[string]bool{}
	for _, r := range s.Rules {
		if r.ID == "" || len(r.ID) > 64 || seen[r.ID] || r.Version < 1 {
			return fmt.Errorf("invalid or duplicate rule ID/version: %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Severity {
		case "low", "medium", "high":
		default:
			return fmt.Errorf("%s: invalid severity", r.ID)
		}
		if r.WindowSeconds == 0 || r.WindowSeconds > 3600 || r.CooldownSeconds > 3600 {
			return fmt.Errorf("%s: window must be 1..3600s and cooldown <=3600s", r.ID)
		}
		for _, list := range [][]string{r.Executables, r.Ancestors, r.Directories} {
			if len(list) > 128 {
				return fmt.Errorf("%s: too many predicates", r.ID)
			}
			for _, s := range list {
				if s == "" || len(s) > 256 {
					return fmt.Errorf("%s: invalid predicate", r.ID)
				}
			}
		}
		for _, dir := range r.Directories {
			if !path.IsAbs(dir) || path.Clean(dir) == "/" {
				return fmt.Errorf("%s: directories must be absolute and narrower than root", r.ID)
			}
		}
		switch r.Kind {
		case "server_shell":
			if len(r.Executables) == 0 || len(r.Ancestors) == 0 {
				return fmt.Errorf("%s: executables and ancestors required", r.ID)
			}
		case "temp_exec":
			if len(r.Directories) == 0 {
				return fmt.Errorf("%s: directories required", r.ID)
			}
		case "shell_connect":
			if len(r.Executables) == 0 {
				return fmt.Errorf("%s: executables required", r.ID)
			}
		case "download_exec":
			if len(r.Executables) == 0 || len(r.Directories) == 0 {
				return fmt.Errorf("%s: executables and directories required", r.ID)
			}
		default:
			return fmt.Errorf("%s: unknown kind %q", r.ID, r.Kind)
		}
	}
	return nil
}
