// Package event defines Vigil's versioned, portable telemetry format.
package event

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

const Version = 1

type Type string

const (
	Fork    Type = "fork"
	Exec    Type = "exec"
	Exit    Type = "exit"
	Connect Type = "connect"
	Gap     Type = "gap"
)

// Identity uses a kernel-observed group leader birth time, never a PID alone.
type Identity struct {
	PID     uint32 `json:"pid"`
	StartNS uint64 `json:"start_ns"`
}

func (i Identity) Valid() bool { return i.PID != 0 && i.StartNS != 0 }

func (i Identity) Key(host, boot string) string {
	if !i.Valid() {
		return ""
	}
	return fmt.Sprintf("%s/%s/%d/%d", host, boot, i.PID, i.StartNS)
}

type Network struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Result  int64  `json:"result"`
}

func (n Network) Outcome() string {
	if n.Result == 0 {
		return "succeeded"
	}
	if n.Result == -115 {
		return "pending"
	} // Linux EINPROGRESS
	return "failed"
}

type Event struct {
	Version           int      `json:"version"`
	ID                string   `json:"id"`
	Host              string   `json:"host"`
	Boot              string   `json:"boot"`
	Run               string   `json:"run"`
	Sequence          uint64   `json:"sequence"`
	TimeNS            uint64   `json:"time_ns"`
	Type              Type     `json:"type"`
	Process           Identity `json:"process"`
	Parent            Identity `json:"parent,omitempty"`
	TID               uint32   `json:"tid,omitempty"`
	UID               uint32   `json:"uid"`
	GID               uint32   `json:"gid"`
	Cgroup            uint64   `json:"cgroup,omitempty"`
	Comm              string   `json:"comm,omitempty"`
	Filename          string   `json:"filename,omitempty"`
	FilenameTruncated bool     `json:"filename_truncated,omitempty"`
	ReadError         bool     `json:"read_error,omitempty"`
	GroupDead         bool     `json:"group_dead,omitempty"`
	OldPID            uint32   `json:"old_pid,omitempty"`
	Network           *Network `json:"network,omitempty"`
	GapReason         string   `json:"gap_reason,omitempty"`
}

func (e Event) Key() string       { return e.Process.Key(e.Host, e.Boot) }
func (e Event) ParentKey() string { return e.Parent.Key(e.Host, e.Boot) }

func validPart(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func (e Event) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported event version %d", e.Version)
	}
	if !validPart(e.Host) || !validPart(e.Boot) || !validPart(e.Run) {
		return errors.New("host, boot and run must be bounded identifier strings")
	}
	if e.ID == "" || len(e.ID) > 256 || e.TimeNS == 0 {
		return errors.New("event requires id and positive monotonic time")
	}
	if len(e.Comm) > 64 || len(e.Filename) > 4096 || len(e.GapReason) > 1024 {
		return errors.New("event field exceeds limit")
	}
	if e.Type == Gap {
		if e.GapReason == "" {
			return errors.New("gap requires a reason")
		}
		return nil
	}
	if !e.Process.Valid() {
		return errors.New("event requires process PID and birth time")
	}
	switch e.Type {
	case Fork, Exec, Exit:
		if e.Network != nil {
			return errors.New("network payload on non-connect event")
		}
	case Connect:
		if e.Network == nil {
			return errors.New("connect requires network payload")
		}
		if _, err := netip.ParseAddr(e.Network.Address); err != nil {
			return fmt.Errorf("invalid destination: %w", err)
		}
	default:
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	return nil
}

func AlertID(rule, eventID string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + eventID))
	return hex.EncodeToString(h[:16])
}

type Alert struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`
	RuleVersion int      `json:"rule_version"`
	Severity    string   `json:"severity"`
	ProcessKey  string   `json:"process_key"`
	TimeNS      uint64   `json:"time_ns"`
	Summary     string   `json:"summary"`
	Evidence    []Event  `json:"evidence"`
	Coverage    []string `json:"coverage,omitempty"`
}
