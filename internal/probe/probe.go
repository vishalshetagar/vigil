// Package probe provides the platform-specific kernel collector.
package probe

type Stats struct {
	Emitted    uint64 `json:"emitted"`
	RingLost   uint64 `json:"ring_lost"`
	ReadErrors uint64 `json:"read_errors"`
	MapErrors  uint64 `json:"map_errors"`
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}
