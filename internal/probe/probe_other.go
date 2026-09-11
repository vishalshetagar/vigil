//go:build !linux || !amd64

package probe

import "errors"

var errPlatform = errors.New("live capture requires Linux amd64; replay and history queries work on this platform")

type Collector struct{}

func Open() (*Collector, error)                   { return nil, errPlatform }
func OpenWithRingSize(uint32) (*Collector, error) { return nil, errPlatform }
func (*Collector) Read() ([]byte, error)          { return nil, errPlatform }
func (*Collector) Stats() (Stats, error)          { return Stats{}, errPlatform }
func (*Collector) Stop()                          {}
func (*Collector) Drain() error                   { return errPlatform }
func (*Collector) Close()                         {}
func IsClosed(error) bool                         { return false }
func Doctor() []Check                             { return []Check{{"platform", false, errPlatform.Error()}} }
