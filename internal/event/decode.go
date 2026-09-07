package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

const WireSize = 384

// Wire mirrors bpf/include/events.h. Padding is explicit; decode never casts memory.
type Wire struct {
	Version       uint16
	Type          uint16
	Size          uint32
	TimeNS        uint64
	StartNS       uint64
	ParentStartNS uint64
	Cgroup        uint64
	Sequence      uint64
	PID           uint32
	TID           uint32
	PPID          uint32
	UID           uint32
	GID           uint32
	CPU           uint32
	Flags         uint32
	OldPID        uint32
	Result        int64
	Family        uint16
	Port          uint16
	Padding       uint32
	Address       [16]byte
	Comm          [16]byte
	Filename      [256]byte
}

func cstring(b []byte) string {
	if n := bytes.IndexByte(b, 0); n >= 0 {
		return string(b[:n])
	}
	return string(b)
}

func Decode(raw []byte) (Event, error) {
	if len(raw) != WireSize {
		return Event{}, fmt.Errorf("wire length %d, want %d", len(raw), WireSize)
	}
	var w Wire
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &w); err != nil {
		return Event{}, err
	}
	if w.Version != Version || w.Size != WireSize {
		return Event{}, fmt.Errorf("unsupported wire header version=%d size=%d", w.Version, w.Size)
	}
	if w.Flags & ^uint32(7) != 0 {
		return Event{}, fmt.Errorf("unknown wire flags %x", w.Flags)
	}
	e := Event{Version: Version, TimeNS: w.TimeNS, Sequence: w.Sequence, Process: Identity{w.PID, w.StartNS}, Parent: Identity{w.PPID, w.ParentStartNS}, TID: w.TID, UID: w.UID, GID: w.GID, Cgroup: w.Cgroup, Comm: cstring(w.Comm[:]), Filename: cstring(w.Filename[:]), FilenameTruncated: w.Flags&1 != 0, ReadError: w.Flags&2 != 0, GroupDead: w.Flags&4 != 0, OldPID: w.OldPID}
	switch w.Type {
	case 1:
		e.Type = Fork
	case 2:
		e.Type = Exec
	case 3:
		e.Type = Exit
	case 4:
		e.Type = Connect
		var addr netip.Addr
		switch w.Family {
		case 2:
			addr = netip.AddrFrom4([4]byte(w.Address[:4]))
		case 10:
			addr = netip.AddrFrom16(w.Address)
		default:
			return Event{}, fmt.Errorf("unsupported address family %d", w.Family)
		}
		e.Network = &Network{Address: addr.String(), Port: w.Port, Result: w.Result}
	default:
		return Event{}, fmt.Errorf("unknown wire type %d", w.Type)
	}
	if !e.Process.Valid() || e.TimeNS == 0 {
		return Event{}, fmt.Errorf("invalid kernel identity/time")
	}
	return e, nil
}
