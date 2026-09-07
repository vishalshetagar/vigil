package event

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecode(t *testing.T) {
	w := Wire{Version: 1, Type: 4, Size: WireSize, TimeNS: 5, PID: 42, StartNS: 3, Family: 2, Port: 443, Result: -115, Flags: 1}
	w.Address = [16]byte{127, 0, 0, 1}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, w); err != nil {
		t.Fatal(err)
	}
	if b.Len() != WireSize {
		t.Fatal("ABI size mismatch", b.Len())
	}
	e, err := Decode(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if e.Network.Address != "127.0.0.1" || e.Network.Outcome() != "pending" || !e.FilenameTruncated {
		t.Fatalf("bad decode: %+v", e)
	}
	bad := append([]byte(nil), b.Bytes()...)
	bad[0] = 99
	if _, err = Decode(bad); err == nil {
		t.Fatal("accepted unknown ABI")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(make([]byte, WireSize))
	f.Add([]byte{1, 2})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b) })
}

func TestIdentity(t *testing.T) {
	a := Identity{42, 10}
	b := Identity{42, 20}
	if a.Key("h", "b") == b.Key("h", "b") {
		t.Fatal("PID reuse collision")
	}
	if a.Key("h", "b") == a.Key("h", "c") {
		t.Fatal("boot collision")
	}
}
