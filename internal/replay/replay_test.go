package replay

import (
	"strings"
	"testing"
	"vigil/internal/event"
)

func TestRejectMalformed(t *testing.T) {
	for _, s := range []string{"{}", `{"version":1,"unknown":1}`, strings.Repeat("x", 70<<10)} {
		if err := Read(strings.NewReader(s), func(event.Event) error { return nil }); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
