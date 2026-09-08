// Package replay streams bounded normalized JSONL through the live processing path.
package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"vigil/internal/event"
)

func Read(r io.Reader, consume func(event.Event) error) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 64<<10)
	line := 0
	for s.Scan() {
		line++
		b := bytes.TrimSpace(s.Bytes())
		if len(b) == 0 {
			continue
		}
		var ev event.Event
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&ev); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		var trailing any
		if err := d.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("line %d: multiple JSON values", line)
		}
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := consume(ev); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("line %d: %w", line+1, err)
	}
	return nil
}
