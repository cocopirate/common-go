package jobx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONB is a jsonb column that round-trips as raw JSON.
//
// It exists (rather than a bare json.RawMessage) because Scan has to accept the
// two shapes a driver hands back — []byte from lib/pq/pgx and string from
// sqlite — and because a NULL column must come back as an empty value, not as
// the four bytes "null": IsZero and len checks throughout this package read the
// empty value as "no data" and a literal "null" would read as data.
//
// Unparseable input is rejected at the driver boundary (Value) rather than
// written: a malformed summary is unreadable forever, and the column is what the
// console reads progress and artifact pointers out of.
type JSONB json.RawMessage

func (j *JSONB) Scan(v any) error {
	if v == nil {
		*j = nil
		return nil
	}
	var raw []byte
	switch t := v.(type) {
	case []byte:
		raw = t
	case string:
		raw = []byte(t)
	default:
		return fmt.Errorf("jobx.JSONB: unsupported type %T", v)
	}
	if len(raw) == 0 {
		*j = nil
		return nil
	}
	// Copied: drivers may reuse the backing array across rows.
	cp := append([]byte(nil), raw...)
	*j = JSONB(cp)
	return nil
}

func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	if !json.Valid(j) {
		return nil, fmt.Errorf("jobx.JSONB: invalid json")
	}
	return []byte(j), nil
}

func (j JSONB) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

func (j *JSONB) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		*j = nil
		return nil
	}
	*j = JSONB(append([]byte(nil), b...))
	return nil
}

// JSONFrom marshals v into a JSONB. A value that cannot be marshalled becomes
// nil (SQL NULL) rather than an error: every caller is on a path that is
// already committing a task row, and failing there would lose the task.
func JSONFrom(v any) JSONB {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return JSONB(b)
}

// JSONToMap reads a JSONB object as a map. A non-object or malformed value
// returns an empty map, so callers can merge into it unconditionally.
func JSONToMap(j JSONB) map[string]any {
	out := map[string]any{}
	if len(j) == 0 {
		return out
	}
	_ = json.Unmarshal(j, &out)
	return out
}
