package scope

import (
	"fmt"
	"time"
)

// Duration is a time.Duration that marshals to and from YAML strings such as
// "10s". Plain numbers are interpreted as seconds, which keeps hand-written
// scope files forgiving without ever silently meaning nanoseconds.
type Duration time.Duration

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String renders the duration.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML accepts "10s", "1m30s" or a bare number of seconds.
//
// The value is decoded as an untyped scalar rather than tried as a string
// first, because YAML will happily hand the integer 5 to a string variable:
// decoding as a string and parsing would then fail on the missing unit, and a
// bare number would be unreachable despite being documented.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var v any
	if err := unmarshal(&v); err != nil {
		return fmt.Errorf("duration must be a string like %q or a number of seconds", "10s")
	}
	switch t := v.(type) {
	case string:
		p, err := time.ParseDuration(t)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", t, err)
		}
		*d = Duration(p)
	case int:
		*d = Duration(time.Duration(t) * time.Second)
	case int64:
		*d = Duration(time.Duration(t) * time.Second)
	case float64:
		*d = Duration(time.Duration(t * float64(time.Second)))
	default:
		return fmt.Errorf("duration must be a string like %q or a number of seconds", "10s")
	}
	return nil
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }
