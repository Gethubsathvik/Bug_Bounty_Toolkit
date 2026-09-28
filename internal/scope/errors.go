package scope

import "errors"

var (
	// ErrInvalidHost is returned when a host cannot be canonicalized safely.
	ErrInvalidHost = errors.New("scope: invalid host")
	// ErrInvalidAddr is returned when an IP/CIDR literal cannot be parsed.
	ErrInvalidAddr = errors.New("scope: invalid address")
	// ErrInvalidRule is returned for a malformed scope rule.
	ErrInvalidRule = errors.New("scope: invalid rule")
	// ErrNoScope is returned when an operation requiring scope is attempted
	// without a loaded scope.
	ErrNoScope = errors.New("scope: no scope configured")
	// ErrTargetDenied is returned when a target is not in scope.
	ErrTargetDenied = errors.New("scope: target denied")
)
