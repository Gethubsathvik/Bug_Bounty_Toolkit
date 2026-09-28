package models

import "errors"

// Validation errors surfaced by models. Callers should compare with errors.Is.
var (
	ErrFindingNoID                = errors.New("finding: missing id")
	ErrFindingNoType              = errors.New("finding: missing type")
	ErrFindingBadSeverity         = errors.New("finding: invalid severity")
	ErrFindingBadConfidence       = errors.New("finding: invalid confidence")
	ErrFindingNoFirstSeen         = errors.New("finding: missing first_seen")
	ErrFindingNoVerificationSteps = errors.New("finding: manual verification required but no steps given")
	ErrTargetNoValue              = errors.New("target: missing value")
	ErrTargetBadKind              = errors.New("target: invalid kind")
)
