package policy

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidDataClassification identifies an unknown sensitivity label.
	ErrInvalidDataClassification = errors.New("invalid data classification")
)

// DataClassification identifies a declared data sensitivity class.
type DataClassification string

const (
	// DataClassificationPublic identifies data intended for unrestricted disclosure.
	DataClassificationPublic DataClassification = "public"
	// DataClassificationInternal identifies non-public organization or project data.
	DataClassificationInternal DataClassification = "internal"
	// DataClassificationConfidential identifies sensitive data requiring approved handling.
	DataClassificationConfidential DataClassification = "confidential"
	// DataClassificationRestricted identifies data requiring the strongest handling controls.
	DataClassificationRestricted DataClassification = "restricted"
)

// Validate verifies that the classification is known.
func (c DataClassification) Validate() error {
	if _, ok := dataClassificationRank(c); !ok {
		return fmt.Errorf("validate data classification: %w", ErrInvalidDataClassification)
	}
	return nil
}

// Compare orders two valid classifications from least to most sensitive.
func (c DataClassification) Compare(other DataClassification) (int, error) {
	left, leftOK := dataClassificationRank(c)
	right, rightOK := dataClassificationRank(other)
	if !leftOK || !rightOK {
		return 0, fmt.Errorf("compare data classification: %w", ErrInvalidDataClassification)
	}
	switch {
	case left < right:
		return -1, nil
	case left > right:
		return 1, nil
	default:
		return 0, nil
	}
}

func dataClassificationRank(classification DataClassification) (uint8, bool) {
	switch classification {
	case DataClassificationPublic:
		return 1, true
	case DataClassificationInternal:
		return 2, true
	case DataClassificationConfidential:
		return 3, true
	case DataClassificationRestricted:
		return 4, true
	default:
		return 0, false
	}
}
