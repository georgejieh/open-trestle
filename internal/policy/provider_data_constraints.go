package policy

import "strings"

// ProviderDataConstraints binds privacy inputs for a later route decision.
type ProviderDataConstraints struct {
	classification        DataClassification
	allowedZones          AllowedProviderZones
	contentLoggingAllowed bool
}

// NewProviderDataConstraints creates immutable provider data constraints.
func NewProviderDataConstraints(classification DataClassification, allowedZones AllowedProviderZones, contentLoggingAllowed bool) (ProviderDataConstraints, error) {
	if err := classification.Validate(); err != nil {
		return ProviderDataConstraints{}, err
	}
	if err := allowedZones.Validate(); err != nil {
		return ProviderDataConstraints{}, err
	}
	return ProviderDataConstraints{
		classification:        DataClassification(strings.Clone(string(classification))),
		allowedZones:          allowedZones,
		contentLoggingAllowed: contentLoggingAllowed,
	}, nil
}

// Classification returns the declared data sensitivity.
func (c ProviderDataConstraints) Classification() DataClassification { return c.classification }

// AllowedProviderZones returns the immutable provider zone allowance.
func (c ProviderDataConstraints) AllowedProviderZones() AllowedProviderZones { return c.allowedZones }

// ContentLoggingAllowed reports whether valid constraints permit provider logging of raw or reconstructable content.
func (c ProviderDataConstraints) ContentLoggingAllowed() bool {
	return c.Validate() == nil && c.contentLoggingAllowed
}

// Validate verifies that every privacy input is valid.
func (c ProviderDataConstraints) Validate() error {
	if err := c.classification.Validate(); err != nil {
		return err
	}
	return c.allowedZones.Validate()
}
