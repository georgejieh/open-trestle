package policy

import (
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrDuplicateProviderZone identifies a repeated zone in one allowance input.
	ErrDuplicateProviderZone = errors.New("duplicate provider zone")
)

// AllowedProviderZones is an immutable set of zones a later route decision may consider.
type AllowedProviderZones struct {
	zones uint8
}

// NewAllowedProviderZones creates a canonical provider zone allowance.
func NewAllowedProviderZones(zones ...provider.ProviderZone) (AllowedProviderZones, error) {
	var zoneBits uint8
	for _, zone := range zones {
		bit, ok := providerZoneBit(zone)
		if !ok {
			return AllowedProviderZones{}, fmt.Errorf("validate provider zone allowance: %w", provider.ErrInvalidProviderZone)
		}
		if zoneBits&bit != 0 {
			return AllowedProviderZones{}, fmt.Errorf("validate provider zone allowance: %w", ErrDuplicateProviderZone)
		}
		zoneBits |= bit
	}
	return AllowedProviderZones{zones: zoneBits}, nil
}

// Allows reports whether the allowance contains one known provider zone.
func (a AllowedProviderZones) Allows(zone provider.ProviderZone) bool {
	bit, ok := providerZoneBit(zone)
	return ok && a.zones&bit != 0
}

// Validate verifies that the allowance contains only known provider zones.
func (a AllowedProviderZones) Validate() error {
	if a.zones&^validProviderZoneBits() != 0 {
		return fmt.Errorf("validate provider zone allowance: %w", provider.ErrInvalidProviderZone)
	}
	return nil
}

func providerZoneBit(zone provider.ProviderZone) (uint8, bool) {
	if zone < provider.ProviderZoneLocal || zone > provider.ProviderZoneSubscriptionOAuth || zone.String() == "" {
		return 0, false
	}
	return 1 << (zone - 1), true
}

func validProviderZoneBits() uint8 {
	return (1 << uint8(provider.ProviderZoneSubscriptionOAuth)) - 1
}
