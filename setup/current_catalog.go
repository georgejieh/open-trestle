package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// CurrentIntegrationPermissionCheckerIdentity identifies the broker-backed
// integration permission checker. It does not grant permission to create tokens.
func CurrentIntegrationPermissionCheckerIdentity() string {
	sum := sha256.Sum256([]byte("open-trestle/setup-checker/v2\x00integration_permissions_validated"))
	return hex.EncodeToString(sum[:])
}

// CurrentCheckerCatalog selects current integration authority while preserving
// every other built-in checker binding. Historical catalogs remain unchanged.
func CurrentCheckerCatalog(profile Profile) (CheckerCatalog, error) {
	historical, err := BuiltInCheckerCatalog(profile)
	if err != nil {
		return CheckerCatalog{}, err
	}
	authorities := historical.Authorities()
	for i := range authorities {
		if authorities[i].Key == CheckIntegrationPermissionsValidated {
			authorities[i].CheckerIdentity = CurrentIntegrationPermissionCheckerIdentity()
		}
	}
	return NewCheckerCatalog(authorities)
}

// NewCurrentPlan creates fresh setup state with current checker authority.
// It does not import or upgrade historical plans or receipts.
func NewCurrentPlan(profile Profile, tenantID, repositoryID, recoveryOwner string, at time.Time) (Plan, error) {
	catalog, err := CurrentCheckerCatalog(profile)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	return NewPlanWithCheckerCatalog(profile, tenantID, repositoryID, recoveryOwner, catalog, at)
}

// currentIntegrationOperationAuthorized separates readable history from current
// authority for integration checks and their dependent webhook checks.
func currentIntegrationOperationAuthorized(plan Plan, key CheckKey) bool {
	if key != CheckIntegrationPermissionsValidated && key != CheckWebhookValidated {
		return true
	}
	identity, found := plan.checkerCatalog.Resolve(CheckIntegrationPermissionsValidated)
	return found && identity == CurrentIntegrationPermissionCheckerIdentity()
}
