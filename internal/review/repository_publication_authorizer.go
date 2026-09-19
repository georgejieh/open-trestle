package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
)

var ErrInvalidRepositoryPublicationAuthorizer = errors.New("invalid repository publication authorizer")

type RepositoryPublicationAuthorizer struct {
	identity, tenantID, repositoryID, policyIdentity, principalIdentity string
	lifetime                                                            time.Duration
}

func NewRepositoryPublicationAuthorizer(tenantID, repositoryID, policyIdentity, principalIdentity string, lifetime time.Duration) (*RepositoryPublicationAuthorizer, error) {
	if _, err := audit.NewReviewScope(tenantID, repositoryID, "authority-probe"); err != nil || !nonzeroPublicationAuthority(policyIdentity) || !nonzeroPublicationAuthority(principalIdentity) || lifetime < time.Minute || lifetime > 24*time.Hour || lifetime%time.Millisecond != 0 {
		return nil, ErrInvalidRepositoryPublicationAuthorizer
	}
	value := &RepositoryPublicationAuthorizer{tenantID: strings.Clone(tenantID), repositoryID: strings.Clone(repositoryID), policyIdentity: strings.Clone(policyIdentity), principalIdentity: strings.Clone(principalIdentity), lifetime: lifetime}
	value.identity = deriveRepositoryPublicationAuthorizerIdentity(value)
	return value, nil
}
func (a *RepositoryPublicationAuthorizer) Identity() string {
	if a == nil {
		return ""
	}
	return a.identity
}
func (a *RepositoryPublicationAuthorizer) Validate() error {
	if a == nil {
		return ErrInvalidRepositoryPublicationAuthorizer
	}
	probe, err := NewRepositoryPublicationAuthorizer(a.tenantID, a.repositoryID, a.policyIdentity, a.principalIdentity, a.lifetime)
	if err != nil || probe.identity != a.identity {
		return ErrInvalidRepositoryPublicationAuthorizer
	}
	return nil
}
func (a *RepositoryPublicationAuthorizer) Authorize(ctx context.Context, scope audit.ReviewScope, plan PublicationPlan, at time.Time) (PublicationAuthorization, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || scope.Validate() != nil || plan.Validate() != nil || scope.TenantID() != a.tenantID || scope.RepositoryID() != a.repositoryID || plan.ReviewScopeIdentity() != scope.Identity() || at.IsZero() {
		return PublicationAuthorization{}, ErrInvalidRepositoryPublicationAuthorizer
	}
	issued := at.UTC().Truncate(time.Millisecond)
	expires := issued.Add(a.lifetime)
	effect, err := policy.NewEffectAuthorization(a.policyIdentity, a.principalIdentity, scope.Identity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationRepositoryPolicy, issued, expires)
	if err != nil {
		return PublicationAuthorization{}, ErrInvalidRepositoryPublicationAuthorizer
	}
	authorization, err := NewPublicationAuthorization(plan, effect, issued)
	if err != nil {
		return PublicationAuthorization{}, err
	}
	return authorization, nil
}
func deriveRepositoryPublicationAuthorizerIdentity(a *RepositoryPublicationAuthorizer) string {
	encoded, _ := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Tenant     string `json:"tenant"`
		Repository string `json:"repository"`
		Policy     string `json:"policy"`
		Principal  string `json:"principal"`
		Lifetime   int64  `json:"lifetime_milliseconds"`
	}{"open-trestle/repository-publication-authorizer", 1, a.tenantID, a.repositoryID, a.policyIdentity, a.principalIdentity, a.lifetime.Milliseconds()})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func nonzeroPublicationAuthority(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, v := range decoded {
		if v != 0 {
			return true
		}
	}
	return false
}
