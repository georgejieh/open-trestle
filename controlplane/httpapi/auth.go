package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxStaticTokens           = 256
	minCredentialBytes        = 32
	maxCredentialBytes        = 512
	maxPrincipalIdentityBytes = 128
)

var (
	// ErrInvalidPrincipal identifies malformed or ambiguous API authority.
	ErrInvalidPrincipal = errors.New("invalid API principal")
	// ErrInvalidAuthenticator identifies a missing or excessive credential set.
	ErrInvalidAuthenticator = errors.New("invalid API authenticator")
	// ErrInvalidCredential identifies an unsafe configured bearer secret.
	ErrInvalidCredential = errors.New("invalid API credential")
	// ErrDuplicateCredential identifies two authorities bound to one secret.
	ErrDuplicateCredential = errors.New("duplicate API credential")
	// ErrAuthenticationFailed identifies absent or unrecognized credentials.
	ErrAuthenticationFailed = errors.New("API authentication failed")
)

// Capability is a closed authority granted to an authenticated principal.
type Capability uint8

const (
	CapabilityRunRead Capability = iota + 1
	CapabilityRunWrite
	CapabilityTaskClaim
	CapabilityTaskComplete
	CapabilityRuntimeRead
)

func (c Capability) String() string {
	switch c {
	case CapabilityRunRead:
		return "run_read"
	case CapabilityRunWrite:
		return "run_write"
	case CapabilityTaskClaim:
		return "task_claim"
	case CapabilityTaskComplete:
		return "task_complete"
	case CapabilityRuntimeRead:
		return "runtime_read"
	default:
		return ""
	}
}
func (c Capability) Validate() error {
	if c.String() == "" {
		return ErrInvalidPrincipal
	}
	return nil
}

// Principal binds one identity to one tenant and an exact repository allowlist.
type Principal struct {
	identity, tenantID string
	repositories       []string
	capabilities       []Capability
}

func NewPrincipal(identity, tenantID string, repositories []string, capabilities []Capability) (Principal, error) {
	if !validPrincipalIdentity(identity) || len(repositories) == 0 || len(repositories) > 256 || len(capabilities) == 0 || len(capabilities) > 5 {
		return Principal{}, ErrInvalidPrincipal
	}
	if _, err := audit.NewReviewScope(tenantID, "repository-placeholder", "review-run-placeholder"); err != nil {
		return Principal{}, ErrInvalidPrincipal
	}
	canonicalRepositories := append([]string(nil), repositories...)
	sort.Strings(canonicalRepositories)
	for index, repositoryID := range canonicalRepositories {
		if _, err := audit.NewReviewScope(tenantID, repositoryID, "review-run-placeholder"); err != nil {
			return Principal{}, ErrInvalidPrincipal
		}
		if index > 0 && repositoryID == canonicalRepositories[index-1] {
			return Principal{}, ErrInvalidPrincipal
		}
	}
	canonicalCapabilities := append([]Capability(nil), capabilities...)
	sort.Slice(canonicalCapabilities, func(i, j int) bool { return canonicalCapabilities[i] < canonicalCapabilities[j] })
	for index, capability := range canonicalCapabilities {
		if capability.Validate() != nil {
			return Principal{}, ErrInvalidPrincipal
		}
		if index > 0 && capability == canonicalCapabilities[index-1] {
			return Principal{}, ErrInvalidPrincipal
		}
	}
	return Principal{identity: identity, tenantID: tenantID, repositories: canonicalRepositories, capabilities: canonicalCapabilities}, nil
}
func (p Principal) Identity() string           { return p.identity }
func (p Principal) TenantID() string           { return p.tenantID }
func (p Principal) Repositories() []string     { return append([]string(nil), p.repositories...) }
func (p Principal) Capabilities() []Capability { return append([]Capability(nil), p.capabilities...) }
func (p Principal) AllowsRepository(repositoryID string) bool {
	index := sort.SearchStrings(p.repositories, repositoryID)
	return index < len(p.repositories) && p.repositories[index] == repositoryID
}
func (p Principal) HasCapability(capability Capability) bool {
	index := sort.Search(len(p.capabilities), func(i int) bool { return p.capabilities[i] >= capability })
	return index < len(p.capabilities) && p.capabilities[index] == capability
}
func (p Principal) Validate() error {
	rebuilt, err := NewPrincipal(p.identity, p.tenantID, p.repositories, p.capabilities)
	if err != nil || rebuilt.identity != p.identity {
		return ErrInvalidPrincipal
	}
	return nil
}
func (p Principal) String() string   { return "API principal" }
func (p Principal) GoString() string { return "httpapi.Principal{<redacted>}" }
func (p Principal) Format(state fmt.State, verb rune) {
	writeRedactedAPIFormat(state, verb, "API principal", "httpapi.Principal{<redacted>}")
}

// Authenticator resolves an opaque bearer credential without exposing it downstream.
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

// StaticToken is startup configuration. Callers should discard it after construction.
type StaticToken struct {
	Token     string
	Principal Principal
}

// StaticTokenAuthenticator retains only SHA-256 credential digests.
type staticTokenPrincipal struct {
	digest    [sha256.Size]byte
	principal Principal
}
type StaticTokenAuthenticator struct{ principals []staticTokenPrincipal }

func NewStaticTokenAuthenticator(tokens []StaticToken) (*StaticTokenAuthenticator, error) {
	if len(tokens) == 0 || len(tokens) > maxStaticTokens {
		return nil, ErrInvalidAuthenticator
	}
	principals := make([]staticTokenPrincipal, 0, len(tokens))
	for _, entry := range tokens {
		if !validCredential(entry.Token) {
			return nil, ErrInvalidCredential
		}
		if err := entry.Principal.Validate(); err != nil {
			return nil, err
		}
		digest := sha256.Sum256([]byte(entry.Token))
		for _, existing := range principals {
			if subtle.ConstantTimeCompare(existing.digest[:], digest[:]) == 1 {
				return nil, ErrDuplicateCredential
			}
		}
		principals = append(principals, staticTokenPrincipal{digest: digest, principal: entry.Principal})
	}
	return &StaticTokenAuthenticator{principals: principals}, nil
}
func (a *StaticTokenAuthenticator) Authenticate(ctx context.Context, credential string) (Principal, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validCredential(credential) {
		return Principal{}, ErrAuthenticationFailed
	}
	digest := sha256.Sum256([]byte(credential))
	var principal Principal
	matched := 0
	for _, candidate := range a.principals {
		equal := subtle.ConstantTimeCompare(candidate.digest[:], digest[:])
		if equal == 1 {
			principal = candidate.principal
		}
		matched |= equal
	}
	if matched != 1 {
		return Principal{}, ErrAuthenticationFailed
	}
	return principal, nil
}
func validCredential(value string) bool {
	if len(value) < minCredentialBytes || len(value) > maxCredentialBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, " \t\r\n\x00")
}
func validPrincipalIdentity(value string) bool {
	if len(value) == 0 || len(value) > maxPrincipalIdentityBytes || !utf8.ValidString(value) {
		return false
	}
	for index, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || index > 0 && strings.ContainsRune("._:@/-", r)
		if !valid {
			return false
		}
	}
	return true
}
func writeRedactedAPIFormat(state fmt.State, verb rune, plain, goSyntax string) {
	formatted := plain
	if verb == 'q' {
		formatted = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		formatted = goSyntax
	}
	_, _ = state.Write([]byte(formatted))
}
