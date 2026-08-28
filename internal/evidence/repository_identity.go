package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxRepositoryNamespaceSegments     = 32
	maxRepositoryNamespaceSegmentBytes = 255
	maxRepositoryNameBytes             = 255
	maxRepositoryScopeBytes            = 4096
	maxRepositoryAuthorityBytes        = 253
	maxRepositoryAuthorityLabelBytes   = 63
)

// RepositoryIdentity records a canonical provider-neutral repository scope tuple.
type RepositoryIdentity struct {
	identity  string
	authority string
	namespace []string
	name      string
}

// NewRepositoryIdentity validates a canonical repository authority and scope.
func NewRepositoryIdentity(authority string, namespace []string, name string) (RepositoryIdentity, error) {
	if err := validateRepositoryAuthority(authority); err != nil {
		return RepositoryIdentity{}, err
	}
	if len(namespace) == 0 || len(namespace) > maxRepositoryNamespaceSegments {
		return RepositoryIdentity{}, fmt.Errorf("repository namespace has %d segments, want 1 to %d", len(namespace), maxRepositoryNamespaceSegments)
	}
	canonicalNamespace := make([]string, len(namespace))
	scopeBytes := len(namespace)
	for i, segment := range namespace {
		if err := validateRepositoryScopeValue("namespace segment", segment, maxRepositoryNamespaceSegmentBytes); err != nil {
			return RepositoryIdentity{}, fmt.Errorf("repository namespace segment %d: %w", i, err)
		}
		canonicalNamespace[i] = segment
		scopeBytes += len(segment)
	}
	if err := validateRepositoryScopeValue("name", name, maxRepositoryNameBytes); err != nil {
		return RepositoryIdentity{}, fmt.Errorf("repository name: %w", err)
	}
	scopeBytes += len(name)
	if scopeBytes > maxRepositoryScopeBytes {
		return RepositoryIdentity{}, fmt.Errorf("repository scope has %d bytes, want at most %d", scopeBytes, maxRepositoryScopeBytes)
	}
	preimage := struct {
		Contract      string   `json:"contract"`
		SchemaVersion int      `json:"schema_version"`
		Authority     string   `json:"authority"`
		Namespace     []string `json:"namespace"`
		Name          string   `json:"name"`
	}{
		Contract:      "open-trestle/repository-identity",
		SchemaVersion: 1,
		Authority:     authority,
		Namespace:     canonicalNamespace,
		Name:          name,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryIdentity{}, fmt.Errorf("encode repository identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryIdentity{
		identity:  hex.EncodeToString(digest[:]),
		authority: authority,
		namespace: canonicalNamespace,
		name:      name,
	}, nil
}

func validateRepositoryAuthority(authority string) error {
	if len(authority) == 0 || len(authority) > maxRepositoryAuthorityBytes {
		return fmt.Errorf("repository authority has %d bytes, want 1 to %d", len(authority), maxRepositoryAuthorityBytes)
	}
	labels := strings.Split(authority, ".")
	if len(labels) == 4 && allDecimalAuthorityLabels(labels) {
		for _, label := range labels {
			if !isCanonicalIPv4Octet(label) {
				return fmt.Errorf("repository authority %q is not canonical IPv4", authority)
			}
		}
		return nil
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > maxRepositoryAuthorityLabelBytes {
			return fmt.Errorf("repository authority label has %d bytes, want 1 to %d", len(label), maxRepositoryAuthorityLabelBytes)
		}
		for i := 0; i < len(label); i++ {
			if !isLowerDNSByte(label[i]) && label[i] != '-' {
				return fmt.Errorf("repository authority contains unsupported byte %q", label[i])
			}
		}
		if !isLowerDNSByte(label[0]) || !isLowerDNSByte(label[len(label)-1]) {
			return fmt.Errorf("repository authority label must start and end with an alphanumeric byte")
		}
	}
	return nil
}

func allDecimalAuthorityLabels(labels []string) bool {
	for _, label := range labels {
		if len(label) == 0 {
			return false
		}
		for i := 0; i < len(label); i++ {
			if label[i] < '0' || label[i] > '9' {
				return false
			}
		}
	}
	return true
}

func isCanonicalIPv4Octet(octet string) bool {
	if len(octet) == 0 || len(octet) > 3 || len(octet) > 1 && octet[0] == '0' {
		return false
	}
	value := 0
	for i := 0; i < len(octet); i++ {
		value = value*10 + int(octet[i]-'0')
	}
	return value <= 255
}

func isLowerDNSByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validateRepositoryScopeValue(field, value string, maxBytes int) error {
	if len(value) == 0 || len(value) > maxBytes {
		return fmt.Errorf("%s has %d bytes, want 1 to %d", field, len(value), maxBytes)
	}
	if value[0] == ' ' || value[len(value)-1] == ' ' {
		return fmt.Errorf("%s must not start or end with a space", field)
	}
	hasAlphanumeric := false
	for i := 0; i < len(value); i++ {
		candidate := value[i]
		if isASCIIAlphanumeric(candidate) {
			hasAlphanumeric = true
			continue
		}
		if candidate != '.' && candidate != '_' && candidate != '-' && candidate != ' ' {
			return fmt.Errorf("%s contains unsupported byte %q", field, candidate)
		}
	}
	if !hasAlphanumeric {
		return fmt.Errorf("%s must contain an ASCII alphanumeric byte", field)
	}
	return nil
}

func isASCIIAlphanumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// Identity returns the versioned canonical SHA-256 identity.
func (r RepositoryIdentity) Identity() string {
	return r.identity
}

// Authority returns the canonical repository authority.
func (r RepositoryIdentity) Authority() string {
	return r.authority
}

// Namespace returns a copy of the ordered repository namespace.
func (r RepositoryIdentity) Namespace() []string {
	return append([]string{}, r.namespace...)
}

// Name returns the exact repository name.
func (r RepositoryIdentity) Name() string {
	return r.name
}
