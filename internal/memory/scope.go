package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxScopeIdentifierBytes = 128
	maxScopePathPrefixes    = 64
	maxScopePathBytes       = 1_024
)

var (
	// ErrInvalidScopeIdentifier identifies a malformed tenant, repository, or actor ID.
	ErrInvalidScopeIdentifier = errors.New("invalid memory scope identifier")
	// ErrInvalidRefVisibility identifies an unknown ref reachability mode.
	ErrInvalidRefVisibility = errors.New("invalid memory ref visibility")
	// ErrInvalidRefSetIdentity identifies a malformed server-derived ref set digest.
	ErrInvalidRefSetIdentity = errors.New("invalid memory ref set identity")
	// ErrInvalidScopePathPrefix identifies a missing, unsafe, or excessive repository path prefix.
	ErrInvalidScopePathPrefix = errors.New("invalid memory scope path prefix")
	// ErrDuplicateScopePathPrefix identifies a repeated path authorization.
	ErrDuplicateScopePathPrefix = errors.New("duplicate memory scope path prefix")
	// ErrInvalidScopeIdentity identifies scope fields inconsistent with their content identity.
	ErrInvalidScopeIdentity = errors.New("invalid memory scope identity")
)

// RefVisibility identifies how the server computed the authorized ref set.
type RefVisibility uint8

const (
	RefVisibilityExact RefVisibility = iota + 1
	RefVisibilityReachable
)

func (v RefVisibility) String() string {
	switch v {
	case RefVisibilityExact:
		return "exact"
	case RefVisibilityReachable:
		return "reachable"
	default:
		return ""
	}
}

// ParseRefVisibility parses one exact stable visibility token.
func ParseRefVisibility(value string) (RefVisibility, error) {
	for visibility := RefVisibilityExact; visibility <= RefVisibilityReachable; visibility++ {
		if visibility.String() == value {
			return visibility, nil
		}
	}
	return 0, ErrInvalidRefVisibility
}

func (v RefVisibility) Validate() error {
	if v.String() == "" {
		return ErrInvalidRefVisibility
	}
	return nil
}

// Scope is a hard memory storage, query, cache, and ranking partition.
type Scope struct {
	identity       string
	tenantID       string
	repositoryID   string
	actorID        string
	refVisibility  RefVisibility
	refSetIdentity string
	pathPrefixes   []string
}

// NewScope creates one immutable server-authorized memory partition.
func NewScope(tenantID, repositoryID, actorID string, visibility RefVisibility, refSetIdentity string, pathPrefixes []string) (Scope, error) {
	for _, identifier := range []string{tenantID, repositoryID, actorID} {
		if !validScopeIdentifier(identifier) {
			return Scope{}, ErrInvalidScopeIdentifier
		}
	}
	if err := visibility.Validate(); err != nil {
		return Scope{}, err
	}
	if !validDigest(refSetIdentity) {
		return Scope{}, ErrInvalidRefSetIdentity
	}
	prefixes, err := canonicalScopePathPrefixes(pathPrefixes)
	if err != nil {
		return Scope{}, err
	}
	scope := Scope{
		tenantID: strings.Clone(tenantID), repositoryID: strings.Clone(repositoryID), actorID: strings.Clone(actorID),
		refVisibility: visibility, refSetIdentity: strings.Clone(refSetIdentity), pathPrefixes: prefixes,
	}
	scope.identity = deriveScopeIdentity(scope)
	return scope, nil
}

func (s Scope) Identity() string             { return s.identity }
func (s Scope) TenantID() string             { return s.tenantID }
func (s Scope) RepositoryID() string         { return s.repositoryID }
func (s Scope) ActorID() string              { return s.actorID }
func (s Scope) RefVisibility() RefVisibility { return s.refVisibility }
func (s Scope) RefSetIdentity() string       { return s.refSetIdentity }
func (s Scope) PathPrefixes() []string       { return append([]string(nil), s.pathPrefixes...) }
func (s Scope) String() string               { return "memory scope" }
func (s Scope) GoString() string             { return "memory.Scope{<redacted>}" }
func (s Scope) Format(state fmt.State, verb rune) {
	formatted := "memory scope"
	if verb == 'q' {
		formatted = `"memory scope"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "memory.Scope{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// AllowsPath reports whether one clean repository-relative path is authorized.
func (s Scope) AllowsPath(candidate string) bool {
	if s.Validate() != nil || !validRepositoryPath(candidate, false) {
		return false
	}
	for _, prefix := range s.pathPrefixes {
		if prefix == "." || candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}
	return false
}

// Validate verifies partition fields, canonical prefix reduction, and identity.
func (s Scope) Validate() error {
	for _, identifier := range []string{s.tenantID, s.repositoryID, s.actorID} {
		if !validScopeIdentifier(identifier) {
			return ErrInvalidScopeIdentifier
		}
	}
	if err := s.refVisibility.Validate(); err != nil {
		return err
	}
	if !validDigest(s.refSetIdentity) {
		return ErrInvalidRefSetIdentity
	}
	canonical, err := canonicalScopePathPrefixes(s.pathPrefixes)
	if err != nil {
		return err
	}
	if len(canonical) != len(s.pathPrefixes) {
		return ErrInvalidScopePathPrefix
	}
	for index := range canonical {
		if canonical[index] != s.pathPrefixes[index] {
			return ErrInvalidScopePathPrefix
		}
	}
	if s.identity != deriveScopeIdentity(s) {
		return ErrInvalidScopeIdentity
	}
	return nil
}

func canonicalScopePathPrefixes(prefixes []string) ([]string, error) {
	if len(prefixes) == 0 || len(prefixes) > maxScopePathPrefixes {
		return nil, ErrInvalidScopePathPrefix
	}
	canonical := append([]string(nil), prefixes...)
	seen := make(map[string]struct{}, len(canonical))
	for _, prefix := range canonical {
		if !validRepositoryPath(prefix, true) {
			return nil, ErrInvalidScopePathPrefix
		}
		if _, exists := seen[prefix]; exists {
			return nil, ErrDuplicateScopePathPrefix
		}
		seen[prefix] = struct{}{}
	}
	sort.Strings(canonical)
	reduced := make([]string, 0, len(canonical))
	for _, prefix := range canonical {
		covered := false
		for _, parent := range reduced {
			if parent == "." || strings.HasPrefix(prefix, parent+"/") {
				covered = true
				break
			}
		}
		if !covered {
			reduced = append(reduced, strings.Clone(prefix))
		}
	}
	return reduced, nil
}

func validRepositoryPath(value string, allowRoot bool) bool {
	if len(value) == 0 || len(value) > maxScopePathBytes || !utf8.ValidString(value) || path.IsAbs(value) || path.Clean(value) != value || strings.ContainsRune(value, '\\') {
		return false
	}
	if value == "." {
		return allowRoot
	}
	if value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func validScopeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxScopeIdentifierBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return isScopeAlphaNumeric(value[0]) && isScopeAlphaNumeric(value[len(value)-1])
}

func isScopeAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func deriveScopeIdentity(scope Scope) string {
	preimage := struct {
		Contract       string   `json:"contract"`
		Version        int      `json:"version"`
		Tenant         string   `json:"tenant"`
		Repository     string   `json:"repository"`
		Actor          string   `json:"actor"`
		RefVisibility  string   `json:"ref_visibility"`
		RefSetIdentity string   `json:"ref_set_identity"`
		PathPrefixes   []string `json:"path_prefixes"`
	}{
		Contract: "open-trestle/memory-scope", Version: 1,
		Tenant: scope.tenantID, Repository: scope.repositoryID, Actor: scope.actorID,
		RefVisibility: scope.refVisibility.String(), RefSetIdentity: scope.refSetIdentity,
		PathPrefixes: scope.pathPrefixes,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
