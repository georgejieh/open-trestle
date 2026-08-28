package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SourceAdapterKind identifies a source protocol and object-model family.
type SourceAdapterKind string

// SourceAdapterCapability identifies a statically declared source operation.
type SourceAdapterCapability string

const (
	SourceAdapterKindGit SourceAdapterKind = "git"

	SourceCapabilityReadManifest SourceAdapterCapability = "read_manifest"
	SourceCapabilityReadContent  SourceAdapterCapability = "read_content"
	SourceCapabilityReadDiff     SourceAdapterCapability = "read_diff"

	maxSourceAdapterNameBytes    = 128
	maxSourceAdapterVersionBytes = 32
	maxSourceAdapterCapabilities = 3
)

// SourceAdapterIdentity records a canonical source adapter self-description.
type SourceAdapterIdentity struct {
	identity     string
	kind         SourceAdapterKind
	name         string
	version      string
	majorVersion uint32
	capabilities []SourceAdapterCapability
}

// NewSourceAdapterIdentity validates a static source adapter descriptor.
func NewSourceAdapterIdentity(kind SourceAdapterKind, name, version string, capabilities []SourceAdapterCapability) (SourceAdapterIdentity, error) {
	if kind != SourceAdapterKindGit {
		return SourceAdapterIdentity{}, fmt.Errorf("unsupported source adapter kind %q", kind)
	}
	if err := validateSourceAdapterName(name); err != nil {
		return SourceAdapterIdentity{}, err
	}
	majorVersion, err := parseSourceAdapterVersion(version)
	if err != nil {
		return SourceAdapterIdentity{}, err
	}
	if len(capabilities) == 0 || len(capabilities) > maxSourceAdapterCapabilities {
		return SourceAdapterIdentity{}, fmt.Errorf("source adapter has %d capabilities, want 1 to %d", len(capabilities), maxSourceAdapterCapabilities)
	}
	canonicalCapabilities := append([]SourceAdapterCapability{}, capabilities...)
	for _, capability := range canonicalCapabilities {
		switch capability {
		case SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff:
		default:
			return SourceAdapterIdentity{}, fmt.Errorf("unsupported source adapter capability %q", capability)
		}
	}
	sort.Slice(canonicalCapabilities, func(i, j int) bool {
		return canonicalCapabilities[i] < canonicalCapabilities[j]
	})
	for i := 1; i < len(canonicalCapabilities); i++ {
		if canonicalCapabilities[i] == canonicalCapabilities[i-1] {
			return SourceAdapterIdentity{}, fmt.Errorf("duplicate source adapter capability %q", canonicalCapabilities[i])
		}
	}
	preimage := struct {
		Contract      string                    `json:"contract"`
		SchemaVersion int                       `json:"schema_version"`
		Kind          SourceAdapterKind         `json:"kind"`
		Name          string                    `json:"name"`
		Version       string                    `json:"version"`
		Capabilities  []SourceAdapterCapability `json:"capabilities"`
	}{
		Contract:      "open-trestle/source-adapter-identity",
		SchemaVersion: 1,
		Kind:          kind,
		Name:          name,
		Version:       version,
		Capabilities:  canonicalCapabilities,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return SourceAdapterIdentity{}, fmt.Errorf("encode source adapter identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return SourceAdapterIdentity{
		identity:     hex.EncodeToString(digest[:]),
		kind:         kind,
		name:         name,
		version:      version,
		majorVersion: majorVersion,
		capabilities: canonicalCapabilities,
	}, nil
}

func validateSourceAdapterName(name string) error {
	if len(name) == 0 || len(name) > maxSourceAdapterNameBytes {
		return fmt.Errorf("source adapter name has %d bytes, want 1 to %d", len(name), maxSourceAdapterNameBytes)
	}
	previousSeparator := false
	for i := 0; i < len(name); i++ {
		candidate := name[i]
		if isLowerASCIIAlphanumeric(candidate) {
			previousSeparator = false
			continue
		}
		if candidate != '.' && candidate != '_' && candidate != '-' {
			return fmt.Errorf("source adapter name contains unsupported byte %q", candidate)
		}
		if i == 0 || i == len(name)-1 || previousSeparator {
			return fmt.Errorf("source adapter name has a misplaced separator")
		}
		previousSeparator = true
	}
	return nil
}

func isLowerASCIIAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func parseSourceAdapterVersion(version string) (uint32, error) {
	if len(version) == 0 || len(version) > maxSourceAdapterVersionBytes {
		return 0, fmt.Errorf("source adapter version has %d bytes, want 1 to %d", len(version), maxSourceAdapterVersionBytes)
	}
	components := strings.Split(version, ".")
	if len(components) != 3 {
		return 0, fmt.Errorf("source adapter version must contain three decimal components")
	}
	var majorVersion uint32
	for i, component := range components {
		if len(component) == 0 || len(component) > 1 && component[0] == '0' {
			return 0, fmt.Errorf("source adapter version component %d is not canonical", i)
		}
		for j := 0; j < len(component); j++ {
			if component[j] < '0' || component[j] > '9' {
				return 0, fmt.Errorf("source adapter version component %d is not decimal", i)
			}
		}
		parsed, err := strconv.ParseUint(component, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("source adapter version component %d exceeds uint32", i)
		}
		if i == 0 {
			majorVersion = uint32(parsed)
		}
	}
	return majorVersion, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (a SourceAdapterIdentity) Identity() string {
	return a.identity
}

// Kind returns the source protocol and object-model family.
func (a SourceAdapterIdentity) Kind() SourceAdapterKind {
	return a.kind
}

// Name returns the stable adapter implementation name.
func (a SourceAdapterIdentity) Name() string {
	return a.name
}

// Version returns the exact adapter contract version.
func (a SourceAdapterIdentity) Version() string {
	return a.version
}

// MajorVersion returns the adapter contract major version.
func (a SourceAdapterIdentity) MajorVersion() uint32 {
	return a.majorVersion
}

// Capabilities returns the canonical static capability set.
func (a SourceAdapterIdentity) Capabilities() []SourceAdapterCapability {
	return append([]SourceAdapterCapability{}, a.capabilities...)
}

// HasCapability reports whether the exact capability is declared.
func (a SourceAdapterIdentity) HasCapability(capability SourceAdapterCapability) bool {
	index := sort.Search(len(a.capabilities), func(i int) bool {
		return a.capabilities[i] >= capability
	})
	return index < len(a.capabilities) && a.capabilities[index] == capability
}
