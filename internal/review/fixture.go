package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/policy"
)

const (
	fixtureSchemaVersion = 1
	maxFixtureBytes      = 1 << 20
)

// Fixture is a validated, content-addressed local review input.
type Fixture struct {
	identity              string
	request               ReviewRequest
	providerRoute         config.ProviderRoute
	requestedCapabilities []policy.Capability
}

// LoadFixture decodes and validates one local review fixture.
func LoadFixture(reader io.Reader, configuration config.LocalConfig) (Fixture, error) {
	if configuration.ProviderRoute() != config.ProviderRouteLocal {
		return Fixture{}, fmt.Errorf("local fixture configuration is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxFixtureBytes+1))
	if err != nil {
		return Fixture{}, fmt.Errorf("read fixture: %w", err)
	}
	if len(content) > maxFixtureBytes {
		return Fixture{}, fmt.Errorf("fixture exceeds %d bytes", maxFixtureBytes)
	}
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return Fixture{}, fmt.Errorf("validate fixture keys: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var wire fixtureWire
	if err := decoder.Decode(&wire); err != nil {
		return Fixture{}, fmt.Errorf("decode fixture: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return Fixture{}, fmt.Errorf("fixture must contain exactly one JSON value")
		}
		return Fixture{}, fmt.Errorf("decode trailing fixture content: %w", err)
	}
	if wire.SchemaVersion != fixtureSchemaVersion {
		return Fixture{}, fmt.Errorf("unsupported fixture schema version: %d", wire.SchemaVersion)
	}
	if config.ProviderRoute(wire.ProviderRoute) != configuration.ProviderRoute() {
		return Fixture{}, fmt.Errorf("provider route %q is not permitted", wire.ProviderRoute)
	}
	if wire.RequestedCapabilities == nil {
		wire.RequestedCapabilities = make([]policy.Capability, 0)
	}
	for _, capability := range wire.RequestedCapabilities {
		decision, err := configuration.Decide(capability)
		if err != nil {
			return Fixture{}, fmt.Errorf("evaluate requested capability %q: %w", capability, err)
		}
		if decision.Outcome() != policy.DecisionAllow {
			return Fixture{}, newOutcomeError(OutcomeBlocked, fmt.Errorf("requested capability %q is denied: %s", capability, decision.Reason()))
		}
	}

	ranges := make([]evidence.SourceRange, len(wire.Request.Snapshot.Ranges))
	for i, wireRange := range wire.Request.Snapshot.Ranges {
		sourceRange, err := evidence.NewSourceRange(wireRange.Path, wireRange.StartLine, wireRange.EndLine)
		if err != nil {
			return Fixture{}, fmt.Errorf("validate source range %d: %w", i, err)
		}
		ranges[i] = sourceRange
	}
	snapshot, err := NewReviewSnapshot(wire.Request.Snapshot.Workspace, wire.Request.Snapshot.Revision, ranges)
	if err != nil {
		return Fixture{}, fmt.Errorf("validate snapshot: %w", err)
	}
	request, err := NewReviewRequest(wire.Request.ID, snapshot)
	if err != nil {
		return Fixture{}, fmt.Errorf("validate request: %w", err)
	}

	canonical, err := json.Marshal(wire)
	if err != nil {
		return Fixture{}, fmt.Errorf("encode canonical fixture: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return Fixture{
		identity:              hex.EncodeToString(digest[:]),
		request:               request,
		providerRoute:         configuration.ProviderRoute(),
		requestedCapabilities: append([]policy.Capability(nil), wire.RequestedCapabilities...),
	}, nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	return scanJSONValue(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, isString := keyToken.(string)
			if !isString {
				return fmt.Errorf("object key must be a string")
			}
			if !isCanonicalJSONKey(key) {
				return fmt.Errorf("JSON key must use lowercase ASCII spelling: %q", key)
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON key: %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected JSON delimiter: %q", delimiter)
	}
}

func isCanonicalJSONKey(key string) bool {
	if key == "" {
		return false
	}
	for _, value := range key {
		if value != '_' && (value < 'a' || value > 'z') {
			return false
		}
	}
	return true
}

func consumeJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return fmt.Errorf("unexpected JSON delimiter: %q", token)
	}
	return nil
}

// Identity returns the canonical SHA-256 fixture identity.
func (f Fixture) Identity() string {
	return f.identity
}

// Request returns the validated review request.
func (f Fixture) Request() ReviewRequest {
	return f.request
}

// ProviderRoute returns the validated provider route.
func (f Fixture) ProviderRoute() config.ProviderRoute {
	return f.providerRoute
}

// RequestedCapabilities returns a copy of requested runtime capabilities.
func (f Fixture) RequestedCapabilities() []policy.Capability {
	return append([]policy.Capability(nil), f.requestedCapabilities...)
}

type fixtureWire struct {
	SchemaVersion         int                 `json:"schema_version"`
	ProviderRoute         string              `json:"provider_route"`
	RequestedCapabilities []policy.Capability `json:"requested_capabilities"`
	Request               requestWire         `json:"request"`
}

type requestWire struct {
	ID       string       `json:"id"`
	Snapshot snapshotWire `json:"snapshot"`
}

type snapshotWire struct {
	Workspace string      `json:"workspace"`
	Revision  string      `json:"revision"`
	Ranges    []rangeWire `json:"ranges"`
}

type rangeWire struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
