package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxEncodedInventoryBytes = 8 << 20

type routeInventoryWire struct {
	SchemaVersion int                   `json:"schema_version"`
	Routes        []routeDefinitionWire `json:"routes"`
}
type routeDefinitionWire struct {
	Zone                           string   `json:"zone"`
	ProviderID                     string   `json:"provider_id"`
	AdapterID                      string   `json:"adapter_id"`
	ConnectionID                   string   `json:"connection_id"`
	ModelID                        string   `json:"model_id"`
	ModelVersion                   string   `json:"model_version"`
	MaxContextTokens               uint64   `json:"max_context_tokens"`
	MaxOutputTokens                uint64   `json:"max_output_tokens"`
	Features                       []string `json:"features"`
	ContentLogging                 string   `json:"content_logging"`
	PricingKnown                   bool     `json:"pricing_known"`
	InputMicroUSDPerMillionTokens  uint64   `json:"input_micro_usd_per_million_tokens"`
	OutputMicroUSDPerMillionTokens uint64   `json:"output_micro_usd_per_million_tokens"`
	Quality                        string   `json:"quality"`
	RegistryRevision               uint64   `json:"registry_revision"`
	RegistryStatus                 string   `json:"registry_status"`
	EvidenceManifestBase64         string   `json:"evidence_manifest_base64"`
	OperationalRevision            uint64   `json:"operational_revision"`
	Health                         string   `json:"health"`
	Quota                          string   `json:"quota"`
	PerformanceRevision            uint64   `json:"performance_revision"`
	LatencyKnown                   bool     `json:"latency_known"`
	P95LatencyMilliseconds         uint32   `json:"p95_latency_milliseconds"`
	LatencySampleCount             uint32   `json:"latency_sample_count"`
}

func DecodeRouteInventory(ctx context.Context, reader io.Reader) (RouteInventory, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil {
		return RouteInventory{}, ErrInvalidRouteInventory
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxEncodedInventoryBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxEncodedInventoryBytes || validateUniqueJSONKeys(encoded) != nil {
		return RouteInventory{}, ErrInvalidRouteInventory
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire routeInventoryWire
	if decoder.Decode(&wire) != nil || wire.SchemaVersion != 1 || decoder.Decode(&struct{}{}) != io.EOF {
		return RouteInventory{}, ErrInvalidRouteInventory
	}
	definitions := make([]RouteDefinition, len(wire.Routes))
	for index, value := range wire.Routes {
		definition, err := decodeRouteDefinition(value)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		definitions[index] = definition
	}
	return NewRouteInventory(ctx, definitions)
}
func decodeRouteDefinition(value routeDefinitionWire) (RouteDefinition, error) {
	zone, err := provider.ParseProviderZone(value.Zone)
	if err != nil {
		return RouteDefinition{}, err
	}
	route, err := provider.NewRouteReference(zone, value.ProviderID, value.AdapterID, value.ConnectionID, value.ModelID, value.ModelVersion)
	if err != nil {
		return RouteDefinition{}, err
	}
	features := make([]provider.ModelFeature, len(value.Features))
	for index, token := range value.Features {
		features[index], err = provider.ParseModelFeature(token)
		if err != nil {
			return RouteDefinition{}, err
		}
	}
	capabilities, err := provider.NewModelCapabilities(value.MaxContextTokens, value.MaxOutputTokens, features)
	if err != nil {
		return RouteDefinition{}, err
	}
	logging, err := provider.ParseContentLoggingMode(value.ContentLogging)
	if err != nil {
		return RouteDefinition{}, err
	}
	var pricing provider.RoutePricing
	if value.PricingKnown {
		pricing, err = provider.NewRoutePricing(value.InputMicroUSDPerMillionTokens, value.OutputMicroUSDPerMillionTokens)
	} else {
		if value.InputMicroUSDPerMillionTokens != 0 || value.OutputMicroUSDPerMillionTokens != 0 {
			return RouteDefinition{}, ErrInvalidRouteInventory
		}
		pricing = provider.NewUnknownRoutePricing()
	}
	if err != nil {
		return RouteDefinition{}, err
	}
	quality, err := provider.ParseRouteQualityTier(value.Quality)
	if err != nil {
		return RouteDefinition{}, err
	}
	status, err := provider.ParseRouteRegistryStatus(value.RegistryStatus)
	if err != nil {
		return RouteDefinition{}, err
	}
	manifest, err := base64.StdEncoding.Strict().DecodeString(value.EvidenceManifestBase64)
	if err != nil {
		return RouteDefinition{}, err
	}
	health, err := provider.ParseRouteHealth(value.Health)
	if err != nil {
		return RouteDefinition{}, err
	}
	quota, err := provider.ParseRouteQuota(value.Quota)
	if err != nil {
		return RouteDefinition{}, err
	}
	if !value.LatencyKnown && (value.P95LatencyMilliseconds != 0 || value.LatencySampleCount != 0) || value.LatencyKnown && (value.P95LatencyMilliseconds == 0 || value.LatencySampleCount == 0) {
		return RouteDefinition{}, ErrInvalidRouteInventory
	}
	return RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: logging, Pricing: pricing, Quality: quality, RegistryRevision: value.RegistryRevision, RegistryStatus: status, EvidenceManifest: manifest, OperationalRevision: value.OperationalRevision, Health: health, Quota: quota, PerformanceRevision: value.PerformanceRevision, P95LatencyMilliseconds: value.P95LatencyMilliseconds, LatencySampleCount: value.LatencySampleCount}, nil
}
func validateUniqueJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
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
			key, ok := keyToken.(string)
			if !ok || !canonicalJSONKey(key) {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON key")
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
		return fmt.Errorf("unexpected JSON delimiter")
	}
}
func canonicalJSONKey(key string) bool {
	if key == "" {
		return false
	}
	for _, value := range key {
		if value != '_' && (value < 'a' || value > 'z') && (value < '0' || value > '9') {
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
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}
