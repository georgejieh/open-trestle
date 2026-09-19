// Package openai provides a bounded adapter for the OpenAI Responses API.
package openai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	defaultEndpoint       = "https://api.openai.com/v1"
	defaultRequestTimeout = 2 * time.Minute
	maximumRequestTimeout = 5 * time.Minute
	maximumResponseBytes  = 8 << 20
	maximumErrorBodyBytes = 4096
	maximumAPIKeyBytes    = 4096
	maximumHeaderBytes    = 64 << 10
	maximumOutputItems    = 64
)

var (
	// ErrInvalidConfig identifies an unsafe or incomplete adapter configuration.
	ErrInvalidConfig = errors.New("invalid OpenAI adapter configuration")
	// ErrInvalidAPIKey identifies an empty, excessive, or header-unsafe API key.
	ErrInvalidAPIKey = errors.New("invalid OpenAI API key")
	// ErrCredentialsUnavailable identifies a credential provider failure.
	ErrCredentialsUnavailable = errors.New("OpenAI credentials unavailable")
)

// APIKey is an immutable header-safe credential value.
type APIKey struct{ value string }

// NewAPIKey copies and validates one API key.
func NewAPIKey(value []byte) (APIKey, error) {
	key := APIKey{value: string(value)}
	if err := key.Validate(); err != nil {
		return APIKey{}, err
	}
	return key, nil
}

// Validate verifies that the credential remains bounded and safe for an HTTP header.
func (k APIKey) Validate() error {
	if len(k.value) == 0 || len(k.value) > maximumAPIKeyBytes || strings.TrimSpace(k.value) != k.value {
		return ErrInvalidAPIKey
	}
	for index := 0; index < len(k.value); index++ {
		if k.value[index] < 0x21 || k.value[index] > 0x7e {
			return ErrInvalidAPIKey
		}
	}
	return nil
}

func (k APIKey) String() string   { return "OpenAI API key" }
func (k APIKey) GoString() string { return "openai.APIKey{<redacted>}" }
func (k APIKey) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "OpenAI API key", "openai.APIKey{<redacted>}")
}

// APIKeyProvider retrieves credentials at request time.
type APIKeyProvider interface {
	Retrieve(context.Context) (APIKey, error)
}

// Config binds one adapter instance to an exact approved route namespace.
type Config struct {
	AdapterID          string
	ProviderID         string
	ConnectionID       string
	Zone               provider.ProviderZone
	ContentLoggingMode provider.ContentLoggingMode
	Endpoint           string
	Credentials        APIKeyProvider
	CredentialIdentity string
	HTTPClientIdentity string
	HTTPClient         *http.Client
}

// Adapter executes exact authorized requests against the Responses API.
type Adapter struct {
	adapterID             string
	providerID            string
	connectionID          string
	zone                  provider.ProviderZone
	contentLoggingMode    provider.ContentLoggingMode
	endpoint              *url.URL
	credentials           APIKeyProvider
	credentialIdentity    string
	httpClientIdentity    string
	configurationIdentity string
	httpClient            *http.Client
}

// New validates configuration without retrieving credentials or making a request.
func New(config Config) (*Adapter, error) {
	endpointValue := config.Endpoint
	if endpointValue == "" {
		endpointValue = defaultEndpoint
	}
	endpoint, err := provider.ParseServiceEndpoint(endpointValue)
	locality, localityErr := provider.ClassifyServiceEndpoint(endpointValue)
	zoneMatches := config.Zone == provider.ProviderZoneLocal && locality == provider.ServiceEndpointLoopback || config.Zone == provider.ProviderZonePrivateRemote && locality == provider.ServiceEndpointRemote
	if err != nil || localityErr != nil || !zoneMatches || nilInterface(config.Credentials) || !validConfigurationIdentity(config.CredentialIdentity) {
		return nil, ErrInvalidConfig
	}
	if config.ContentLoggingMode.Validate() != nil {
		return nil, ErrInvalidConfig
	}
	if _, err := provider.NewRouteReference(
		config.Zone,
		config.ProviderID,
		config.AdapterID,
		config.ConnectionID,
		"model",
		"",
	); err != nil {
		return nil, ErrInvalidConfig
	}
	httpClientIdentity := config.HTTPClientIdentity
	if config.HTTPClient == nil {
		if httpClientIdentity != "" {
			return nil, ErrInvalidConfig
		}
		httpClientIdentity = defaultHTTPClientIdentity()
	} else if !validConfigurationIdentity(httpClientIdentity) {
		return nil, ErrInvalidConfig
	}
	client, err := boundedClient(config.HTTPClient)
	if err != nil {
		return nil, err
	}
	endpointCopy := *endpoint
	endpointCopy.Path = strings.TrimSuffix(endpointCopy.Path, "/")
	adapter := &Adapter{
		adapterID:          strings.Clone(config.AdapterID),
		providerID:         strings.Clone(config.ProviderID),
		connectionID:       strings.Clone(config.ConnectionID),
		zone:               config.Zone,
		contentLoggingMode: config.ContentLoggingMode,
		endpoint:           &endpointCopy,
		credentials:        config.Credentials,
		credentialIdentity: strings.Clone(config.CredentialIdentity),
		httpClientIdentity: strings.Clone(httpClientIdentity),
		httpClient:         client,
	}
	adapter.configurationIdentity = deriveConfigurationIdentity(adapter)
	return adapter, nil
}

func boundedClient(configured *http.Client) (*http.Client, error) {
	if configured == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cloneTLSConfig(transport.TLSClientConfig)
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		transport.MaxResponseHeaderBytes = maximumHeaderBytes
		configured = &http.Client{Transport: transport, Timeout: defaultRequestTimeout}
	}
	clone := *configured
	if clone.Timeout == 0 {
		clone.Timeout = defaultRequestTimeout
	}
	if clone.Timeout < 0 || clone.Timeout > maximumRequestTimeout {
		return nil, ErrInvalidConfig
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrInvalidConfig }
	return &clone, nil
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return &tls.Config{}
	}
	return config.Clone()
}

func validEndpoint(endpoint *url.URL) bool {
	if endpoint == nil {
		return false
	}
	parsed, err := provider.ParseServiceEndpoint(endpoint.String())
	return err == nil && parsed.String() == endpoint.String()
}

// AdapterID returns the exact configured implementation identity.
func (a *Adapter) AdapterID() string {
	if a == nil {
		return ""
	}
	return a.adapterID
}

// ConfigurationIdentity binds the adapter's non-secret connection authority.
func (a *Adapter) ConfigurationIdentity() string {
	if a == nil {
		return ""
	}
	return a.configurationIdentity
}
func deriveConfigurationIdentity(a *Adapter) string {
	if a == nil || a.endpoint == nil {
		return ""
	}
	encoded, _ := json.Marshal(struct {
		Contract            string `json:"contract"`
		Version             int    `json:"version"`
		Adapter             string `json:"adapter"`
		Provider            string `json:"provider"`
		Connection          string `json:"connection"`
		Zone                string `json:"zone"`
		Logging             string `json:"logging"`
		Endpoint            string `json:"endpoint"`
		Credential          string `json:"credential"`
		HTTPClient          string `json:"http_client"`
		TimeoutMilliseconds int64  `json:"timeout_milliseconds"`
	}{"open-trestle/openai-responses-adapter", 3, a.adapterID, a.providerID, a.connectionID, a.zone.String(), a.contentLoggingMode.String(), a.endpoint.String(), a.credentialIdentity, a.httpClientIdentity, a.httpClient.Timeout.Milliseconds()})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func defaultHTTPClientIdentity() string {
	encoded, _ := json.Marshal(struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Timeout        int64  `json:"timeout_milliseconds"`
		MaximumHeaders int64  `json:"maximum_header_bytes"`
		MinimumTLS     uint16 `json:"minimum_tls_version"`
	}{"open-trestle/openai-default-http-client", 1, defaultRequestTimeout.Milliseconds(), maximumHeaderBytes, tls.VersionTLS12})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validConfigurationIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 || identity != strings.ToLower(identity) {
		return false
	}
	decoded, err := hex.DecodeString(identity)
	if err != nil {
		return false
	}
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

// Validate verifies the immutable adapter configuration.
func (a *Adapter) Validate() error {
	if a == nil || a.endpoint == nil || a.httpClient == nil || nilInterface(a.credentials) || !validEndpoint(a.endpoint) || !validConfigurationIdentity(a.credentialIdentity) || !validConfigurationIdentity(a.httpClientIdentity) || a.configurationIdentity != deriveConfigurationIdentity(a) {
		return ErrInvalidConfig
	}
	_, err := provider.NewRouteReference(a.zone, a.providerID, a.adapterID, a.connectionID, "model", "")
	locality, localityErr := provider.ClassifyServiceEndpoint(a.endpoint.String())
	zoneMatches := a.zone == provider.ProviderZoneLocal && locality == provider.ServiceEndpointLoopback || a.zone == provider.ProviderZonePrivateRemote && locality == provider.ServiceEndpointRemote
	if err != nil || localityErr != nil || !zoneMatches || a.contentLoggingMode.Validate() != nil || a.httpClient.Timeout <= 0 || a.httpClient.Timeout > maximumRequestTimeout {
		return ErrInvalidConfig
	}
	return nil
}

// DispatchRoute sends content only after the gateway has constructed an exact authorization.
func (a *Adapter) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	if nilInterface(ctx) {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0)
	}
	if ctx.Err() != nil {
		return failed(gateway.RouteFailureCancelled, gateway.RouteReplayNotDispatched, 0)
	}
	if a == nil || a.Validate() != nil || request.Validate() != nil {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0)
	}
	authorization := request.Authorization()
	if authorization.ContentLoggingMode() != a.contentLoggingMode {
		return failed(gateway.RouteFailurePolicyDenied, gateway.RouteReplayNotDispatched, 0)
	}
	return a.execute(ctx, authorization.RouteReference(), authorization.MaxOutputTokens(), request.Request())
}

func (a *Adapter) execute(
	ctx context.Context,
	route provider.RouteReference,
	maxOutputTokens uint32,
	providerRequest provider.Request,
) gateway.RouteDispatchResult {
	if nilInterface(ctx) {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0)
	}
	if ctx.Err() != nil {
		return failed(gateway.RouteFailureCancelled, gateway.RouteReplayNotDispatched, 0)
	}
	if a == nil || a.Validate() != nil || route.Validate() != nil || providerRequest.Validate() != nil ||
		maxOutputTokens == 0 || !a.routeMatches(route) || !utf8.Valid(providerRequest.Payload()) {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0)
	}
	credentials, err := a.credentials.Retrieve(ctx)
	if ctx.Err() != nil {
		return failed(gateway.RouteFailureCancelled, gateway.RouteReplayNotDispatched, 0)
	}
	if err != nil || credentials.Validate() != nil {
		return failed(gateway.RouteFailureAuthentication, gateway.RouteReplayNotDispatched, 0)
	}
	request, err := a.newRequest(ctx, credentials, modelSelector(route), maxOutputTokens, providerRequest.Payload())
	if err != nil {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0)
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		failure := gateway.RouteFailureTransport
		if errors.Is(err, context.DeadlineExceeded) {
			failure = gateway.RouteFailureTimeout
		} else if ctx.Err() != nil {
			failure = gateway.RouteFailureCancelled
		}
		return failed(failure, gateway.RouteReplayOutcomeUnknown, 0)
	}
	if response == nil {
		return failed(gateway.RouteFailureTransport, gateway.RouteReplayOutcomeUnknown, 0)
	}
	if response.StatusCode != http.StatusOK {
		return classifyHTTPFailure(response)
	}
	content, ok := readBounded(response)
	if !ok {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown, 0)
	}
	normalized, err := normalizeResponse(content, route)
	if err != nil {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown, 0)
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(normalized)
	if err != nil {
		return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown, 0)
	}
	return result
}

func (a *Adapter) routeMatches(route provider.RouteReference) bool {
	return route.AdapterID() == a.adapterID && route.ProviderID() == a.providerID &&
		route.ConnectionID() == a.connectionID && route.Zone() == a.zone
}

type requestWire struct {
	Model           string         `json:"model"`
	Input           []requestInput `json:"input"`
	MaxOutputTokens uint32         `json:"max_output_tokens"`
	Store           bool           `json:"store"`
}
type requestInput struct {
	Role    string                `json:"role"`
	Content []requestInputContent `json:"content"`
}
type requestInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (a *Adapter) newRequest(
	ctx context.Context,
	credentials APIKey,
	model string,
	maxOutputTokens uint32,
	payload []byte,
) (*http.Request, error) {
	wire := requestWire{
		Model: model,
		Input: []requestInput{{
			Role:    "user",
			Content: []requestInputContent{{Type: "input_text", Text: string(payload)}},
		}},
		MaxOutputTokens: maxOutputTokens,
		Store:           false,
	}
	content, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	requestURL := *a.endpoint
	requestURL.Path += "/responses"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+credentials.value)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func classifyHTTPFailure(response *http.Response) gateway.RouteDispatchResult {
	if response == nil {
		return failed(gateway.RouteFailureTransport, gateway.RouteReplayOutcomeUnknown, 0)
	}
	drainAndClose(response.Body)
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return failed(gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect, 0)
	case http.StatusForbidden:
		return failed(gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect, 0)
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return failed(gateway.RouteFailureTimeout, gateway.RouteReplayOutcomeUnknown, 0)
	case http.StatusTooManyRequests:
		return failed(gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, retryAfterMilliseconds(response.Header.Get("Retry-After")))
	case http.StatusRequestEntityTooLarge:
		return failed(gateway.RouteFailureBudgetExhausted, gateway.RouteReplayNoSideEffect, 0)
	}
	if response.StatusCode >= 500 {
		return failed(gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0)
	}
	return failed(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0)
}

func retryAfterMilliseconds(value string) uint32 {
	seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds == 0 {
		return 0
	}
	const maximum = ^uint32(0)
	if seconds > uint64(maximum)/1000 {
		return maximum
	}
	return uint32(seconds * 1000)
}

func readBounded(response *http.Response) ([]byte, bool) {
	if response == nil || response.Body == nil || response.ContentLength > maximumResponseBytes {
		if response != nil {
			drainAndClose(response.Body)
		}
		return nil, false
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(content) == 0 || len(content) > maximumResponseBytes {
		return nil, false
	}
	return content, true
}

type responseWire struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Status            string                 `json:"status"`
	Model             string                 `json:"model"`
	Output            []json.RawMessage      `json:"output"`
	Usage             *usageWire             `json:"usage"`
	IncompleteDetails *incompleteDetailsWire `json:"incomplete_details"`
}
type incompleteDetailsWire struct {
	Reason string `json:"reason"`
}
type usageWire struct {
	InputTokens       uint64                 `json:"input_tokens"`
	OutputTokens      uint64                 `json:"output_tokens"`
	TotalTokens       uint64                 `json:"total_tokens"`
	InputTokenDetails *inputTokenDetailsWire `json:"input_tokens_details"`
}
type inputTokenDetailsWire struct {
	CachedTokens uint64 `json:"cached_tokens"`
}
type outputHeaderWire struct {
	Type string `json:"type"`
}
type messageWire struct {
	ID      string               `json:"id"`
	Type    string               `json:"type"`
	Status  string               `json:"status"`
	Role    string               `json:"role"`
	Content []messageContentWire `json:"content"`
}
type reasoningWire struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Status  string                 `json:"status"`
	Summary []reasoningSummaryWire `json:"summary"`
}
type reasoningSummaryWire struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type messageContentWire struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
	Refusal string `json:"refusal"`
}

func modelSelector(route provider.RouteReference) string {
	if route.ModelVersion() != "" {
		return route.ModelVersion()
	}
	return route.ModelID()
}

func normalizeResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if err := validateJSONShape(content); err != nil {
		return provider.Response{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	var wire responseWire
	if err := decoder.Decode(&wire); err != nil {
		return provider.Response{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return provider.Response{}, err
	}
	if wire.ID == "" || len(wire.ID) > 512 || wire.Object != "response" || wire.Model != modelSelector(route) || len(wire.Output) > maximumOutputItems {
		return provider.Response{}, ErrInvalidConfig
	}
	finish, err := finishReason(wire)
	if err != nil {
		return provider.Response{}, err
	}
	parts, err := normalizeOutput(wire.Output, wire.Status)
	if err != nil {
		return provider.Response{}, err
	}
	usage, err := normalizeUsage(wire.Usage)
	if err != nil {
		return provider.Response{}, err
	}
	return provider.NewResponse(provider.CapabilityReviewV1, finish, parts, usage)
}

func finishReason(wire responseWire) (provider.ResponseFinishReason, error) {
	switch wire.Status {
	case "completed":
		if wire.IncompleteDetails != nil && wire.IncompleteDetails.Reason != "" {
			return 0, ErrInvalidConfig
		}
		return provider.ResponseFinishStop, nil
	case "incomplete":
		if wire.IncompleteDetails == nil {
			return 0, ErrInvalidConfig
		}
		switch wire.IncompleteDetails.Reason {
		case "max_output_tokens":
			return provider.ResponseFinishLength, nil
		case "content_filter":
			return provider.ResponseFinishContentFilter, nil
		default:
			return 0, ErrInvalidConfig
		}
	default:
		return 0, ErrInvalidConfig
	}
}

func normalizeOutput(output []json.RawMessage, responseStatus string) ([]provider.ResponsePart, error) {
	parts := make([]provider.ResponsePart, 0)
	for _, raw := range output {
		var header outputHeaderWire
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, err
		}
		switch header.Type {
		case "reasoning":
			var reasoning reasoningWire
			if err := json.Unmarshal(raw, &reasoning); err != nil || !validReasoning(reasoning) {
				return nil, ErrInvalidConfig
			}
			continue
		case "message":
			var message messageWire
			if err := json.Unmarshal(raw, &message); err != nil || message.ID == "" || len(message.ID) > 512 ||
				message.Role != "assistant" || (message.Status != "completed" && message.Status != "incomplete") ||
				responseStatus == "completed" && message.Status != "completed" || len(message.Content) > maximumOutputItems {
				return nil, ErrInvalidConfig
			}
			for _, item := range message.Content {
				part, err := normalizeContent(item)
				if err != nil {
					return nil, err
				}
				parts = append(parts, part)
				if len(parts) > maximumOutputItems {
					return nil, ErrInvalidConfig
				}
			}
		default:
			return nil, ErrInvalidConfig
		}
	}
	if len(parts) == 0 {
		return nil, ErrInvalidConfig
	}
	return parts, nil
}

func validReasoning(reasoning reasoningWire) bool {
	if reasoning.ID == "" || len(reasoning.ID) > 512 || reasoning.Summary == nil ||
		(reasoning.Status != "" && reasoning.Status != "completed" && reasoning.Status != "incomplete") ||
		len(reasoning.Summary) > maximumOutputItems {
		return false
	}
	for _, summary := range reasoning.Summary {
		if summary.Type != "summary_text" || summary.Text == "" {
			return false
		}
	}
	return true
}

func normalizeContent(item messageContentWire) (provider.ResponsePart, error) {
	switch item.Type {
	case "output_text":
		if item.Text == "" || item.Refusal != "" {
			return provider.ResponsePart{}, ErrInvalidConfig
		}
		if json.Valid([]byte(item.Text)) {
			return provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(item.Text))
		}
		return provider.NewResponsePart(provider.ResponsePartAssistantText, "text/plain; charset=utf-8", []byte(item.Text))
	case "refusal":
		if item.Refusal == "" || item.Text != "" {
			return provider.ResponsePart{}, ErrInvalidConfig
		}
		return provider.NewResponsePart(provider.ResponsePartRefusal, "text/plain; charset=utf-8", []byte(item.Refusal))
	default:
		return provider.ResponsePart{}, ErrInvalidConfig
	}
}

func normalizeUsage(wire *usageWire) (provider.RouteTokenUsage, error) {
	if wire == nil {
		return provider.NewUnknownRouteTokenUsage(), nil
	}
	cached := uint64(0)
	if wire.InputTokenDetails != nil {
		cached = wire.InputTokenDetails.CachedTokens
	}
	if wire.InputTokens > ^uint64(0)-wire.OutputTokens || wire.TotalTokens != wire.InputTokens+wire.OutputTokens {
		return provider.RouteTokenUsage{}, ErrInvalidConfig
	}
	return provider.NewRouteTokenUsage(wire.InputTokens, wire.OutputTokens, cached)
}

func validateJSONShape(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
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
			if !ok || !canonicalResponseKey(key) {
				return ErrInvalidConfig
			}
			folded := strings.ToLower(key)
			if _, exists := keys[folded]; exists {
				return ErrInvalidConfig
			}
			keys[folded] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeDelimiter(decoder, ']')
	default:
		return ErrInvalidConfig
	}
}

func canonicalResponseKey(key string) bool {
	if key == "" {
		return false
	}
	for _, value := range key {
		if value >= 'A' && value <= 'Z' || value < 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func consumeDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return ErrInvalidConfig
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return ErrInvalidConfig
	}
	return nil
}

func failed(failure gateway.RouteFailureClass, safety gateway.RouteReplaySafety, retryAfter uint32) gateway.RouteDispatchResult {
	result, _ := gateway.NewFailedRouteDispatchResult(
		failure,
		safety,
		provider.NewUnknownRouteTokenUsage(),
		retryAfter,
	)
	return result
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maximumErrorBodyBytes))
	_ = body.Close()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func writeRedacted(state fmt.State, verb rune, normal, detailed string) {
	value := normal
	if verb == 'q' {
		value = strconv.Quote(normal)
	} else if verb == 'v' && state.Flag('#') {
		value = detailed
	}
	_, _ = state.Write([]byte(value))
}

func (a *Adapter) String() string   { return "OpenAI Responses adapter" }
func (a *Adapter) GoString() string { return "openai.Adapter{<redacted>}" }
func (a *Adapter) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "OpenAI Responses adapter", "openai.Adapter{<redacted>}")
}

var _ gateway.RouteDispatcher = (*Adapter)(nil)
