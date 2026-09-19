package github

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/webhook"
)

const (
	runtimeWebhookSecretEncodedBytes   = 64
	runtimeWebhookSecretSourceBytes    = 32
	runtimeWebhookSecretMinimumSymbols = 12
	runtimeWebhookSecretMaximumPeriod  = 32
	conformanceAcceptedPayload         = `{"action":"opened","number":7,"pull_request":{"base":{"sha":"0000000000000000000000000000000000000000"},"head":{"sha":"1111111111111111111111111111111111111111"}},"repository":{"full_name":"open-trestle/conformance"}}`
	conformanceConflictPayload         = `{"action":"reopened","number":7,"pull_request":{"base":{"sha":"0000000000000000000000000000000000000000"},"head":{"sha":"2222222222222222222222222222222222222222"}},"repository":{"full_name":"open-trestle/conformance"}}`
	conformanceIgnoredPayload          = `{"action":"closed","number":7,"repository":{"full_name":"open-trestle/conformance"}}`
	conformanceDeliveryID              = "open-trestle-webhook-conformance-v1"
	conformanceIgnoredID               = "open-trestle-webhook-conformance-ignored-v1"
)

var (
	// ErrInvalidWebhookConformance identifies invalid scope, key, credential reference, secret, context, or store input.
	ErrInvalidWebhookConformance = errors.New("invalid GitHub webhook conformance input")
	// ErrWebhookConformanceFailed identifies behavior that contradicts the fixed webhook contract.
	ErrWebhookConformanceFailed = errors.New("GitHub webhook conformance failed")
)

func productionWebhookAllowlist() map[string][]string {
	return map[string][]string{"pull_request": {"opened", "ready_for_review", "reopened", "synchronize"}}
}

// VerifierConfigurationIdentity binds the runtime verifier scope, secret key identifier, and fixed allowlist.
func VerifierConfigurationIdentity(scope webhook.RepositoryScope, keyID string) (string, error) {
	if scope.Validate() != nil || !validWebhookKeyID(keyID) {
		return "", ErrInvalidWebhookConformance
	}
	encoded, err := json.Marshal(struct {
		Contract      string              `json:"contract"`
		SchemaVersion int                 `json:"schema_version"`
		ScopeIdentity string              `json:"scope_identity"`
		TenantID      string              `json:"tenant_id"`
		RepositoryID  string              `json:"repository_id"`
		KeyID         string              `json:"key_id"`
		Algorithm     string              `json:"algorithm"`
		Allowed       map[string][]string `json:"allowed"`
	}{"open-trestle/github-webhook-verifier-configuration", 1, scope.Identity(), scope.TenantID(), scope.RepositoryID(), keyID, "hmac-sha256", productionWebhookAllowlist()})
	if err != nil {
		return "", ErrInvalidWebhookConformance
	}
	return digestWebhookConformance(encoded), nil
}

// ValidateRuntimeSecret enforces the canonical encoded-key policy used by setup and the daemon.
// It validates capacity and rejects trivial structure; entropy provenance remains an operator responsibility.
func ValidateRuntimeSecret(secret []byte) error {
	if len(secret) != runtimeWebhookSecretEncodedBytes {
		return ErrInvalidVerifier
	}
	var seen [16]bool
	distinct := 0
	for _, candidate := range secret {
		index := -1
		switch {
		case candidate >= '0' && candidate <= '9':
			index = int(candidate - '0')
		case candidate >= 'a' && candidate <= 'f':
			index = int(candidate-'a') + 10
		default:
			return ErrInvalidVerifier
		}
		if !seen[index] {
			seen[index] = true
			distinct++
		}
	}
	if distinct < runtimeWebhookSecretMinimumSymbols {
		return ErrInvalidVerifier
	}
	for period := 1; period <= runtimeWebhookSecretMaximumPeriod; period++ {
		repeated := true
		for index := period; index < len(secret); index++ {
			if secret[index] != secret[index%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return ErrInvalidVerifier
		}
	}
	return nil
}

// NewRuntimeVerifier constructs the exact production GitHub allowlist for one repository scope.
func NewRuntimeVerifier(secret []byte, scope webhook.RepositoryScope, keyID string) (*Verifier, error) {
	if ValidateRuntimeSecret(secret) != nil {
		return nil, ErrInvalidVerifier
	}
	identity, err := VerifierConfigurationIdentity(scope, keyID)
	if err != nil {
		return nil, ErrInvalidVerifier
	}
	return NewVerifier(secret, identity, productionWebhookAllowlist())
}

// ConformanceAuthorityIdentity binds the exact credential-free webhook probe contract.
func ConformanceAuthorityIdentity(scope webhook.RepositoryScope, keyID, credentialReferenceIdentity string) (string, error) {
	verifierIdentity, err := VerifierConfigurationIdentity(scope, keyID)
	if err != nil || !validDigest(credentialReferenceIdentity) {
		return "", ErrInvalidWebhookConformance
	}
	payloadDigest := func(value string) string { return digestWebhookConformance([]byte(value)) }
	encoded, err := json.Marshal(struct {
		Contract                       string              `json:"contract"`
		SchemaVersion                  int                 `json:"schema_version"`
		ScopeIdentity                  string              `json:"scope_identity"`
		TenantID                       string              `json:"tenant_id"`
		RepositoryID                   string              `json:"repository_id"`
		Source                         string              `json:"source"`
		KeyID                          string              `json:"key_id"`
		CredentialReferenceIdentity    string              `json:"credential_reference_identity"`
		VerifierConfigurationIdentity  string              `json:"verifier_configuration_identity"`
		Algorithm                      string              `json:"algorithm"`
		Method                         string              `json:"method"`
		Path                           string              `json:"path"`
		ContentType                    string              `json:"content_type"`
		SignatureHeader                string              `json:"signature_header"`
		DeliveryHeader                 string              `json:"delivery_header"`
		EventHeader                    string              `json:"event_header"`
		Allowed                        map[string][]string `json:"allowed"`
		SecretEncoding                 string              `json:"secret_encoding"`
		SecretEncodedBytes             int                 `json:"secret_encoded_bytes"`
		SecretSourceBytes              int                 `json:"secret_source_bytes"`
		SecretMinimumDistinctSymbols   int                 `json:"secret_minimum_distinct_symbols"`
		SecretMaximumRepeatedPeriod    int                 `json:"secret_maximum_repeated_period"`
		MaximumAllowedEvents           int                 `json:"maximum_allowed_events"`
		MaximumAllowedActions          int                 `json:"maximum_allowed_actions"`
		MaximumPayloadBytes            int                 `json:"maximum_payload_bytes"`
		MaximumHeaderBytes             int                 `json:"maximum_header_bytes"`
		MaximumConcurrentRequests      int                 `json:"maximum_concurrent_requests"`
		ConformanceRequests            int                 `json:"conformance_requests"`
		AcceptedPayloadDigest          string              `json:"accepted_payload_digest"`
		ConflictPayloadDigest          string              `json:"conflict_payload_digest"`
		IgnoredPayloadDigest           string              `json:"ignored_payload_digest"`
		AcceptedDeliveryID             string              `json:"accepted_delivery_id"`
		IgnoredDeliveryID              string              `json:"ignored_delivery_id"`
		ExpectedStatuses               []int               `json:"expected_statuses"`
		ResponseContract               string              `json:"response_contract"`
		ResponseSchemaVersion          int                 `json:"response_schema_version"`
		CacheControl                   string              `json:"cache_control"`
		ContentTypeOptions             string              `json:"content_type_options"`
		DuplicateIdentityStable        bool                `json:"duplicate_identity_stable"`
		ConflictPreservesRecord        bool                `json:"conflict_preserves_record"`
		IgnoredActionNotPersisted      bool                `json:"ignored_action_not_persisted"`
		InitialRecords                 int                 `json:"initial_records"`
		FinalRecords                   int                 `json:"final_records"`
		StoreContract                  string              `json:"store_contract"`
		StoreDirectoryMode             string              `json:"store_directory_mode"`
		DurableBeforeAcknowledge       bool                `json:"durable_before_acknowledge"`
		DisposableStoreCleanupRequired bool                `json:"disposable_store_cleanup_required"`
		CleanupMethod                  string              `json:"cleanup_method"`
		MaximumCleanupEntries          int                 `json:"maximum_cleanup_entries"`
		ListenerUsed                   bool                `json:"listener_used"`
		NetworkRequests                int                 `json:"network_requests"`
	}{"open-trestle/github-webhook-conformance-authority", 1, scope.Identity(), scope.TenantID(), scope.RepositoryID(), webhook.SourceGitHub.String(), keyID, credentialReferenceIdentity, verifierIdentity, "hmac-sha256", http.MethodPost, "/webhooks/github", "application/json", "X-Hub-Signature-256", "X-GitHub-Delivery", "X-GitHub-Event", productionWebhookAllowlist(), "lowercase_hex", runtimeWebhookSecretEncodedBytes, runtimeWebhookSecretSourceBytes, runtimeWebhookSecretMinimumSymbols, runtimeWebhookSecretMaximumPeriod, maxAllowedEvents, maxAllowedActions, maxHTTPWebhookBodyBytes, maxWebhookHeaderBytes, 1, 5, payloadDigest(conformanceAcceptedPayload), payloadDigest(conformanceConflictPayload), payloadDigest(conformanceIgnoredPayload), conformanceDeliveryID, conformanceIgnoredID, []int{http.StatusUnauthorized, http.StatusAccepted, http.StatusOK, http.StatusConflict, http.StatusAccepted}, "open-trestle/webhook-response", 1, "no-store", "nosniff", true, true, true, 0, 1, "open-trestle/file-webhook-store/v1", "0700", true, true, "bounded_nonrecursive_remove", 2, false, 0})
	if err != nil {
		return "", ErrInvalidWebhookConformance
	}
	return digestWebhookConformance(encoded), nil
}

// ConformanceObservation is a content-free record of the fixed webhook cycle.
type ConformanceObservation struct {
	identity, authorityIdentity, verifierIdentity, acceptanceIdentity, deliveryIdentity, bodyDigest string
}

func (o ConformanceObservation) Identity() string           { return o.identity }
func (o ConformanceObservation) AuthorityIdentity() string  { return o.authorityIdentity }
func (o ConformanceObservation) VerifierIdentity() string   { return o.verifierIdentity }
func (o ConformanceObservation) AcceptanceIdentity() string { return o.acceptanceIdentity }
func (o ConformanceObservation) String() string             { return "GitHub webhook conformance observation" }
func (o ConformanceObservation) GoString() string           { return "github.ConformanceObservation{<redacted>}" }
func (o ConformanceObservation) Format(state fmt.State, verb rune) {
	value := o.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = o.GoString()
	}
	_, _ = state.Write([]byte(value))
}
func (o ConformanceObservation) Validate() error {
	if !validDigest(o.authorityIdentity) || !validDigest(o.verifierIdentity) || !validDigest(o.acceptanceIdentity) || !validDigest(o.deliveryIdentity) || !validDigest(o.bodyDigest) {
		return ErrWebhookConformanceFailed
	}
	if o.identity != webhookConformanceObservationIdentity(o.authorityIdentity, o.verifierIdentity, o.acceptanceIdentity, o.deliveryIdentity, o.bodyDigest) {
		return ErrWebhookConformanceFailed
	}
	return nil
}

// VerifyConformance executes the fixed requests directly against the production handler and one empty FileStore.
func VerifyConformance(ctx context.Context, secret []byte, scope webhook.RepositoryScope, keyID, credentialReferenceIdentity string, store *webhook.FileStore) (ConformanceObservation, error) {
	if ctx == nil || ctx.Err() != nil || store == nil {
		return ConformanceObservation{}, ErrInvalidWebhookConformance
	}
	authorityIdentity, err := ConformanceAuthorityIdentity(scope, keyID, credentialReferenceIdentity)
	if err != nil {
		return ConformanceObservation{}, err
	}
	verifierIdentity, _ := VerifierConfigurationIdentity(scope, keyID)
	verifier, err := NewRuntimeVerifier(secret, scope, keyID)
	if err != nil {
		return ConformanceObservation{}, ErrInvalidWebhookConformance
	}
	defer verifier.Close()
	initial, err := store.List(ctx, scope, webhook.SourceGitHub, "", 10)
	if err != nil {
		return ConformanceObservation{}, err
	}
	if len(initial) != 0 {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	policy, err := webhook.NewAdmissionPolicy([]webhook.VerifierAuthority{{Scope: scope, Source: webhook.SourceGitHub, VerifierIdentity: verifierIdentity}})
	if err != nil {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	inbox, err := webhook.NewInbox(store, policy)
	if err != nil {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	handler, err := NewHTTPHandler(scope, verifier, inbox, fixedConformanceClock{at}, 1)
	if err != nil {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	bad := serveConformance(ctx, handler, conformanceDeliveryID, conformanceAcceptedPayload, strings.Repeat("0", sha256.Size*2))
	first := serveConformance(ctx, handler, conformanceDeliveryID, conformanceAcceptedPayload, signConformance(secret, conformanceAcceptedPayload))
	duplicate := serveConformance(ctx, handler, conformanceDeliveryID, conformanceAcceptedPayload, signConformance(secret, conformanceAcceptedPayload))
	conflict := serveConformance(ctx, handler, conformanceDeliveryID, conformanceConflictPayload, signConformance(secret, conformanceConflictPayload))
	ignored := serveConformance(ctx, handler, conformanceIgnoredID, conformanceIgnoredPayload, signConformance(secret, conformanceIgnoredPayload))
	if ctx.Err() != nil {
		return ConformanceObservation{}, ctx.Err()
	}
	if bad.status != http.StatusUnauthorized || bad.value.Error != "unauthenticated" || bad.value.AcceptanceIdentity != "" || bad.value.Duplicate || bad.value.Ignored || first.status != http.StatusAccepted || first.value.Error != "" || first.value.AcceptanceIdentity == "" || first.value.Duplicate || first.value.Ignored || duplicate.status != http.StatusOK || duplicate.value.Error != "" || !duplicate.value.Duplicate || duplicate.value.Ignored || duplicate.value.AcceptanceIdentity != first.value.AcceptanceIdentity || conflict.status != http.StatusConflict || conflict.value.Error != "delivery_conflict" || conflict.value.AcceptanceIdentity != "" || conflict.value.Duplicate || conflict.value.Ignored || ignored.status != http.StatusAccepted || ignored.value.Error != "" || !ignored.value.Ignored || ignored.value.Duplicate || ignored.value.AcceptanceIdentity != "" {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	for _, response := range []conformanceHTTPResponse{bad, first, duplicate, conflict, ignored} {
		if response.invalid || response.header.Get("Cache-Control") != "no-store" || response.header.Get("Content-Type") != "application/json" || response.header.Get("X-Content-Type-Options") != "nosniff" {
			return ConformanceObservation{}, ErrWebhookConformanceFailed
		}
	}
	entries, err := store.List(ctx, scope, webhook.SourceGitHub, "", 10)
	if err != nil {
		return ConformanceObservation{}, err
	}
	if len(entries) != 1 || entries[0].Validate() != nil {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	stored := entries[0]
	payload := stored.Delivery().Payload()
	defer clear(payload)
	if !bytes.Equal(payload, []byte(conformanceAcceptedPayload)) || stored.Delivery().DeliveryID() != conformanceDeliveryID || stored.Delivery().EventType() != "pull_request" || stored.Delivery().Action() != "opened" || stored.Delivery().VerifierIdentity() != verifierIdentity || stored.Receipt().Identity() != first.value.AcceptanceIdentity {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	observation := ConformanceObservation{authorityIdentity: authorityIdentity, verifierIdentity: verifierIdentity, acceptanceIdentity: stored.Receipt().Identity(), deliveryIdentity: stored.Delivery().Identity(), bodyDigest: stored.Delivery().BodyDigest()}
	observation.identity = webhookConformanceObservationIdentity(observation.authorityIdentity, observation.verifierIdentity, observation.acceptanceIdentity, observation.deliveryIdentity, observation.bodyDigest)
	if observation.Validate() != nil {
		return ConformanceObservation{}, ErrWebhookConformanceFailed
	}
	return observation, nil
}

type fixedConformanceClock struct{ at time.Time }

func (c fixedConformanceClock) Now() time.Time { return c.at }

type conformanceResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *conformanceResponseWriter) Header() http.Header { return w.header }
func (w *conformanceResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *conformanceResponseWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(value)
}

type conformanceHTTPResponse struct {
	status  int
	header  http.Header
	value   webhookResponse
	invalid bool
}

func serveConformance(ctx context.Context, handler http.Handler, deliveryID, payload, signature string) conformanceHTTPResponse {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1/webhooks/github", strings.NewReader(payload))
	if err != nil {
		return conformanceHTTPResponse{invalid: true}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256="+signature)
	writer := &conformanceResponseWriter{header: make(http.Header)}
	handler.ServeHTTP(writer, request)
	var value webhookResponse
	bodyLength := writer.body.Len()
	decoder := json.NewDecoder(io.LimitReader(&writer.body, 4097))
	decodeErr := decoder.Decode(&value)
	var extra json.RawMessage
	extraErr := decoder.Decode(&extra)
	return conformanceHTTPResponse{writer.status, writer.header.Clone(), value, decodeErr != nil || extraErr != io.EOF || bodyLength > 4096 || value.Contract != "open-trestle/webhook-response" || value.SchemaVersion != 1}
}
func signConformance(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
func webhookConformanceObservationIdentity(authority, verifier, acceptance, delivery, body string) string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Authority     string `json:"authority_identity"`
		Verifier      string `json:"verifier_identity"`
		Acceptance    string `json:"acceptance_identity"`
		Delivery      string `json:"delivery_identity"`
		Body          string `json:"body_digest"`
	}{"open-trestle/github-webhook-conformance-observation", 1, authority, verifier, acceptance, delivery, body})
	return digestWebhookConformance(encoded)
}
func digestWebhookConformance(value []byte) string {
	digest := sha256.Sum256(append([]byte("open-trestle/github-webhook-conformance/v1\x00"), value...))
	return hex.EncodeToString(digest[:])
}
func validWebhookKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate > 0x7e {
			return false
		}
	}
	return true
}
