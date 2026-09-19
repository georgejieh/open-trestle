package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

var _ fmt.Formatter = RetainedMemoryInput{}
var _ fmt.Stringer = RetainedMemoryInput{}
var _ fmt.GoStringer = RetainedMemoryInput{}

const rmProducer = "084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f"
const rmObserved int64 = 1700000000000
const rmUntil int64 = rmObserved + 60000
const rmMaximum int64 = 253402300799999
const rmLiteralText = "<&> é e\u0301 \u2028\u2029\n\toperator advisory"

type rmScopeWire struct {
	Identity   string   `json:"identity"`
	Tenant     string   `json:"tenant_id"`
	Repository string   `json:"repository_id"`
	Actor      string   `json:"actor_id"`
	Visibility string   `json:"ref_visibility"`
	RefSet     string   `json:"ref_set_identity"`
	Prefixes   []string `json:"path_prefixes"`
}

type rmHeadWire struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Identity  string `json:"identity"`
}

type rmRecordWire struct {
	Identity string   `json:"record_identity"`
	Kind     string   `json:"kind"`
	Taint    string   `json:"taint"`
	Path     string   `json:"path"`
	Symbols  []string `json:"symbols"`
	Text     string   `json:"text"`
	Evidence []string `json:"evidence_ids"`
	Producer string   `json:"producer_identity"`
	Observed int64    `json:"observed_at"`
	From     int64    `json:"valid_from"`
	Until    int64    `json:"valid_until"`
}

type rmEnvelopeWire struct {
	Contract    string         `json:"contract"`
	Version     int            `json:"schema_version"`
	Attestation string         `json:"attestation"`
	Scope       rmScopeWire    `json:"scope"`
	Repository  string         `json:"repository_identity"`
	Head        rmHeadWire     `json:"head_revision"`
	Policy      string         `json:"runtime_policy_identity"`
	Paths       []string       `json:"allowed_paths"`
	Records     []rmRecordWire `json:"records"`
}

func rmJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rmHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func rmHeadBytes(t *testing.T, w rmHeadWire) []byte {
	return rmJSON(t, struct {
		Contract  string `json:"contract"`
		Version   int    `json:"schema_version"`
		Kind      string `json:"kind"`
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	}{"open-trestle/revision-identity", 1, w.Kind, w.Algorithm, w.Digest})
}

func rmScopeBytes(t *testing.T, w rmScopeWire) []byte {
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Tenant     string   `json:"tenant"`
		Repository string   `json:"repository"`
		Actor      string   `json:"actor"`
		Visibility string   `json:"ref_visibility"`
		RefSet     string   `json:"ref_set_identity"`
		Prefixes   []string `json:"path_prefixes"`
	}{"open-trestle/memory-scope", 1, w.Tenant, w.Repository, w.Actor, w.Visibility, w.RefSet, w.Prefixes})
}

func rmNoteBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	return rmJSON(t, []any{"open-trestle/operator-feedback-note", 1, scopeID, r.Path, r.Text, r.Observed, r.From, r.Until})
}

func rmRecordBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	// Native empty arrays are null; only the new wire symbols array is [].
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Scope      string   `json:"scope"`
		Kind       string   `json:"kind"`
		Taint      string   `json:"taint"`
		Path       string   `json:"path"`
		Symbols    []string `json:"symbols"`
		TextDigest string   `json:"text_digest"`
		TextBytes  int      `json:"text_bytes"`
		Evidence   []string `json:"evidence"`
		Derived    []string `json:"derived_from"`
		Counter    []string `json:"counter_evidence"`
		Producer   string   `json:"producer"`
		Observed   int64    `json:"observed_at"`
		From       int64    `json:"valid_from"`
		Until      int64    `json:"valid_until"`
		Stale      int64    `json:"stale_after"`
		Freshness  string   `json:"freshness"`
		Confidence uint16   `json:"confidence"`
	}{"open-trestle/memory-record", 1, scopeID, r.Kind, r.Taint, r.Path, nil,
		rmHash([]byte(r.Text)), len(r.Text), r.Evidence, nil, nil, r.Producer,
		r.Observed, r.From, r.Until, 0, "", 0})
}

func rmInputBytes(t *testing.T, w rmEnvelopeWire) []byte {
	return rmJSON(t, []any{"open-trestle/protected-retained-input", 1, "local-only", 65536, 16, 16, 4096, 1024, 8192, 32768, 604800000, w})
}

func rmScope(t *testing.T, w rmScopeWire) memory.Scope {
	t.Helper()
	visibility, err := memory.ParseRefVisibility(w.Visibility)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope(w.Tenant, w.Repository, w.Actor, visibility, w.RefSet, w.Prefixes)
	if err != nil || scope.Validate() != nil {
		t.Fatal("invalid native scope fixture")
	}
	if scope.Identity() != rmHash(rmScopeBytes(t, w)) || scope.Identity() != w.Identity ||
		scope.TenantID() != w.Tenant || scope.RepositoryID() != w.Repository || scope.ActorID() != w.Actor ||
		scope.RefVisibility().String() != w.Visibility || scope.RefSetIdentity() != w.RefSet ||
		!reflect.DeepEqual(scope.PathPrefixes(), w.Prefixes) {
		t.Fatal("native scope recipe drift")
	}
	return scope
}

func rmNativeRecord(t *testing.T, scope memory.Scope, r rmRecordWire) memory.Record {
	t.Helper()
	kind, err := memory.ParseRecordKind(r.Kind)
	if err != nil {
		t.Fatal(err)
	}
	taint, err := memory.ParseTaintClass(r.Taint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := memory.NewRecord(scope, memory.RecordInput{
		Kind: kind, Taint: taint, Path: r.Path, Text: r.Text, EvidenceIDs: r.Evidence,
		ProducerIdentity: r.Producer, ObservedAt: time.UnixMilli(r.Observed).UTC(),
		ValidFrom: time.UnixMilli(r.From).UTC(), ValidUntil: time.UnixMilli(r.Until).UTC(),
	})
	if err != nil || record.Validate() != nil || record.Identity() != r.Identity {
		t.Fatal("native record recipe drift")
	}
	return record
}

func rmReseal(t *testing.T, w *rmEnvelopeWire, native bool) {
	t.Helper()
	w.Head.Identity = rmHash(rmHeadBytes(t, w.Head))
	w.Scope.RefSet = w.Head.Identity
	w.Scope.Identity = rmHash(rmScopeBytes(t, w.Scope))
	for i := range w.Records {
		r := &w.Records[i]
		r.Evidence = []string{"operator-note:" + rmHash(rmNoteBytes(t, w.Scope.Identity, *r))}
		r.Identity = rmHash(rmRecordBytes(t, w.Scope.Identity, *r))
	}
	sort.Strings(w.Paths)
	sort.Slice(w.Records, func(i, j int) bool { return w.Records[i].Identity < w.Records[j].Identity })
	if native {
		head, err := evidence.NewRevisionIdentity(evidence.RevisionKind(w.Head.Kind), evidence.RevisionAlgorithm(w.Head.Algorithm), w.Head.Digest)
		if err != nil || head.Identity() != w.Head.Identity || string(head.Kind()) != w.Head.Kind || string(head.Algorithm()) != w.Head.Algorithm || head.Digest() != w.Head.Digest {
			t.Fatal("native head recipe drift")
		}
		scope := rmScope(t, w.Scope)
		for _, record := range w.Records {
			rmNativeRecord(t, scope, record)
		}
	}
}

func rmRepository(t *testing.T, name string) evidence.RepositoryIdentity {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"team"}, name)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func rmEnvelope(t *testing.T, policyID string, count int, text string) rmEnvelopeWire {
	t.Helper()
	w := rmEnvelopeWire{
		Contract: "open-trestle/retained-memory-input", Version: 1, Attestation: "operator_attested_advisory_feedback",
		Scope:      rmScopeWire{Tenant: "tenant-a", Repository: "logical-repo", Actor: "local-reviewer", Visibility: "exact", Prefixes: []string{"."}},
		Repository: rmRepository(t, "source-repository").Identity(),
		Head:       rmHeadWire{Kind: "git_commit", Algorithm: "sha1", Digest: strings.Repeat("a", 40)}, Policy: policyID,
		Paths: []string{}, Records: []rmRecordWire{},
	}
	for i := 0; i < count; i++ {
		path := fmt.Sprintf("src/file-%02d.go", i)
		w.Paths = append(w.Paths, path)
		w.Records = append(w.Records, rmRecordWire{Kind: "human_feedback", Taint: "user_controlled", Path: path, Symbols: []string{}, Text: text, Producer: rmProducer, Observed: rmObserved, From: rmObserved, Until: rmUntil})
	}
	rmReseal(t, &w, true)
	return w
}

func rmPolicy(t *testing.T, zone provider.ProviderZone, endpoint string, mixed bool) RuntimePolicy {
	t.Helper()
	definition := routeDefinition(t, "model-a")
	route, err := provider.NewRouteReference(zone, "provider-a", "adapter-a", "connection-a", "model-a", "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	definition.Route = route
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{definition})
	if err != nil || inventory.Validate() != nil {
		t.Fatal("invalid inventory fixture")
	}
	zones := []string{zone.String()}
	if mixed {
		zones = []string{"local", "private_remote"}
	}
	wire := runtimePolicyWire{
		SchemaVersion: 1, InventoryIdentity: inventory.Identity(), ReviewPolicyIdentity: strings.Repeat("a", 64),
		MinContextTokens: 32000, MinOutputTokens: 4096, RequiredFeatures: []string{"structured_output"},
		Classification: "confidential", AllowedZones: zones, ContentLoggingAllowed: false,
		EstimatedInputTokens: 8000, MaxOutputTokens: 4096, MaxCostMicroUSD: 100000,
		PreferredRouteRecordIdentities: []string{inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()},
		VerificationIndependence:       "distinct_provider", PublicationMinimumSeverity: "medium", PublicationMaxInlineFindings: 20,
		PublicationMinimumIndependence: "distinct_provider", PublicationBlockOnInconclusive: true,
		Connections: []providerConnectionWire{{Implementation: "openai_responses", AdapterID: "adapter-a", Endpoint: endpoint, CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_RETAINED_TEST"}},
	}
	value, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(rmJSON(t, wire)), inventory)
	if err != nil || value.Validate() != nil || value.ValidateAgainstInventory(inventory) != nil {
		t.Fatal("invalid decoded policy fixture")
	}
	for _, connection := range value.Connections() {
		locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
		if err != nil || (zone == provider.ProviderZoneLocal && locality != provider.ServiceEndpointLoopback) {
			t.Fatal("policy endpoint fixture drift")
		}
	}
	return value
}

func rmError(t *testing.T, err error) {
	t.Helper()
	if err != ErrInvalidRetainedMemoryInput || !errors.Is(err, ErrInvalidRetainedMemoryInput) || errors.Unwrap(err) != nil || err.Error() != "invalid retained memory input" {
		t.Fatal("failure did not return fixed unwrapped sentinel")
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, ErrProtectedConfiguration, memory.ErrInvalidMemoryText, memory.ErrInvalidScopeIdentity, ErrInvalidRouteInventory} {
		if errors.Is(err, cause) {
			t.Fatal("underlying cause escaped")
		}
	}
}

func rmZero(t *testing.T, value RetainedMemoryInput) {
	t.Helper()
	if value.Identity() != "" || !reflect.DeepEqual(value.Scope(), memory.Scope{}) || value.Records() != nil || !reflect.DeepEqual(value, RetainedMemoryInput{}) {
		t.Fatal("failure published nonzero output")
	}
}

func rmFormat(t *testing.T, value RetainedMemoryInput) {
	t.Helper()
	if value.String() != "retained memory input" || value.GoString() != "runtimeconfig.RetainedMemoryInput{<redacted>}" {
		t.Fatal("method redaction drift")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%x", "%d", "%f", "%#q", "%01000.1s", "%1000000.0v", "%+1000000.1q"} {
		want := "retained memory input"
		if strings.HasSuffix(format, "q") {
			want = `"retained memory input"`
		}
		if format == "%#v" {
			want = "runtimeconfig.RetainedMemoryInput{<redacted>}"
		}
		if got := fmt.Sprintf(format, value); got != want {
			t.Fatalf("redaction drift for format %s", format)
		}
	}
	if fmt.Sprintf("%T", value) != "runtimeconfig.RetainedMemoryInput" || !strings.HasPrefix(fmt.Sprintf("%p", &value), "0x") {
		t.Fatal("fmt type/pointer behavior drift")
	}
	if string(rmJSON(t, value)) != "{}" {
		t.Fatal("JSON unexpectedly exports authority")
	}
}

func rmDecodedBytes(t *testing.T, encoded []byte) int {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	total := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return total
		}
		if err != nil {
			t.Fatal(err)
		}
		if value, ok := token.(string); ok {
			total += len(value)
		}
	}
}

func TestRetainedMemoryInputZeroAndJSONCannotMint(t *testing.T) {
	var zero RetainedMemoryInput
	rmZero(t, zero)
	rmFormat(t, zero)
	rmError(t, zero.ValidateFor(memory.Scope{}, evidence.RepositoryIdentity{}, RuntimePolicy{}, time.Time{}))
	typeOf := reflect.TypeOf(zero)
	for i := 0; i < typeOf.NumField(); i++ {
		if typeOf.Field(i).IsExported() {
			t.Fatal("exported authority field")
		}
	}
	if _, ok := any(&zero).(json.Unmarshaler); ok {
		t.Fatal("unsupported public JSON decoder")
	}
	for _, raw := range []string{`{}`, `{"identity":"forged","verified":true,"records":[{"text":"private-note"}]}`, `null`} {
		var value RetainedMemoryInput
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			t.Fatal(err)
		}
		rmZero(t, value)
		rmError(t, value.ValidateFor(memory.Scope{}, evidence.RepositoryIdentity{}, RuntimePolicy{}, time.UnixMilli(rmObserved)))
	}
}

func TestLoadProtectedRetainedMemoryInputRejectsArguments(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	scope, repository, at := rmScope(t, w.Scope), rmRepository(t, "source-repository"), time.UnixMilli(rmObserved)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name       string
		ctx        context.Context
		path       string
		scope      memory.Scope
		repository evidence.RepositoryIdentity
		policy     RuntimePolicy
		at         time.Time
	}{
		{"nil-context", nil, "private-note-missing", scope, repository, policy, at},
		{"canceled", ctx, "private-note-missing", scope, repository, policy, at},
		{"empty-path", context.Background(), "", scope, repository, policy, at},
		{"zero-scope", context.Background(), "", memory.Scope{}, repository, policy, at},
		{"zero-repository", context.Background(), "", scope, evidence.RepositoryIdentity{}, policy, at},
		{"zero-policy", context.Background(), "", scope, repository, RuntimePolicy{}, at},
		{"zero-at", context.Background(), "", scope, repository, policy, time.Time{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := LoadProtectedRetainedMemoryInput(test.ctx, test.path, test.scope, test.repository, test.policy, test.at)
			rmError(t, err)
			rmZero(t, value)
		})
	}
}

const rmLiteralRepository = `{"contract":"open-trestle/repository-identity","schema_version":1,"authority":"example.test","namespace":["team"],"name":"source-repository"}`

const rmLiteralHead = `{"contract":"open-trestle/revision-identity","schema_version":1,"kind":"git_commit","algorithm":"sha1","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

const rmLiteralScope = `{"contract":"open-trestle/memory-scope","version":1,"tenant":"tenant-a","repository":"logical-repo","actor":"local-reviewer","ref_visibility":"exact","ref_set_identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075","path_prefixes":["."]}`

const rmLiteralNote = `["open-trestle/operator-feedback-note",1,"c7f4f16d79f8d5fca043cc24496f98c862f155c7cda8f84dc33df8471e9b0e81","src/file-00.go","\u003c\u0026\u003e é é \u2028\u2029\n\toperator advisory",1700000000000,1700000000000,1700000060000]`

const rmLiteralNativeRecord = `{"contract":"open-trestle/memory-record","version":1,"scope":"c7f4f16d79f8d5fca043cc24496f98c862f155c7cda8f84dc33df8471e9b0e81","kind":"human_feedback","taint":"user_controlled","path":"src/file-00.go","symbols":null,"text_digest":"fda3cda4a20dd982c3a00e24cc92e4d8a9136c19277361da5e86b059667291d1","text_bytes":36,"evidence":["operator-note:afe4093bebce7079c6781fee256cc0aea133c87ffdb97c450e2bcc55ef576ab0"],"derived_from":null,"counter_evidence":null,"producer":"084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f","observed_at":1700000000000,"valid_from":1700000000000,"valid_until":1700000060000,"stale_after":0,"freshness":"","confidence":0}`

const rmLiteralEnvelope = `{"contract":"open-trestle/retained-memory-input","schema_version":1,"attestation":"operator_attested_advisory_feedback","scope":{"identity":"c7f4f16d79f8d5fca043cc24496f98c862f155c7cda8f84dc33df8471e9b0e81","tenant_id":"tenant-a","repository_id":"logical-repo","actor_id":"local-reviewer","ref_visibility":"exact","ref_set_identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075","path_prefixes":["."]},"repository_identity":"eb39d6c4b3b358d532b0f47aa093fa8cc3ee9f7cb4d5f9d1aa94df450d4c5c99","head_revision":{"kind":"git_commit","algorithm":"sha1","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075"},"runtime_policy_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_paths":["src/file-00.go"],"records":[{"record_identity":"6212191c80bec6200b93f5e63b446eb75068851d70fd390a22863b4ee99cad67","kind":"human_feedback","taint":"user_controlled","path":"src/file-00.go","symbols":[],"text":"\u003c\u0026\u003e é é \u2028\u2029\n\toperator advisory","evidence_ids":["operator-note:afe4093bebce7079c6781fee256cc0aea133c87ffdb97c450e2bcc55ef576ab0"],"producer_identity":"084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f","observed_at":1700000000000,"valid_from":1700000000000,"valid_until":1700000060000}]}`

const rmLiteralInput = `["open-trestle/protected-retained-input",1,"local-only",65536,16,16,4096,1024,8192,32768,604800000,{"contract":"open-trestle/retained-memory-input","schema_version":1,"attestation":"operator_attested_advisory_feedback","scope":{"identity":"c7f4f16d79f8d5fca043cc24496f98c862f155c7cda8f84dc33df8471e9b0e81","tenant_id":"tenant-a","repository_id":"logical-repo","actor_id":"local-reviewer","ref_visibility":"exact","ref_set_identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075","path_prefixes":["."]},"repository_identity":"eb39d6c4b3b358d532b0f47aa093fa8cc3ee9f7cb4d5f9d1aa94df450d4c5c99","head_revision":{"kind":"git_commit","algorithm":"sha1","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075"},"runtime_policy_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_paths":["src/file-00.go"],"records":[{"record_identity":"6212191c80bec6200b93f5e63b446eb75068851d70fd390a22863b4ee99cad67","kind":"human_feedback","taint":"user_controlled","path":"src/file-00.go","symbols":[],"text":"\u003c\u0026\u003e é é \u2028\u2029\n\toperator advisory","evidence_ids":["operator-note:afe4093bebce7079c6781fee256cc0aea133c87ffdb97c450e2bcc55ef576ab0"],"producer_identity":"084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f","observed_at":1700000000000,"valid_from":1700000000000,"valid_until":1700000060000}]}]`

func TestRetainedMemoryInputIndependentLiteralRecipes(t *testing.T) {
	w := rmEnvelope(t, strings.Repeat("a", 64), 1, rmLiteralText)
	for _, test := range []struct {
		name            string
		got             []byte
		literal, digest string
	}{
		{"head", rmHeadBytes(t, w.Head), rmLiteralHead, "48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075"},
		{"scope", rmScopeBytes(t, w.Scope), rmLiteralScope, "c7f4f16d79f8d5fca043cc24496f98c862f155c7cda8f84dc33df8471e9b0e81"},
		{"note", rmNoteBytes(t, w.Scope.Identity, w.Records[0]), rmLiteralNote, "afe4093bebce7079c6781fee256cc0aea133c87ffdb97c450e2bcc55ef576ab0"},
		{"native_record", rmRecordBytes(t, w.Scope.Identity, w.Records[0]), rmLiteralNativeRecord, "6212191c80bec6200b93f5e63b446eb75068851d70fd390a22863b4ee99cad67"},
		{"envelope", rmJSON(t, w), rmLiteralEnvelope, "e224e55a81ca15471254c963295f0913e4b4c71d584f67734503aa484884a49e"},
		{"input", rmInputBytes(t, w), rmLiteralInput, "59875000ae3f1e721d64eabd4f12fd5110b79c99613df5407992f9b63a5b2ea5"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if string(test.got) != test.literal || rmHash(test.got) != test.digest {
				t.Fatal("independent literal identity recipe drift")
			}
		})
	}
	if rmHash([]byte(rmLiteralRepository)) != "eb39d6c4b3b358d532b0f47aa093fa8cc3ee9f7cb4d5f9d1aa94df450d4c5c99" || w.Repository != "eb39d6c4b3b358d532b0f47aa093fa8cc3ee9f7cb4d5f9d1aa94df450d4c5c99" {
		t.Fatal("independent repository recipe drift")
	}
	if rmHash([]byte("open-trestle/operator-retained-feedback/v1")) != rmProducer {
		t.Fatal("producer domain drift")
	}
	if !bytes.Contains(rmRecordBytes(t, w.Scope.Identity, w.Records[0]), []byte(`"symbols":null`)) || !bytes.Contains(rmJSON(t, w.Records[0]), []byte(`"symbols":[]`)) {
		t.Fatal("native nil arrays confused with wire arrays")
	}
	if w.Scope.Repository == w.Repository || w.Scope.RefSet == w.Head.Digest {
		t.Fatal("logical/native identity separation lost")
	}
}
