package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func investigationArtifactKind(t *testing.T, token string) Kind {
	t.Helper()
	kind, _, _, _, err := parseEnums(token, "confidential", "host", "process_private")
	if err != nil || kind.String() != token {
		t.Fatalf("artifact token %q is not recognized", token)
	}
	return kind
}

// These envelopes carry inert codec data, not successful tool or model records.
func investigationArtifactFixture(t *testing.T, token string) Artifact {
	t.Helper()
	kind := investigationArtifactKind(t, token)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(scope, kind, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate,
		[]string{strings.Repeat("b", 64), strings.Repeat("a", 64)}, []byte(`{"fixture":"inert token record"}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestInvestigationArtifactTokensRoundTripInertEnvelopes(t *testing.T) {
	for i, token := range []string{"investigation_turn", "investigation_tool_result"} {
		t.Run(token, func(t *testing.T) {
			value := investigationArtifactFixture(t, token)
			if uint8(value.Kind()) != uint8(15+i) || value.Validate() != nil {
				t.Fatal("new kind was not appended after the existing fourteen values")
			}
			encoded, err := Encode(value)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(encoded)
			if err != nil || parsed.Identity() != value.Identity() || parsed.Scope() != value.Scope() || parsed.Kind() != value.Kind() || parsed.PayloadDigest() != value.PayloadDigest() || !bytes.Equal(parsed.Payload(), value.Payload()) || !bytes.Equal(mustEncode(t, parsed), encoded) {
				t.Fatal("new token lost exact canonical artifact readback")
			}
			if !reflect.DeepEqual(parsed.Provenance(), []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}) || parsed.Origin() != OriginHost || parsed.Protection() != ProtectionProcessPrivate || parsed.Classification() != ClassificationConfidential {
				t.Fatal("artifact token changed declared handling or sorted provenance")
			}
			payload, provenance := parsed.Payload(), parsed.Provenance()
			payload[0], provenance[0] = 'x', strings.Repeat("c", 64)
			encoded[0] = 'x'
			if parsed.Validate() != nil || parsed.Identity() != value.Identity() || !bytes.Equal(parsed.Payload(), value.Payload()) {
				t.Fatal("token readback exposed mutable payload or metadata")
			}
			store, err := NewMemoryStore(ProtectionProcessPrivate, 2)
			if err != nil {
				t.Fatal(err)
			}
			if added, err := store.Put(context.Background(), parsed, time.UnixMilli(200)); err != nil || !added {
				t.Fatal("inert token envelope did not enter actual scoped store")
			}
			if added, err := store.Put(context.Background(), parsed, time.UnixMilli(200)); err != nil || added {
				t.Fatal("identical artifact storage lost existing idempotence")
			}
			other, err := audit.NewReviewScope("tenant-b", "repo-a", "run-token")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(context.Background(), other, parsed.Identity(), time.UnixMilli(200)); !errors.Is(err, ErrArtifactNotFound) {
				t.Fatal("new artifact kind bypassed exact scope partitioning")
			}
			if _, err := store.Get(context.Background(), parsed.Scope(), parsed.Identity(), time.UnixMilli(1000)); !errors.Is(err, ErrArtifactExpired) {
				t.Fatal("new artifact kind bypassed expiry")
			}
		})
	}
}

func TestInvestigationArtifactTokenNearMissesRefuse(t *testing.T) {
	for _, token := range []string{"", "investigation", "investigation_turns", "investigation_tool", "investigation_tool_results", "Investigation_turn", "investigation-turn", " investigation_turn", "investigation_turn\n", "investigation_tool_result ", "investigation_tool_result\x00"} {
		kind, _, _, _, err := parseEnums(token, "confidential", "host", "process_private")
		if err == nil || kind != 0 {
			t.Fatal("unknown or near-miss artifact token admitted")
		}
	}
}

func TestInvestigationArtifactEnvelopesKeepBindingAndMetadataChecks(t *testing.T) {
	for _, token := range []string{"investigation_turn", "investigation_tool_result"} {
		value := investigationArtifactFixture(t, token)
		changes := map[string]func(*record){
			"scope":                func(r *record) { r.TenantID = "tenant-b" },
			"payload":              func(r *record) { r.Payload = []byte("different inert payload") },
			"origin":               func(r *record) { r.Origin = "model" },
			"protection":           func(r *record) { r.Protection = "envelope_encrypted" },
			"provenance":           func(r *record) { r.Provenance[0] = strings.Repeat("c", 64) },
			"provenance order":     func(r *record) { r.Provenance[0], r.Provenance[1] = r.Provenance[1], r.Provenance[0] },
			"duplicate provenance": func(r *record) { r.Provenance[1] = r.Provenance[0] },
			"missing provenance":   func(r *record) { r.Provenance = nil },
			"expired interval":     func(r *record) { r.ExpiresAtMilliseconds = r.CreatedAtMilliseconds },
			"unknown kind":         func(r *record) { r.Kind = "investigation_unknown" },
		}
		for name, change := range changes {
			t.Run(token+"/"+name, func(t *testing.T) {
				wire := toRecord(value)
				change(&wire)
				encoded, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				if parsed, err := Parse(encoded); err == nil || parsed.Identity() != "" {
					t.Fatal("tampered token envelope validated")
				}
			})
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
			text := fmt.Sprintf(verb, value)
			if strings.Contains(text, "inert token record") || strings.Contains(text, value.Identity()) || strings.Contains(text, "tenant-a") {
				t.Fatal("artifact formatting exposed token fixture data")
			}
		}
	}
}

func TestInvestigationArtifactTokensDoNotRaisePayloadOrEnvelopeLimits(t *testing.T) {
	if maxPayloadBytes != 16<<20 || maxEncodedArtifactBytes != 22<<20 {
		t.Fatal("artifact payload or envelope cap changed")
	}
	value := investigationArtifactFixture(t, "investigation_turn")
	payload := bytes.Repeat([]byte{'x'}, (16<<20)+1)
	for _, size := range []int{16 << 20, (16 << 20) + 1} {
		bounded, err := New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), payload[:size], value.CreatedAt(), value.ExpiresAt())
		if size > 16<<20 {
			if err == nil || bounded.Identity() != "" {
				t.Fatal("new kind admitted payload beyond unchanged cap")
			}
			continue
		}
		if err != nil {
			t.Fatal("exact existing payload bound refused")
		}
		encoded, err := Encode(bounded)
		if err != nil || len(encoded) > 22<<20 {
			t.Fatal("maximum payload exceeded unchanged envelope cap")
		}
		if parsed, err := Parse(encoded); err != nil || parsed.Identity() != bounded.Identity() {
			t.Fatal("exact payload-bound token envelope failed readback")
		}
	}
	if _, err := Parse(bytes.Repeat([]byte{' '}, (22<<20)+1)); err == nil {
		t.Fatal("oversized envelope admitted")
	}
}

func TestInvestigationArtifactAdditionPreservesOldKindsAndFixtureIdentities(t *testing.T) {
	kinds := []Kind{KindSourceSnapshot, KindChangeModel, KindDeterministicEvidence, KindRetrievalResult, KindContextPacket, KindCandidateBatch, KindVerificationBatch, KindVerifiedFindingSet, KindPublicationPlan, KindRunExport, KindTaskInput, KindWebhookDelivery, KindSourceFile, KindPublicationReceipt}
	tokens := []string{"source_snapshot", "change_model", "deterministic_evidence", "retrieval_result", "context_packet", "candidate_batch", "verification_batch", "verified_finding_set", "publication_plan", "run_export", "task_input", "webhook_delivery", "source_file", "publication_receipt"}
	for i, kind := range kinds {
		parsed, _, _, _, err := parseEnums(tokens[i], "confidential", "host", "process_private")
		if uint8(kind) != uint8(i+1) || kind.String() != tokens[i] || err != nil || parsed != kind {
			t.Fatal("existing artifact numeric value or string changed")
		}
	}
	encoded, err := os.ReadFile("../handlers/model/testdata/model-context-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if json.Unmarshal(encoded, &fixture) != nil {
		t.Fatal("existing model-context fixture could not be read")
	}
	for name, identity := range map[string]string{
		"generation_context":  "15f22c9225283f142880f60176dad90f2e2925ffb2c80daf3a8bc3d14ae394c9",
		"generation_input":    "e83e28fc630f6deba9f1dc3fb5551b0c794213f5da16871474749ed6886e85de",
		"generation_result":   "d531073360d994ca982cf46329ab728d7654d9c4718f7b859545de5d83a2dba7",
		"verification_result": "a8ea330695e9a77e29f13f5f681ae68c5a60cfa66d56e1fc843bac7611a311fc",
	} {
		value, err := Parse(fixture[name])
		if err != nil || value.Identity() != identity || !bytes.Equal(mustEncode(t, value), fixture[name]) {
			t.Fatalf("unchanged legacy artifact fixture %s lost exact bytes or identity", name)
		}
	}
}

func TestInvestigationArtifactTokensKeepConstructorProvenanceBounds(t *testing.T) {
	for _, token := range []string{"investigation_turn", "investigation_tool_result"} {
		value := investigationArtifactFixture(t, token)
		if invalid, err := New(audit.ReviewScope{}, value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), value.Payload(), value.CreatedAt(), value.ExpiresAt()); err == nil || invalid.Identity() != "" {
			t.Fatal("token extension bypassed scope construction")
		}
		provenance := make([]string, 33)
		for i := range provenance {
			provenance[i] = fmt.Sprintf("%064x", i+1)
		}
		for _, count := range []int{32, 33} {
			bounded, err := New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), provenance[:count], value.Payload(), value.CreatedAt(), value.ExpiresAt())
			if count == 32 {
				if err != nil || bounded.Validate() != nil {
					t.Fatal("exact provenance-count boundary refused")
				}
			} else if err == nil || bounded.Identity() != "" {
				t.Fatal("provenance-count ceiling expanded")
			}
		}
	}
}

func TestInvestigationArtifactKindsMatchPublicSchema(t *testing.T) {
	encoded, err := os.ReadFile("../schemas/artifact/runtime-artifact-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	want := []string{"source_snapshot", "change_model", "deterministic_evidence", "retrieval_result", "context_packet", "candidate_batch", "verification_batch", "verified_finding_set", "publication_plan", "run_export", "task_input", "webhook_delivery", "source_file", "publication_receipt", "investigation_turn", "investigation_tool_result"}
	if !reflect.DeepEqual(schema.Properties["kind"].Enum, want) {
		t.Fatal("public artifact schema changed old kinds or omitted the append-only investigation tokens")
	}
	for i, token := range want {
		if Kind(i+1).String() != token || investigationArtifactKind(t, token) != Kind(i+1) {
			t.Fatal("runtime artifact kinds disagree with the actual public schema")
		}
	}
}
