package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

// Source-only contract tests. These values are metadata, never durable acceptance,
// a dispatch permit, provider state, or erasure proof. No storage facade is used.
const ovOperationContract = `open-trestle/artifact-erasure-operation`
const ovFenceContract = `open-trestle/artifact-erasure-fence`
const ovOther = `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
const ovScopeIdentity = `4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa`
const ovNamespaceIdentity = `84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80`
const ovArtifactIdentity = `cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5`
const ovAdmissionIdentity = `968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3`
const ovAuthorizationIdentity = `86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992`
const ovDocumentDigest = `6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8`
const ovPolicyIdentity = `debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca`
const ovOperationIdentity = `c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050`
const ovFenceIdentity = `188c587e4605df05ea58ef7ab5baa0f0ecfacc197207d4cbf26df299ef447096`
const ovOperationUnsigned = `{"contract":"open-trestle/artifact-erasure-operation","schema_version":2,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","ownership":"all_versions_at_exact_key","prepared_at_milliseconds":1000,"erasure_protocol":"same-key-fence-v2","legacy_receipt_identity":""}`
const ovOperationJSON = `{"contract":"open-trestle/artifact-erasure-operation","schema_version":2,"identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","ownership":"all_versions_at_exact_key","prepared_at_milliseconds":1000,"erasure_protocol":"same-key-fence-v2","legacy_receipt_identity":""}`
const ovFenceUnsigned = `{"contract":"open-trestle/artifact-erasure-fence","schema_version":1,"erasure_protocol":"same-key-fence-v2","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","prepared_at_milliseconds":1000}`
const ovFenceJSON = `{"contract":"open-trestle/artifact-erasure-fence","schema_version":1,"identity":"188c587e4605df05ea58ef7ab5baa0f0ecfacc197207d4cbf26df299ef447096","erasure_protocol":"same-key-fence-v2","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","prepared_at_milliseconds":1000}`
const ovPolicyJSON = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"authorization-fixture/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":900,"not_after_milliseconds":1400}`
const ovGrantJSON = `{"contract":"open-trestle/artifact-erasure-authorization","schema_version":2,"identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","hold_clearance_identity":"9999999999999999999999999999999999999999999999999999999999999999","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","reason":"expired","issued_at_milliseconds":900,"expires_at_milliseconds":1500,"legacy_receipt_identity":""}`
const ovAdmissionJSON = `{"contract":"open-trestle/artifact-admission","schema_version":1,"identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const ovArtifactUnsigned = `{"scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000}`
const ovScopeUnsigned = `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-auth","repository":"repo-auth","review_run":"run-auth"}`

const ovOriginalArtifactJSON = `{"contract":"open-trestle/runtime-artifact","schema_version":1,"identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","payload":"c3ludGhldGljIGF1dGhvcml6YXRpb24gYWRtaXNzaW9u","created_at_milliseconds":100,"expires_at_milliseconds":1000}`

var ovOperationOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity original_authorization_identity authorization_document_digest policy_identity protected_policy_identity ownership prepared_at_milliseconds erasure_protocol legacy_receipt_identity")
var ovFenceOrder = strings.Fields("contract schema_version identity erasure_protocol namespace_identity scope_identity artifact_identity operation_identity prepared_at_milliseconds")

func ovHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ovQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func ovFields(t *testing.T, wire string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

// This ordered raw-member recipe is independent of the product encoder. It
// preserves exact integers and removes only identity from the hash preimage.
func ovOrdered(t *testing.T, fields map[string]json.RawMessage, order []string, unsigned bool) string {
	t.Helper()
	var members []string
	for _, key := range order {
		if unsigned && key == "identity" {
			continue
		}
		value, ok := fields[key]
		if !ok {
			t.Fatal("missing test recipe member", key)
		}
		members = append(members, ovQuote(key)+":"+string(value))
	}
	return "{" + strings.Join(members, ",") + "}"
}

func ovVariant(t *testing.T, wire string, order []string, domain string, changes map[string]string) string {
	t.Helper()
	fields := ovFields(t, wire)
	for key, value := range changes {
		if _, ok := fields[key]; !ok {
			t.Fatal("unknown test recipe member", key)
		}
		fields[key] = json.RawMessage(value)
	}
	fields["identity"] = json.RawMessage(ovQuote(ovHash(domain + ovOrdered(t, fields, order, true))))
	return ovOrdered(t, fields, order, false)
}

func ovOperationVariant(t *testing.T, changes map[string]string) string {
	return ovVariant(t, ovOperationJSON, ovOperationOrder, ovOperationContract+"/v2\x00", changes)
}

func ovFenceVariant(t *testing.T, changes map[string]string) string {
	return "OTAF0001" + ovVariant(t, ovFenceJSON, ovFenceOrder, ovFenceContract+"/v1\x00", changes)
}

func ovScope(t *testing.T, tenant, repository, run string) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope(tenant, repository, run)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func ovMatchingScope(t *testing.T) audit.ReviewScope {
	return ovScope(t, "tenant-auth", "repo-auth", "run-auth")
}

func ovError(t *testing.T, got, want error) {
	t.Helper()
	if got != want || !errors.Is(got, want) {
		t.Fatalf("closed error got %v, want %v", got, want)
	}
}

func ovZeroOperation(t *testing.T, value artifact.ErasureOperation) {
	t.Helper()
	if !reflect.DeepEqual(value, artifact.ErasureOperation{}) || value.Validate() == nil || !value.PreparedAt().IsZero() || value.Scope() != (audit.ReviewScope{}) || !reflect.DeepEqual(value.Ref(), artifact.ErasureOperationRef{}) {
		t.Fatal("operation failure did not return zero metadata")
	}
	for _, s := range []string{value.Identity(), value.NamespaceIdentity(), value.ArtifactIdentity(), value.AdmissionIdentity(), value.OriginalAuthorizationIdentity(), value.AuthorizationDocumentDigest(), value.PolicyIdentity(), value.ProtectedPolicyIdentity(), value.Ownership(), value.ErasureProtocol(), value.LegacyReceiptIdentity()} {
		if s != "" {
			t.Fatal("zero operation getter retained data")
		}
	}
}

func ovZeroFence(t *testing.T, value artifact.ErasureFence) {
	t.Helper()
	if !reflect.DeepEqual(value, artifact.ErasureFence{}) || value.Validate() == nil || !value.PreparedAt().IsZero() {
		t.Fatal("fence failure did not return zero metadata")
	}
	for _, s := range []string{value.Identity(), value.ErasureProtocol(), value.NamespaceIdentity(), value.ScopeIdentity(), value.ArtifactIdentity(), value.OperationIdentity()} {
		if s != "" {
			t.Fatal("zero fence getter retained data")
		}
	}
}

func ovParse(t *testing.T, wire string, scope audit.ReviewScope) artifact.ErasureOperation {
	t.Helper()
	value, err := artifact.ParseErasureOperation([]byte(wire), scope)
	if err != nil || value.Validate() != nil || value.Scope() != scope || value.Ref().Validate() != nil || value.Ref().Scope() != scope || value.Ref().NamespaceIdentity() != value.NamespaceIdentity() || value.Ref().OperationIdentity() != value.Identity() {
		t.Fatal("explicit-scope metadata parse/ref rejected", err)
	}
	encoded, err := artifact.EncodeErasureOperation(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("operation canonical roundtrip differs", err)
	}
	return value
}

func ovParseFence(t *testing.T, wire string) artifact.ErasureFence {
	t.Helper()
	value, err := artifact.ParseErasureFence([]byte(wire))
	if err != nil || value.Validate() != nil {
		t.Fatal("fence metadata parse rejected", err)
	}
	encoded, err := artifact.EncodeErasureFence(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("framed fence roundtrip differs", err)
	}
	return value
}

func ovBadOperation(t *testing.T, wire string, scope audit.ReviewScope, want error) {
	t.Helper()
	value, err := artifact.ParseErasureOperation([]byte(wire), scope)
	ovError(t, err, want)
	ovZeroOperation(t, value)
}

func ovBadFence(t *testing.T, wire string, want error) {
	t.Helper()
	value, err := artifact.ParseErasureFence([]byte(wire))
	ovError(t, err, want)
	ovZeroFence(t, value)
}

func TestOperationValuesLiteralVectors(t *testing.T) {
	for _, vector := range []struct{ preimage, identity string }{
		{ovOperationContract + "/v2\x00" + ovOperationUnsigned, ovOperationIdentity},
		{ovFenceContract + "/v1\x00" + ovFenceUnsigned, ovFenceIdentity},
		{ovScopeUnsigned, ovScopeIdentity}, {ovArtifactUnsigned, ovArtifactIdentity},
		{ovGrantJSON, ovDocumentDigest},
	} {
		if ovHash(vector.preimage) != vector.identity {
			t.Fatal("independent literal vector differs")
		}
	}
	for _, record := range []struct{ wire, unsigned, id, domain string }{
		{ovOperationJSON, ovOperationUnsigned, ovOperationIdentity, ovOperationContract + "/v2\x00"},
		{ovFenceJSON, ovFenceUnsigned, ovFenceIdentity, ovFenceContract + "/v1\x00"},
	} {
		if strings.Replace(record.wire, `"identity":"`+record.id+`",`, "", 1) != record.unsigned {
			t.Fatal("identity omission changed original canonical order")
		}
		for _, wrong := range []string{record.unsigned, strings.TrimSuffix(record.domain, "\x00") + record.unsigned, strings.ReplaceAll(record.domain, "\x00", `\x00`) + record.unsigned, "OTAF0001" + record.domain + record.unsigned, record.domain + record.wire} {
			if ovHash(wrong) == record.id {
				t.Fatal("vector does not discriminate hash recipe")
			}
		}
	}
	scope := ovMatchingScope(t)
	value := ovParse(t, ovOperationJSON, scope)
	if value.Identity() != ovOperationIdentity || value.NamespaceIdentity() != ovNamespaceIdentity || value.ArtifactIdentity() != ovArtifactIdentity || value.AdmissionIdentity() != ovAdmissionIdentity || value.OriginalAuthorizationIdentity() != ovAuthorizationIdentity || value.AuthorizationDocumentDigest() != ovDocumentDigest || value.PolicyIdentity() != strings.Repeat("5", 64) || value.ProtectedPolicyIdentity() != ovPolicyIdentity || value.Ownership() != "all_versions_at_exact_key" || value.ErasureProtocol() != "same-key-fence-v2" || value.LegacyReceiptIdentity() != "" || value.PreparedAt() != time.UnixMilli(1000).UTC() {
		t.Fatal("operation getters differ from literal")
	}
	// A parsed operation builds content bytes only; it has no accepted-state API.
	fence, err := artifact.NewErasureFence(value)
	if err != nil || fence.Validate() != nil {
		t.Fatal("shape-only fence rejected", err)
	}
	wire, err := artifact.EncodeErasureFence(fence)
	if err != nil || string(wire) != "OTAF0001"+ovFenceJSON || len(wire) > 4096 || string(wire[:9]) != "OTAF0001{" {
		t.Fatal("fence framing is not eight-byte magic immediately followed by JSON", err)
	}
	ovParseFence(t, string(wire))
	if fence.Identity() != ovFenceIdentity || fence.ErasureProtocol() != value.ErasureProtocol() || fence.NamespaceIdentity() != value.NamespaceIdentity() || fence.ScopeIdentity() != scope.Identity() || fence.ArtifactIdentity() != value.ArtifactIdentity() || fence.OperationIdentity() != value.Identity() || fence.PreparedAt() != value.PreparedAt() {
		t.Fatal("fence projection differs")
	}
	for _, forbidden := range []string{"tenant_id", "repository_id", "review_run_id", "payload_digest", "admission_identity", "authorization_document_digest", "protected_policy_identity", "kms", "witness", "document", `"key":`, "tenant-auth", "repo-auth", "run-auth"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatal("fence contains non-projection data", forbidden)
		}
	}
	for _, forbidden := range []string{"tenant_id", "repository_id", "review_run_id", "tenant-auth", "repo-auth", "run-auth"} {
		if strings.Contains(ovOperationJSON, forbidden) {
			t.Fatal("operation wire contains raw scope")
		}
	}
}

func TestOperationValuesRefAndExplicitScope(t *testing.T) {
	scope := ovMatchingScope(t)
	ref, err := artifact.NewErasureOperationRef(scope, ovNamespaceIdentity, ovOperationIdentity)
	if err != nil || ref.Validate() != nil || ref.Scope() != scope || ref.NamespaceIdentity() != ovNamespaceIdentity || ref.OperationIdentity() != ovOperationIdentity {
		t.Fatal("ref lost usable full scope", err)
	}
	for _, ids := range [][2]string{{"", ovOperationIdentity}, {ovNamespaceIdentity, ""}, {strings.Repeat("0", 64), ovOperationIdentity}, {ovNamespaceIdentity, strings.ToUpper(ovOperationIdentity)}, {strings.Repeat("a", 63), ovOperationIdentity}, {ovNamespaceIdentity, strings.Repeat("a", 65)}, {ovOther + "\x00", ovOperationIdentity}, {ovNamespaceIdentity, strings.Repeat("g", 64)}} {
		bad, err := artifact.NewErasureOperationRef(scope, ids[0], ids[1])
		ovError(t, err, artifact.ErrInvalidErasureContract)
		if !reflect.DeepEqual(bad, artifact.ErasureOperationRef{}) {
			t.Fatal("ref error retained state")
		}
	}
	for _, invalid := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), ovOther + "\x00", " " + ovOther, strings.Repeat("é", 32)} {
		for _, ids := range [][2]string{{invalid, ovOperationIdentity}, {ovNamespaceIdentity, invalid}} {
			bad, err := artifact.NewErasureOperationRef(scope, ids[0], ids[1])
			ovError(t, err, artifact.ErrInvalidErasureContract)
			if !reflect.DeepEqual(bad, artifact.ErasureOperationRef{}) {
				t.Fatal("invalid ref digest retained state")
			}
		}
	}
	bad, err := artifact.NewErasureOperationRef(audit.ReviewScope{}, ovNamespaceIdentity, ovOperationIdentity)
	ovError(t, err, artifact.ErrInvalidErasureContract)
	if !reflect.DeepEqual(bad, artifact.ErasureOperationRef{}) {
		t.Fatal("invalid scope retained ref")
	}
	for _, other := range []audit.ReviewScope{ovScope(t, "other-tenant", "repo-auth", "run-auth"), ovScope(t, "tenant-auth", "other-repo", "run-auth"), ovScope(t, "tenant-auth", "repo-auth", "other-run")} {
		ovBadOperation(t, ovOperationJSON, other, artifact.ErrErasureIdentityMismatch)
		wire := ovOperationVariant(t, map[string]string{"scope_identity": ovQuote(other.Identity())})
		ovParse(t, wire, other)
		ovBadOperation(t, wire, scope, artifact.ErrErasureIdentityMismatch)
	}
	ovBadOperation(t, ovOperationJSON, audit.ReviewScope{}, artifact.ErrInvalidErasureContract)
	ovBadOperation(t, strings.Replace(ovOperationJSON, ovOperationIdentity, ovOther, 1), audit.ReviewScope{}, artifact.ErrInvalidErasureContract)
	ovParse(t, ovOperationJSON, scope)
	long := ovScope(t, strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128))
	longRef, err := artifact.NewErasureOperationRef(long, ovOther, ovOther)
	if err != nil || longRef.Validate() != nil {
		t.Fatal("maximal valid scope rejected", err)
	}
	ovParse(t, ovOperationVariant(t, map[string]string{"scope_identity": ovQuote(long.Identity())}), long)
}

// Exhaustive per-member canonical mutations are finite, not a fuzz root.
func ovNoncanonical(t *testing.T, wire string, order []string) map[string]string {
	t.Helper()
	fields := ovFields(t, wire)
	cases := map[string]string{"empty": "", "null": "null", "array": "[]", "bool": "true", "leading": " " + wire, "trailing": wire + "\n", "second": wire + "{}", "unknown": strings.TrimSuffix(wire, "}") + `,"unknown":1}`, "bom": "\xef\xbb\xbf" + wire, "invalid-utf8": wire + "\xff", "nul": wire + "\x00", "truncated": wire[:len(wire)-1]}
	for i, key := range order {
		member := ovQuote(key) + ":" + string(fields[key])
		without := strings.Replace(wire, member+",", "", 1)
		if without == wire {
			without = strings.Replace(wire, ","+member, "", 1)
		}
		cases["missing/"+key] = without
		cases["null/"+key] = strings.Replace(wire, member, ovQuote(key)+":null", 1)
		cases["duplicate/"+key] = strings.Replace(wire, member, member+","+member, 1)
		cases["conflicting-duplicate/"+key] = strings.Replace(wire, member, ovQuote(key)+":null,"+member, 1)
		cases["alias-duplicate/"+key] = strings.Replace(wire, member, ovQuote(strings.ToUpper(key))+":"+string(fields[key])+","+member, 1)
		if len(fields[key]) > 2 && fields[key][0] == '"' {
			text := string(fields[key])
			escaped := `"\u` + fmt.Sprintf("%04x", text[1]) + text[2:]
			cases["escaped-member-value/"+key] = strings.Replace(wire, member, ovQuote(key)+":"+escaped, 1)
		}
		cases["alias/"+key] = strings.Replace(wire, ovQuote(key)+":", ovQuote(strings.ToUpper(key))+":", 1)
		cases["escaped-key/"+key] = strings.Replace(wire, ovQuote(key)+":", `"\u`+fmt.Sprintf("%04x", key[0])+key[1:]+`":`, 1)
		cases["wrong-type/"+key] = strings.Replace(wire, member, ovQuote(key)+":[]", 1)
		if i+1 < len(order) {
			reordered := append([]string(nil), order...)
			reordered[i], reordered[i+1] = reordered[i+1], reordered[i]
			cases["order/"+key] = ovOrdered(t, fields, reordered, false)
		}
	}
	cases["escaped-value"] = strings.Replace(wire, "open-trestle/", `open-trestle\/`, 1)
	return cases
}

func TestOperationValuesCanonicalRejection(t *testing.T) {
	for name, wire := range ovNoncanonical(t, ovOperationJSON, ovOperationOrder) {
		t.Run("operation/"+name, func(t *testing.T) { ovBadOperation(t, wire, ovMatchingScope(t), artifact.ErrInvalidErasureContract) })
	}
	for name, wire := range ovNoncanonical(t, ovFenceJSON, ovFenceOrder) {
		t.Run("fence/"+name, func(t *testing.T) { ovBadFence(t, "OTAF0001"+wire, artifact.ErrInvalidErasureContract) })
	}
	for _, field := range []string{"tenant_id", "repository_id", "review_run_id", "payload_digest", "key", "authorization_document", "witness", "accepted"} {
		ovBadOperation(t, strings.TrimSuffix(ovOperationJSON, "}")+","+ovQuote(field)+`:"forbidden"}`, ovMatchingScope(t), artifact.ErrInvalidErasureContract)
		ovBadFence(t, "OTAF0001"+strings.TrimSuffix(ovFenceJSON, "}")+","+ovQuote(field)+`:"forbidden"}`, artifact.ErrInvalidErasureContract)
	}
	for _, size := range []int{16383, 16384, 16385} {
		ovBadOperation(t, ovOperationJSON+strings.Repeat(" ", size-len(ovOperationJSON)), ovMatchingScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, size := range []int{4095, 4096, 4097, 4104} {
		wire := "OTAF0001" + ovFenceJSON
		ovBadFence(t, wire+strings.Repeat(" ", size-len(wire)), artifact.ErrInvalidErasureContract)
	}
	for _, wire := range []string{"", "OTAF000", "OTAF0001", ovFenceJSON, "OTAF0002" + ovFenceJSON, "otaf0001" + ovFenceJSON, "OTAF0001\x00\x00\x02\x00" + ovFenceJSON, "OTAF0001OTAF0001" + ovFenceJSON} {
		ovBadFence(t, wire, artifact.ErrInvalidErasureContract)
	}
}

func TestOperationValuesRehashedShapeAndIdentity(t *testing.T) {
	for _, fixture := range []struct {
		name, wire, domain string
		order              []string
		fence              bool
	}{
		{"operation", ovOperationJSON, ovOperationContract + "/v2\x00", ovOperationOrder, false},
		{"fence", ovFenceJSON, ovFenceContract + "/v1\x00", ovFenceOrder, true},
	} {
		check := func(t *testing.T, wire string, want error) {
			if fixture.fence {
				ovBadFence(t, "OTAF0001"+wire, want)
			} else {
				ovBadOperation(t, wire, ovMatchingScope(t), want)
			}
		}
		fields := ovFields(t, fixture.wire)
		for _, key := range fixture.order {
			if key != "identity" && !strings.HasSuffix(key, "_identity") && key != "authorization_document_digest" {
				continue
			}
			for i, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), ovOther + "\x00", " " + ovOther, strings.Repeat("é", 32)} {
				if key == "legacy_receipt_identity" && bad == "" {
					continue
				}
				t.Run(fixture.name+"/digest/"+key+fmt.Sprint(i), func(t *testing.T) {
					wire := ovVariant(t, fixture.wire, fixture.order, fixture.domain, map[string]string{key: ovQuote(bad)})
					if key == "identity" {
						wire = strings.Replace(fixture.wire, string(fields[key]), ovQuote(bad), 1)
					}
					check(t, wire, artifact.ErrInvalidErasureContract)
				})
			}
		}
		for key, bads := range map[string][]string{
			"contract": {`"wrong"`, `""`}, "schema_version": {"0", "3", "-1", "2.0", "2e0", "null"},
			"erasure_protocol":         {`""`, `"same-key-fence-v1"`, `"same-key-fence-v2 "`},
			"prepared_at_milliseconds": {"0", "-1", "253402300800000", "9223372036854775807", "9223372036854775808", "1000.0", "1e3", `"1000"`, "null"},
		} {
			for i, bad := range bads {
				t.Run(fixture.name+"/shape/"+key+fmt.Sprint(i), func(t *testing.T) {
					check(t, ovVariant(t, fixture.wire, fixture.order, fixture.domain, map[string]string{key: bad}), artifact.ErrInvalidErasureContract)
				})
			}
		}
		wrongVersion := "1"
		if fixture.fence {
			wrongVersion = "2"
		}
		check(t, ovVariant(t, fixture.wire, fixture.order, fixture.domain, map[string]string{"schema_version": wrongVersion}), artifact.ErrInvalidErasureContract)
		wrongID := strings.Replace(fixture.wire, string(fields["identity"]), ovQuote(ovOther), 1)
		check(t, wrongID, artifact.ErrErasureIdentityMismatch)
		// Structural errors win over a simultaneously stale stored identity.
		check(t, strings.Replace(wrongID, `"prepared_at_milliseconds":1000`, `"prepared_at_milliseconds":0`, 1), artifact.ErrInvalidErasureContract)
	}
	for _, bad := range []string{`""`, `"current_version"`, `"all_versions_at_exact_key "`} {
		ovBadOperation(t, ovOperationVariant(t, map[string]string{"ownership": bad}), ovMatchingScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, millis := range []int64{1, 999, 1000, 253402300799999} {
		value := ovParse(t, ovOperationVariant(t, map[string]string{"prepared_at_milliseconds": fmt.Sprint(millis)}), ovMatchingScope(t))
		if value.PreparedAt() != time.UnixMilli(millis).UTC() {
			t.Fatal("operation time shape altered")
		}
		fence := ovParseFence(t, ovFenceVariant(t, map[string]string{"prepared_at_milliseconds": fmt.Sprint(millis)}))
		if fence.PreparedAt() != time.UnixMilli(millis).UTC() {
			t.Fatal("fence time shape altered")
		}
	}
}

func TestOperationValuesIndependentRebindings(t *testing.T) {
	scope := ovMatchingScope(t)
	base := ovParse(t, ovOperationJSON, scope)
	for _, key := range []string{"namespace_identity", "artifact_identity", "admission_identity", "original_authorization_identity", "authorization_document_digest", "policy_identity", "protected_policy_identity", "legacy_receipt_identity", "prepared_at_milliseconds"} {
		t.Run(key, func(t *testing.T) {
			replacement := ovQuote(ovOther)
			if key == "prepared_at_milliseconds" {
				replacement = "1001"
			}
			wire := ovOperationVariant(t, map[string]string{key: replacement})
			value := ovParse(t, wire, scope)
			if value.Identity() == base.Identity() {
				t.Fatal("operation member not identity-bound")
			}
			if key == "legacy_receipt_identity" && value.LegacyReceiptIdentity() != ovOther {
				t.Fatal("historical metadata lineage lost")
			}
			fence, err := artifact.NewErasureFence(value)
			if err != nil || fence.Validate() != nil || fence.OperationIdentity() != value.Identity() {
				t.Fatal("rebound metadata fence rejected", err)
			}
			fields := ovFields(t, wire)
			want := ovFenceVariant(t, map[string]string{"namespace_identity": string(fields["namespace_identity"]), "scope_identity": string(fields["scope_identity"]), "artifact_identity": string(fields["artifact_identity"]), "operation_identity": string(fields["identity"]), "prepared_at_milliseconds": string(fields["prepared_at_milliseconds"])})
			encoded, err := artifact.EncodeErasureFence(fence)
			if err != nil || string(encoded) != want || fence.Identity() == ovFenceIdentity {
				t.Fatal("fence independent projection/hash differs", err)
			}
			// Change one well-shaped field without rebinding the stored ID.
			stale := strings.Replace(wire, string(fields["identity"]), ovQuote(base.Identity()), 1)
			ovBadOperation(t, stale, scope, artifact.ErrErasureIdentityMismatch)
		})
	}
	for _, key := range []string{"namespace_identity", "scope_identity", "artifact_identity", "operation_identity", "prepared_at_milliseconds"} {
		replacement := ovQuote(ovOther)
		if key == "prepared_at_milliseconds" {
			replacement = "1001"
		}
		wire := ovFenceVariant(t, map[string]string{key: replacement})
		fence := ovParseFence(t, wire)
		if fence.Identity() == ovFenceIdentity {
			t.Fatal("fence member not identity-bound", key)
		}
		ovBadFence(t, strings.Replace(wire, ovQuote(fence.Identity()), ovQuote(ovFenceIdentity), 1), artifact.ErrErasureIdentityMismatch)
	}
}

func TestOperationValuesCopiesZeroAndRedaction(t *testing.T) {
	ovZeroOperation(t, artifact.ErasureOperation{})
	ovZeroFence(t, artifact.ErasureFence{})
	zeroRef := artifact.ErasureOperationRef{}
	if zeroRef.Validate() == nil || zeroRef.Scope() != (audit.ReviewScope{}) || zeroRef.NamespaceIdentity() != "" || zeroRef.OperationIdentity() != "" {
		t.Fatal("zero ref is usable")
	}
	if b, err := artifact.EncodeErasureOperation(artifact.ErasureOperation{}); err != artifact.ErrInvalidErasureContract || len(b) != 0 {
		t.Fatal("zero operation encoded")
	}
	if b, err := artifact.EncodeErasureFence(artifact.ErasureFence{}); err != artifact.ErrInvalidErasureContract || len(b) != 0 {
		t.Fatal("zero fence encoded")
	}
	f, err := artifact.NewErasureFence(artifact.ErasureOperation{})
	ovError(t, err, artifact.ErrInvalidErasureContract)
	ovZeroFence(t, f)
	operationBytes, fenceBytes := []byte(ovOperationJSON), []byte("OTAF0001"+ovFenceJSON)
	value, err := artifact.ParseErasureOperation(operationBytes, ovMatchingScope(t))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := artifact.ParseErasureFence(fenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	copyValue, copyFence := value, fence
	for i := range operationBytes {
		operationBytes[i] = 'x'
	}
	for i := range fenceBytes {
		fenceBytes[i] = 'x'
	}
	for _, v := range []artifact.ErasureOperation{value, copyValue} {
		first, err := artifact.EncodeErasureOperation(v)
		if err != nil || string(first) != ovOperationJSON {
			t.Fatal("operation aliases parse input")
		}
		second, err := artifact.EncodeErasureOperation(v)
		if err != nil {
			t.Fatal(err)
		}
		first[0] = 'x'
		third, err := artifact.EncodeErasureOperation(v)
		if err != nil || string(second) != ovOperationJSON || !bytes.Equal(second, third) {
			t.Fatal("operation encoder aliases output")
		}
	}
	for _, v := range []artifact.ErasureFence{fence, copyFence} {
		first, err := artifact.EncodeErasureFence(v)
		if err != nil || string(first) != "OTAF0001"+ovFenceJSON {
			t.Fatal("fence aliases parse input")
		}
		second, err := artifact.EncodeErasureFence(v)
		if err != nil {
			t.Fatal(err)
		}
		first[0] = 'x'
		third, err := artifact.EncodeErasureFence(v)
		if err != nil || string(second) != "OTAF0001"+ovFenceJSON || !bytes.Equal(second, third) {
			t.Fatal("fence encoder aliases output")
		}
	}
	type redacted interface {
		String() string
		GoString() string
		Format(fmt.State, rune)
	}
	for _, pair := range []struct{ value, zero redacted }{{value, artifact.ErasureOperation{}}, {fence, artifact.ErasureFence{}}, {value.Ref(), artifact.ErasureOperationRef{}}} {
		if pair.value.String() == "" || pair.value.String() != pair.zero.String() || pair.value.GoString() == "" || pair.value.GoString() != pair.zero.GoString() {
			t.Fatal("string methods are not constant redaction")
		}
		kind := reflect.TypeOf(pair.value)
		for i := 0; i < kind.NumField(); i++ {
			if kind.Field(i).PkgPath == "" {
				t.Fatal("mutable exported value field", kind.Field(i).Name)
			}
		}
		// Runtime strings retain vet checks elsewhere while intentionally exercising
		// mismatched verbs and width/precision without compiler format diagnostics.
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%f", "%T", "%10000v", "%10000.10000q", "%#10000x", "%0.1s"} {
			got, zero := fmt.Sprintf(format, pair.value), fmt.Sprintf(format, pair.zero)
			if got == "" || got != zero || len(got) > 160 || strings.Contains(got, "%!") {
				t.Fatal("formatter is not bounded constant redaction", format)
			}
			for _, secret := range []string{ovOperationIdentity, ovFenceIdentity, ovNamespaceIdentity, ovScopeIdentity, ovArtifactIdentity, ovAdmissionIdentity, ovDocumentDigest, ovPolicyIdentity, "tenant-auth", "repo-auth", "run-auth", "all_versions_at_exact_key", "same-key-fence-v2"} {
				if strings.Contains(got, secret) {
					t.Fatal("formatter exposed metadata", format)
				}
			}
		}
	}
}
