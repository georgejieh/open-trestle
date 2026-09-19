package artifact_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

// Shape and metadata predicates are not protected permission or journal acceptance.
const azContract = `open-trestle/artifact-erasure-authorization`
const azNamespaceIdentity = `84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80`
const azScopeIdentity = `4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa`
const azArtifactIdentity = `cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5`
const azAdmissionIdentity = `968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3`
const azPolicyIdentity = `f05d7c4a0d1bd9ac1a92c9dcde87d2ff0fb7bf489718b44569175df99595d259`
const azIdentity = `86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992`
const azDocumentDigest = `6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8`
const azNamespaceUnsigned = `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"authorization-fixture/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222"}`
const azScopeUnsigned = `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-auth","repository":"repo-auth","review_run":"run-auth"}`
const azArtifactUnsigned = `{"scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000}`
const azAdmissionUnsigned = `{"contract":"open-trestle/artifact-admission","schema_version":1,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const azAdmissionJSON = `{"contract":"open-trestle/artifact-admission","schema_version":1,"identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const azPolicyUnsigned = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"authorization-fixture/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":1,"not_after_milliseconds":2}`
const azPolicyJSON = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"identity":"f05d7c4a0d1bd9ac1a92c9dcde87d2ff0fb7bf489718b44569175df99595d259","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"authorization-fixture/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":1,"not_after_milliseconds":2}`
const azUnsigned = `{"contract":"open-trestle/artifact-erasure-authorization","schema_version":2,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","hold_clearance_identity":"9999999999999999999999999999999999999999999999999999999999999999","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","reason":"expired","issued_at_milliseconds":900,"expires_at_milliseconds":1500,"legacy_receipt_identity":""}`
const azJSON = `{"contract":"open-trestle/artifact-erasure-authorization","schema_version":2,"identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","hold_clearance_identity":"9999999999999999999999999999999999999999999999999999999999999999","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","reason":"expired","issued_at_milliseconds":900,"expires_at_milliseconds":1500,"legacy_receipt_identity":""}`
const azHistoricalV1 = `{"contract":"open-trestle/artifact-deletion-authorization","schema_version":1,"identity":"c29e878419cca15b867f426b30149b5bed9598cb6a2b148cfd3435d9d2da4f33","tenant_id":"tenant-h0","repository_id":"repo-h0","review_run_id":"run-remote-h0","artifact_identity":"a56b573345b57d1ff8dce1c5cfb9df629ff44750b820ee4ffff1809318a3c450","policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","principal_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","hold_clearance_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","reason":"expired","issued_at_milliseconds":1000,"expires_at_milliseconds":61000}`
const azHistoricalV1Digest = `deb40fee1297a00024f32d8074dd51729e51f19f242d972ee1441cd88e44839b`
const azOther = `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

var azOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity tenant_id repository_id review_run_id artifact_identity admission_identity policy_identity principal_identity hold_clearance_identity ownership fence_retention_policy_identity reason issued_at_milliseconds expires_at_milliseconds legacy_receipt_identity")

func azHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func azFields(t *testing.T, wire string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func azQuote(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// Raw members retain exact integers; only the independent ordered recipe hashes them.
func azOrdered(t *testing.T, fields map[string]json.RawMessage, order []string, unsigned bool) string {
	t.Helper()
	var members []string
	for _, key := range order {
		if unsigned && key == "identity" {
			continue
		}
		value, ok := fields[key]
		if !ok {
			t.Fatal("test recipe missing field", key)
		}
		members = append(members, azQuote(key)+":"+string(value))
	}
	return "{" + strings.Join(members, ",") + "}"
}

func azVariant(t *testing.T, changes map[string]string) string {
	t.Helper()
	fields := azFields(t, azJSON)
	for key, value := range changes {
		if _, ok := fields[key]; !ok {
			t.Fatal("unknown test field", key)
		}
		fields[key] = json.RawMessage(value)
	}
	fields["identity"] = json.RawMessage(azQuote(azHash(azContract + "/v2\x00" + azOrdered(t, fields, azOrder, true))))
	return azOrdered(t, fields, azOrder, false)
}

func azScope(t *testing.T, tenant, repository, run string) audit.ReviewScope {
	t.Helper()
	value, err := audit.NewReviewScope(tenant, repository, run)
	if err != nil {
		t.Fatal("actual scope fixture rejected", err)
	}
	return value
}

func azOptions(t *testing.T) artifact.ErasureAuthorizationV2Options {
	t.Helper()
	return artifact.ErasureAuthorizationV2Options{
		Scope:             azScope(t, "tenant-auth", "repo-auth", "run-auth"),
		NamespaceIdentity: azNamespaceIdentity, ArtifactIdentity: azArtifactIdentity, AdmissionIdentity: azAdmissionIdentity,
		PolicyIdentity: strings.Repeat("5", 64), PrincipalIdentity: strings.Repeat("8", 64), HoldClearanceIdentity: strings.Repeat("9", 64),
		FenceRetentionPolicyIdentity: strings.Repeat("4", 64), Reason: artifact.DeletionExpired,
		IssuedAt: time.UnixMilli(900).UTC(), ExpiresAt: time.UnixMilli(1500).UTC(),
	}
}

func azNew(t *testing.T, options artifact.ErasureAuthorizationV2Options) artifact.ErasureAuthorizationV2 {
	t.Helper()
	value, err := artifact.NewErasureAuthorizationV2(options)
	if err != nil || value.Validate() != nil {
		t.Fatal("valid shape rejected", err)
	}
	return value
}

func azParse(t *testing.T, wire string) artifact.ErasureAuthorizationV2 {
	t.Helper()
	value, err := artifact.ParseErasureAuthorizationV2([]byte(wire))
	if err != nil || value.Validate() != nil {
		t.Fatal("canonical shape rejected", err)
	}
	encoded, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("shape roundtrip changed canonical bytes")
	}
	return value
}

func azError(t *testing.T, got, want error) {
	t.Helper()
	texts := map[error]string{
		artifact.ErrInvalidErasureContract:         "invalid erasure contract",
		artifact.ErrErasureIdentityMismatch:        "erasure identity mismatch",
		artifact.ErrErasureAuthorityRequired:       "erasure authority required",
		artifact.ErrErasureBindingMismatch:         "erasure binding mismatch",
		artifact.ErrErasureLegacyInventoryRequired: "erasure legacy inventory required",
	}
	text, ok := texts[want]
	if !ok || got != want || !errors.Is(got, want) {
		t.Fatal("wrong closed error classification")
	}
	if got.Error() != text || errors.Unwrap(got) != nil {
		t.Fatal("error leaked cause or noncanonical text")
	}
}

func azUnminted(t *testing.T, value artifact.ErasureAuthorizationV2, policy artifact.ProtectedErasurePolicy) {
	t.Helper()
	if value.ProtectedPolicyIdentity() != "" || value.ProtectedDocumentDigest() != "" {
		t.Fatal("shape minted protected getters")
	}
	azError(t, value.ValidateProtected(policy), artifact.ErrErasureAuthorityRequired)
}

func azZero(t *testing.T, value artifact.ErasureAuthorizationV2) {
	t.Helper()
	azError(t, value.Validate(), artifact.ErrInvalidErasureContract)
	azUnminted(t, value, artifact.ProtectedErasurePolicy{})
	scope := value.Scope()
	if value.Identity() != "" || value.NamespaceIdentity() != "" || value.ArtifactIdentity() != "" || value.AdmissionIdentity() != "" ||
		value.PolicyIdentity() != "" || value.PrincipalIdentity() != "" || value.HoldClearanceIdentity() != "" || value.Ownership() != "" ||
		value.FenceRetentionPolicyIdentity() != "" || value.LegacyReceiptIdentity() != "" || value.Reason() != 0 ||
		scope.Identity() != "" || scope.TenantID() != "" || scope.RepositoryID() != "" || scope.ReviewRunID() != "" ||
		!value.IssuedAt().IsZero() || !value.ExpiresAt().IsZero() {
		t.Fatal("failed output retained metadata")
	}
	if value.AllowsAdmission(artifact.ArtifactAdmission{}, time.UnixMilli(1000)) {
		t.Fatal("zero shape allows admission")
	}
	encoded, err := artifact.EncodeErasureAuthorizationV2(value)
	azError(t, err, artifact.ErrInvalidErasureContract)
	if encoded != nil {
		t.Fatal("failed Encode returned bytes")
	}
}

func azDeny(t *testing.T, wire string, want error) {
	t.Helper()
	value, err := artifact.ParseErasureAuthorizationV2([]byte(wire))
	azError(t, err, want)
	azZero(t, value)
}

func azAdmission(t *testing.T, scope audit.ReviewScope, namespace string, protection artifact.Protection, payload string, admitted int64) artifact.ArtifactAdmission {
	t.Helper()
	actual, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted,
		artifact.OriginHost, protection, []string{strings.Repeat("a", 64)}, []byte(payload), time.UnixMilli(100).UTC(), time.UnixMilli(1000).UTC())
	if err != nil || actual.Validate() != nil {
		t.Fatal("actual artifact fixture rejected", err)
	}
	value, err := artifact.NewArtifactAdmission(actual, namespace, time.UnixMilli(admitted).UTC())
	if err != nil || value.Validate() != nil {
		t.Fatal("actual admission fixture rejected", err)
	}
	return value
}

func azMatchingAdmission(t *testing.T) artifact.ArtifactAdmission {
	t.Helper()
	return azAdmission(t, azScope(t, "tenant-auth", "repo-auth", "run-auth"), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 500)
}

func TestAuthorizationV2LiteralShape(t *testing.T) {
	for _, vector := range []struct{ preimage, identity string }{
		{"open-trestle/artifact-storage-namespace/v1\x00" + azNamespaceUnsigned, azNamespaceIdentity},
		{azScopeUnsigned, azScopeIdentity}, {azArtifactUnsigned, azArtifactIdentity},
		{"open-trestle/artifact-admission/v1\x00" + azAdmissionUnsigned, azAdmissionIdentity},
		{"open-trestle/protected-artifact-erasure-policy/v1\x00" + azPolicyUnsigned, azPolicyIdentity},
		{azContract + "/v2\x00" + azUnsigned, azIdentity}, {azJSON, azDocumentDigest},
	} {
		if azHash(vector.preimage) != vector.identity {
			t.Fatal("independent literal SHA256 vector disagrees")
		}
	}
	if strings.Replace(azJSON, `"identity":"`+azIdentity+`",`, "", 1) != azUnsigned {
		t.Fatal("literal unsigned ordering differs")
	}
	namespace, err := artifact.NewStorageNamespace(strings.Repeat("1", 64), "authorization-fixture/a_0-z", strings.Repeat("2", 64))
	if err != nil || namespace.Identity() != azNamespaceIdentity {
		t.Fatal("real namespace differs from vector")
	}
	admission := azMatchingAdmission(t)
	admissionWire, err := artifact.EncodeArtifactAdmission(admission)
	if err != nil || string(admissionWire) != azAdmissionJSON {
		t.Fatal("real admission differs from independent literal")
	}
	options := azOptions(t)
	for _, value := range []artifact.ErasureAuthorizationV2{azNew(t, options), azParse(t, azJSON)} {
		if value.Identity() != azIdentity || value.Scope() != options.Scope || value.NamespaceIdentity() != options.NamespaceIdentity ||
			value.ArtifactIdentity() != options.ArtifactIdentity || value.AdmissionIdentity() != options.AdmissionIdentity ||
			value.PolicyIdentity() != options.PolicyIdentity || value.PrincipalIdentity() != options.PrincipalIdentity ||
			value.HoldClearanceIdentity() != options.HoldClearanceIdentity || value.Ownership() != "all_versions_at_exact_key" ||
			value.FenceRetentionPolicyIdentity() != options.FenceRetentionPolicyIdentity || value.LegacyReceiptIdentity() != "" || value.Reason() != options.Reason ||
			value.IssuedAt() != options.IssuedAt || value.ExpiresAt() != options.ExpiresAt {
			t.Fatal("constructor/parser getters differ")
		}
		encoded, err := artifact.EncodeErasureAuthorizationV2(value)
		if err != nil || string(encoded) != azJSON {
			t.Fatal("canonical literal encoding differs")
		}
		azUnminted(t, value, artifact.ProtectedErasurePolicy{})
		if !value.AllowsAdmission(admission, time.UnixMilli(1000)) {
			t.Fatal("unminted shape lost metadata predicate")
		}
	}
	for _, preimage := range []string{azUnsigned, azContract + `/v2\x00` + azUnsigned, azContract + "/v1\x00" + azUnsigned} {
		azDeny(t, strings.Replace(azJSON, azIdentity, azHash(preimage), 1), artifact.ErrErasureIdentityMismatch)
	}
}

func TestAuthorizationV2ConstructorBounds(t *testing.T) {
	setters := map[string]func(*artifact.ErasureAuthorizationV2Options, string){
		"namespace": func(o *artifact.ErasureAuthorizationV2Options, s string) { o.NamespaceIdentity = s },
		"artifact":  func(o *artifact.ErasureAuthorizationV2Options, s string) { o.ArtifactIdentity = s },
		"admission": func(o *artifact.ErasureAuthorizationV2Options, s string) { o.AdmissionIdentity = s },
		"policy":    func(o *artifact.ErasureAuthorizationV2Options, s string) { o.PolicyIdentity = s },
		"principal": func(o *artifact.ErasureAuthorizationV2Options, s string) { o.PrincipalIdentity = s },
		"hold":      func(o *artifact.ErasureAuthorizationV2Options, s string) { o.HoldClearanceIdentity = s },
		"fence":     func(o *artifact.ErasureAuthorizationV2Options, s string) { o.FenceRetentionPolicyIdentity = s },
		"legacy":    func(o *artifact.ErasureAuthorizationV2Options, s string) { o.LegacyReceiptIdentity = s },
	}
	for field, set := range setters {
		for index, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), "operator@example.test", azOther + "\n"} {
			if field == "legacy" && bad == "" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", field, index), func(t *testing.T) {
				o := azOptions(t)
				set(&o, bad)
				value, err := artifact.NewErasureAuthorizationV2(o)
				azError(t, err, artifact.ErrInvalidErasureContract)
				azZero(t, value)
			})
		}
		minimal := "0000000000000000000000000000000000000000000000000000000000000001"
		o := azOptions(t)
		set(&o, minimal)
		value := azNew(t, o)
		wireField := map[string]string{"namespace": "namespace_identity", "artifact": "artifact_identity", "admission": "admission_identity", "policy": "policy_identity", "principal": "principal_identity", "hold": "hold_clearance_identity", "fence": "fence_retention_policy_identity", "legacy": "legacy_receipt_identity"}[field]
		encoded, err := artifact.EncodeErasureAuthorizationV2(value)
		if err != nil || string(encoded) != azVariant(t, map[string]string{wireField: azQuote(minimal)}) {
			t.Fatal("constructor failed to bind changed digest")
		}
		azUnminted(t, value, artifact.ProtectedErasurePolicy{})
	}
	for _, reason := range []artifact.DeletionReason{0, 4, 255} {
		o := azOptions(t)
		o.Reason = reason
		value, err := artifact.NewErasureAuthorizationV2(o)
		azError(t, err, artifact.ErrInvalidErasureContract)
		azZero(t, value)
	}
	o := azOptions(t)
	o.Scope = audit.ReviewScope{}
	value, err := artifact.NewErasureAuthorizationV2(o)
	azError(t, err, artifact.ErrInvalidErasureContract)
	azZero(t, value)
	for _, side := range []string{"issued", "expires"} {
		for name, at := range map[string]time.Time{
			"zero": {}, "epoch": time.UnixMilli(0).UTC(), "negative": time.UnixMilli(-1).UTC(),
			"sub-ms": time.UnixMilli(1000).UTC().Add(time.Nanosecond),
			"east":   time.UnixMilli(1000).In(time.FixedZone("east", 3600)), "west": time.UnixMilli(1000).In(time.FixedZone("west", -3600)),
			"max plus one": time.UnixMilli(253402300800000).UTC(),
			"far calendar": time.Date(1000000000, 1, 1, 0, 0, 0, 0, time.UTC),
		} {
			t.Run(side+"/"+name, func(t *testing.T) {
				o := azOptions(t)
				if side == "issued" {
					o.IssuedAt = at
				} else {
					o.ExpiresAt = at
				}
				value, err := artifact.NewErasureAuthorizationV2(o)
				azError(t, err, artifact.ErrInvalidErasureContract)
				azZero(t, value)
			})
		}
	}
	for _, interval := range []struct {
		start, end int64
		valid      bool
	}{
		{1, 2, true}, {1, 900001, true}, {1, 900002, false}, {900, 900, false}, {900, 899, false},
		{253402300799998, 253402300799999, true}, {253402300799999, 253402300800000, false},
	} {
		o := azOptions(t)
		o.IssuedAt = time.UnixMilli(interval.start).UTC()
		o.ExpiresAt = time.UnixMilli(interval.end).UTC()
		value, err := artifact.NewErasureAuthorizationV2(o)
		if !interval.valid {
			azError(t, err, artifact.ErrInvalidErasureContract)
			azZero(t, value)
			continue
		}
		if err != nil || value.Validate() != nil {
			t.Fatal("valid time boundary rejected")
		}
		wire := azVariant(t, map[string]string{"issued_at_milliseconds": fmt.Sprint(interval.start), "expires_at_milliseconds": fmt.Sprint(interval.end)})
		azParse(t, wire)
		encoded, encodeErr := artifact.EncodeErasureAuthorizationV2(value)
		if encodeErr != nil || string(encoded) != wire || value.IssuedAt() != o.IssuedAt || value.ExpiresAt() != o.ExpiresAt {
			t.Fatal("constructor changed exact time boundaries")
		}
	}
	o = azOptions(t)
	o.IssuedAt = o.IssuedAt.In(time.FixedZone("zero-offset alias", 0))
	o.ExpiresAt = o.ExpiresAt.In(time.FixedZone("another alias", 0))
	value = azNew(t, o)
	if value.Identity() != azIdentity || value.IssuedAt().Location() != time.UTC || value.ExpiresAt().Location() != time.UTC {
		t.Fatal("zero-offset alias changed identity or UTC getter")
	}
}

func TestAuthorizationV2CanonicalCodec(t *testing.T) {
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]", "object": "{}", "invalid UTF8": string([]byte{0xff}), "BOM": "\xef\xbb\xbf" + azJSON,
		"duplicate":         strings.Replace(azJSON, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
		"escaped duplicate": strings.Replace(azJSON, `"schema_version":2`, `"schema_version":2,"schema_\u0076ersion":2`, 1),
		"unknown":           strings.Replace(azJSON, `"schema_version":2`, `"schema_version":2,"private_marker":true`, 1),
		"case alias":        strings.Replace(azJSON, `"namespace_identity"`, `"Namespace_Identity"`, 1),
		"escaped key":       strings.Replace(azJSON, `"namespace_identity"`, `"namespace_\u0069dentity"`, 1),
		"escaped value":     strings.Replace(azJSON, `"tenant-auth"`, `"\u0074enant-auth"`, 1),
		"order":             strings.Replace(azJSON, `"contract":"`+azContract+`","schema_version":2`, `"schema_version":2,"contract":"`+azContract+`"`, 1),
		"leading space":     " " + azJSON, "trailing newline": azJSON + "\n", "inner space": strings.Replace(azJSON, ",", ", ", 1),
		"trailing object": azJSON + "{}", "trailing null": azJSON + "null", "trailing junk": azJSON + "x",
		"cap": strings.Repeat("x", 8192), "cap plus one": strings.Repeat("x", 8193),
		"padded cap": azJSON + strings.Repeat(" ", 8192-len(azJSON)), "padded cap plus one": azJSON + strings.Repeat(" ", 8193-len(azJSON)),
	}
	for key, value := range azFields(t, azJSON) {
		token := azQuote(key) + ":" + string(value)
		cases["null "+key] = strings.Replace(azJSON, token, azQuote(key)+":null", 1)
		without := strings.Replace(azJSON, token+",", "", 1)
		if without == azJSON {
			without = strings.Replace(azJSON, ","+token, "", 1)
		}
		cases["missing "+key] = without
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) { azDeny(t, wire, artifact.ErrInvalidErasureContract) })
	}
	for _, field := range []string{"identity", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "policy_identity", "principal_identity", "hold_clearance_identity", "fence_retention_policy_identity", "legacy_receipt_identity"} {
		for index, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
			if field == "legacy_receipt_identity" && bad == "" {
				continue
			}
			t.Run(fmt.Sprintf("digest/%s/%d", field, index), func(t *testing.T) {
				wire := azVariant(t, map[string]string{field: azQuote(bad)})
				if field == "identity" {
					wire = strings.Replace(azJSON, azIdentity, bad, 1)
				}
				azDeny(t, wire, artifact.ErrInvalidErasureContract)
			})
		}
	}
	for _, field := range []string{"issued_at_milliseconds", "expires_at_milliseconds"} {
		for _, bad := range []string{"0", "-1", "253402300800000", "9223372036854775807", "-9223372036854775808", "9223372036854775808", "900.5", "900.0", "9e2", `"900"`} {
			t.Run(field+"/"+bad, func(t *testing.T) {
				azDeny(t, azVariant(t, map[string]string{field: bad}), artifact.ErrInvalidErasureContract)
			})
		}
	}
	for name, change := range map[string]map[string]string{
		"equal": {"expires_at_milliseconds": "900"}, "reversed": {"expires_at_milliseconds": "899"},
		"lifetime plus one": {"expires_at_milliseconds": "900901"},
		"contract":          {"contract": `"other"`}, "v1": {"schema_version": "1"}, "v3": {"schema_version": "3"}, "fractional version": {"schema_version": "2.0"},
		"ownership": {"ownership": `"current_version"`}, "empty ownership": {"ownership": `""`},
		"reason": {"reason": `"unknown"`}, "reason case": {"reason": `"Expired"`}, "reason empty": {"reason": `""`},
	} {
		t.Run(name, func(t *testing.T) { azDeny(t, azVariant(t, change), artifact.ErrInvalidErasureContract) })
	}
}

func TestAuthorizationV2FullBindingsAndNoV1Upcast(t *testing.T) {
	for field, replacement := range map[string]string{
		"namespace_identity": azQuote(azOther), "artifact_identity": azQuote(azOther), "admission_identity": azQuote(azOther),
		"policy_identity": azQuote(azOther), "principal_identity": azQuote(azOther), "hold_clearance_identity": azQuote(azOther),
		"fence_retention_policy_identity": azQuote(azOther), "legacy_receipt_identity": azQuote(azOther),
		"reason": `"tenant_erasure"`, "issued_at_milliseconds": "899", "expires_at_milliseconds": "1501",
	} {
		t.Run(field, func(t *testing.T) {
			wire := azVariant(t, map[string]string{field: replacement})
			value := azParse(t, wire)
			if value.Identity() == azIdentity {
				t.Fatal("canonical field not identity-bound")
			}
			azUnminted(t, value, artifact.ProtectedErasurePolicy{})
			azDeny(t, strings.Replace(wire, value.Identity(), azIdentity, 1), artifact.ErrErasureIdentityMismatch)
		})
	}
	azDeny(t, azVariant(t, map[string]string{"scope_identity": azQuote(azOther)}), artifact.ErrErasureIdentityMismatch)
	for _, field := range []string{"tenant_id", "repository_id", "review_run_id"} {
		t.Run(field, func(t *testing.T) {
			changes := map[string]string{field: `"other-scope"`}
			azDeny(t, azVariant(t, changes), artifact.ErrErasureIdentityMismatch)
			fields := azFields(t, azVariant(t, changes))
			preimage := `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":` + string(fields["tenant_id"]) + `,"repository":` + string(fields["repository_id"]) + `,"review_run":` + string(fields["review_run_id"]) + `}`
			changes["scope_identity"] = azQuote(azHash(preimage))
			value := azParse(t, azVariant(t, changes))
			if value.Scope().Identity() == azScopeIdentity || value.Identity() == azIdentity {
				t.Fatal("full scope not bound")
			}
			for _, bad := range []string{"", "Upper", "a/b", "a b", "a\x00b", "-a", "a-", strings.Repeat("a", 129)} {
				azDeny(t, azVariant(t, map[string]string{field: azQuote(bad)}), artifact.ErrInvalidErasureContract)
			}
		})
	}
	o := azOptions(t)
	o.Scope = azScope(t, strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128))
	o.LegacyReceiptIdentity = azOther
	value := azNew(t, o)
	encoded, err := artifact.EncodeErasureAuthorizationV2(value)
	if value.Scope() != o.Scope || value.LegacyReceiptIdentity() != azOther {
		t.Fatal("constructor lost maximum scope or legacy shape")
	}
	if err != nil {
		t.Fatal(err)
	}
	azParse(t, string(encoded))
	if azHash(azHistoricalV1) != azHistoricalV1Digest {
		t.Fatal("captured historical bytes changed")
	}
	legacy, err := artifact.ParseDeletionAuthorization([]byte(azHistoricalV1))
	if err != nil || legacy.Validate() != nil {
		t.Fatal("historical v1 no longer readable")
	}
	oldBytes, err := artifact.EncodeDeletionAuthorization(legacy)
	if err != nil || string(oldBytes) != azHistoricalV1 {
		t.Fatal("historical v1 bytes changed")
	}
	azDeny(t, azHistoricalV1, artifact.ErrInvalidErasureContract)
}

func TestAuthorizationV2AllowsAdmissionMetadataOnly(t *testing.T) {
	admission := azMatchingAdmission(t)
	for _, reason := range []artifact.DeletionReason{artifact.DeletionExpired, artifact.DeletionTenantErasure, artifact.DeletionRepositoryErasure} {
		o := azOptions(t)
		o.Reason = reason
		value := azNew(t, o)
		wire, err := artifact.EncodeErasureAuthorizationV2(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, shape := range []artifact.ErasureAuthorizationV2{value, azParse(t, string(wire))} {
			azUnminted(t, shape, artifact.ProtectedErasurePolicy{})
			for _, instant := range []struct {
				name              string
				at                time.Time
				inWindow, expired bool
			}{
				{"zero", time.Time{}, false, false}, {"before", o.IssuedAt.Add(-time.Nanosecond), false, false},
				{"start", o.IssuedAt, true, false}, {"fractional start", o.IssuedAt.Add(time.Nanosecond), true, false},
				{"before artifact expiry", admission.ExpiresAt().Add(-time.Nanosecond), true, false},
				{"artifact expiry", admission.ExpiresAt(), true, true}, {"end minus ns", o.ExpiresAt.Add(-time.Nanosecond), true, true},
				{"end", o.ExpiresAt, false, true}, {"after", o.ExpiresAt.Add(time.Nanosecond), false, true},
				{"offset fractional", admission.ExpiresAt().Add(time.Nanosecond).In(time.FixedZone("caller", -7*3600)), true, true},
				{"offset start", o.IssuedAt.In(time.FixedZone("caller-east", 3600)), true, false},
				{"offset end", o.ExpiresAt.In(time.FixedZone("caller-west", -3600)), false, true},
			} {
				t.Run(reason.String()+"/"+instant.name, func(t *testing.T) {
					want := instant.inWindow && (reason != artifact.DeletionExpired || instant.expired)
					if shape.AllowsAdmission(admission, instant.at) != want {
						t.Fatal("metadata/time predicate differs")
					}
				})
			}
		}
	}
	value := azNew(t, azOptions(t))
	for _, other := range []artifact.ArtifactAdmission{
		{}, azAdmission(t, admission.Scope(), azOther, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 500),
		azAdmission(t, admission.Scope(), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "different payload", 500),
		azAdmission(t, admission.Scope(), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 501),
		azAdmission(t, azScope(t, "tenant-other", "repo-auth", "run-auth"), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 500),
		azAdmission(t, azScope(t, "tenant-auth", "repo-other", "run-auth"), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 500),
		azAdmission(t, azScope(t, "tenant-auth", "repo-auth", "run-other"), azNamespaceIdentity, artifact.ProtectionEnvelopeEncrypted, "synthetic authorization admission", 500),
	} {
		if value.AllowsAdmission(other, time.UnixMilli(1000)) {
			t.Fatal("foreign/zero admission matched")
		}
	}
	for field, replacement := range map[string]string{"namespace_identity": azQuote(azOther), "artifact_identity": azQuote(azOther), "admission_identity": azQuote(azOther)} {
		shape := azParse(t, azVariant(t, map[string]string{field: replacement}))
		if shape.AllowsAdmission(admission, time.UnixMilli(1000)) {
			t.Fatal("valid rebound foreign grant matched")
		}
	}
	for _, scope := range []audit.ReviewScope{
		azScope(t, "tenant-other", "repo-auth", "run-auth"), azScope(t, "tenant-auth", "repo-other", "run-auth"), azScope(t, "tenant-auth", "repo-auth", "run-other"),
	} {
		o := azOptions(t)
		o.Scope = scope
		shape := azNew(t, o)
		if shape.AllowsAdmission(admission, time.UnixMilli(1000)) {
			t.Fatal("fully valid grant-side scope mismatch allowed")
		}
	}
	for _, field := range []string{"policy_identity", "principal_identity", "hold_clearance_identity", "fence_retention_policy_identity"} {
		shape := azParse(t, azVariant(t, map[string]string{field: azQuote(azOther)}))
		if !shape.AllowsAdmission(admission, time.UnixMilli(1000)) {
			t.Fatal("metadata predicate inferred protected policy or hold permission")
		}
		azUnminted(t, shape, artifact.ProtectedErasurePolicy{})
	}
	private := azAdmission(t, admission.Scope(), azNamespaceIdentity, artifact.ProtectionProcessPrivate, "synthetic authorization admission", 500)
	o := azOptions(t)
	o.ArtifactIdentity = private.ArtifactIdentity()
	o.AdmissionIdentity = private.Identity()
	if azNew(t, o).AllowsAdmission(private, time.UnixMilli(1000)) {
		t.Fatal("fully bound process-private admission allowed")
	}
}

func azRedacted(t *testing.T, value artifact.ErasureAuthorizationV2, private ...string) {
	t.Helper()
	zero := artifact.ErasureAuthorizationV2{}
	if value.String() == "" || value.GoString() == "" || value.String() != zero.String() || value.GoString() != zero.GoString() {
		t.Fatal("String/GoString not constant redaction")
	}
	// Runtime formats exercise mismatched verbs without suppressing printf vet.
	formatValue := func(format string, v any) string { return fmt.Sprintf(format, v) }
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%c", "%f", "%x", "%1000000.1s"} {
		for _, candidate := range []any{value, &value} {
			rendered := formatValue(format, candidate)
			if rendered == "" || rendered != formatValue(format, zero) || len(rendered) > 128 {
				t.Fatal("format is not bounded constant redaction")
			}
			for _, marker := range append([]string{azIdentity, azNamespaceIdentity, azScopeIdentity, azArtifactIdentity, azAdmissionIdentity, azPolicyIdentity, azDocumentDigest, "tenant-auth", "repo-auth", "run-auth", azJSON, strings.Repeat("8", 64), strings.Repeat("9", 64)}, private...) {
				if marker != "" && strings.Contains(rendered, marker) {
					t.Fatal("format exposed metadata/witness/path")
				}
			}
		}
	}
}

func TestAuthorizationV2ValueIsolationAndRedaction(t *testing.T) {
	o := azOptions(t)
	value := azNew(t, o)
	copied := value
	o.NamespaceIdentity = azOther
	o.Scope = audit.ReviewScope{}
	o.IssuedAt = time.Time{}
	wire, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := artifact.ParseErasureAuthorizationV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire[0] = 'x'
	for _, shape := range []artifact.ErasureAuthorizationV2{value, copied, parsed} {
		fresh, err := artifact.EncodeErasureAuthorizationV2(shape)
		if err != nil || !bytes.Equal(fresh, []byte(azJSON)) || shape.Identity() != azIdentity {
			t.Fatal("options or encoded buffer changed immutable value")
		}
		azUnminted(t, shape, artifact.ProtectedErasurePolicy{})
		azRedacted(t, shape)
	}
	azRedacted(t, artifact.ErasureAuthorizationV2{})
}

func TestAuthorizationV2UnmintedAndLoaderInputs(t *testing.T) {
	azZero(t, artifact.ErasureAuthorizationV2{})
	zero, err := artifact.NewErasureAuthorizationV2(artifact.ErasureAuthorizationV2Options{})
	azError(t, err, artifact.ErrInvalidErasureContract)
	azZero(t, zero)
	zero, err = artifact.ParseErasureAuthorizationV2(nil)
	azError(t, err, artifact.ErrInvalidErasureContract)
	azZero(t, zero)
	for _, wire := range []string{"{}", "null", azJSON, `{"Verified":true,"ProtectedPolicyIdentity":"` + azPolicyIdentity + `","ProtectedDocumentDigest":"` + azDocumentDigest + `"}`} {
		var value artifact.ErasureAuthorizationV2
		_ = json.Unmarshal([]byte(wire), &value)
		azUnminted(t, value, artifact.ProtectedErasurePolicy{})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled, context.Background()} {
		for _, path := range []string{"", "relative.json", "/private-nonexistent-authorization-fixture", "/private/./grant", "/private//grant", "/private/child/../grant", "/private/grant\x00marker", "/" + strings.Repeat("x", 4096)} {
			policy, err := artifact.LoadProtectedErasurePolicy(ctx, path)
			azError(t, err, artifact.ErrErasureAuthorityRequired)
			if policy.Validate() == nil || policy.Identity() != "" || len(policy.Bytes()) != 0 {
				t.Fatal("denied policy retained authority")
			}
			value, err := artifact.LoadErasureAuthorizationV2(ctx, path, policy)
			azError(t, err, artifact.ErrErasureAuthorityRequired)
			azZero(t, value)
		}
	}
}
