package artifact_test

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func evMetaAttestationStrings(a artifact.ErasureAttestationV2) map[string]string {
	return map[string]string{
		"namespace_identity":              a.NamespaceIdentity(),
		"scope_identity":                  a.ScopeIdentity(),
		"artifact_identity":               a.ArtifactIdentity(),
		"payload_digest":                  a.PayloadDigest(),
		"admission_identity":              a.AdmissionIdentity(),
		"operation_identity":              a.OperationIdentity(),
		"original_authorization_identity": a.OriginalAuthorizationIdentity(),
		"authorization_document_digest":   a.AuthorizationDocumentDigest(),
		"erasure_protocol":                a.ErasureProtocol(),
		"policy_identity":                 a.PolicyIdentity(),
		"protected_policy_identity":       a.ProtectedPolicyIdentity(),
		"resume_policy_identity":          a.ResumePolicyIdentity(),
		"configuration_evidence_identity": a.ConfigurationEvidenceIdentity(),
		"fence_identity":                  a.FenceIdentity(),
		"fence_version_identity":          a.FenceVersionIdentity(),
		"verification_identity":           a.VerificationIdentity(),
		"proof_scope":                     a.ProofScope(),
		"remaining_record":                a.RemainingRecord(),
		"legacy_receipt_identity":         a.LegacyReceiptIdentity(),
		"identity":                        a.Identity(),
	}
}
func evMetaZeroAttestation(t *testing.T, a artifact.ErasureAttestationV2) {
	t.Helper()
	evMetaExactZero(t, a, artifact.ErasureAttestationV2{})
	evMetaError(t, a.Validate(), artifact.ErrInvalidErasureContract)
	for k, s := range evMetaAttestationStrings(a) {
		if s != "" {
			t.Fatal("zero attestation getter", k)
		}
	}
	if a.PreparedAt() != (time.Time{}) || a.VerifiedAt() != (time.Time{}) || a.CompletedAt() != (time.Time{}) || a.RemainingDataVersions() != 0 || a.RemainingDeleteMarkers() != 0 {
		t.Fatal("zero attestation fields")
	}
	b, e := artifact.EncodeErasureAttestationV2(a)
	evMetaError(t, e, artifact.ErrInvalidErasureContract)
	if b != nil {
		t.Fatal("zero attestation encode")
	}
}
func evMetaDeniedAttestation(t *testing.T, wire string, want error) {
	t.Helper()
	a, e := artifact.ParseErasureAttestationV2([]byte(wire), evMetaScope(t))
	evMetaError(t, e, want)
	evMetaZeroAttestation(t, a)
}
func evMetaWantAttestation(t *testing.T, a artifact.ErasureAttestationV2, wire string) {
	t.Helper()
	evMetaError(t, a.Validate(), nil)
	b, e := artifact.EncodeErasureAttestationV2(a)
	evMetaError(t, e, nil)
	if string(b) != wire {
		t.Fatal("attestation literal bytes")
	}
	m := evMetaFields(t, wire)
	for key, s := range evMetaAttestationStrings(a) {
		if s != evMetaString(t, m, key) {
			t.Fatal("attestation getter", key)
		}
	}
	for key, value := range map[string]int64{"prepared_at_milliseconds": a.PreparedAt().UnixMilli(), "verified_at_milliseconds": a.VerifiedAt().UnixMilli(), "completed_at_milliseconds": a.CompletedAt().UnixMilli(), "remaining_data_versions": int64(a.RemainingDataVersions()), "remaining_delete_markers": int64(a.RemainingDeleteMarkers())} {
		if evMetaJSON(value) != string(m[key]) {
			t.Fatal("attestation scalar getter", key)
		}
	}
	if a.PreparedAt().Location() != time.UTC || a.VerifiedAt().Location() != time.UTC || a.CompletedAt().Location() != time.UTC {
		t.Fatal("attestation UTC")
	}
}
func evMetaAdmissionValue(t *testing.T) artifact.ArtifactAdmission {
	t.Helper()
	a, e := artifact.ParseArtifactAdmission([]byte(evMetaAdmission))
	if e != nil {
		t.Fatal(e)
	}
	return a
}

func TestEvMetaAttestationCandidateMetadataAndAuthority(t *testing.T) {
	a := evMetaAttestation(t)
	evMetaWantAttestation(t, a, evMetaWire("attestation"))
	e := evMetaEvidence(t, "candidate_evidence")
	if string(e.RecordBytes()) != evMetaWire("attestation") {
		t.Fatal("candidate payload")
	}
	for _, tc := range []struct {
		op           artifact.ErasureOperation
		admission    artifact.ArtifactAdmission
		verification artifact.ErasureVerification
	}{
		{evMetaOp(t), evMetaAdmissionValue(t), evMetaVerification(t)},
		{artifact.ErasureOperation{}, artifact.ArtifactAdmission{}, artifact.ErasureVerification{}},
	} {
		v, err := artifact.NewAttestationCandidateEvidence(tc.op, tc.admission, artifact.ProtectedErasurePolicy{}, tc.verification)
		evMetaError(t, err, artifact.ErrErasureAuthorityRequired)
		evMetaZeroEvidence(t, v)
	}
}

func TestEvMetaAttestationShapeScopeAndClaims(t *testing.T) {
	wire := evMetaWire("attestation")
	for _, change := range []map[string]string{
		{"erasure_protocol": `"same-key-fence-v1"`}, {"proof_scope": `"current_only"`}, {"remaining_data_versions": "0"}, {"remaining_data_versions": "2"}, {"remaining_data_versions": "4294967296"}, {"remaining_delete_markers": "1"}, {"remaining_record": `"ciphertext"`}, {"legacy_receipt_identity": evMetaJSON(evMetaOther)},
		{"prepared_at_milliseconds": "0"}, {"verified_at_milliseconds": "253402300800000"}, {"completed_at_milliseconds": "0"},
	} {
		evMetaDeniedAttestation(t, evMetaChange(t, wire, change, true), artifact.ErrInvalidErasureContract)
	}
	for _, change := range []map[string]string{{"prepared_at_milliseconds": "1008"}, {"completed_at_milliseconds": "1006"}} {
		evMetaDeniedAttestation(t, evMetaChange(t, wire, change, true), artifact.ErrErasureBindingMismatch)
	}
	for _, field := range []string{"namespace_identity", "scope_identity", "artifact_identity", "payload_digest", "admission_identity", "operation_identity", "original_authorization_identity", "authorization_document_digest", "policy_identity", "protected_policy_identity", "resume_policy_identity", "configuration_evidence_identity", "fence_identity", "fence_version_identity", "verification_identity"} {
		for _, id := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 65)} {
			evMetaDeniedAttestation(t, evMetaChange(t, wire, map[string]string{field: evMetaJSON(id)}, true), artifact.ErrInvalidErasureContract)
		}
	}
	for _, parts := range [][3]string{{"other-tenant", "repo-auth", "run-auth"}, {"tenant-auth", "other-repo", "run-auth"}, {"tenant-auth", "repo-auth", "other-run"}} {
		s, e := audit.NewReviewScope(parts[0], parts[1], parts[2])
		evMetaError(t, e, nil)
		a, err := artifact.ParseErasureAttestationV2([]byte(wire), s)
		evMetaError(t, err, artifact.ErrErasureIdentityMismatch)
		evMetaZeroAttestation(t, a)
	}
	a, err := artifact.ParseErasureAttestationV2([]byte(wire), audit.ReviewScope{})
	evMetaError(t, err, artifact.ErrInvalidErasureContract)
	evMetaZeroAttestation(t, a)
	claimed := evMetaChange(t, wire, map[string]string{"resume_policy_identity": evMetaJSON(evMetaOther), "configuration_evidence_identity": evMetaJSON(evMetaOther), "artifact_identity": evMetaJSON(evMetaOther), "fence_identity": evMetaJSON(evMetaOther)}, true)
	a, err = artifact.ParseErasureAttestationV2([]byte(claimed), evMetaScope(t))
	evMetaError(t, err, nil)
	evMetaWantAttestation(t, a, claimed)
	// Candidate parsing cannot reconstruct the omitted verification wrapper.
	evMetaParseEvidence(t, evMetaChange(t, evMetaWire("candidate_evidence"), map[string]string{"parent_identities": `["` + evMetaOther + `"]`}, true))
	evMetaDeniedEvidence(t, evMetaChange(t, evMetaWire("candidate_evidence"), map[string]string{"observed_at_milliseconds": "1009"}, true), artifact.ErrErasureBindingMismatch)
}

func TestEvMetaPublicationLiteralAndRelationships(t *testing.T) {
	candidate, read := evMetaEvidence(t, "candidate_evidence"), evMetaEvidence(t, "proof_response")
	e, err := artifact.NewAttestationPublicationEvidence(candidate, read, evMetaTime(1011))
	evMetaError(t, err, nil)
	evMetaWantEvidence(t, e, evMetaWire("published_evidence"))
	for _, tc := range []struct {
		name            string
		candidate, read artifact.ErasureEvidence
		at              time.Time
		want            error
	}{
		{"zero-candidate", artifact.ErasureEvidence{}, read, evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"zero-read", candidate, artifact.ErasureEvidence{}, evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"wrong-candidate-kind", evMetaEvidence(t, "verification_evidence"), read, evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"wrong-read-kind", candidate, evMetaEvidence(t, "fence_evidence"), evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"absent", candidate, evMetaEvidence(t, "matrix_attestation_read_absent"), evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"marker", candidate, evMetaEvidence(t, "branch_delete_marker"), evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"list", candidate, evMetaEvidence(t, "terminal_response"), evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"fence-content", candidate, evMetaEvidence(t, "initial_response"), evMetaTime(1011), artifact.ErrInvalidErasureContract},
		{"before-read", candidate, read, evMetaTime(1009), artifact.ErrErasureBindingMismatch},
		{"read-before-candidate", candidate, evMetaResponseChange(t, "proof_response", map[string]string{"observed_at_milliseconds": "1007"}), evMetaTime(1011), artifact.ErrErasureBindingMismatch},
		{"zero-time", candidate, read, time.Time{}, artifact.ErrInvalidErasureContract},
		{"offset-time", candidate, read, evMetaTime(1011).In(time.FixedZone("offset", 60)), artifact.ErrInvalidErasureContract},
		{"sub-ms", candidate, read, evMetaTime(1011).Add(time.Nanosecond), artifact.ErrInvalidErasureContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, x := artifact.NewAttestationPublicationEvidence(tc.candidate, tc.read, tc.at)
			evMetaError(t, x, tc.want)
			evMetaZeroEvidence(t, v)
		})
	}
	changedBody := evMetaChange(t, evMetaWire("attestation"), map[string]string{"configuration_evidence_identity": evMetaJSON(evMetaOther)}, true)
	changedRead := evMetaResponseChange(t, "proof_response", map[string]string{"record_hex": evMetaJSON(evMetaHex(changedBody)), "content_digest": evMetaJSON(evMetaHash(changedBody)), "response_bytes": evMetaJSON(len(changedBody))})
	v, x := artifact.NewAttestationPublicationEvidence(candidate, changedRead, evMetaTime(1011))
	evMetaError(t, x, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, v)
	e, err = artifact.NewAttestationPublicationEvidence(candidate, read, evMetaTime(1010).In(time.FixedZone("alias", 0)))
	evMetaError(t, err, nil)
	evMetaWantEvidence(t, e, evMetaChange(t, evMetaWire("published_evidence"), map[string]string{"observed_at_milliseconds": "1010"}, true))
	// Parent content and the stored winner are not inputs to a standalone parser.
	evMetaParseEvidence(t, evMetaChange(t, evMetaWire("published_evidence"), map[string]string{"parent_identities": `["` + read.Identity() + `","` + candidate.Identity() + `"]`}, true))
}

func TestEvMetaAttestationCopiesAndFormatting(t *testing.T) {
	wire := evMetaWire("attestation")
	input := []byte(wire)
	a, e := artifact.ParseErasureAttestationV2(input, evMetaScope(t))
	evMetaError(t, e, nil)
	input[0] = 'X'
	for i := 0; i < 2; i++ {
		b, err := artifact.EncodeErasureAttestationV2(a)
		evMetaError(t, err, nil)
		b[0] = 'X'
		evMetaWantAttestation(t, a, wire)
	}
	var zero artifact.ErasureAttestationV2
	evMetaZeroAttestation(t, zero)
	evMetaFormat(t, []any{a, &a, zero, &zero}, "artifact erasure attestation", "artifact.ErasureAttestationV2{<redacted>}")
}

var _ interface {
	Validate() error
	Identity() string
	NamespaceIdentity() string
	ScopeIdentity() string
	ArtifactIdentity() string
	PayloadDigest() string
	AdmissionIdentity() string
	OperationIdentity() string
	OriginalAuthorizationIdentity() string
	AuthorizationDocumentDigest() string
	ErasureProtocol() string
	PolicyIdentity() string
	ProtectedPolicyIdentity() string
	ResumePolicyIdentity() string
	ConfigurationEvidenceIdentity() string
	FenceIdentity() string
	FenceVersionIdentity() string
	VerificationIdentity() string
	ProofScope() string
	RemainingRecord() string
	LegacyReceiptIdentity() string
	PreparedAt() time.Time
	VerifiedAt() time.Time
	CompletedAt() time.Time
	RemainingDataVersions() uint32
	RemainingDeleteMarkers() uint32
	String() string
	GoString() string
} = artifact.ErasureAttestationV2{}
