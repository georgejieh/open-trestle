//go:build unix

package artifact_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func evMetaProtectedPolicy(t *testing.T, wire string) artifact.ProtectedErasurePolicy {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "erasure-policy.json")
	if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("protected regular file", err)
	}
	p, err := artifact.LoadProtectedErasurePolicy(context.Background(), path)
	evMetaError(t, err, nil)
	evMetaError(t, p.Validate(), nil)
	if string(p.Bytes()) != wire {
		t.Fatal("protected snapshot bytes")
	}
	return p
}
func evMetaConstructCandidate(t *testing.T, p artifact.ProtectedErasurePolicy, wire string) artifact.ErasureEvidence {
	t.Helper()
	v, e := artifact.NewAttestationCandidateEvidence(evMetaOp(t), evMetaAdmissionValue(t), p, evMetaVerification(t))
	evMetaError(t, e, nil)
	evMetaWantEvidence(t, v, wire)
	a, e := artifact.ParseErasureAttestationV2(v.RecordBytes(), evMetaScope(t))
	evMetaError(t, e, nil)
	m := evMetaFields(t, wire)
	body := evMetaString(t, m, "record_hex")
	if evMetaHex(string(v.RecordBytes())) != body {
		t.Fatal("candidate record")
	}
	if a.ProtectedPolicyIdentity() != evMetaOp(t).ProtectedPolicyIdentity() || a.ResumePolicyIdentity() != p.Identity() || a.ConfigurationEvidenceIdentity() != p.ConfigurationEvidenceIdentity() {
		t.Fatal("original and selected policy snapshots")
	}
	return v
}

func TestEvMetaCandidateProtectedLiteralAndRefresh(t *testing.T) {
	original := evMetaProtectedPolicy(t, evMetaPolicy)
	evMetaConstructCandidate(t, original, evMetaWire("candidate_evidence"))
	refresh := evMetaProtectedPolicy(t, evMetaWire("refresh_policy"))
	if refresh.AllowsAt(evMetaOp(t).PreparedAt()) || !refresh.AllowsAt(evMetaTime(1007)) || !refresh.AllowsAt(evMetaTime(1008)) {
		t.Fatal("refresh time control")
	}
	candidate := evMetaConstructCandidate(t, refresh, evMetaWire("refresh_candidate"))
	a, e := artifact.ParseErasureAttestationV2(candidate.RecordBytes(), evMetaScope(t))
	evMetaError(t, e, nil)
	evMetaWantAttestation(t, a, evMetaWire("refresh_attestation"))
	snapshot := refresh.Bytes()
	snapshot[0] = 'X'
	evMetaConstructCandidate(t, refresh, evMetaWire("refresh_candidate"))
}

func TestEvMetaCandidateProtectedPredicatesAndPrecedence(t *testing.T) {
	p := evMetaProtectedPolicy(t, evMetaPolicy)
	op, a, v := evMetaOp(t), evMetaAdmissionValue(t), evMetaVerification(t)
	for _, tc := range []struct {
		name         string
		op           artifact.ErasureOperation
		admission    artifact.ArtifactAdmission
		verification artifact.ErasureVerification
		want         error
	}{
		{"zero-operation", artifact.ErasureOperation{}, a, v, artifact.ErrInvalidErasureContract},
		{"zero-admission", op, artifact.ArtifactAdmission{}, v, artifact.ErrInvalidErasureContract},
		{"zero-verification", op, a, artifact.ErasureVerification{}, artifact.ErrInvalidErasureContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := artifact.NewAttestationCandidateEvidence(tc.op, tc.admission, p, tc.verification)
			evMetaError(t, err, tc.want)
			evMetaZeroEvidence(t, e)
		})
	}
	for _, change := range []map[string]string{{"namespace_identity": evMetaJSON(evMetaOther)}, {"artifact_identity": evMetaJSON(evMetaOther)}, {"admission_identity": evMetaJSON(evMetaOther)}, {"prepared_at_milliseconds": "1009"}} {
		wire := evMetaChange(t, evMetaOperation, change, true)
		other, err := artifact.ParseErasureOperation([]byte(wire), evMetaScope(t))
		evMetaError(t, err, nil)
		e, err := artifact.NewAttestationCandidateEvidence(other, a, p, v)
		evMetaError(t, err, artifact.ErrErasureBindingMismatch)
		evMetaZeroEvidence(t, e)
	}
	legacyWire := evMetaChange(t, evMetaOperation, map[string]string{"legacy_receipt_identity": evMetaJSON(evMetaOther)}, true)
	legacy, err := artifact.ParseErasureOperation([]byte(legacyWire), evMetaScope(t))
	evMetaError(t, err, nil)
	e, err := artifact.NewAttestationCandidateEvidence(legacy, a, p, v)
	evMetaError(t, err, artifact.ErrErasureLegacyInventoryRequired)
	evMetaZeroEvidence(t, e)
	e, err = artifact.NewAttestationCandidateEvidence(legacy, a, artifact.ProtectedErasurePolicy{}, v)
	evMetaError(t, err, artifact.ErrErasureAuthorityRequired)
	evMetaZeroEvidence(t, e)
	for _, change := range []map[string]string{{"erasure_policy_identity": evMetaJSON(evMetaOther)}, {"not_before_milliseconds": "1008"}, {"not_after_milliseconds": "1008"}, {"not_after_milliseconds": "1007"}} {
		policy := evMetaProtectedPolicy(t, evMetaChange(t, evMetaPolicy, change, true))
		e, err := artifact.NewAttestationCandidateEvidence(op, a, policy, v)
		evMetaError(t, err, artifact.ErrErasureBindingMismatch)
		evMetaZeroEvidence(t, e)
	}
	for _, change := range []map[string]string{{"artifact_identity": evMetaJSON(evMetaOther)}, {"verified_at_milliseconds": "999", "completed_at_milliseconds": "1008"}} {
		wire := evMetaChange(t, evMetaWire("verification"), change, true)
		other, err := artifact.ParseErasureVerification([]byte(wire), evMetaRef(t))
		evMetaError(t, err, nil)
		e, err := artifact.NewAttestationCandidateEvidence(op, a, p, other)
		evMetaError(t, err, artifact.ErrErasureBindingMismatch)
		evMetaZeroEvidence(t, e)
	}
	// Each different admission comes from a real public artifact constructor.
	for _, tc := range []struct {
		name, tenant, payload, namespace string
		admitted                         int64
	}{
		{"payload", "tenant-auth", "different payload", op.NamespaceIdentity(), 500},
		{"scope", "other-tenant", "synthetic authorization admission", op.NamespaceIdentity(), 500},
		{"namespace", "tenant-auth", "synthetic authorization admission", evMetaOther, 500},
		{"admission-time", "tenant-auth", "synthetic authorization admission", op.NamespaceIdentity(), 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := audit.NewReviewScope(tc.tenant, "repo-auth", "run-auth")
			evMetaError(t, err, nil)
			value, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64)}, []byte(tc.payload), evMetaTime(100), evMetaTime(1000))
			evMetaError(t, err, nil)
			other, err := artifact.NewArtifactAdmission(value, tc.namespace, evMetaTime(tc.admitted))
			evMetaError(t, err, nil)
			e, err := artifact.NewAttestationCandidateEvidence(op, other, p, v)
			evMetaError(t, err, artifact.ErrErasureBindingMismatch)
			evMetaZeroEvidence(t, e)
		})
	}
}
