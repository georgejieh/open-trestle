//go:build unix

package artifact_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

var ovPolicyOrder = strings.Fields("contract schema_version identity namespace_identity backend_configuration_identity prefix namespace_epoch_identity backend_kind database_authority_identity namespace_mode protocol ownership fence_retention_policy_identity erasure_policy_identity recovery_policy_identity configuration_evidence_identity not_before_milliseconds not_after_milliseconds")

// Positive authority fixtures use only the accepted public protected wrappers.
// File effects here are test fixtures, not provider or journal acceptance.
func ovProtectedFile(t *testing.T, wire string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "operation-authority.json")
	if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ovLoadPolicy(t *testing.T, changes map[string]string) artifact.ProtectedErasurePolicy {
	t.Helper()
	wire := ovVariant(t, ovPolicyJSON, ovPolicyOrder, "open-trestle/protected-artifact-erasure-policy/v1\x00", changes)
	policy, err := artifact.LoadProtectedErasurePolicy(context.Background(), ovProtectedFile(t, wire))
	if err != nil || policy.Validate() != nil || string(policy.Bytes()) != wire {
		t.Fatal("actual protected policy fixture rejected", err)
	}
	return policy
}

func ovLoadGrant(t *testing.T, wire string, policy artifact.ProtectedErasurePolicy) artifact.ErasureAuthorizationV2 {
	t.Helper()
	grant, err := artifact.LoadErasureAuthorizationV2(context.Background(), ovProtectedFile(t, wire), policy)
	if err != nil || grant.ValidateProtected(policy) != nil || grant.Validate() != nil || grant.ProtectedDocumentDigest() != ovHash(wire) || grant.ProtectedPolicyIdentity() != policy.Identity() {
		t.Fatal("actual protected grant fixture rejected", err)
	}
	return grant
}

func ovActualAdmission(t *testing.T, scope audit.ReviewScope, namespace, payload string, protection artifact.Protection, created, expires, admitted int64) (artifact.Artifact, artifact.ArtifactAdmission) {
	t.Helper()
	actual, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginHost, protection, []string{strings.Repeat("a", 64)}, []byte(payload), time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC())
	if err != nil || actual.Validate() != nil {
		t.Fatal("actual artifact rejected", err)
	}
	admission, err := artifact.NewArtifactAdmission(actual, namespace, time.UnixMilli(admitted).UTC())
	if err != nil || admission.Validate() != nil {
		t.Fatal("actual admission rejected", err)
	}
	return actual, admission
}

func ovBaseAdmission(t *testing.T) artifact.ArtifactAdmission {
	t.Helper()
	actual, admission := ovActualAdmission(t, ovMatchingScope(t), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 100, 1000, 500)
	if actual.Identity() != ovArtifactIdentity || admission.Identity() != ovAdmissionIdentity {
		t.Fatal("actual identity fixture differs")
	}
	original, err := artifact.Encode(actual)
	if err != nil || string(original) != ovOriginalArtifactJSON {
		t.Fatal("original v1 artifact canonical wire changed", err)
	}
	wire, err := artifact.EncodeArtifactAdmission(admission)
	if err != nil || string(wire) != ovAdmissionJSON {
		t.Fatal("original canonical admission changed", err)
	}
	return admission
}

func ovGrantOptions(admission artifact.ArtifactAdmission, policy artifact.ProtectedErasurePolicy, reason artifact.DeletionReason, issued, expires int64) artifact.ErasureAuthorizationV2Options {
	return artifact.ErasureAuthorizationV2Options{
		Scope: admission.Scope(), NamespaceIdentity: admission.NamespaceIdentity(), ArtifactIdentity: admission.ArtifactIdentity(), AdmissionIdentity: admission.Identity(),
		PolicyIdentity: policy.ErasurePolicyIdentity(), PrincipalIdentity: strings.Repeat("8", 64), HoldClearanceIdentity: strings.Repeat("9", 64), FenceRetentionPolicyIdentity: policy.FenceRetentionPolicyIdentity(),
		Reason: reason, IssuedAt: time.UnixMilli(issued).UTC(), ExpiresAt: time.UnixMilli(expires).UTC(),
	}
}

func ovNewGrant(t *testing.T, options artifact.ErasureAuthorizationV2Options) artifact.ErasureAuthorizationV2 {
	t.Helper()
	value, err := artifact.NewErasureAuthorizationV2(options)
	if err != nil || value.Validate() != nil {
		t.Fatal("unminted grant shape rejected", err)
	}
	return value
}

func ovGrantWire(t *testing.T, value artifact.ErasureAuthorizationV2) string {
	t.Helper()
	wire, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func ovCandidate(t *testing.T, grant artifact.ErasureAuthorizationV2, admission artifact.ArtifactAdmission, policy artifact.ProtectedErasurePolicy, at time.Time) artifact.ErasureOperation {
	t.Helper()
	if grant.ValidateProtected(policy) != nil || !policy.AllowsAt(at) || !grant.AllowsAdmission(admission, at) {
		t.Fatal("positive fixture does not satisfy both active predicates and protected binding")
	}
	value, err := artifact.NewErasureOperationCandidate(grant, admission, policy, at)
	if err != nil || value.Validate() != nil {
		t.Fatal("eligible metadata candidate rejected", err)
	}
	if value.Scope() != admission.Scope() || value.NamespaceIdentity() != admission.NamespaceIdentity() || value.ArtifactIdentity() != admission.ArtifactIdentity() || value.AdmissionIdentity() != admission.Identity() || value.OriginalAuthorizationIdentity() != grant.Identity() || value.AuthorizationDocumentDigest() != grant.ProtectedDocumentDigest() || value.PolicyIdentity() != grant.PolicyIdentity() || value.ProtectedPolicyIdentity() != policy.Identity() || value.Ownership() != grant.Ownership() || value.PreparedAt() != at.UTC() || value.PreparedAt().Location() != time.UTC || value.ErasureProtocol() != policy.Protocol() || value.LegacyReceiptIdentity() != "" {
		t.Fatal("candidate did not copy exact admitted bindings")
	}
	if value.Ref().Validate() != nil || value.Ref().Scope() != admission.Scope() || value.Ref().NamespaceIdentity() != admission.NamespaceIdentity() || value.Ref().OperationIdentity() != value.Identity() {
		t.Fatal("candidate ref unusable")
	}
	return value
}

func ovDeniedCandidate(t *testing.T, grant artifact.ErasureAuthorizationV2, admission artifact.ArtifactAdmission, policy artifact.ProtectedErasurePolicy, at time.Time, want error) {
	t.Helper()
	value, err := artifact.NewErasureOperationCandidate(grant, admission, policy, at)
	ovError(t, err, want)
	ovZeroOperation(t, value)
}

func TestOperationCandidateProtectedLiteral(t *testing.T) {
	policy := ovLoadPolicy(t, nil)
	grant := ovLoadGrant(t, ovGrantJSON, policy)
	admission := ovBaseAdmission(t)
	value := ovCandidate(t, grant, admission, policy, time.UnixMilli(1000).UTC())
	if value.Identity() != ovOperationIdentity {
		t.Fatal("loaded candidate differs from independent literal")
	}
	wire, err := artifact.EncodeErasureOperation(value)
	if err != nil || string(wire) != ovOperationJSON {
		t.Fatal("candidate canonical wire differs", err)
	}
	decoded := ovParse(t, string(wire), admission.Scope())
	if decoded.Identity() != value.Identity() {
		t.Fatal("metadata roundtrip changed identity")
	}
	fence, err := artifact.NewErasureFence(decoded)
	if err != nil {
		t.Fatal("parsed operation cannot build fence content", err)
	}
	encoded, err := artifact.EncodeErasureFence(fence)
	if err != nil || string(encoded) != "OTAF0001"+ovFenceJSON {
		t.Fatal("parsed candidate fence content differs", err)
	}
	// Snapshot and Go-value copies survive source-file removal. This is still
	// configured-local metadata, not durable operation acceptance or Create.
	policyPath, grantPath := ovProtectedFile(t, ovPolicyJSON), ovProtectedFile(t, ovGrantJSON)
	copiedPolicy, err := artifact.LoadProtectedErasurePolicy(context.Background(), policyPath)
	if err != nil {
		t.Fatal(err)
	}
	copiedGrant, err := artifact.LoadErasureAuthorizationV2(context.Background(), grantPath, copiedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(grantPath); err != nil {
		t.Fatal(err)
	}
	copied := ovCandidate(t, copiedGrant, admission, copiedPolicy, time.UnixMilli(1000).UTC())
	copiedWire, err := artifact.EncodeErasureOperation(copied)
	if err != nil || !bytes.Equal(copiedWire, wire) {
		t.Fatal("snapshot candidate changed after unlink", err)
	}
}

func TestOperationCandidateTimeWindows(t *testing.T) {
	policy := ovLoadPolicy(t, nil)
	grant := ovLoadGrant(t, ovGrantJSON, policy)
	admission := ovBaseAdmission(t)
	for _, tc := range []struct {
		name                  string
		millis                int64
		policyOK, admissionOK bool
	}{
		{"before-policy-and-grant", 899, false, false},
		{"policy-and-grant-start-but-not-expired", 900, true, false},
		{"just-before-artifact-expiry", 999, true, false},
		{"exact-artifact-expiry", 1000, true, true},
		{"last-policy-ms", 1399, true, true},
		{"policy-end-grant-still-active", 1400, false, true},
		{"last-grant-ms-policy-inactive", 1499, false, true},
		{"grant-end", 1500, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.UnixMilli(tc.millis).UTC()
			if policy.AllowsAt(at) != tc.policyOK || grant.AllowsAdmission(admission, at) != tc.admissionOK {
				t.Fatal("fixture does not discriminate interval")
			}
			if tc.policyOK && tc.admissionOK {
				ovCandidate(t, grant, admission, policy, at)
			} else {
				ovDeniedCandidate(t, grant, admission, policy, at, artifact.ErrErasureBindingMismatch)
			}
		})
	}
	wide := ovLoadPolicy(t, map[string]string{"not_before_milliseconds": "800", "not_after_milliseconds": "1600"})
	wideGrant := ovLoadGrant(t, ovGrantJSON, wide)
	for _, at := range []time.Time{time.UnixMilli(899).UTC(), time.UnixMilli(1500).UTC()} {
		if !wide.AllowsAt(at) || wideGrant.AllowsAdmission(admission, at) {
			t.Fatal("active policy vs inactive grant control missing")
		}
		ovDeniedCandidate(t, wideGrant, admission, wide, at, artifact.ErrErasureBindingMismatch)
	}
	for _, reason := range []artifact.DeletionReason{artifact.DeletionTenantErasure, artifact.DeletionRepositoryErasure} {
		shape := ovNewGrant(t, ovGrantOptions(admission, policy, reason, 900, 1500))
		loaded := ovLoadGrant(t, ovGrantWire(t, shape), policy)
		ovCandidate(t, loaded, admission, policy, time.UnixMilli(900).UTC())
	}
	base := ovCandidate(t, grant, admission, policy, time.UnixMilli(1000).UTC())
	alias := ovCandidate(t, grant, admission, policy, time.UnixMilli(1000).In(time.FixedZone("zero-offset-alias", 0)))
	if alias.Identity() != base.Identity() || alias.PreparedAt().Location() != time.UTC {
		t.Fatal("zero-offset aliases changed identity or UTC getter")
	}
	for _, at := range []time.Time{time.Time{}, time.UnixMilli(0).UTC(), time.UnixMilli(-1).UTC(), time.UnixMilli(1000).UTC().Add(time.Nanosecond), time.UnixMilli(1000).In(time.FixedZone("nonzero-offset", 3600)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1000000000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(-1000000000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		ovDeniedCandidate(t, grant, admission, policy, at, artifact.ErrInvalidErasureContract)
	}
	for _, millis := range []int64{1, 253402300799999} {
		// Syntactically valid limits are binding failures for this fixture.
		ovDeniedCandidate(t, grant, admission, policy, time.UnixMilli(millis).UTC(), artifact.ErrErasureBindingMismatch)
	}
	for _, edge := range []struct {
		name                                              string
		created, expires, admitted, issued, end, prepared int64
		reason                                            artifact.DeletionReason
	}{
		{"first-positive-ms", 1, 1000, 1, 1, 2, 1, artifact.DeletionTenantErasure},
		{"last-active-ms", 253402300798999, 253402300799499, 253402300799249, 253402300799499, 253402300799999, 253402300799998, artifact.DeletionExpired},
	} {
		t.Run(edge.name, func(t *testing.T) {
			p := ovLoadPolicy(t, map[string]string{"not_before_milliseconds": fmt.Sprint(edge.issued), "not_after_milliseconds": fmt.Sprint(edge.end)})
			_, a := ovActualAdmission(t, ovMatchingScope(t), p.NamespaceIdentity(), "edge artifact", artifact.ProtectionEnvelopeEncrypted, edge.created, edge.expires, edge.admitted)
			g := ovLoadGrant(t, ovGrantWire(t, ovNewGrant(t, ovGrantOptions(a, p, edge.reason, edge.issued, edge.end))), p)
			ovCandidate(t, g, a, p, time.UnixMilli(edge.prepared).UTC())
		})
	}
}

func TestOperationCandidateExactBindings(t *testing.T) {
	policy := ovLoadPolicy(t, nil)
	grant := ovLoadGrant(t, ovGrantJSON, policy)
	base := ovBaseAdmission(t)
	at := time.UnixMilli(1000).UTC()
	for _, tc := range []struct {
		name               string
		scope              audit.ReviewScope
		namespace, payload string
		protection         artifact.Protection
		admitted           int64
	}{
		{"tenant", ovScope(t, "other-tenant", "repo-auth", "run-auth"), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 500},
		{"repository", ovScope(t, "tenant-auth", "other-repo", "run-auth"), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 500},
		{"run", ovScope(t, "tenant-auth", "repo-auth", "other-run"), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 500},
		{"namespace", ovMatchingScope(t), ovOther, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 500},
		{"artifact", ovMatchingScope(t), ovNamespaceIdentity, "different payload", artifact.ProtectionEnvelopeEncrypted, 500},
		{"admission-only", ovMatchingScope(t), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 501},
		{"protection", ovMatchingScope(t), ovNamespaceIdentity, "synthetic authorization admission", artifact.ProtectionProcessPrivate, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, admission := ovActualAdmission(t, tc.scope, tc.namespace, tc.payload, tc.protection, 100, 1000, tc.admitted)
			if grant.ValidateProtected(policy) != nil || !policy.AllowsAt(at) || grant.AllowsAdmission(admission, at) {
				t.Fatal("mismatch fixture did not isolate metadata binding")
			}
			ovDeniedCandidate(t, grant, admission, policy, at, artifact.ErrErasureBindingMismatch)
			if tc.name == "admission-only" && admission.ArtifactIdentity() != base.ArtifactIdentity() {
				t.Fatal("admission-only control changed artifact")
			}
			// Even an exact loaded grant cannot make process-private content eligible.
			if tc.name == "protection" {
				g := ovLoadGrant(t, ovGrantWire(t, ovNewGrant(t, ovGrantOptions(admission, policy, artifact.DeletionExpired, 900, 1500))), policy)
				if g.AllowsAdmission(admission, at) {
					t.Fatal("non-envelope content eligible")
				}
				ovDeniedCandidate(t, g, admission, policy, at, artifact.ErrErasureBindingMismatch)
			}
		})
	}
	for _, change := range []map[string]string{{"database_authority_identity": ovQuote(ovOther)}, {"configuration_evidence_identity": ovQuote(ovOther)}, {"recovery_policy_identity": ovQuote(ovOther)}, {"not_after_milliseconds": "1401"}} {
		other := ovLoadPolicy(t, change)
		ovError(t, grant.ValidateProtected(other), artifact.ErrErasureBindingMismatch)
		ovDeniedCandidate(t, grant, base, other, at, artifact.ErrErasureBindingMismatch)
		fresh := ovLoadGrant(t, ovGrantJSON, other)
		value := ovCandidate(t, fresh, base, other, at)
		if value.Identity() == ovOperationIdentity || value.OriginalAuthorizationIdentity() != ovAuthorizationIdentity || value.AuthorizationDocumentDigest() != ovDocumentDigest || value.ProtectedPolicyIdentity() != other.Identity() {
			t.Fatal("exact protected policy snapshot did not rebind candidate")
		}
	}
	for _, field := range []string{"erasure_policy_identity", "fence_retention_policy_identity"} {
		other := ovLoadPolicy(t, map[string]string{field: ovQuote(ovOther)})
		ovDeniedCandidate(t, grant, base, other, at, artifact.ErrErasureBindingMismatch)
		g := ovLoadGrant(t, ovGrantWire(t, ovNewGrant(t, ovGrantOptions(base, other, artifact.DeletionExpired, 900, 1500))), other)
		value := ovCandidate(t, g, base, other, at)
		if value.Identity() == ovOperationIdentity || value.PolicyIdentity() != other.ErasurePolicyIdentity() {
			t.Fatal("matched replacement policy did not rebind candidate")
		}
	}
	// A second real namespace and admission rule out fixture-specific bindings.
	namespace, err := artifact.NewStorageNamespace(strings.Repeat("1", 64), "operation-other/a_0-z", strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	otherNamespacePolicy := ovLoadPolicy(t, map[string]string{"prefix": ovQuote(namespace.Prefix()), "namespace_identity": ovQuote(namespace.Identity())})
	_, otherAdmission := ovActualAdmission(t, ovMatchingScope(t), namespace.Identity(), "synthetic authorization admission", artifact.ProtectionEnvelopeEncrypted, 100, 1000, 500)
	otherGrant := ovLoadGrant(t, ovGrantWire(t, ovNewGrant(t, ovGrantOptions(otherAdmission, otherNamespacePolicy, artifact.DeletionExpired, 900, 1500))), otherNamespacePolicy)
	ovCandidate(t, otherGrant, otherAdmission, otherNamespacePolicy, at)
	ovDeniedCandidate(t, otherGrant, base, otherNamespacePolicy, at, artifact.ErrErasureBindingMismatch)
	// All protected authorizations below are eligible for the same admission.
	// Each document change must bind its own original authorization and digest.
	for _, mutate := range []func(*artifact.ErasureAuthorizationV2Options){
		func(o *artifact.ErasureAuthorizationV2Options) { o.PrincipalIdentity = ovOther },
		func(o *artifact.ErasureAuthorizationV2Options) { o.HoldClearanceIdentity = ovOther },
		func(o *artifact.ErasureAuthorizationV2Options) { o.IssuedAt = time.UnixMilli(901).UTC() },
		func(o *artifact.ErasureAuthorizationV2Options) { o.ExpiresAt = time.UnixMilli(1501).UTC() },
	} {
		o := ovGrantOptions(base, policy, artifact.DeletionExpired, 900, 1500)
		mutate(&o)
		wire := ovGrantWire(t, ovNewGrant(t, o))
		g := ovLoadGrant(t, wire, policy)
		value := ovCandidate(t, g, base, policy, at)
		if value.Identity() == ovOperationIdentity || value.OriginalAuthorizationIdentity() == ovAuthorizationIdentity || value.AuthorizationDocumentDigest() != ovHash(wire) || value.AuthorizationDocumentDigest() == ovDocumentDigest {
			t.Fatal("exact loaded grant document did not rebind candidate")
		}
	}
}

func TestOperationCandidateAuthorityPriority(t *testing.T) {
	policy := ovLoadPolicy(t, nil)
	loaded := ovLoadGrant(t, ovGrantJSON, policy)
	admission := ovBaseAdmission(t)
	at := time.UnixMilli(1000).UTC()
	shape := ovNewGrant(t, ovGrantOptions(admission, policy, artifact.DeletionExpired, 900, 1500))
	parsed, err := artifact.ParseErasureAuthorizationV2([]byte(ovGrantJSON))
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []artifact.ErasureAuthorizationV2{shape, parsed} {
		if !policy.AllowsAt(at) || !grant.AllowsAdmission(admission, at) || grant.Identity() != loaded.Identity() {
			t.Fatal("unminted control must satisfy identical metadata predicate")
		}
		ovError(t, grant.ValidateProtected(policy), artifact.ErrErasureAuthorityRequired)
		ovDeniedCandidate(t, grant, admission, policy, at, artifact.ErrErasureAuthorityRequired)
		ovDeniedCandidate(t, grant, artifact.ArtifactAdmission{}, policy, time.Time{}, artifact.ErrErasureAuthorityRequired)
	}
	ovDeniedCandidate(t, artifact.ErasureAuthorizationV2{}, artifact.ArtifactAdmission{}, artifact.ProtectedErasurePolicy{}, time.Time{}, artifact.ErrErasureAuthorityRequired)
	ovDeniedCandidate(t, loaded, artifact.ArtifactAdmission{}, artifact.ProtectedErasurePolicy{}, time.Time{}, artifact.ErrErasureAuthorityRequired)
	other := ovLoadPolicy(t, map[string]string{"not_after_milliseconds": "1401"})
	ovDeniedCandidate(t, loaded, artifact.ArtifactAdmission{}, other, time.Time{}, artifact.ErrErasureBindingMismatch)
	ovDeniedCandidate(t, loaded, artifact.ArtifactAdmission{}, policy, at, artifact.ErrInvalidErasureContract)
	ovDeniedCandidate(t, loaded, artifact.ArtifactAdmission{}, policy, time.Time{}, artifact.ErrInvalidErasureContract)
	_, foreign := ovActualAdmission(t, ovMatchingScope(t), ovOther, "foreign", artifact.ProtectionEnvelopeEncrypted, 100, 1000, 500)
	ovDeniedCandidate(t, loaded, foreign, policy, time.Time{}, artifact.ErrInvalidErasureContract)
	o := ovGrantOptions(admission, policy, artifact.DeletionExpired, 900, 1500)
	o.LegacyReceiptIdentity = ovOther
	legacy := ovNewGrant(t, o)
	if !legacy.AllowsAdmission(admission, at) {
		t.Fatal("legacy metadata control should remain shape-eligible")
	}
	ovDeniedCandidate(t, legacy, admission, policy, at, artifact.ErrErasureAuthorityRequired)
	legacyWire := ovGrantWire(t, legacy)
	legacyParsed, err := artifact.ParseErasureAuthorizationV2([]byte(legacyWire))
	if err != nil {
		t.Fatal(err)
	}
	ovDeniedCandidate(t, legacyParsed, admission, policy, at, artifact.ErrErasureAuthorityRequired)
	denied, err := artifact.LoadErasureAuthorizationV2(context.Background(), ovProtectedFile(t, legacyWire), policy)
	ovError(t, err, artifact.ErrErasureLegacyInventoryRequired)
	if !reflect.DeepEqual(denied, artifact.ErasureAuthorizationV2{}) {
		t.Fatal("legacy loader minted metadata/witness")
	}
	// These pure calls intentionally succeed for historical metadata. There is
	// no fake acceptance result, accepted-operation setter, Prepare, or Resume.
	metadata := ovParse(t, ovOperationVariant(t, map[string]string{"legacy_receipt_identity": ovQuote(ovOther)}), admission.Scope())
	fence, err := artifact.NewErasureFence(metadata)
	if err != nil || fence.Validate() != nil {
		t.Fatal("legacy metadata fence content rejected", err)
	}
	if b, err := artifact.EncodeErasureFence(fence); err != nil || len(b) == 0 {
		t.Fatal("legacy fence bytes rejected", err)
	}
}
