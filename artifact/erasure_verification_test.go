package artifact_test

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func evMetaVerificationStrings(v artifact.ErasureVerification) map[string]string {
	return map[string]string{
		"namespace_identity":        v.NamespaceIdentity(),
		"scope_identity":            v.ScopeIdentity(),
		"artifact_identity":         v.ArtifactIdentity(),
		"operation_identity":        v.OperationIdentity(),
		"fence_evidence_identity":   v.FenceEvidenceIdentity(),
		"fence_version_identity":    v.FenceVersionIdentity(),
		"current_response_identity": v.CurrentResponseIdentity(),
		"identity":                  v.Identity(),
	}
}
func evMetaZeroVerification(t *testing.T, v artifact.ErasureVerification) {
	t.Helper()
	evMetaExactZero(t, v, artifact.ErasureVerification{})
	evMetaError(t, v.Validate(), artifact.ErrInvalidErasureContract)
	for k, s := range evMetaVerificationStrings(v) {
		if s != "" {
			t.Fatal("zero verification getter", k)
		}
	}
	if v.VerifiedAt() != (time.Time{}) || v.CompletedAt() != (time.Time{}) || len(v.ListResponseIdentities()) != 0 {
		t.Fatal("zero verification fields")
	}
	b, e := artifact.EncodeErasureVerification(v)
	evMetaError(t, e, artifact.ErrInvalidErasureContract)
	if b != nil {
		t.Fatal("zero verification encode")
	}
}
func evMetaDeniedVerification(t *testing.T, wire string, want error) {
	t.Helper()
	v, e := artifact.ParseErasureVerification([]byte(wire), evMetaRef(t))
	evMetaError(t, e, want)
	evMetaZeroVerification(t, v)
}
func evMetaWantVerification(t *testing.T, v artifact.ErasureVerification, wire string) {
	t.Helper()
	evMetaError(t, v.Validate(), nil)
	b, e := artifact.EncodeErasureVerification(v)
	evMetaError(t, e, nil)
	if string(b) != wire {
		t.Fatal("verification literal bytes")
	}
	m := evMetaFields(t, wire)
	for key, s := range evMetaVerificationStrings(v) {
		if s != evMetaString(t, m, key) {
			t.Fatal("verification getter", key)
		}
	}
	if evMetaJSON(v.ListResponseIdentities()) != string(m["list_response_identities"]) || evMetaJSON(v.VerifiedAt().UnixMilli()) != string(m["verified_at_milliseconds"]) || evMetaJSON(v.CompletedAt().UnixMilli()) != string(m["completed_at_milliseconds"]) || v.VerifiedAt().Location() != time.UTC || v.CompletedAt().Location() != time.UTC {
		t.Fatal("verification fields")
	}
}
func evMetaResponseChange(t *testing.T, name string, changes map[string]string) artifact.ErasureEvidence {
	t.Helper()
	inner := evMetaChange(t, evMetaWire(name+"_record"), changes, true)
	outer := evMetaNested(t, evMetaWire(name), inner)
	if at, ok := changes["observed_at_milliseconds"]; ok {
		outer = evMetaChange(t, outer, map[string]string{"observed_at_milliseconds": at}, true)
	}
	if id, ok := changes["attempt_identity"]; ok {
		m := evMetaFields(t, inner)
		outer = evMetaChange(t, outer, map[string]string{"attempt_identity": id, "slot": evMetaJSON("response:" + evMetaString(t, m, "attempt_identity"))}, true)
	}
	return evMetaParseEvidence(t, outer)
}

func TestEvMetaVerificationAndWrapperLiterals(t *testing.T) {
	op, fence, list, current := evMetaOp(t), evMetaEvidence(t, "fence_evidence"), evMetaEvidence(t, "terminal_response"), evMetaEvidence(t, "final_response")
	parents := []artifact.ErasureEvidence{list}
	v, e := artifact.NewErasureVerification(op, fence, parents, current, evMetaTime(1008))
	evMetaError(t, e, nil)
	evMetaWantVerification(t, v, evMetaWire("verification"))
	parents[0] = artifact.ErasureEvidence{}
	evMetaWantVerification(t, v, evMetaWire("verification"))
	parsed := evMetaVerification(t)
	evMetaWantVerification(t, parsed, evMetaWire("verification"))
	for _, value := range []artifact.ErasureVerification{v, parsed} {
		wrapper, err := artifact.NewVerificationEvidence(value)
		evMetaError(t, err, nil)
		evMetaWantEvidence(t, wrapper, evMetaWire("verification_evidence"))
	}
	equal, e := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1007).In(time.FixedZone("alias", 0)))
	evMetaError(t, e, nil)
	evMetaWantVerification(t, equal, evMetaChange(t, evMetaWire("verification"), map[string]string{"completed_at_milliseconds": "1007"}, true))
}

func TestEvMetaVerificationAvailableRelations(t *testing.T) {
	op, fence, list, current := evMetaOp(t), evMetaEvidence(t, "fence_evidence"), evMetaEvidence(t, "terminal_response"), evMetaEvidence(t, "final_response")
	for _, tc := range []struct {
		name    string
		op      artifact.ErasureOperation
		fence   artifact.ErasureEvidence
		lists   []artifact.ErasureEvidence
		current artifact.ErasureEvidence
		at      time.Time
		want    error
	}{
		{"zero-op", artifact.ErasureOperation{}, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"zero-fence", op, artifact.ErasureEvidence{}, []artifact.ErasureEvidence{list}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"wrong-fence-kind", op, list, []artifact.ErasureEvidence{list}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"nil-list", op, fence, nil, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"empty-list", op, fence, []artifact.ErasureEvidence{}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"two-lists", op, fence, []artifact.ErasureEvidence{list, list}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"wrong-list-kind", op, fence, []artifact.ErasureEvidence{fence}, current, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"zero-current", op, fence, []artifact.ErasureEvidence{list}, artifact.ErasureEvidence{}, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"wrong-current-kind", op, fence, []artifact.ErasureEvidence{list}, fence, evMetaTime(1008), artifact.ErrInvalidErasureContract},
		{"completed-before-read", op, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1006), artifact.ErrErasureBindingMismatch},
		{"bad-time", op, fence, []artifact.ErasureEvidence{list}, current, time.Time{}, artifact.ErrInvalidErasureContract},
		{"submillisecond", op, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1008).Add(time.Nanosecond), artifact.ErrInvalidErasureContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := artifact.NewErasureVerification(tc.op, tc.fence, tc.lists, tc.current, tc.at)
			evMetaError(t, e, tc.want)
			evMetaZeroVerification(t, v)
		})
	}
	for _, tc := range []struct {
		name          string
		list, current artifact.ErasureEvidence
		want          error
	}{
		{"list-before-fence", evMetaResponseChange(t, "terminal_response", map[string]string{"observed_at_milliseconds": "1002"}), current, artifact.ErrErasureBindingMismatch},
		{"read-before-list", list, evMetaResponseChange(t, "final_response", map[string]string{"observed_at_milliseconds": "1004"}), artifact.ErrErasureBindingMismatch},
		{"same-attempt-claim", list, evMetaResponseChange(t, "final_response", map[string]string{"attempt_identity": evMetaJSON(list.AttemptIdentity())}), artifact.ErrErasureBindingMismatch},
		{"different-current-token", list, evMetaResponseChange(t, "final_response", map[string]string{"version_id": `"another-version"`}), artifact.ErrErasureBindingMismatch},
		{"wrong-list-version-identity", evMetaResponseChange(t, "terminal_response", map[string]string{"entries": `[{"version_identity":"` + evMetaOther + `","kind":"data","version_id":"fence-v1","is_latest":true}]`}), current, artifact.ErrErasureBindingMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{tc.list}, tc.current, evMetaTime(1008))
			evMetaError(t, e, tc.want)
			evMetaZeroVerification(t, v)
		})
	}
	// An empty-output-cursor singleton is only a response shape.
	for _, changes := range []map[string]string{{"entries": "[]"}, {"entries": `[{"version_identity":"` + evMetaOther + `","kind":"delete_marker","version_id":"marker","is_latest":true}]`}, {"entries": `[{"version_identity":"` + evMetaVectors["required_version"].identity + `","kind":"data","version_id":"fence-v1","is_latest":false}]`}, {"truncated": "true", "key_marker": evMetaJSON(evMetaKey(t).Key()), "version_id_marker": `"more"`}} {
		l := evMetaResponseChange(t, "terminal_response", changes)
		v, e := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{l}, current, evMetaTime(1008))
		evMetaError(t, e, artifact.ErrInvalidErasureContract)
		evMetaZeroVerification(t, v)
	}
	z, err := artifact.NewVerificationEvidence(artifact.ErasureVerification{})
	evMetaError(t, err, artifact.ErrInvalidErasureContract)
	evMetaZeroEvidence(t, z)
}

func TestEvMetaVerificationParserAndWrapperRelations(t *testing.T) {
	wire := evMetaWire("verification")
	m := evMetaFields(t, wire)
	for _, change := range []map[string]string{
		{"list_response_identities": "[]"}, {"list_response_identities": `["` + evMetaOther + `","` + strings.Repeat("a", 64) + `"]`}, {"list_response_identities": "null"},
		{"list_response_identities": "[" + string(m["fence_evidence_identity"]) + "]"}, {"current_response_identity": string(m["fence_evidence_identity"])},
		{"fence_version_identity": `""`}, {"artifact_identity": `""`}, {"verified_at_milliseconds": "0"}, {"completed_at_milliseconds": "253402300800000"},
	} {
		evMetaDeniedVerification(t, evMetaChange(t, wire, change, true), artifact.ErrInvalidErasureContract)
	}
	evMetaDeniedVerification(t, evMetaChange(t, wire, map[string]string{"completed_at_milliseconds": "1006"}, true), artifact.ErrErasureBindingMismatch)
	for _, key := range []string{"namespace_identity", "scope_identity", "operation_identity"} {
		evMetaDeniedVerification(t, evMetaChange(t, wire, map[string]string{key: evMetaJSON(evMetaOther)}, true), artifact.ErrErasureIdentityMismatch)
	}
	for _, change := range []map[string]string{
		{"parent_identities": "[" + evMetaJSON(evMetaVectors["terminal_response"].identity) + "," + evMetaJSON(evMetaVectors["fence_evidence"].identity) + "," + evMetaJSON(evMetaVectors["final_response"].identity) + "]"},
		{"parent_identities": `["` + evMetaOther + `","` + evMetaVectors["terminal_response"].identity + `","` + evMetaVectors["final_response"].identity + `"]`},
		{"observed_at_milliseconds": "1009"},
	} {
		wire := evMetaChange(t, evMetaWire("verification_evidence"), change, true)
		evMetaDeniedEvidence(t, wire, artifact.ErrErasureBindingMismatch)
		evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"identity": evMetaJSON(strings.Repeat("e", 64))}, false), artifact.ErrErasureBindingMismatch)
	}
	evMetaDeniedEvidence(t, evMetaChange(t, evMetaWire("verification_evidence"), map[string]string{"slot": evMetaJSON("verification:" + evMetaOther)}, true), artifact.ErrInvalidErasureContract)
	// The explicit ref contains no artifact or dependency preimages.
	claimed := evMetaChange(t, wire, map[string]string{"artifact_identity": evMetaJSON(evMetaOther), "fence_version_identity": evMetaJSON(evMetaOther), "fence_evidence_identity": evMetaJSON(strings.Repeat("a", 64)), "list_response_identities": `["` + strings.Repeat("c", 64) + `"]`, "current_response_identity": evMetaJSON(strings.Repeat("d", 64)), "verified_at_milliseconds": "1", "completed_at_milliseconds": "1"}, true)
	v, e := artifact.ParseErasureVerification([]byte(claimed), evMetaRef(t))
	evMetaError(t, e, nil)
	evMetaWantVerification(t, v, claimed)
	wrapper, e := artifact.NewVerificationEvidence(v)
	evMetaError(t, e, nil)
	if wrapper.Ref() != evMetaRef(t) {
		t.Fatal("wrapper ref")
	}
}

func TestEvMetaVerificationCopiesAndFormatting(t *testing.T) {
	wire := evMetaWire("verification")
	input := []byte(wire)
	v, e := artifact.ParseErasureVerification(input, evMetaRef(t))
	evMetaError(t, e, nil)
	input[0] = 'X'
	for i := 0; i < 2; i++ {
		ids := v.ListResponseIdentities()
		ids[0] = evMetaOther
		b, err := artifact.EncodeErasureVerification(v)
		evMetaError(t, err, nil)
		b[0] = 'X'
		evMetaWantVerification(t, v, wire)
	}
	var zero artifact.ErasureVerification
	evMetaZeroVerification(t, zero)
	evMetaFormat(t, []any{v, &v, zero, &zero}, "artifact erasure verification", "artifact.ErasureVerification{<redacted>}")
}

var _ interface {
	Validate() error
	Identity() string
	NamespaceIdentity() string
	ScopeIdentity() string
	ArtifactIdentity() string
	OperationIdentity() string
	FenceEvidenceIdentity() string
	FenceVersionIdentity() string
	CurrentResponseIdentity() string
	ListResponseIdentities() []string
	VerifiedAt() time.Time
	CompletedAt() time.Time
	String() string
	GoString() string
} = artifact.ErasureVerification{}

func TestEvMetaVerificationEqualTimesAndOmittedRequests(t *testing.T) {
	op, fence, current := evMetaOp(t), evMetaEvidence(t, "fence_evidence"), evMetaEvidence(t, "final_response")
	req := evMetaRequest(t, evMetaChange(t, evMetaWire("list_continuation_request"), map[string]string{"page_limit": "256"}, true))
	a, e := artifact.NewErasureAttempt(req, 2, evMetaTime(1004))
	evMetaError(t, e, nil)
	inner := evMetaChange(t, evMetaWire("terminal_response_record"), map[string]string{"attempt_identity": evMetaJSON(a.Identity())}, true)
	outer := evMetaChange(t, evMetaNested(t, evMetaWire("terminal_response"), inner), map[string]string{"attempt_identity": evMetaJSON(a.Identity()), "slot": evMetaJSON("response:" + a.Identity())}, true)
	list := evMetaNewResponse(t, evMetaOptions(t, a, inner), outer)
	v, e := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1008))
	evMetaError(t, e, nil)
	expected := evMetaChange(t, evMetaWire("verification"), map[string]string{"list_response_identities": "[" + evMetaJSON(evMetaString(t, evMetaFields(t, outer), "identity")) + "]"}, true)
	evMetaWantVerification(t, v, expected)
	// The verification constructor has no input cursor, requested limit, or permit.
	list = evMetaResponseChange(t, "terminal_response", map[string]string{"observed_at_milliseconds": "1003"})
	current = evMetaResponseChange(t, "final_response", map[string]string{"observed_at_milliseconds": "1003"})
	v, e = artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, current, evMetaTime(1003))
	evMetaError(t, e, nil)
	expected = evMetaChange(t, evMetaWire("verification"), map[string]string{"list_response_identities": "[" + evMetaJSON(list.Identity()) + "]", "current_response_identity": evMetaJSON(current.Identity()), "verified_at_milliseconds": "1003", "completed_at_milliseconds": "1003"}, true)
	evMetaWantVerification(t, v, expected)
	// Reusing the initial response is not a separate final response claim.
	old := evMetaEvidence(t, "initial_response")
	v, e = artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{evMetaEvidence(t, "terminal_response")}, old, evMetaTime(1008))
	evMetaError(t, e, artifact.ErrErasureBindingMismatch)
	evMetaZeroVerification(t, v)
	entries := `[{"version_identity":"` + evMetaVectors["required_version"].identity + `","kind":"data","version_id":"fence-v1","is_latest":true},{"version_identity":"` + evMetaOther + `","kind":"data","version_id":"sibling","is_latest":false}]`
	list = evMetaResponseChange(t, "terminal_response", map[string]string{"entries": entries})
	v, e = artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, evMetaEvidence(t, "final_response"), evMetaTime(1008))
	evMetaError(t, e, artifact.ErrInvalidErasureContract)
	evMetaZeroVerification(t, v)
}
