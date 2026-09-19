package artifact_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func TestEvMetaUnknownLiteralAndTimes(t *testing.T) {
	a := evMetaAttempt(t, "initial")
	e, err := artifact.NewAttemptUnknownEvidence(a, evMetaTime(1002))
	evMetaError(t, err, nil)
	evMetaWantEvidence(t, e, evMetaWire("unknown_evidence"))
	for _, at := range []time.Time{time.Time{}, evMetaTime(0), evMetaTime(-1), evMetaTime(1002).Add(time.Nanosecond), evMetaTime(1002).In(time.FixedZone("offset", 60)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		v, x := artifact.NewAttemptUnknownEvidence(a, at)
		evMetaError(t, x, artifact.ErrInvalidErasureContract)
		evMetaZeroEvidence(t, v)
	}
	v, x := artifact.NewAttemptUnknownEvidence(a, evMetaTime(1000))
	evMetaError(t, x, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, v)
	v, x = artifact.NewAttemptUnknownEvidence(artifact.ErasureAttempt{}, evMetaTime(1002))
	evMetaError(t, x, artifact.ErrInvalidErasureContract)
	evMetaZeroEvidence(t, v)
	v, x = artifact.NewAttemptUnknownEvidence(a, evMetaTime(1002).In(time.FixedZone("alias", 0)))
	evMetaError(t, x, nil)
	evMetaWantEvidence(t, v, evMetaWire("unknown_evidence"))
	for _, name := range []string{"matrix_current_read_unavailable", "matrix_current_read_malformed", "matrix_current_read_absent"} {
		evMetaEvidence(t, name)
		evMetaWantEvidence(t, e, evMetaWire("unknown_evidence"))
	}
}

func TestEvMetaFenceExplicitKeyLiteral(t *testing.T) {
	op, key := evMetaOp(t), evMetaKey(t)
	parsed := evMetaEvidence(t, "initial_response")
	direct := evMetaNewResponse(t, evMetaOptions(t, evMetaAttempt(t, "initial"), evMetaWire("initial_response_record")), evMetaWire("initial_response"))
	encoded, err := artifact.EncodeErasureEvidence(direct)
	evMetaError(t, err, nil)
	again := evMetaParseEvidence(t, string(encoded))
	for _, parent := range []artifact.ErasureEvidence{parsed, direct, again} {
		e, x := artifact.NewFenceObservationEvidence(op, key, parent, evMetaTime(1003))
		evMetaError(t, x, nil)
		evMetaWantEvidence(t, e, evMetaWire("fence_evidence"))
		evMetaParseEvidence(t, evMetaWire("fence_evidence"))
		if string(e.RecordBytes()) != evMetaWire("required_version") {
			t.Fatal("explicit key version bytes")
		}
	}
	otherKey, err := artifact.NewExactObjectKey(key.NamespaceIdentity(), "another/metadata/key")
	evMetaError(t, err, nil)
	e, err := artifact.NewFenceObservationEvidence(op, otherKey, parsed, evMetaTime(1003))
	evMetaError(t, err, nil)
	record := evMetaChange(t, evMetaWire("required_version"), map[string]string{"key": evMetaJSON(otherKey.Key())}, true)
	wire := evMetaNested(t, evMetaWire("fence_evidence"), record)
	evMetaWantEvidence(t, e, wire)
	// This alternate key is a metadata claim, not authority for either request key.
	for _, parent := range []artifact.ErasureEvidence{artifact.ErasureEvidence{}, evMetaEvidence(t, "unknown_evidence"), evMetaEvidence(t, "fence_evidence"), evMetaEvidence(t, "matrix_current_read_absent"), evMetaEvidence(t, "matrix_current_read_present"), evMetaEvidence(t, "branch_delete_marker")} {
		v, x := artifact.NewFenceObservationEvidence(op, key, parent, evMetaTime(1003))
		evMetaError(t, x, artifact.ErrInvalidErasureContract)
		evMetaZeroEvidence(t, v)
	}
	for _, k := range []artifact.ExactObjectKey{{}} {
		v, x := artifact.NewFenceObservationEvidence(op, k, parsed, evMetaTime(1003))
		evMetaError(t, x, artifact.ErrInvalidErasureContract)
		evMetaZeroEvidence(t, v)
	}
	wrongNS, err := artifact.NewExactObjectKey(evMetaOther, key.Key())
	evMetaError(t, err, nil)
	v, x := artifact.NewFenceObservationEvidence(op, wrongNS, parsed, evMetaTime(1003))
	evMetaError(t, x, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, v)
	v, x = artifact.NewFenceObservationEvidence(artifact.ErasureOperation{}, key, parsed, evMetaTime(1003))
	evMetaError(t, x, artifact.ErrInvalidErasureContract)
	evMetaZeroEvidence(t, v)
	for _, at := range []time.Time{time.Time{}, evMetaTime(1003).Add(time.Nanosecond), evMetaTime(1003).In(time.FixedZone("offset", 3600))} {
		v, x := artifact.NewFenceObservationEvidence(op, key, parsed, at)
		evMetaError(t, x, artifact.ErrInvalidErasureContract)
		evMetaZeroEvidence(t, v)
	}
	v, x = artifact.NewFenceObservationEvidence(op, key, parsed, evMetaTime(1001))
	evMetaError(t, x, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, v)
	e, err = artifact.NewFenceObservationEvidence(op, key, parsed, evMetaTime(1002))
	evMetaError(t, err, nil)
	evMetaWantEvidence(t, e, evMetaChange(t, evMetaWire("fence_evidence"), map[string]string{"observed_at_milliseconds": "1002"}, true))
}

func TestEvMetaEvidenceTagsSlotsParents(t *testing.T) {
	names := []string{"initial_response", "unknown_evidence", "fence_evidence", "verification_evidence", "candidate_evidence", "published_evidence"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			wire := evMetaWire(name)
			evMetaEvidence(t, name)
			m := evMetaFields(t, wire)
			for _, changes := range []map[string]string{
				{"kind": `"Response"`}, {"kind": `"other"`}, {"slot": `"other"`}, {"slot": `""`}, {"observed_at_milliseconds": "0"}, {"observed_at_milliseconds": "253402300800000"},
				{"parent_identities": "null"}, {"parent_identities": `["` + evMetaOther + `","` + evMetaOther + `"]`}, {"parent_identities": `["` + strings.Repeat("0", 64) + `"]`}, {"parent_identities": `["` + evMetaOther + `","` + strings.Repeat("a", 64) + `","` + strings.Repeat("c", 64) + `","` + strings.Repeat("d", 64) + `"]`},
			} {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, changes, true), artifact.ErrInvalidErasureContract)
			}
			if evMetaString(t, m, "attempt_identity") == "" {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"attempt_identity": evMetaJSON(evMetaOther)}, true), artifact.ErrInvalidErasureContract)
			} else {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"attempt_identity": `""`}, true), artifact.ErrInvalidErasureContract)
			}
			kind := evMetaString(t, m, "kind")
			if kind == "response" || kind == "unknown" {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"parent_identities": `["` + evMetaOther + `"]`}, true), artifact.ErrInvalidErasureContract)
			} else {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"parent_identities": "[]"}, true), artifact.ErrInvalidErasureContract)
			}
			if kind == "unknown" || kind == "published" {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"record_hex": `"7b7d"`}, true), artifact.ErrInvalidErasureContract)
			} else {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"record_hex": `""`}, true), artifact.ErrInvalidErasureContract)
			}
		})
	}
}

func TestEvMetaNullArraysRehashed(t *testing.T) {
	for _, name := range []string{"unknown_evidence", "initial_response", "matrix_current_read_absent", "matrix_version_list_present"} {
		t.Run("parents/"+name, func(t *testing.T) {
			wire := evMetaChange(t, evMetaWire(name), map[string]string{"parent_identities": "null"}, true)
			evMetaDeniedEvidence(t, wire, artifact.ErrInvalidErasureContract)
		})
	}
	for name, v := range evMetaVectors {
		if !strings.HasSuffix(name, "_record") || !strings.Contains(v.wire, `"contract":"open-trestle/artifact-erasure-response"`) {
			continue
		}
		t.Run("entries/"+name, func(t *testing.T) {
			outerName := strings.TrimSuffix(name, "_record")
			inner := evMetaChange(t, v.wire, map[string]string{"entries": "null"}, true)
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire(outerName), inner), artifact.ErrInvalidErasureContract)
		})
	}
	inner := evMetaChange(t, evMetaWire("verification"), map[string]string{"list_response_identities": "null"}, true)
	evMetaDeniedVerification(t, inner, artifact.ErrInvalidErasureContract)
	evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("verification_evidence"), inner), artifact.ErrInvalidErasureContract)
}

func TestEvMetaCanonicalGrammar(t *testing.T) {
	cases := []struct {
		name, wire string
		deny       func(*testing.T, string, error)
	}{
		{"evidence", evMetaWire("unknown_evidence"), evMetaDeniedEvidence},
		{"response", evMetaWire("initial_response_record"), func(t *testing.T, w string, e error) {
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), w), e)
		}},
		{"verification", evMetaWire("verification"), evMetaDeniedVerification},
		{"attestation", evMetaWire("attestation"), evMetaDeniedAttestation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := evMetaFields(t, tc.wire)
			for key, raw := range m {
				t.Run(key, func(t *testing.T) {
					pair := evMetaJSON(key) + ":" + string(raw)
					for name, w := range map[string]string{
						"duplicate":  strings.Replace(tc.wire, pair, pair+","+pair, 1),
						"case-alias": strings.Replace(tc.wire, evMetaJSON(key)+":", evMetaJSON(strings.ToUpper(key))+":", 1),
						"missing":    strings.Replace(strings.Replace(tc.wire, ","+pair, "", 1), pair+",", "", 1),
						"null":       strings.Replace(tc.wire, pair, evMetaJSON(key)+":null", 1),
					} {
						t.Run(name, func(t *testing.T) { tc.deny(t, w, artifact.ErrInvalidErasureContract) })
					}
				})
			}
			for name, w := range map[string]string{
				"empty": "", "whitespace": " " + tc.wire, "newline": tc.wire + "\n", "bom": "\xef\xbb\xbf" + tc.wire, "trailing": tc.wire + "{}", "invalid-utf8": strings.Replace(tc.wire, "open-trestle", "open-\xfftrestle", 1),
				"unknown":          strings.TrimSuffix(tc.wire, "}") + `,"unknown":0}`,
				"reordered":        strings.Replace(tc.wire, `"contract":`+string(m["contract"])+`,"schema_version":`+string(m["schema_version"]), `"schema_version":`+string(m["schema_version"])+`,"contract":`+string(m["contract"]), 1),
				"escaped-contract": strings.Replace(tc.wire, "open-trestle", `\u006fpen-trestle`, 1),
				"surrogate":        strings.Replace(tc.wire, "open-trestle", `\ud800`, 1),
				"slash-escape":     strings.Replace(tc.wire, "open-trestle/", `open-trestle\/`, 1),
				"wrong-version":    evMetaChange(t, tc.wire, map[string]string{"schema_version": "3"}, true),
				"wrong-contract":   evMetaChange(t, tc.wire, map[string]string{"contract": `"open-trestle/other"`}, true),
			} {
				t.Run(name, func(t *testing.T) { tc.deny(t, w, artifact.ErrInvalidErasureContract) })
			}
			for _, field := range []string{"schema_version", "observed_at_milliseconds", "verified_at_milliseconds", "completed_at_milliseconds", "prepared_at_milliseconds", "response_bytes", "remaining_data_versions", "remaining_delete_markers"} {
				if _, ok := m[field]; !ok {
					continue
				}
				for _, raw := range []string{"-1", "+1", "1.0", "1e0", "01", "9223372036854775808", `"1"`} {
					tc.deny(t, evMetaChange(t, tc.wire, map[string]string{field: raw}, false), artifact.ErrInvalidErasureContract)
				}
			}
			tc.deny(t, evMetaChange(t, tc.wire, map[string]string{"identity": evMetaJSON(evMetaOther)}, false), artifact.ErrErasureIdentityMismatch)
			for _, id := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("z", 64)} {
				tc.deny(t, evMetaChange(t, tc.wire, map[string]string{"identity": evMetaJSON(id)}, false), artifact.ErrInvalidErasureContract)
			}
		})
	}
}

func TestEvMetaNestedTypesHexAndCaps(t *testing.T) {
	for _, name := range []string{"initial_response", "fence_evidence", "verification_evidence", "candidate_evidence"} {
		t.Run(name, func(t *testing.T) {
			wire := evMetaWire(name)
			raw := evMetaString(t, evMetaFields(t, wire), "record_hex")
			for _, value := range []string{"0", "zz", strings.ToUpper(raw), "00" + raw, "7b7d", hex.EncodeToString([]byte(evMetaWire("published_evidence"))), hex.EncodeToString([]byte(evMetaPolicy)), hex.EncodeToString([]byte(evMetaAllowance))} {
				evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"record_hex": evMetaJSON(value)}, true), artifact.ErrInvalidErasureContract)
			}
			cap := 262144
			if name == "fence_evidence" {
				cap = 4096
			}
			if name == "verification_evidence" || name == "candidate_evidence" {
				cap = 8192
			}
			evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{"record_hex": evMetaJSON(strings.Repeat("20", cap+1))}, true), artifact.ErrInvalidErasureContract)
		})
	}
	for _, name := range []string{"initial_response", "unknown_evidence", "fence_evidence", "verification_evidence", "candidate_evidence", "published_evidence"} {
		evMetaDeniedEvidence(t, evMetaWire(name)+strings.Repeat(" ", 1048577), artifact.ErrInvalidErasureContract)
	}
	evMetaDeniedVerification(t, evMetaWire("verification")+strings.Repeat(" ", 8193), artifact.ErrInvalidErasureContract)
	evMetaDeniedAttestation(t, evMetaWire("attestation")+strings.Repeat(" ", 8193), artifact.ErrInvalidErasureContract)
	for _, tc := range []struct {
		kind string
		cap  int
	}{{"fence", 4096}, {"operation", 16384}, {"attestation", 8192}} {
		inner := evMetaChange(t, evMetaWire("initial_response_record"), map[string]string{"content_kind": evMetaJSON(tc.kind), "record_hex": evMetaJSON(strings.Repeat("20", tc.cap+1)), "response_bytes": "1"}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), inner), artifact.ErrInvalidErasureContract)
	}
}

func TestEvMetaEvidenceBindingPrecedenceAndClaims(t *testing.T) {
	wire := evMetaWire("initial_response")
	ref := evMetaRef(t)
	otherRef, err := artifact.NewErasureOperationRef(evMetaScope(t), ref.NamespaceIdentity(), evMetaOther)
	evMetaError(t, err, nil)
	e, err := artifact.ParseErasureEvidence([]byte(wire), otherRef)
	evMetaError(t, err, artifact.ErrErasureIdentityMismatch)
	evMetaZeroEvidence(t, e)
	e, err = artifact.ParseErasureEvidence([]byte(wire), artifact.ErasureOperationRef{})
	evMetaError(t, err, artifact.ErrInvalidErasureContract)
	evMetaZeroEvidence(t, e)
	for _, changes := range []map[string]string{{"operation_identity": evMetaJSON(evMetaOther)}, {"attempt_identity": evMetaJSON(evMetaOther)}, {"observed_at_milliseconds": "1003"}} {
		inner := evMetaChange(t, evMetaWire("initial_response_record"), changes, true)
		outer := evMetaNested(t, wire, inner)
		evMetaDeniedEvidence(t, outer, artifact.ErrErasureBindingMismatch)
		outer = evMetaChange(t, outer, map[string]string{"identity": evMetaJSON(evMetaOther)}, false)
		evMetaDeniedEvidence(t, outer, artifact.ErrErasureBindingMismatch)
	}
	stale := evMetaChange(t, evMetaWire("initial_response_record"), map[string]string{"identity": evMetaJSON(evMetaOther)}, false)
	outer := evMetaNested(t, wire, stale)
	evMetaDeniedEvidence(t, outer, artifact.ErrErasureIdentityMismatch)
	e, err = artifact.ParseErasureEvidence([]byte(outer), otherRef)
	evMetaError(t, err, artifact.ErrErasureIdentityMismatch)
	evMetaZeroEvidence(t, e)
	broken := evMetaChange(t, outer, map[string]string{"parent_identities": "null"}, false)
	e, err = artifact.ParseErasureEvidence([]byte(broken), otherRef)
	evMetaError(t, err, artifact.ErrInvalidErasureContract)
	evMetaZeroEvidence(t, e)
	for _, field := range []string{"namespace_identity", "scope_identity", "operation_identity"} {
		evMetaDeniedEvidence(t, evMetaChange(t, wire, map[string]string{field: evMetaJSON(evMetaOther)}, true), artifact.ErrErasureIdentityMismatch)
	}
	// Omitted request and key preimages cannot be authenticated by a parser.
	inner := evMetaChange(t, evMetaWire("terminal_response_record"), map[string]string{"entries": `[{"version_identity":"` + evMetaOther + `","kind":"data","version_id":"fence-v1","is_latest":true}]`}, true)
	evMetaParseEvidence(t, evMetaNested(t, evMetaWire("terminal_response"), inner))
	inner = evMetaChange(t, evMetaWire("matrix_current_read_unavailable_record"), map[string]string{"attempt_identity": evMetaJSON(evMetaOther)}, true)
	outer = evMetaNested(t, evMetaWire("matrix_current_read_unavailable"), inner)
	outer = evMetaChange(t, outer, map[string]string{"attempt_identity": evMetaJSON(evMetaOther), "slot": evMetaJSON("response:" + evMetaOther)}, true)
	evMetaParseEvidence(t, outer)
}

func TestEvMetaEvidenceImmutabilityAndFormatting(t *testing.T) {
	var zero artifact.ErasureEvidence
	evMetaZeroEvidence(t, zero)
	for _, name := range []string{"initial_response", "unknown_evidence", "fence_evidence", "verification_evidence", "candidate_evidence", "published_evidence"} {
		t.Run(name, func(t *testing.T) {
			wire := evMetaWire(name)
			input := []byte(wire)
			v, err := artifact.ParseErasureEvidence(input, evMetaRef(t))
			evMetaError(t, err, nil)
			input[0] = 'X'
			evMetaWantEvidence(t, v, wire)
			for i := 0; i < 2; i++ {
				p := v.ParentIdentities()
				if len(p) > 0 {
					p[0] = evMetaOther
				}
				r := v.RecordBytes()
				if len(r) > 0 {
					r[0] = 'X'
				}
				b, e := artifact.EncodeErasureEvidence(v)
				evMetaError(t, e, nil)
				b[0] = 'X'
				evMetaWantEvidence(t, v, wire)
			}
			evMetaFormat(t, []any{v, &v, zero, &zero}, "artifact erasure evidence", "artifact.ErasureEvidence{<redacted>}")
		})
	}
}

var _ interface {
	Validate() error
	Identity() string
	Kind() string
	Slot() string
	AttemptIdentity() string
	ObservedAt() time.Time
	ParentIdentities() []string
	RecordBytes() []byte
	Ref() artifact.ErasureOperationRef
	String() string
	GoString() string
} = artifact.ErasureEvidence{}
var _ audit.ReviewScope = artifact.ErasureEvidence{}.Ref().Scope()

func TestEvMetaCompletionCrossRefBindings(t *testing.T) {
	read := evMetaReboundRead(t, "initial_response", evMetaOther)
	e, err := artifact.NewFenceObservationEvidence(evMetaOp(t), evMetaKey(t), read, evMetaTime(1003))
	evMetaError(t, err, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, e)
	current := evMetaReboundRead(t, "final_response", evMetaOther)
	v, err := artifact.NewErasureVerification(evMetaOp(t), evMetaEvidence(t, "fence_evidence"), []artifact.ErasureEvidence{evMetaEvidence(t, "terminal_response")}, current, evMetaTime(1008))
	evMetaError(t, err, artifact.ErrErasureBindingMismatch)
	evMetaZeroVerification(t, v)
	proof := evMetaReboundRead(t, "proof_response", evMetaOther)
	e, err = artifact.NewAttestationPublicationEvidence(evMetaEvidence(t, "candidate_evidence"), proof, evMetaTime(1011))
	evMetaError(t, err, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, e)
	for _, tc := range []struct{ outer, inner string }{{"candidate_evidence", "attestation"}, {"verification_evidence", "verification"}} {
		for _, field := range []string{"namespace_identity", "scope_identity", "operation_identity"} {
			inner := evMetaChange(t, evMetaWire(tc.inner), map[string]string{field: evMetaJSON(evMetaOther)}, true)
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire(tc.outer), inner), artifact.ErrErasureIdentityMismatch)
		}
	}
	record := evMetaChange(t, evMetaWire("required_version"), map[string]string{"namespace_identity": evMetaJSON(evMetaOther)}, true)
	evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("fence_evidence"), record), artifact.ErrErasureBindingMismatch)
	record = evMetaChange(t, evMetaWire("required_version"), map[string]string{"kind": `"delete_marker"`}, true)
	evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("fence_evidence"), record), artifact.ErrInvalidErasureContract)
}

func TestEvMetaScalarGrammarAndStructuralPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		deny       func(*testing.T, string, error)
	}{
		{"evidence", evMetaWire("unknown_evidence"), evMetaDeniedEvidence},
		{"response", evMetaWire("initial_response_record"), func(t *testing.T, w string, e error) {
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), w), e)
		}},
		{"verification", evMetaWire("verification"), evMetaDeniedVerification},
	} {
		m := evMetaFields(t, tc.wire)
		for key := range m {
			if key != "identity" && !strings.HasSuffix(key, "_identity") && key != "content_digest" {
				continue
			}
			if evMetaString(t, m, key) == "" {
				continue
			}
			for _, id := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("F", 64), strings.Repeat("g", 64)} {
				tc.deny(t, evMetaChange(t, tc.wire, map[string]string{key: evMetaJSON(id)}, key != "identity"), artifact.ErrInvalidErasureContract)
			}
		}
	}
	for _, name := range []string{"fence_evidence", "verification_evidence", "candidate_evidence", "published_evidence"} {
		e := evMetaEvidence(t, name)
		wire := evMetaChange(t, evMetaWire(name), map[string]string{"identity": evMetaJSON(e.ParentIdentities()[0])}, false)
		evMetaDeniedEvidence(t, wire, artifact.ErrInvalidErasureContract)
	}
	for _, name := range []string{"matrix_current_read_absent", "matrix_intent_create_created", "matrix_version_delete_deleted", "matrix_current_read_conflict", "matrix_current_read_denied", "matrix_current_read_malformed", "matrix_current_read_unavailable", "matrix_current_read_abandoned"} {
		for key, raw := range map[string]string{
			"content_kind": `"ciphertext"`, "version_kind": `"data"`, "version_id": `"v1"`, "content_digest": evMetaJSON(evMetaOther), "record_hex": `"7b7d"`, "response_bytes": "1", "entries": `[{"version_identity":"` + evMetaOther + `","kind":"data","version_id":"v1","is_latest":true}]`, "key_marker": `"other/key"`, "version_id_marker": `"v1"`, "truncated": "true",
		} {
			inner := evMetaChange(t, evMetaWire(name+"_record"), map[string]string{key: raw}, true)
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire(name), inner), artifact.ErrInvalidErasureContract)
		}
	}
	evMetaDeniedAttestation(t, evMetaChange(t, evMetaWire("attestation"), map[string]string{"schema_version": "1"}, true), artifact.ErrInvalidErasureContract)
	body := evMetaChange(t, evMetaOperation, map[string]string{"schema_version": "1"}, true)
	o := evMetaOptions(t, evMetaAttempt(t, "matrix_intent_read"), evMetaWire("matrix_intent_read_present_record"))
	o.CanonicalRecord = []byte(body)
	o.ContentDigest = evMetaHash(body)
	o.ResponseBytes = uint32(len(body))
	evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
}

func TestEvMetaInclusiveMetadataBounds(t *testing.T) {
	for _, keyText := range []string{"k", strings.Repeat("k", 1024)} {
		key, err := artifact.NewExactObjectKey(evMetaRef(t).NamespaceIdentity(), keyText)
		evMetaError(t, err, nil)
		record := evMetaChange(t, evMetaWire("required_version"), map[string]string{"key": evMetaJSON(keyText)}, true)
		expected := evMetaNested(t, evMetaWire("fence_evidence"), record)
		e, err := artifact.NewFenceObservationEvidence(evMetaOp(t), key, evMetaEvidence(t, "initial_response"), evMetaTime(1003))
		evMetaError(t, err, nil)
		evMetaWantEvidence(t, e, expected)
	}
	for _, ms := range []int64{1, 253402300799999} {
		raw := evMetaJSON(ms)
		unknown := evMetaChange(t, evMetaWire("unknown_evidence"), map[string]string{"observed_at_milliseconds": raw}, true)
		evMetaParseEvidence(t, unknown)
		verification := evMetaChange(t, evMetaWire("verification"), map[string]string{"verified_at_milliseconds": raw, "completed_at_milliseconds": raw}, true)
		v, err := artifact.ParseErasureVerification([]byte(verification), evMetaRef(t))
		evMetaError(t, err, nil)
		evMetaWantVerification(t, v, verification)
		attestation := evMetaChange(t, evMetaWire("attestation"), map[string]string{"prepared_at_milliseconds": raw, "verified_at_milliseconds": raw, "completed_at_milliseconds": raw}, true)
		a, err := artifact.ParseErasureAttestationV2([]byte(attestation), evMetaScope(t))
		evMetaError(t, err, nil)
		evMetaWantAttestation(t, a, attestation)
	}
	e, err := artifact.NewAttemptUnknownEvidence(evMetaAttempt(t, "initial"), evMetaTime(253402300799999))
	evMetaError(t, err, nil)
	evMetaWantEvidence(t, e, evMetaChange(t, evMetaWire("unknown_evidence"), map[string]string{"observed_at_milliseconds": "253402300799999"}, true))
}

func TestEvMetaNestedResponseCanonicalFields(t *testing.T) {
	inner := evMetaWire("initial_response_record")
	m := evMetaFields(t, inner)
	recordHex := evMetaString(t, m, "record_hex")
	for _, value := range []string{"0", "gg", strings.ToUpper(recordHex), "7b7d", evMetaHex(evMetaWire("candidate_evidence")), evMetaHex(evMetaWire("verification"))} {
		changed := evMetaChange(t, inner, map[string]string{"record_hex": evMetaJSON(value)}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), changed), artifact.ErrInvalidErasureContract)
	}
	m = evMetaFields(t, evMetaWire("terminal_response_record"))
	entry := strings.TrimSuffix(strings.TrimPrefix(string(m["entries"]), "["), "]")
	fields := evMetaFields(t, entry)
	for key, raw := range fields {
		pair := evMetaJSON(key) + ":" + string(raw)
		for _, bad := range []string{strings.Replace(entry, pair, pair+","+pair, 1), strings.Replace(entry, evMetaJSON(key)+":", evMetaJSON(strings.ToUpper(key))+":", 1), strings.Replace(strings.Replace(entry, ","+pair, "", 1), pair+",", "", 1), strings.Replace(entry, pair, evMetaJSON(key)+":null", 1), strings.TrimSuffix(entry, "}") + `,"extra":0}`} {
			changed := evMetaChange(t, evMetaWire("terminal_response_record"), map[string]string{"entries": "[" + bad + "]"}, true)
			evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("terminal_response"), changed), artifact.ErrInvalidErasureContract)
		}
	}
	duplicate := strings.Replace(entry, `"kind":"data"`, `"kind":"delete_marker"`, 1)
	changed := evMetaChange(t, evMetaWire("terminal_response_record"), map[string]string{"entries": "[" + entry + "," + duplicate + "]"}, true)
	evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("terminal_response"), changed), artifact.ErrInvalidErasureContract)
}
