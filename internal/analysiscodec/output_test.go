package analysiscodec

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

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

func frozenClosure(t *testing.T, scenario string) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, Result) {
	t.Helper()
	base, head, change, output := verifyOldCodeGolden(t, readOldCodeGolden(t, scenario))
	result, err := ParseResultArtifact(output, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	return base, head, change, output, result
}
func rebuildEvidence(t *testing.T, original artifact.Artifact, payload []byte) artifact.Artifact {
	t.Helper()
	a, err := artifact.New(original.Scope(), original.Kind(), original.MediaType(), original.Classification(), original.Origin(), original.Protection(), original.Provenance(), payload, original.CreatedAt(), original.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func rejectResult(t *testing.T, original, change, base, head artifact.Artifact, payload []byte) {
	t.Helper()
	result, err := ParseResultArtifact(rebuildEvidence(t, original, payload), change, base, head)
	if !errors.Is(err, ErrInvalidResult) || !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("invalid result accepted: %#v err=%v", result, err)
	}
}
func canonicalMutation(t *testing.T, result Result, mutate func(*Result)) []byte {
	t.Helper()
	result.items = append([]Item(nil), result.items...)
	result.removed = append([]Item(nil), result.removed...)
	result.gaps = append([]Gap(nil), result.gaps...)
	result.checks = append([]DeterministicCheck(nil), result.checks...)
	result.observations = append([]Observation(nil), result.observations...)
	mutate(&result)
	result.identity = deriveIdentity(result)
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func wireMutation(t *testing.T, payload []byte, mutate func(*resultWire), rehash bool) []byte {
	t.Helper()
	var wire resultWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	mutate(&wire)
	if rehash {
		wire.Identity = ""
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		wire.Identity = hex.EncodeToString(hash[:])
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func changeEntryForPath(t *testing.T, changeArtifact, base, head artifact.Artifact, path string) changecodec.Entry {
	t.Helper()
	change, err := changecodec.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range change.Entries() {
		if entry.Path() == path {
			return entry
		}
	}
	t.Fatalf("missing change entry for %s", path)
	return changecodec.Entry{}
}

func TestFrozenVersionMutationAndParserRejections(t *testing.T) {
	base, head, change, output, result := frozenClosure(t, "produced-v4-failed-one-observation")
	cases := []struct {
		name    string
		payload []byte
	}{

		{"unknown field", bytes.Replace(output.Payload(), []byte(`"contract":`), []byte(`"unknown":true,"contract":`), 1)},
		{"whitespace", append([]byte(" "), output.Payload()...)},
		{"trailing", append(append([]byte{}, output.Payload()...), []byte("{}")...)},
		{"result identity", wireMutation(t, output.Payload(), func(w *resultWire) { w.Identity = strings.Repeat("a", 64) }, false)},
		{"missing item", canonicalMutation(t, result, func(r *Result) { r.items = nil })},
		{"duplicate coverage", canonicalMutation(t, result, func(r *Result) {
			r.gaps = append(r.gaps, Gap{changeEntryIdentity: r.items[0].changeEntryIdentity, changeExecutionIdentity: r.items[0].changeExecutionIdentity, path: r.items[0].path, startLine: r.items[0].startLine, endLine: r.items[0].endLine, reason: "resource_limit"})
		})},
		{"invalid item binding", canonicalMutation(t, result, func(r *Result) { r.items[0].bindingIdentity = strings.Repeat("a", 64) })},
		{"observation outside change", canonicalMutation(t, result, func(r *Result) {
			observation := &r.observations[0]
			observation.startLine = 12
			observation.endLine = 12
			binding := Item{path: observation.path, startLine: observation.startLine, endLine: observation.endLine, digest: observation.digest, fileIdentity: observation.fileIdentity, fileDigest: observation.fileDigest, sliceBytes: observation.sliceBytes}
			observation.evidenceID = deriveBindingIdentity(binding)
			observation.identity = deriveObservationIdentity(*observation)
			if deriveBindingIdentity(binding) != observation.evidenceID || !validDigest(observation.evidenceID) || !validDigest(observation.digest) || !validDigest(observation.fileIdentity) || !validDigest(observation.fileDigest) || !validDigest(observation.fingerprint) || !validDigest(observation.checkIdentity) || observation.sliceBytes <= 0 || observation.path != "gate.go" || observation.checkIdentity != r.checks[0].Identity() {
				t.Fatal("outside observation does not preserve valid binding, metadata and check")
			}
			if sourceRange, err := evidence.NewSourceRange(observation.path, observation.startLine, observation.endLine); err != nil || sourceRange.StartLine() != 12 || sourceRange.EndLine() != 12 {
				t.Fatalf("invalid outside physical range: %v", err)
			}
			changed := changeEntryForPath(t, change, base, head, observation.path)
			for _, value := range changed.Ranges() {
				if value.StartLine() <= observation.startLine && observation.endLine <= value.EndLine() {
					t.Fatal("outside observation is contained in changed range")
				}
			}
		})},
		{"observation malformed fingerprint with rehashed identities", canonicalMutation(t, result, func(r *Result) {
			r.observations[0].fingerprint = strings.Repeat("z", 64)
			r.observations[0].identity = deriveObservationIdentity(r.observations[0])
		})},
		{"observation stale inner identity with rehashed outer identity", canonicalMutation(t, result, func(r *Result) {
			r.observations[0].fingerprint = hashObservationValue("different-valid-fingerprint-for-isolated-characterization")
		})},
		{"observation bad binding", canonicalMutation(t, result, func(r *Result) {
			r.observations[0].evidenceID = strings.Repeat("a", 64)
			r.observations[0].identity = deriveObservationIdentity(r.observations[0])
		})},
		{"forged check inner count", canonicalMutation(t, result, func(r *Result) { r.checks = append([]DeterministicCheck(nil), r.checks...); r.checks[0].matches++ })},
		{"reidentified check count mismatch", canonicalMutation(t, result, func(r *Result) {
			check, err := NewDeterministicCheck(r.changeIdentity, CheckFailed, 1, 1, 1, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			r.checks = []DeterministicCheck{check}
			r.observations[0].checkIdentity = check.Identity()
			r.observations[0].identity = deriveObservationIdentity(r.observations[0])
		})},
	}
	zeroBase, zeroHead, zeroChange, zeroOutput, _ := frozenClosure(t, "synthetic-v4-zero-match")
	t.Run("v4 missing observations", func(t *testing.T) {
		rejectResult(t, zeroOutput, zeroChange, zeroBase, zeroHead, bytes.Replace(zeroOutput.Payload(), []byte(`,"observations":[]`), nil, 1))
	})
	t.Run("v4 null observations", func(t *testing.T) {
		rejectResult(t, zeroOutput, zeroChange, zeroBase, zeroHead, bytes.Replace(zeroOutput.Payload(), []byte(`"observations":[]`), []byte(`"observations":null`), 1))
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { rejectResult(t, output, change, base, head, tc.payload) })
	}
	t.Run("coverage requires exact changed range", func(t *testing.T) {
		entry := changeEntryForPath(t, change, base, head, "gate.go")
		if len(entry.Ranges()) != 1 || entry.Ranges()[0].StartLine() != 1 || entry.Ranges()[0].EndLine() != 3 {
			t.Fatal("gate.go fixture changed its coverage range")
		}
		entries := map[string]changecodec.Entry{entry.Identity(): entry}
		payload := canonicalMutation(t, result, func(r *Result) {
			for index := range r.items {
				item := &r.items[index]
				if item.path != entry.Path() {
					continue
				}
				if item.startLine != 1 || item.endLine != 3 || deriveBindingIdentity(*item) != item.bindingIdentity || !validItem(*item, entries, r.schemaVersion) {
					t.Fatal("genuine gate.go coverage item must pass validItem")
				}
				item.startLine = 3
				item.endLine = 3
				item.bindingIdentity = deriveBindingIdentity(*item)
				item.evidenceID = item.bindingIdentity
				if item.changeEntryIdentity != entry.Identity() || item.changeExecutionIdentity != entry.ExecutionIdentity() || item.fileIdentity != entry.HeadIdentity() || item.fileDigest != entry.HeadDigest() || item.evidenceID != item.bindingIdentity || deriveBindingIdentity(*item) != item.bindingIdentity || !validDigest(item.digest) || !validDigest(item.fileIdentity) || !validDigest(item.fileDigest) || !validDigest(item.evidenceID) || item.sliceBytes <= 0 || item.sliceBytes > 1<<20 {
					t.Fatal("subrange coverage lost its valid binding or metadata")
				}
				sourceRange, err := evidence.NewSourceRange(item.path, item.startLine, item.endLine)
				if err != nil || sourceRange.StartLine() != 3 || sourceRange.EndLine() != 3 {
					t.Fatalf("invalid coverage physical range: %v", err)
				}
				if _, err := evidence.NewEvidenceItem(item.evidenceID, evidence.EvidenceKindSource, item.digest, sourceRange); err != nil {
					t.Fatalf("forged subrange evidence item invalid: %v", err)
				}
				if containsRange(entry.Ranges(), item.startLine, item.endLine) {
					t.Fatal("subrange unexpectedly matches exact changed range")
				}
				if validItem(*item, entries, r.schemaVersion) {
					t.Fatal("forged gate.go subrange passed validItem")
				}
				return
			}
			t.Fatal("missing gate.go coverage item")
		})
		rejectResult(t, output, change, base, head, payload)
	})
	for _, scenario := range []string{"synthetic-v2-no-checks-observations", "synthetic-v3-check-no-observations"} {
		t.Run(scenario, func(t *testing.T) {
			b, h, c, o, _ := frozenClosure(t, scenario)
			rejectResult(t, o, c, b, h, bytes.Replace(o.Payload(), []byte(`"semantic_impact":`), []byte(`"observations":[],"semantic_impact":`), 1))
			if scenario == "synthetic-v2-no-checks-observations" {
				rejectResult(t, o, c, b, h, bytes.Replace(o.Payload(), []byte(`"semantic_impact":`), []byte(`"checks":[],"semantic_impact":`), 1))
			}
		})
	}
}
func TestFrozenAlternateObservationFingerprintParity(t *testing.T) {
	base, head, change, output, result := frozenClosure(t, "produced-v4-failed-one-observation")
	originalFingerprint := result.observations[0].fingerprint
	replacement := hashObservationValue("different-valid-fingerprint-for-isolated-characterization")
	if replacement == originalFingerprint || !validDigest(replacement) {
		t.Fatal("replacement fingerprint must be different and valid")
	}
	payload := canonicalMutation(t, result, func(r *Result) {
		r.observations[0].fingerprint = replacement
		r.observations[0].identity = deriveObservationIdentity(r.observations[0])
	})
	payloadSHA := sha256.Sum256(payload)
	if got := hex.EncodeToString(payloadSHA[:]); got != "7712fd7cf07e44b436d903555315bee74269ff86cb51bc8a80b7f16de18c7a39" {
		t.Fatalf("old-code payload parity changed: %s", got)
	}
	altered := rebuildEvidence(t, output, payload)
	if err := altered.Validate(); err != nil {
		t.Fatalf("rebuilt artifact invalid: %v", err)
	}
	parsed, err := ParseResultArtifact(altered, change, base, head)
	if err != nil {
		t.Fatalf("valid alternate fingerprint rejected: %v", err)
	}
	if len(parsed.observations) != 1 || parsed.observations[0].fingerprint != replacement || parsed.observations[0].identity != "5f10d85e2b2aca42915e8b24ff6e0c8cd83b0e424288b403ec616db52b9468fd" || parsed.identity != "372d566c14166721992f513931a9b3eb8af2f601fb49bccddce5cdc6a8972be1" || altered.Identity() != "f2efdfc2c0917484fc6b42e053f71d974d4d57e7727eaffc016b59c3f350326c" {
		t.Fatalf("old-code identities or fingerprint changed: obs=%s parsed=%s artifact=%s", parsed.observations[0].identity, parsed.identity, altered.Identity())
	}
	if result.observations[0].fingerprint != originalFingerprint || result.checks[0].Identity() != parsed.checks[0].Identity() {
		t.Fatal("mutation altered source observation or check")
	}
}
func TestFrozenContainmentAndTypedConstructors(t *testing.T) {
	base, head, changeArtifact, _, r := frozenClosure(t, "produced-v4-failed-one-observation")
	change, err := changecodec.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	var entry changecodec.Entry
	for _, e := range change.Entries() {
		if e.Path() == "gate.go" {
			entry = e
		}
	}
	if entry.Path() == "" {
		t.Fatal("missing gate.go")
	}
	var coverage Item
	for _, item := range r.Items() {
		if item.Path() == "gate.go" {
			coverage = item
		}
	}
	observation := r.Observations()[0]
	if len(entry.Ranges()) != 1 || entry.Ranges()[0].StartLine() != 1 || entry.Ranges()[0].EndLine() != 3 || coverage.StartLine() != 1 || coverage.EndLine() != 3 || observation.StartLine() != 3 || observation.EndLine() != 3 || coverage.EvidenceID() == observation.EvidenceID() {
		t.Fatal("strict subrange and distinct binding lost")
	}
	// BindSourceSlice is exercised by the live upper producer. This lower test checks its typed result.
	content := []byte("package gate\nimport \"fmt\"\nfunc run() { fmt.Println(\"debug\") }\n")
	file, err := evidence.NewRepositoryFile("gate.go", content)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := evidence.NewSourceRange("gate.go", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := evidence.BindSourceSlice(file, content, whole, content)
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewItem(entry, bound)
	if err != nil || item.EvidenceID() != coverage.EvidenceID() {
		t.Fatalf("coverage item=%#v err=%v", item, err)
	}
	sub, err := evidence.NewSourceRange("gate.go", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	part := []byte("func run() { fmt.Println(\"debug\") }\n")
	match, err := evidence.BindSourceSlice(file, content, sub, part)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewItem(entry, match); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("subrange item accepted: %v", err)
	}
	observed, err := NewObservationFromBinding(r.Checks()[0], entry, match)
	if err != nil || observed.Identity() != observation.Identity() {
		t.Fatalf("subrange observation=%#v err=%v", observed, err)
	}
}
func TestFrozenEnvelopeAndGapRejections(t *testing.T) {
	base, head, change, output, _ := frozenClosure(t, "produced-v4-removed-file-gap")
	parsed, err := ParseResultArtifact(output, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*Result){
		func(r *Result) { r.gaps = nil },
		func(r *Result) { r.gaps = append(r.gaps, r.gaps[0]) },
		func(r *Result) { r.gaps[0].reason = "invalid" },
	} {
		rejectResult(t, output, change, base, head, canonicalMutation(t, parsed, mutation))
	}
	scope, _ := audit.NewReviewScope("different", "repository", "run")
	wrong, err := artifact.New(scope, output.Kind(), output.MediaType(), output.Classification(), output.Origin(), output.Protection(), output.Provenance(), output.Payload(), output.CreatedAt(), output.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := ParseResultArtifact(wrong, change, base, head); !errors.Is(err, ErrInvalidResult) || result.Identity() != "" {
		t.Fatalf("wrong scope=%#v %v", result, err)
	}
	wrong, err = artifact.New(output.Scope(), output.Kind(), output.MediaType(), output.Classification(), output.Origin(), output.Protection(), []string{strings.Repeat("f", 64)}, output.Payload(), output.CreatedAt(), output.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := ParseResultArtifact(wrong, change, base, head); !errors.Is(err, ErrInvalidResult) || result.Identity() != "" {
		t.Fatalf("wrong provenance=%#v %v", result, err)
	}
	if fmt.Sprintf("%v", parsed) != "deterministic evidence result" || fmt.Sprintf("%q", parsed) != `"deterministic evidence result"` || fmt.Sprintf("%#v", parsed) != "analysis.Result{<redacted>}" || fmt.Sprintf("%v", Observation{}) != "deterministic review observation" || fmt.Sprintf("%q", Observation{}) != `"deterministic review observation"` || fmt.Sprintf("%#v", Observation{}) != "analysis.Observation{<redacted>}" {
		t.Fatal("redaction changed")
	}

}

func profileRehash(t *testing.T, profile []byte, changes func(map[string]any)) []byte {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(profile, &p); err != nil {
		t.Fatal(err)
	}
	changes(p)
	identities := func(key string) []string {
		values := p[key].([]any)
		if len(values) == 0 {
			return nil
		}
		ids := make([]string, 0, len(values))
		for _, v := range values {
			ids = append(ids, v.(map[string]any)["identity"].(string))
		}
		return ids
	}
	preimage := struct {
		Adapter, Graph, Input, Base, Head, Change string
		Declarations, References, Gaps            []string
	}{p["adapter_identity"].(string), p["graph_schema"].(string), p["input_identity"].(string), p["base_snapshot_identity"].(string), p["head_snapshot_identity"].(string), p["change_model_identity"].(string), identities("declarations"), identities("references"), identities("gaps")}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	p["identity"] = hex.EncodeToString(hash[:])
	encodedProfile := append([]byte(nil), profile...)
	for _, key := range []string{"base_snapshot_identity", "head_snapshot_identity", "change_model_identity"} {
		old := lookupProfileField(t, profile, key)
		current := p[key].(string)
		if old != current {
			encodedProfile = bytes.Replace(encodedProfile, []byte(`"`+key+`":"`+old+`"`), []byte(`"`+key+`":"`+current+`"`), 1)
		}
	}
	if refs := p["references"].([]any); len(refs) > 0 {
		changed := refs[0].(map[string]any)
		var before map[string]any
		var previous map[string]any
		if err := json.Unmarshal(profile, &before); err != nil {
			t.Fatal(err)
		}
		previous = before["references"].([]any)[0].(map[string]any)
		for _, key := range []string{"declaration_identity", "identity"} {
			old := previous[key].(string)
			current := changed[key].(string)
			if old != current {
				encodedProfile = bytes.Replace(encodedProfile, []byte(`"`+key+`":"`+old+`"`), []byte(`"`+key+`":"`+current+`"`), 1)
			}
		}
	}
	encodedProfile = bytes.Replace(encodedProfile, []byte(`"identity":"`+lookupProfileField(t, profile, "identity")+`"`), []byte(`"identity":"`+p["identity"].(string)+`"`), 1)
	return encodedProfile
}
func TestFrozenSemanticIdentityLinksAndGraphOrphan(t *testing.T) {
	base, head, change, output, _ := frozenClosure(t, "produced-v4-go-affected-test")
	var wire resultWire
	if err := json.Unmarshal(output.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		rehash bool
	}{
		{"invalid profile identity", func(p map[string]any) { p["identity"] = strings.Repeat("a", 64) }, false},
		{"base model link", func(p map[string]any) { p["base_snapshot_identity"] = strings.Repeat("a", 64) }, true},
		{"head model link", func(p map[string]any) { p["head_snapshot_identity"] = strings.Repeat("a", 64) }, true},
		{"change model link", func(p map[string]any) { p["change_model_identity"] = strings.Repeat("a", 64) }, true},
		{"graph reference orphan", func(p map[string]any) {
			ref := p["references"].([]any)[0].(map[string]any)
			ref["declaration_identity"] = strings.Repeat("a", 64)
			preimage := struct {
				Declaration, Path string
				Line, Column      int
				Test              bool
				Grade             string
			}{ref["declaration_identity"].(string), ref["path"].(string), int(ref["line"].(float64)), int(ref["column"].(float64)), ref["affected_test"].(bool), ref["grade"].(string)}
			data, _ := json.Marshal(preimage)
			hash := sha256.Sum256(data)
			ref["identity"] = hex.EncodeToString(hash[:])
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := wire
			if test.rehash {
				candidate.SemanticImpact = profileRehash(t, wire.SemanticImpact, test.change)
			} else {
				var p map[string]any
				if err := json.Unmarshal(wire.SemanticImpact, &p); err != nil {
					t.Fatal(err)
				}
				test.change(p)
				// An invalid inner identity is rejected before canonical profile validation is relevant.
				candidate.SemanticImpact = bytes.Replace(candidate.SemanticImpact, []byte(`"identity":"`+wire.SemanticImpactIdentity(t)+`"`), []byte(`"identity":"`+strings.Repeat("a", 64)+`"`), 1)
			}
			_, profileErr := semanticimpact.DecodeProfile(candidate.SemanticImpact)
			if test.rehash && test.name != "graph reference orphan" && profileErr != nil {
				t.Fatalf("valid rehashed profile rejected before analysis link: %v", profileErr)
			}
			if test.name == "graph reference orphan" && !errors.Is(profileErr, semanticimpact.ErrInvalidInput) {
				t.Fatalf("orphan profile not rejected: %v", profileErr)
			}
			candidate.Identity = ""
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			candidate.Identity = hex.EncodeToString(digest[:])
			data, err = json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			rejectResult(t, output, change, base, head, data)
		})
	}
}
func (w resultWire) SemanticImpactIdentity(t *testing.T) string {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(w.SemanticImpact, &p); err != nil {
		t.Fatal(err)
	}
	return p["identity"].(string)
}

func lookupProfileField(t *testing.T, profile []byte, key string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(profile, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[key].(string)
}

func TestEncodeResultRejectsEmptyIdentityWithoutExtraValidation(t *testing.T) {
	_, _, _, _, result := frozenClosure(t, "produced-v4-failed-one-observation")
	result.identity = ""
	if encoded, err := EncodeResult(result); !errors.Is(err, ErrInvalidResult) || encoded != nil {
		t.Fatalf("empty identity encoded: %v %s", err, encoded)
	}
	result.identity = strings.Repeat("a", 64)
	if encoded, err := EncodeResult(result); err != nil || len(encoded) == 0 {
		t.Fatalf("encoder added full validation: %v %s", err, encoded)
	}
}
