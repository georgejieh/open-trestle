package semanticimpact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileCodecRejectsUnknownAndIdentityTampering(t *testing.T) {
	file := mustFile(t, "a.go", "package p\nfunc A(){}\n")
	changed := mustChangedPath(t, "a.go")
	input, _ := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{changed}, nil, []File{file})
	profile, _ := AnalyzeGo(input)
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProfile(encoded)
	if err != nil || decoded.Identity() != profile.Identity() {
		t.Fatalf("decoded=(%v,%v)", decoded.Identity(), err)
	}
	unknown := bytes.Replace(encoded, []byte(`"schema_version":2`), []byte(`"schema_version":2,"extra":true`), 1)
	if _, err := DecodeProfile(unknown); err == nil {
		t.Fatal("accepted unknown")
	}
	tampered := bytes.Replace(encoded, []byte(profile.Identity()), []byte(strings.Repeat("f", 64)), 1)
	if _, err := DecodeProfile(tampered); err == nil {
		t.Fatal("accepted tamper")
	}
}

func TestProfileCodecBindsSnapshotAndChangeIdentities(t *testing.T) {
	profile := testCodecProfile(t)
	encoded, _ := EncodeProfile(profile)
	for name, value := range map[string]string{"base": profile.BaseSnapshotIdentity(), "head": profile.HeadSnapshotIdentity(), "change": profile.ChangeModelIdentity()} {
		t.Run(name, func(t *testing.T) {
			tampered := bytes.Replace(encoded, []byte(value), []byte(strings.Repeat("d", 64)), 1)
			if _, err := DecodeProfile(tampered); err == nil {
				t.Fatal("accepted cross-wired authority")
			}
		})
	}
}
func TestProfileCodecRejectsNoncanonicalBytes(t *testing.T) {
	profile := testCodecProfile(t)
	encoded, _ := EncodeProfile(profile)
	noncanonical := append([]byte(" "), encoded...)
	if _, err := DecodeProfile(noncanonical); err == nil {
		t.Fatal("accepted noncanonical bytes")
	}
}
func TestProfileCodecRejectsOversizedPositionWithoutPanic(t *testing.T) {
	profile := recordedProfileV1(t)
	profile.references[0].line = 1000000000000
	profile.references[0].identity = referenceIdentity(profile.references[0])
	profile.identity = deriveProfileIdentity(profile)
	encoded, _ := json.Marshal(toProfileWire(profile))
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("panic=%v", value)
		}
	}()
	if _, err := DecodeProfile(encoded); err == nil {
		t.Fatal("accepted oversized line")
	}
}
func testCodecProfile(t *testing.T) Profile {
	t.Helper()
	base := mustFile(t, "a.go", "package p\nfunc A(){}\n")
	head := mustFile(t, "a.go", "package p\nfunc A(){A()}\n")
	input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{mustChangedPath(t, "a.go")}, []File{base}, []File{head})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := AnalyzeGo(input)
	if err != nil || len(profile.declarations) == 0 {
		t.Fatalf("profile=(%#v,%v)", profile, err)
	}
	return profile
}

// recordedProfileV1 builds a profile as the version 1 graph recorded it: the
// current analysis plus one reference candidate.
func recordedProfileV1(t *testing.T) Profile {
	t.Helper()
	profile := testCodecProfile(t)
	profile.graphSchema = goGraphSchemaV1
	profile.adapterIdentity = goAdapterIdentityV1
	declaration := profile.declarations[0]
	reference := recordedReference{declarationIdentity: declaration.identity, declarationKey: declaration.key, filePath: "a.go", line: 2, column: 10, grade: GradeSyntacticCandidate}
	reference.identity = referenceIdentity(reference)
	profile.references = []recordedReference{reference}
	profile.identity = deriveProfileIdentity(profile)
	return profile
}

func TestProfileCodecWritesVersion2WithoutReferences(t *testing.T) {
	profile := testCodecProfile(t)
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if profile.GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v2" || !bytes.Contains(encoded, []byte(`"schema_version":2`)) || bytes.Contains(encoded, []byte(`"references"`)) {
		t.Fatalf("encoded = %s", encoded)
	}
	withReferences := bytes.Replace(encoded, []byte(`"gaps":`), []byte(`"references":[],"gaps":`), 1)
	if _, err := DecodeProfile(withReferences); err == nil {
		t.Fatal("version 2 profile with a references field accepted")
	}
	profile.references = recordedProfileV1(t).references
	profile.identity = deriveProfileIdentity(profile)
	if _, err := EncodeProfile(profile); err == nil {
		t.Fatal("current graph profile with references encoded")
	}
}

func TestProfileCodecReadsRecordedVersion1Profile(t *testing.T) {
	profile := recordedProfileV1(t)
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"schema_version":1`)) || !bytes.Contains(encoded, []byte(`"references":[{`)) {
		t.Fatalf("encoded = %s", encoded)
	}
	decoded, err := DecodeProfile(encoded)
	if err != nil || decoded.Identity() != profile.Identity() || decoded.GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v1" {
		t.Fatalf("decoded = (%v, %v)", decoded.Identity(), err)
	}
	roundtrip, err := EncodeProfile(decoded)
	if err != nil || !bytes.Equal(roundtrip, encoded) {
		t.Fatalf("recorded profile did not re-encode byte for byte: %v", err)
	}
	wrongVersion := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
	if _, err := DecodeProfile(wrongVersion); err == nil {
		t.Fatal("version 1 graph accepted under profile version 2")
	}
}

func TestProfileCodecReadsRecordedVersion1ProfileWithoutReferences(t *testing.T) {
	profile := recordedProfileV1(t)
	profile.references = nil
	profile.identity = deriveProfileIdentity(profile)
	encoded, err := EncodeProfile(profile)
	if err != nil || !bytes.Contains(encoded, []byte(`"references":[]`)) {
		t.Fatalf("encoded = %s, %v", encoded, err)
	}
	decoded, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("version 1 profile without references rejected: %v", err)
	}
	if roundtrip, err := EncodeProfile(decoded); err != nil || !bytes.Equal(roundtrip, encoded) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := DecodeProfile(bytes.Replace(encoded, []byte(`"references":[]`), []byte(`"references":null`), 1)); err == nil {
		t.Fatal("null references accepted")
	}
}

func TestProfileCodecRejectsRehashedOrphanReferences(t *testing.T) {
	for _, identity := range []string{"", strings.Repeat("f", 64)} {
		t.Run(identity, func(t *testing.T) {
			profile := recordedProfileV1(t)
			profile.references[0].declarationIdentity = identity
			profile.references[0].declarationKey = ""
			profile.references[0].identity = referenceIdentity(profile.references[0])
			profile.identity = deriveProfileIdentity(profile)
			encoded, err := json.Marshal(toProfileWire(profile))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeProfile(encoded); err == nil {
				t.Fatal("rehashed orphan reference accepted")
			}
		})
	}
}

func TestProfileCodecRejectsNullCollections(t *testing.T) {
	input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"declarations", "gaps"} {
		t.Run(name, func(t *testing.T) {
			altered := bytes.Replace(encoded, []byte(`"`+name+`":[]`), []byte(`"`+name+`":null`), 1)
			if bytes.Equal(altered, encoded) {
				t.Fatal("collection not replaced")
			}
			if _, err := DecodeProfile(altered); err == nil {
				t.Fatal("noncanonical null collection accepted")
			}
		})
	}
	rebuilt, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := EncodeProfile(rebuilt)
	if err != nil || !bytes.Equal(roundtrip, encoded) {
		t.Fatalf("canonical roundtrip failed: %v", err)
	}
}
