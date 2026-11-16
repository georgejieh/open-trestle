package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func localOwnerFixture() localSourceOwnerRecord {
	return localSourceOwnerRecord{
		StatePath: "/srv/trestle/state", ArtifactPath: "/srv/trestle/state/artifacts", GitObjectsPath: "/srv/git/objects",
		TenantID: "team", RepositoryID: "repo", RepositoryIdentity: strings.Repeat("a", 64),
		AdapterIdentity: strings.Repeat("b", 64), Profile: "loose-only", SourcePathDigest: strings.Repeat("c", 64),
		Git: localSourceDirectoryIdentity{Device: 1, Inode: 2}, State: localSourceDirectoryIdentity{Device: 3, Inode: 4}, Artifact: localSourceDirectoryIdentity{Device: 5, Inode: 6},
	}
}

func TestLocalSourceOwnerRecordRoundTrip(t *testing.T) {
	record := localOwnerFixture()
	encoded, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeLocalSourceOwnerRecord(encoded)
	if err != nil || parsed != record {
		t.Fatalf("round trip: %+v, %v", parsed, err)
	}
	want := `{"contract":"open-trestle/local-source-owner-record","version":1,"state_path":"/srv/trestle/state","artifact_path":"/srv/trestle/state/artifacts","git_objects_path":"/srv/git/objects","tenant_id":"team","repository_id":"repo","repository_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","adapter_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":"loose-only","source_path_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","git":{"device":1,"inode":2},"state":{"device":3,"inode":4},"artifact":{"device":5,"inode":6},"checksum_sha256":"8278a719ea1b78b1a65ed86912ec60232ee1a2b3da2be216eefe2eb4c3a51c69"}` + "\n"
	if string(encoded) != want {
		t.Fatalf("canonical byte fixture mismatch: %q", encoded)
	}
	again, err := encodeLocalSourceOwnerRecord(parsed)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("non-deterministic bytes: %v", err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.HasSuffix(encoded, []byte("\n\n")) {
		t.Fatal("newline policy")
	}
}

func TestLocalSourceOwnerRecordMalformed(t *testing.T) {
	encoded, err := encodeLocalSourceOwnerRecord(localOwnerFixture())
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string][]byte{
		"duplicate":        bytes.Replace(encoded, []byte(`"tenant_id":"team",`), []byte(`"tenant_id":"team","tenant_id":"team",`), 1),
		"unknown":          bytes.Replace(encoded, []byte(`"tenant_id":"team",`), []byte(`"unknown":1,"tenant_id":"team",`), 1),
		"whitespace":       bytes.Replace(encoded, []byte(`,"tenant_id"`), []byte(`, "tenant_id"`), 1),
		"escape":           bytes.Replace(encoded, []byte(`"team"`), []byte(`"t\u0065am"`), 1),
		"trailing":         append(bytes.Clone(encoded), 'x'),
		"no-newline":       bytes.Clone(encoded[:len(encoded)-1]),
		"oversized":        bytes.Repeat([]byte("x"), maxLocalSourceOwnerRecordBytes+1),
		"checksum":         bytes.Replace(encoded, []byte(`"tenant_id":"team"`), []byte(`"tenant_id":"else"`), 1),
		"checksum-non-hex": bytes.Replace(encoded, []byte(`"checksum_sha256":"8278a719ea1b78b1a65ed86912ec60232ee1a2b3da2be216eefe2eb4c3a51c69"`), []byte(`"checksum_sha256":"`+strings.Repeat("g", 64)+`"`), 1),
	}
	for name, input := range variants {
		t.Run(name, func(t *testing.T) {
			_, err := decodeLocalSourceOwnerRecord(input)
			want := ErrLocalSourceOwnerMalformed
			if name == "checksum" {
				want = ErrLocalSourceOwnerChecksum
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

func TestLocalSourceOwnerRecordVersionAndIdentity(t *testing.T) {
	record := localOwnerFixture()
	for name, change := range map[string]func(*localSourceOwnerRecord){
		"zero-inode":    func(r *localSourceOwnerRecord) { r.Git.Inode = 0 },
		"zero-device":   func(r *localSourceOwnerRecord) { r.Artifact.Device = 0 },
		"bad-digest":    func(r *localSourceOwnerRecord) { r.SourcePathDigest = strings.Repeat("0", 64) },
		"bad-adapter":   func(r *localSourceOwnerRecord) { r.AdapterIdentity = "not-a-digest" },
		"control-ID":    func(r *localSourceOwnerRecord) { r.TenantID = "abc\n" },
		"relative-path": func(r *localSourceOwnerRecord) { r.StatePath = "relative" },
		"nul-path": func(r *localSourceOwnerRecord) {
			r.GitObjectsPath = "/srv/git/ob\x00jects"
		},
		"artifact-path": func(r *localSourceOwnerRecord) { r.ArtifactPath = "/other" },
		"profile":       func(r *localSourceOwnerRecord) { r.Profile = "loose-and-pack-index-v1" },
	} {
		t.Run(name, func(t *testing.T) {
			current := record
			change(&current)
			if _, err := encodeLocalSourceOwnerRecord(current); !errors.Is(err, ErrLocalSourceOwnerMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}
	encoded, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	future := bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":2`), 1)
	future = bytes.Replace(future, []byte(`8278a719ea1b78b1a65ed86912ec60232ee1a2b3da2be216eefe2eb4c3a51c69`), []byte(`8c4103d61e3f1b443ef01b2dcc8665bbb2518fa3a35afe61af03e52d26009c78`), 1)
	if _, err := decodeLocalSourceOwnerRecord(future); !errors.Is(err, ErrLocalSourceOwnerVersion) {
		t.Fatalf("future version: %v", err)
	}
}

func TestLocalSourceOwnerRecordMissingAndMismatch(t *testing.T) {
	if _, err := decodeLocalSourceOwnerRecord(nil); !errors.Is(err, ErrLocalSourceOwnerMissing) {
		t.Fatalf("missing: %v", err)
	}
	record := localOwnerFixture()
	if err := matchLocalSourceOwnerRecord(record, record); err != nil {
		t.Fatalf("matching owner: %v", err)
	}
	changed := record
	changed.Git.Inode++
	if err := matchLocalSourceOwnerRecord(record, changed); !errors.Is(err, ErrLocalSourceOwnerMismatch) {
		t.Fatalf("mismatched owner: %v", err)
	}
}

// These inputs are canonical and have valid checksums except the specified
// structural violation; the decoder cannot rely on JSON syntax errors to refuse.
func TestLocalSourceOwnerRecordStructuralPriority(t *testing.T) {
	record := localOwnerFixture()
	payload := localSourceOwnerPayload{Contract: localSourceOwnerRecordContract, Version: 2, localSourceOwnerRecord: record}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	future, err := json.Marshal(localSourceOwnerEnvelope{localSourceOwnerPayload: payload, ChecksumSHA256: localSourceOwnerChecksum(payloadBytes)})
	if err != nil {
		t.Fatal(err)
	}
	future = append(future, '\n')
	if _, err := decodeLocalSourceOwnerRecord(future); !errors.Is(err, ErrLocalSourceOwnerVersion) {
		t.Fatalf("canonical future: %v", err)
	}

	valid, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate-version":       bytes.Replace(valid, []byte(`"version":1,`), []byte(`"version":1,"version":2,`), 1),
		"case-variant-version":    bytes.Replace(valid, []byte(`"version":1,`), []byte(`"version":1,"VERSION":2,`), 1),
		"missing-contract-future": []byte(`{"version":2}` + "\n"),
		"wrong-contract-future":   bytes.Replace(future, []byte(localSourceOwnerRecordContract), []byte("wrong-contract"), 1),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeLocalSourceOwnerRecord(encoded); !errors.Is(err, ErrLocalSourceOwnerMalformed) {
				t.Fatalf("malformed future-looking input: %v", err)
			}
		})
	}
}

func TestLocalSourceOwnerRecordNonopenableAndOversizedCanonicalBytes(t *testing.T) {
	base := localOwnerFixture()
	base.GitObjectsPath = "/srv/git/ob\x00jects"
	large := localOwnerFixture()
	large.StatePath = "/srv/" + strings.Repeat("a", 4000)
	large.ArtifactPath = large.StatePath + "/artifacts"
	large.GitObjectsPath = "/git/" + strings.Repeat("b", 4000)
	large.TenantID = strings.Repeat("c", 4000)
	large.RepositoryID = strings.Repeat("d", 4000)
	for name, record := range map[string]localSourceOwnerRecord{"nul-path": base, "oversized": large} {
		t.Run(name, func(t *testing.T) {
			payload := localSourceOwnerPayload{Contract: localSourceOwnerRecordContract, Version: 1, localSourceOwnerRecord: record}
			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(localSourceOwnerEnvelope{localSourceOwnerPayload: payload, ChecksumSHA256: localSourceOwnerChecksum(payloadBytes)})
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			if name == "oversized" {
				if err := record.validate(); err != nil || len(encoded) <= maxLocalSourceOwnerRecordBytes {
					t.Fatalf("not an otherwise valid oversized record: %v %d", err, len(encoded))
				}
			}
			if _, err := encodeLocalSourceOwnerRecord(record); !errors.Is(err, ErrLocalSourceOwnerMalformed) {
				t.Fatalf("encoder accepted %s: %v", name, err)
			}
			if _, err := decodeLocalSourceOwnerRecord(encoded); !errors.Is(err, ErrLocalSourceOwnerMalformed) {
				t.Fatalf("decoder accepted %s: %v", name, err)
			}
		})
	}
}
