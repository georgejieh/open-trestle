package source

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

// These constants were captured from the source package before codec extraction.
func TestSourceInputOldCodeGoldens(t *testing.T) {
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	v1, err := NewInput(repository, revision, adapter)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := NewBoundInput(repository, revision, adapter, strings.Repeat("0123456789abcdef", 4))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name             string
		input            Input
		wire             string
		identity         string
		artifactIdentity string
		payloadDigest    string
		envelopeSize     int
		envelopeSHA256   string
		envelopePrefix   string
	}{
		{
			name: "v1", input: v1,
			wire:             `{"contract":"open-trestle/source-acquisition-input","schema_version":1,"identity":"de04a723f82431c4efa2e6d918b16db63c05fec0c18e6f98f35df97a09646b58","repository_authority":"github.com","repository_namespace":["owner"],"repository_name":"repo","revision_kind":"git_commit","revision_algorithm":"sha1","revision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","source_adapter_kind":"git","source_adapter_name":"test-source","source_adapter_version":"1.0.0","source_capabilities":["read_content","read_manifest"],"artifact":"manifest_and_content","effect":"read_only"}`,
			identity:         "de04a723f82431c4efa2e6d918b16db63c05fec0c18e6f98f35df97a09646b58",
			artifactIdentity: "cacaa777fa641697095c72ab3a0bc64ef70c7f13a0999927ad54a3c184cadedb",
			payloadDigest:    "f65be5295e2382ddc9301fd317d142ab07199b950a31749b6dbf500073b4fa02",
			envelopeSize:     1487,
			envelopeSHA256:   "e463ce76346a1d3d8c67e014aacb0897653dcc8866c12f9f2fb5fb67a53f9fba",
			envelopePrefix:   "{\"contract\":\"open-trestle/runtime-artifact\",\"schema_version\":1,\"identity\":\"cacaa777fa641697095c72ab3a0bc64ef70c7f13a0999927ad54a3c184cadedb\",\"tenant_id\":\"tenant",
		},
		{
			name: "v2", input: v2,
			wire:             `{"contract":"open-trestle/source-acquisition-input","schema_version":2,"source_root_identity":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","identity":"852a597ca8015a72eaff6efb95b606cb2bff754b13764bfa6dab0340e95b869b","repository_authority":"github.com","repository_namespace":["owner"],"repository_name":"repo","revision_kind":"git_commit","revision_algorithm":"sha1","revision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","source_adapter_kind":"git","source_adapter_name":"test-source","source_adapter_version":"1.0.0","source_capabilities":["read_content","read_manifest"],"artifact":"manifest_and_content","effect":"read_only"}`,
			identity:         "852a597ca8015a72eaff6efb95b606cb2bff754b13764bfa6dab0340e95b869b",
			artifactIdentity: "d5eef83c7ad546c5ffce30eec0be9fc744e9058cbe5623899c3d877c25bede18",
			payloadDigest:    "a199cdb9bfea19e9fcd132ea240bbb717804c7f74095b52197dbfdbff905a160",
			envelopeSize:     1607,
			envelopeSHA256:   "cca2f5e623a3aafb2382208c26d7cbd6bd8d7c4193b58f194e38e07e3e63fef6",
			envelopePrefix:   "{\"contract\":\"open-trestle/runtime-artifact\",\"schema_version\":1,\"identity\":\"d5eef83c7ad546c5ffce30eec0be9fc744e9058cbe5623899c3d877c25bede18\",\"tenant_id\":\"tenant",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			encoded, err := EncodeInput(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != fixture.wire {
				t.Fatalf("EncodeInput = %s, want %s", encoded, fixture.wire)
			}
			if fixture.input.Identity() != fixture.identity {
				t.Fatalf("Input.Identity = %s, want %s", fixture.input.Identity(), fixture.identity)
			}
			parsed, err := ParseInput([]byte(fixture.wire))
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Identity() != fixture.identity || parsed.SchemaVersion() != fixture.input.SchemaVersion() || parsed.SourceRootIdentity() != fixture.input.SourceRootIdentity() {
				t.Fatalf("parsed input identity/version/root = %s/%d/%s", parsed.Identity(), parsed.SchemaVersion(), parsed.SourceRootIdentity())
			}
			reparsedBytes, err := EncodeInput(parsed)
			if err != nil || !bytes.Equal(reparsedBytes, encoded) {
				t.Fatalf("parsed input re-encoding = %s, %v", reparsedBytes, err)
			}
			if fixture.input.String() != "source acquisition input" || fixture.input.GoString() != "source.Input{<redacted>}" ||
				fmt.Sprint(fixture.input) != "source acquisition input" || fmt.Sprintf("%s", fixture.input) != "source acquisition input" ||
				fmt.Sprintf("%q", fixture.input) != `"source acquisition input"` || fmt.Sprintf("%#v", fixture.input) != "source.Input{<redacted>}" {
				t.Fatalf("redacted formatting differs: String=%q GoString=%q v=%q s=%q q=%q sharp=%q", fixture.input.String(), fixture.input.GoString(), fmt.Sprint(fixture.input), fmt.Sprintf("%s", fixture.input), fmt.Sprintf("%q", fixture.input), fmt.Sprintf("%#v", fixture.input))
			}
			value, err := NewInputArtifact(scope, fixture.input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate,
				[]string{strings.Repeat("c", 64)}, time.UnixMilli(1700000000000), time.UnixMilli(1700086400000))
			if err != nil {
				t.Fatal(err)
			}
			if value.Identity() != fixture.artifactIdentity || value.PayloadDigest() != fixture.payloadDigest || !bytes.Equal(value.Payload(), encoded) {
				t.Fatalf("artifact identity/payload digest/payload = %s/%s/%s", value.Identity(), value.PayloadDigest(), value.Payload())
			}
			if value.Scope().Identity() != scope.Identity() || value.Kind() != artifact.KindTaskInput || value.Classification() != artifact.ClassificationConfidential ||
				value.Origin() != artifact.OriginHost || value.Protection() != artifact.ProtectionProcessPrivate || value.MediaType() != "application/json" ||
				len(value.Provenance()) != 1 || value.Provenance()[0] != strings.Repeat("c", 64) ||
				!value.CreatedAt().Equal(time.UnixMilli(1700000000000)) || !value.ExpiresAt().Equal(time.UnixMilli(1700086400000)) {
				t.Fatal("artifact fixed metadata differs")
			}
			envelope, err := artifact.Encode(value)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(envelope)
			if len(envelope) != fixture.envelopeSize || fmt.Sprintf("%x", digest) != fixture.envelopeSHA256 || !bytes.HasPrefix(envelope, []byte(fixture.envelopePrefix)) {
				t.Fatalf("artifact.Encode size/hash/prefix = %d/%x/%q", len(envelope), digest, envelope[:min(160, len(envelope))])
			}
			decoded, err := artifact.Parse(envelope)
			if err != nil {
				t.Fatal(err)
			}
			decodedBytes, err := artifact.Encode(decoded)
			if err != nil || !bytes.Equal(decodedBytes, envelope) || decoded.Identity() != fixture.artifactIdentity ||
				decoded.PayloadDigest() != fixture.payloadDigest || !bytes.Equal(decoded.Payload(), encoded) {
				t.Fatalf("artifact roundtrip = identity %s, digest %s, payload %s, encode error %v", decoded.Identity(), decoded.PayloadDigest(), decoded.Payload(), err)
			}
		})
	}
}

func TestSourceInputOldCodeRejectsMalformedWire(t *testing.T) {
	const v1 = `{"contract":"open-trestle/source-acquisition-input","schema_version":1,"identity":"de04a723f82431c4efa2e6d918b16db63c05fec0c18e6f98f35df97a09646b58","repository_authority":"github.com","repository_namespace":["owner"],"repository_name":"repo","revision_kind":"git_commit","revision_algorithm":"sha1","revision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","source_adapter_kind":"git","source_adapter_name":"test-source","source_adapter_version":"1.0.0","source_capabilities":["read_content","read_manifest"],"artifact":"manifest_and_content","effect":"read_only"}`
	const v2 = `{"contract":"open-trestle/source-acquisition-input","schema_version":2,"source_root_identity":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","identity":"852a597ca8015a72eaff6efb95b606cb2bff754b13764bfa6dab0340e95b869b","repository_authority":"github.com","repository_namespace":["owner"],"repository_name":"repo","revision_kind":"git_commit","revision_algorithm":"sha1","revision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","source_adapter_kind":"git","source_adapter_name":"test-source","source_adapter_version":"1.0.0","source_capabilities":["read_content","read_manifest"],"artifact":"manifest_and_content","effect":"read_only"}`
	root := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name string
		wire []byte
	}{
		{"unknown key", []byte(strings.Replace(v1, `"effect":`, `"unexpected":true,"effect":`, 1))},
		{"trailing newline", []byte(v1 + "\n")},
		{"trailing value", []byte(v1 + `{}`)},
		{"over 16 KiB", append([]byte(v1), bytes.Repeat([]byte(" "), (16<<10)+1)...)},
		{"wrong v2 source root", []byte(strings.Replace(v2, root, "f"+root[1:], 1))},
		{"wrong v2 identity", []byte(strings.Replace(v2, "852a597ca8015a72eaff6efb95b606cb2bff754b13764bfa6dab0340e95b869b", "f52a597ca8015a72eaff6efb95b606cb2bff754b13764bfa6dab0340e95b869b", 1))},
		{"zero v2 source root", []byte(strings.Replace(v2, root, strings.Repeat("0", 64), 1))},
		{"v1 with source root", []byte(strings.Replace(v1, `"schema_version":1,`, `"schema_version":1,"source_root_identity":"`+root+`",`, 1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseInput(tc.wire); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ParseInput error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
