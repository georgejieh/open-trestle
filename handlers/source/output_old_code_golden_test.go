package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/artifactvalidation"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// These full payloads and hashes were captured by the old handler probe at HEAD 425edbc.
const (
	oldSnapshotPayload                  = `{"contract":"open-trestle/source-snapshot","schema_version":1,"identity":"f50d4c8b27d72f755168b2e01b2e37dd90b00f275be45fc6223782c33157a226","acquisition_request_identity":"3b4fb65236f3cb0f2e5ebed3d6eb962c8df51522556e2147f465e537e91be891","acquisition_receipt_identity":"6c8680ef2147de64b87ed222f933aaf17b19bd6d8a9fc9c0be6fdc099988b76a","acquisition_execution_identity":"e552b581ba8929c4e85edd958a790381cc7e3491776c443a65fa9621093402bb","repository_identity":"cd867fa3f5f79345873f8b6dca79ee854722ad13ca567ae191755208f9095435","revision_identity":"48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","manifest_identity":"f45e813330e30bdc83738a0f42731193203d028ad569177f5f21045279dfc0d3","files":[{"path":"empty.txt","digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0,"artifact_identity":"77b01ab57b9e2633827850a14feb8a81156772722674aba055a2433768aecf59"},{"path":"src/main.go","digest":"df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47","size_bytes":13,"artifact_identity":"54c65b26fc0fc35778804372a87211266a10b72e17f5a28a983efeb177f0a63d"}]}`
	oldSnapshotPayloadSHA256            = "8ae8e9c3c8f4b0843bedc35ccebbc8edf1a7f38e9c54c9da755a101dc7396784"
	oldSnapshotPayloadArtifactIdentity  = "72b4405d23e5cf155589ee701b76ac8efdccedf9db4244bf787854696cff052e"
	oldEmptyFilePayload                 = `{"contract":"open-trestle/source-file","schema_version":1,"acquisition_execution_identity":"e552b581ba8929c4e85edd958a790381cc7e3491776c443a65fa9621093402bb","path":"empty.txt","digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0,"content":null}`
	oldEmptyFilePayloadSHA256           = "25be788f9c1ce31a1c135d804aa31f705b61d757be5aaae6892f06016d54c313"
	oldEmptyFilePayloadArtifactIdentity = "77b01ab57b9e2633827850a14feb8a81156772722674aba055a2433768aecf59"
	oldMainFilePayload                  = `{"contract":"open-trestle/source-file","schema_version":1,"acquisition_execution_identity":"e552b581ba8929c4e85edd958a790381cc7e3491776c443a65fa9621093402bb","path":"src/main.go","digest":"df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47","size_bytes":13,"content":"cGFja2FnZSBtYWluCg=="}`
	oldMainFilePayloadSHA256            = "2f7d2b3c0a4f1da288f8e2efd5ef8e5b024efc9fad24742046a122ff26986639"
	oldMainFilePayloadArtifactIdentity  = "54c65b26fc0fc35778804372a87211266a10b72e17f5a28a983efeb177f0a63d"
)

func oldGoldenArtifact(t *testing.T, scope audit.ReviewScope, kind artifact.Kind, provenance []string, payload []byte) artifact.Artifact {
	t.Helper()
	value, err := artifact.New(scope, kind, "application/json", artifact.ClassificationConfidential,
		artifact.OriginRepository, artifact.ProtectionProcessPrivate, provenance, payload,
		time.UnixMilli(200), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertOldGoldenEnvelope(t *testing.T, value artifact.Artifact, scope audit.ReviewScope, kind artifact.Kind, provenance []string, payload, digest, identity string) {
	t.Helper()
	hash := sha256.Sum256([]byte(payload))
	if !bytes.Equal(value.Payload(), []byte(payload)) || hex.EncodeToString(hash[:]) != digest || value.PayloadDigest() != digest || value.Identity() != identity {
		t.Fatalf("%s old-code payload, SHA-256 or artifact identity changed", kind)
	}
	if value.Validate() != nil || value.Scope().Identity() != scope.Identity() || value.Scope().Identity() != "7af12a50a9bbf8a474716edd4f56d36e1cd86789aa0eda88b6b902864625d273" ||
		value.Kind() != kind || value.MediaType() != "application/json" || value.Classification() != artifact.ClassificationConfidential ||
		value.Protection() != artifact.ProtectionProcessPrivate || value.Origin() != artifact.OriginRepository ||
		!reflect.DeepEqual(value.Provenance(), provenance) || !value.CreatedAt().Equal(time.UnixMilli(200)) || !value.ExpiresAt().Equal(time.UnixMilli(10000)) {
		t.Fatalf("%s old-code artifact envelope changed", kind)
	}
	encoded, err := artifact.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := artifact.Parse(encoded)
	if err != nil || roundTrip.Identity() != identity || !bytes.Equal(roundTrip.Payload(), []byte(payload)) ||
		roundTrip.PayloadDigest() != digest || !reflect.DeepEqual(roundTrip.Provenance(), provenance) ||
		roundTrip.Scope().Identity() != scope.Identity() || roundTrip.Kind() != kind ||
		roundTrip.MediaType() != value.MediaType() || roundTrip.Classification() != value.Classification() ||
		roundTrip.Origin() != value.Origin() || roundTrip.Protection() != value.Protection() ||
		!roundTrip.CreatedAt().Equal(value.CreatedAt()) || !roundTrip.ExpiresAt().Equal(value.ExpiresAt()) {
		t.Fatalf("%s envelope roundtrip changed: %v", kind, err)
	}
}

func TestOldCodeSourceOutputGolden(t *testing.T) {
	repository, revision, adapterIdentity, result := sourceFixture(t)
	inner := &sourceAdapter{identity: adapterIdentity, result: result}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewInput(repository, revision, adapterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate,
		[]string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	if inputArtifact.Identity() != "3950b50961a448bdb87f235ef23c79295d514581d0157ff89334ba1a007d09b9" {
		t.Fatal("fixture input identity changed")
	}
	if created, err := store.Put(context.Background(), inputArtifact, time.UnixMilli(100)); err != nil || !created {
		t.Fatalf("input Put: %v %v", created, err)
	}
	request := taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity())
	validated, err := artifactvalidation.NewValidatedTaskHandler(handler, store, fixedClock{at: time.UnixMilli(201)},
		[]artifact.Kind{artifact.KindTaskInput}, []artifact.Kind{artifact.KindSourceSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || completion.Validate() != nil || inner.calls != 1 || completion.OutputIdentity() != oldSnapshotPayloadArtifactIdentity {
		t.Fatalf("handler completion=%#v calls=%d", completion, inner.calls)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	provenance := []string{inputArtifact.Identity(), "e552b581ba8929c4e85edd958a790381cc7e3491776c443a65fa9621093402bb"}
	assertOldGoldenEnvelope(t, output, scope, artifact.KindSourceSnapshot, provenance, oldSnapshotPayload, oldSnapshotPayloadSHA256, oldSnapshotPayloadArtifactIdentity)
	snapshot, err := ParseSnapshotArtifact(output)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Identity() != "f50d4c8b27d72f755168b2e01b2e37dd90b00f275be45fc6223782c33157a226" ||
		snapshot.ArtifactIdentity() != output.Identity() || snapshot.ScopeIdentity() != scope.Identity() ||
		snapshot.Classification() != artifact.ClassificationConfidential || snapshot.Protection() != artifact.ProtectionProcessPrivate ||
		snapshot.AcquisitionRequestIdentity() != "3b4fb65236f3cb0f2e5ebed3d6eb962c8df51522556e2147f465e537e91be891" ||
		snapshot.AcquisitionReceiptIdentity() != "6c8680ef2147de64b87ed222f933aaf17b19bd6d8a9fc9c0be6fdc099988b76a" ||
		snapshot.AcquisitionExecutionIdentity() != provenance[1] ||
		snapshot.RepositoryIdentity() != "cd867fa3f5f79345873f8b6dca79ee854722ad13ca567ae191755208f9095435" ||
		snapshot.RevisionIdentity() != "48a8e29ccc988d91ac800034e3e172d79d0442e3921dae16cf57599baffe0075" ||
		snapshot.SourceAdapterIdentity() != "c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe" ||
		snapshot.ManifestIdentity() != "f45e813330e30bdc83738a0f42731193203d028ad569177f5f21045279dfc0d3" || snapshot.FileCount() != 2 {
		t.Fatal("parsed snapshot getters changed")
	}
	if fmt.Sprint(snapshot) != "source snapshot" || fmt.Sprintf("%#v", snapshot) != "source.Snapshot{<redacted>}" || fmt.Sprintf("%+v", snapshot) != "source snapshot" {
		t.Fatal("snapshot formatting disclosed fields")
	}
	cases := []struct {
		path, payload, sha, identity, digest string
		size                                 int
		content                              []byte
	}{
		{"empty.txt", oldEmptyFilePayload, oldEmptyFilePayloadSHA256, oldEmptyFilePayloadArtifactIdentity, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0, nil},
		{"src/main.go", oldMainFilePayload, oldMainFilePayloadSHA256, oldMainFilePayloadArtifactIdentity, "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47", 13, []byte("package main\n")},
	}
	for i, expected := range cases {
		ref := snapshot.Files()[i]
		if ref.Path() != expected.path || ref.Digest() != expected.digest || ref.SizeBytes() != expected.size || ref.ArtifactIdentity() != expected.identity ||
			fmt.Sprint(ref) != "source file reference" || fmt.Sprintf("%#v", ref) != "source.FileReference{<redacted>}" || fmt.Sprintf("%+v", ref) != "source file reference" {
			t.Fatalf("reference %d changed", i)
		}
		value, err := store.Get(context.Background(), scope, ref.ArtifactIdentity(), time.UnixMilli(201))
		if err != nil {
			t.Fatal(err)
		}
		assertOldGoldenEnvelope(t, value, scope, artifact.KindSourceFile, provenance, expected.payload, expected.sha, expected.identity)
		file, err := ParseFileArtifact(value, snapshot, ref)
		if err != nil || file.ArtifactIdentity() != expected.identity || file.AcquisitionExecutionIdentity() != provenance[1] ||
			file.Path() != expected.path || file.Digest() != expected.digest || file.SizeBytes() != expected.size || !bytes.Equal(file.Content(), expected.content) ||
			fmt.Sprint(file) != "source file" || fmt.Sprintf("%#v", file) != "source.File{<redacted>}" || fmt.Sprintf("%+v", file) != "source file" {
			t.Fatalf("parsed file %s changed: %v", expected.path, err)
		}
	}
	if !strings.HasSuffix(oldEmptyFilePayload, `"content":null}`) {
		t.Fatal("handler empty content no longer null")
	}
	var emptyFile = result.Manifest.Files()[0]
	for _, file := range result.Manifest.Files() {
		if file.Path() == "empty.txt" {
			emptyFile = file
		}
	}
	direct, err := encodeFile(provenance[1], emptyFile, []byte{})
	if err != nil || !bytes.Equal(direct, []byte(strings.Replace(oldEmptyFilePayload, `"content":null}`, `"content":""}`, 1))) {
		t.Fatalf("direct nonnil empty content changed: %v", err)
	}
	testOldSnapshotParserBoundaries(t, scope, provenance, snapshot, output)
}

func testOldSnapshotParserBoundaries(t *testing.T, scope audit.ReviewScope, provenance []string, snapshot Snapshot, output artifact.Artifact) {
	t.Helper()
	empty, err := newSnapshot("", snapshot.AcquisitionRequestIdentity(), snapshot.AcquisitionReceiptIdentity(),
		snapshot.AcquisitionExecutionIdentity(), snapshot.RepositoryIdentity(), snapshot.RevisionIdentity(),
		snapshot.SourceAdapterIdentity(), snapshot.ManifestIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeSnapshot(empty)
	if err != nil || !bytes.HasSuffix(payload, []byte(`"files":[]}`)) {
		t.Fatalf("empty producer files are not []: %v", err)
	}
	emptyArtifact := oldGoldenArtifact(t, scope, artifact.KindSourceSnapshot, provenance, payload)
	parsed, err := ParseSnapshotArtifact(emptyArtifact)
	if err != nil || parsed.FileCount() != 0 || parsed.Identity() != empty.Identity() || parsed.ArtifactIdentity() != emptyArtifact.Identity() || parsed.ScopeIdentity() != scope.Identity() {
		t.Fatalf("valid empty snapshot rejected: %v", err)
	}
	reject := func(name string, payload []byte, provenance []string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			value := oldGoldenArtifact(t, scope, artifact.KindSourceSnapshot, provenance, payload)
			if value.Validate() != nil {
				t.Fatal("invalid test artifact")
			}
			if _, err := ParseSnapshotArtifact(value); !errors.Is(err, ErrInvalidOutput) {
				t.Fatalf("ParseSnapshotArtifact error=%v", err)
			}
		})
	}
	reject("files-null", bytes.Replace(payload, []byte(`"files":[]`), []byte(`"files":null`), 1), provenance)
	reject("unknown-field", bytes.Replace(output.Payload(), []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1), provenance)
	reject("trailing-newline", append(output.Payload(), '\n'), provenance)
	var wire snapshotWire
	if err := json.Unmarshal(output.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	wrong := wire
	wrong.Identity = strings.Repeat("f", 64)
	wrongPayload, err := json.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	reject("wrong-snapshot-identity", wrongPayload, provenance)
	// Set each mutated identity to its canonical wire preimage digest so that
	// these cases exercise file ordering/uniqueness rather than identity mismatch.
	encodeWithOwnIdentity := func(value snapshotWire) []byte {
		t.Helper()
		value.Identity = ""
		preimage, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(preimage)
		value.Identity = hex.EncodeToString(digest[:])
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	duplicate := wire
	duplicate.Files = []fileReferenceWire{wire.Files[0], wire.Files[0]}
	reject("duplicate-files", encodeWithOwnIdentity(duplicate), provenance)
	reversed := wire
	reversed.Files = []fileReferenceWire{wire.Files[1], wire.Files[0]}
	reject("out-of-order-files", encodeWithOwnIdentity(reversed), provenance)
	reject("missing-execution-provenance", output.Payload(), provenance[:1])
}
