package change

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/artifactvalidation"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func realChangeFixture(t *testing.T) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &pairSourceAdapter{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{baseRevision.Identity(): sourceResult(t, map[string][]byte{"a.txt": []byte("old\n"), "removed.txt": []byte("gone\n")}), headRevision.Identity(): sourceResult(t, map[string][]byte{"a.txt": []byte("new\n"), "added.txt": []byte("hello\n")})}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceHandler, _ := sourcehandler.NewHandler(store, adapter, fixedClock{time.UnixMilli(200)})
	changeHandler, _ := NewHandler(store, fixedClock{time.UnixMilli(210)})
	if changeHandler.HandlerIdentity() != "af559535868494caf3a8e78d0df23ebda6f7c186caa06c57b3a9dac7ee78b276" {
		t.Fatalf("handler identity=%s", changeHandler.HandlerIdentity())
	}
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("d", 64), strings.Repeat("e", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	executeSource := func(task controlplane.TaskDefinition, at time.Time) {
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
		if err != nil {
			t.Fatal(err)
		}
		completion := sourceHandler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("source %s=%#v", task.Key(), completion)
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	executeSource(baseTask, time.UnixMilli(101))
	executeSource(headTask, time.UnixMilli(103))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(105))
	if err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "change", changeHandler.HandlerIdentity(), "worker", time.UnixMilli(106))
	if err != nil || !acquired {
		t.Fatalf("change claim=(%v,%v)", acquired, err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, changeTask)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, changeTask, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := artifactvalidation.NewValidatedTaskHandler(changeHandler, store, fixedClock{time.UnixMilli(211)}, []artifact.Kind{artifact.KindSourceSnapshot}, []artifact.Kind{artifact.KindChangeModel})
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("completion=%#v", completion)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(212))
	if err != nil {
		t.Fatal(err)
	}
	baseOutput, _ := store.Get(context.Background(), scope, dependencies[0].OutputIdentity(), time.UnixMilli(212))
	headOutput, _ := store.Get(context.Background(), scope, dependencies[1].OutputIdentity(), time.UnixMilli(212))
	if dependencies[0].TaskKey() == "source-head" {
		baseOutput, headOutput = headOutput, baseOutput
	}
	return output, baseOutput, headOutput, baseArtifact, headArtifact
}

const oldCodeChangePayload = `{"contract":"open-trestle/change-model-result","schema_version":1,"identity":"4c765836bb0d985a6a99596a3e8b3ef37083fe88cf1458f54717b34c3d471884","base_snapshot_artifact":"e325ea3d85bbaf4ce80d30e9f5d2fc77b66a84a76a20785d09784ec778e44a1b","head_snapshot_artifact":"70782fe02b0214e58539c15cef36dc440651ea4745f991e14a3b191d32802654","base_snapshot_identity":"1970b1991ccb11566735ea3597ca364cd9ceeb3c6b63865a8ac49e07abfaed13","head_snapshot_identity":"2428cc0af3b9b96b230f3335712b4fa5894cda2eccbb56e89fe4af279bc95cec","repository_authority":"github.com","repository_namespace":["owner"],"repository_name":"repo","repository_identity":"cd867fa3f5f79345873f8b6dca79ee854722ad13ca567ae191755208f9095435","base_revision_kind":"git_commit","base_revision_algorithm":"sha1","base_revision_digest":"1111111111111111111111111111111111111111","base_revision_identity":"78305386088f6b2d363e47244f09cfadd0509eadceafe8ec62d02162e740fb16","head_revision_kind":"git_commit","head_revision_algorithm":"sha1","head_revision_digest":"2222222222222222222222222222222222222222","head_revision_identity":"c0ab18e878feaccb55fcc2d47631ade6882f31081fa9fba96c4ce62b1298ec95","source_adapter_identity":"c70fe7801224f5d9b67e403caff995c3d6cd8746993d81c3fea3f679f4ec0dbe","base_manifest_identity":"f9171ba26f771d92f4db33e5c6368f9b920a27cace634d9383e10e48ca6ebab8","head_manifest_identity":"263a7b6eddcb0ee09f73b0859dd2c2e870b42e9bfdc916aeb120983ab2cc68b7","delta_identity":"6a63daf653e27f63c8b916e558f34bc6d75d58a75f1d901b4695a5ce82997eb6","entries":[{"path":"a.txt","kind":"modified","delta_identity":"3b22af3e16ed3a828e900eb1a7aa1288d1fa05fefd35783ad2ef06ec940656e5","base_identity":"eb634d820d7efc6c3558072deaad1b4d579b72c0809a2ef9aded9a926c474386","base_digest":"01d09d19c2139a46aebfb577780d123d7396e97201bc7ead210a2ebff8239dee","base_size":4,"head_identity":"5b1b9ea4c2f480ff77ffaeb576926030e168dc103abf64b9fdcf333cd5d2b7b0","head_digest":"7aa7a5359173d05b63cfd682e3c38487f3cb4f7f1d60659fe59fab1505977d4c","head_size":4,"status":"supported","reason":"none","execution_identity":"a9e03c7a9a6a4b02febb1dc450d082eef00f22dccd11d99a6fd8548c695243c0","file_change_identity":"2fc06e2a6774df799a003e61aee24d1e14b855edcdcceb2ce52dd88eb9fa6b8f","line_map_identity":"f67a8e89a93bb3982a9f4fefff3ee5c2504cf9a6596105832554ecd3c1a618f6","ranges":[{"start_line":1,"end_line":1}]},{"path":"added.txt","kind":"added","delta_identity":"6d018693a20997a8e9c49522dc848ed9cd5595574693c65f3de7e04378fe5c5d","base_identity":"","base_digest":"","base_size":0,"head_identity":"486094ed68485198761ef31a77146254728167b1ad72750b40d71cf5a9a96030","head_digest":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","head_size":6,"status":"supported","reason":"none","execution_identity":"ae32ac95a66cde98eccb556d8c3c51beace3015165e5c03291d0acb3f50e00f4","file_change_identity":"111f590a1897a6d115f67e7378ca6de35d5dca51498fbd4430db86b4d85a649b","line_map_identity":"8727f86511b33d2f7f42621bf03b86bdab288356a2d1e8c1420a9b439bb726d2","ranges":[{"start_line":1,"end_line":1}]},{"path":"removed.txt","kind":"removed","delta_identity":"9bc6d75c6c49cd6271bd4c2e009010b8598f3c8243fa8724094017c6e25a6e78","base_identity":"27f25f48dc3c3d624fb0c6127c1b67e3da8c243fa84266f4f3f31a732c200785","base_digest":"4b9f2c32577beb1ebc8ab2a1e226faaa9176a81cd4eedbaa22f8a0db919972b5","base_size":5,"head_identity":"","head_digest":"","head_size":0,"status":"unsupported","reason":"removed_file","execution_identity":"550e891bb9b91b6e4f20b9f2be01f4b1d6b784feda616d681e2501e293ef1f46","file_change_identity":"","line_map_identity":"","ranges":[]}]}`

func TestOldCodeChangeResultGolden(t *testing.T) {
	output, base, head, baseInput, headInput := realChangeFixture(t)
	result, err := ParseResultArtifact(output, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if string(output.Payload()) != oldCodeChangePayload {
		t.Fatalf("payload changed: %s", output.Payload())
	}
	payloadSum := sha256.Sum256(output.Payload())
	if hex.EncodeToString(payloadSum[:]) != "10e4c3356a3a0a25397fc21eb5839b830d5245937b0e29baf6a573ac07cce9d8" || output.PayloadDigest() != "10e4c3356a3a0a25397fc21eb5839b830d5245937b0e29baf6a573ac07cce9d8" {
		t.Fatal("payload digest changed")
	}
	if result.Identity() != "4c765836bb0d985a6a99596a3e8b3ef37083fe88cf1458f54717b34c3d471884" || result.ArtifactIdentity() != "453826f4a59925d7f5e88f2f190c671f7d52c34f1ca5444cad84d34c99d366d6" || output.Identity() != result.ArtifactIdentity() {
		t.Fatal("result/output identity changed")
	}
	encoded, err := artifact.Encode(output)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if len(encoded) != 5637 || hex.EncodeToString(sum[:]) != "0f153968426bd6553fd3bf79e7b771cd91cec5bcba47bfd365728cea507385f7" {
		t.Fatalf("envelope len=%d SHA=%x", len(encoded), sum)
	}
	if output.Scope().Identity() != "f7378d8e413bc34de6d12f4fab1640417514cac205088cde327a564c8d7ecbab" || result.ScopeIdentity() != output.Scope().Identity() || output.Kind() != artifact.KindChangeModel || output.MediaType() != "application/json" || output.Classification() != artifact.ClassificationConfidential || output.Protection() != artifact.ProtectionProcessPrivate || output.Origin() != artifact.OriginDeterministicTool || output.CreatedAt().UnixMilli() != 210 || output.ExpiresAt().UnixMilli() != 10000 {
		t.Fatal("change metadata changed")
	}
	expectedProvenance := []string{"6a63daf653e27f63c8b916e558f34bc6d75d58a75f1d901b4695a5ce82997eb6", "70782fe02b0214e58539c15cef36dc440651ea4745f991e14a3b191d32802654", "c34085a960ebf73edb1fe3734607ab07f321655cec41dc8fce51fe8fea45e86a", "e277b54f3a34603c3b6db7cbbd90053e63560169d586247fd8df360d84fe08a9", "e325ea3d85bbaf4ce80d30e9f5d2fc77b66a84a76a20785d09784ec778e44a1b"}
	if !slices.Equal(output.Provenance(), expectedProvenance) {
		t.Fatalf("provenance=%v", output.Provenance())
	}
	if base.Identity() != "e325ea3d85bbaf4ce80d30e9f5d2fc77b66a84a76a20785d09784ec778e44a1b" || head.Identity() != "70782fe02b0214e58539c15cef36dc440651ea4745f991e14a3b191d32802654" || baseInput.Identity() != "c34085a960ebf73edb1fe3734607ab07f321655cec41dc8fce51fe8fea45e86a" || headInput.Identity() != "e277b54f3a34603c3b6db7cbbd90053e63560169d586247fd8df360d84fe08a9" {
		t.Fatal("source/input artifact identities changed")
	}
	baseSnapshot, err := sourcehandler.ParseSnapshotArtifact(base)
	if err != nil {
		t.Fatal(err)
	}
	headSnapshot, err := sourcehandler.ParseSnapshotArtifact(head)
	if err != nil {
		t.Fatal(err)
	}
	if baseSnapshot.Identity() != "1970b1991ccb11566735ea3597ca364cd9ceeb3c6b63865a8ac49e07abfaed13" || headSnapshot.Identity() != "2428cc0af3b9b96b230f3335712b4fa5894cda2eccbb56e89fe4af279bc95cec" || baseSnapshot.ArtifactIdentity() != base.Identity() || headSnapshot.ArtifactIdentity() != head.Identity() {
		t.Fatal("snapshot identities changed")
	}
	if baseSnapshot.RepositoryIdentity() != result.Repository().Identity() || headSnapshot.RepositoryIdentity() != result.Repository().Identity() || baseSnapshot.RevisionIdentity() != result.BaseRevision().Identity() || headSnapshot.RevisionIdentity() != result.HeadRevision().Identity() || baseSnapshot.SourceAdapterIdentity() != result.SourceAdapterIdentity() || headSnapshot.SourceAdapterIdentity() != result.SourceAdapterIdentity() || headSnapshot.ManifestIdentity() != result.HeadManifestIdentity() {
		t.Fatal("source binding changed")
	}
	if result.BaseSnapshotArtifactIdentity() != base.Identity() || result.HeadSnapshotArtifactIdentity() != head.Identity() || result.BaseSnapshotIdentity() != baseSnapshot.Identity() || result.HeadSnapshotIdentity() != headSnapshot.Identity() || result.DeltaIdentity() != expectedProvenance[0] {
		t.Fatal("result source/delta getters changed")
	}
	for _, value := range []artifact.Artifact{output, base, head, baseInput, headInput} {
		encoded, err := artifact.Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := artifact.Parse(encoded)
		if err != nil || parsed.Identity() != value.Identity() {
			t.Fatalf("artifact parse identity=%s err=%v", parsed.Identity(), err)
		}
		reencoded, err := artifact.Encode(parsed)
		if err != nil || !bytes.Equal(encoded, reencoded) {
			t.Fatalf("artifact reencode identity=%s err=%v", value.Identity(), err)
		}
	}
	first, second, err := ResultArtifactReferences(output)
	if err != nil || first != base.Identity() || second != head.Identity() {
		t.Fatalf("preliminary references=(%s,%s,%v)", first, second, err)
	}
	entries := result.Entries()
	if len(entries) != 3 || entries[0].Path() != "a.txt" || entries[0].Kind() != "modified" || entries[0].Identity() != "3b22af3e16ed3a828e900eb1a7aa1288d1fa05fefd35783ad2ef06ec940656e5" || entries[0].Status() != "supported" || entries[0].Reason() != "none" || entries[0].HeadIdentity() != "5b1b9ea4c2f480ff77ffaeb576926030e168dc103abf64b9fdcf333cd5d2b7b0" || entries[0].HeadDigest() != "7aa7a5359173d05b63cfd682e3c38487f3cb4f7f1d60659fe59fab1505977d4c" || entries[0].HeadSizeBytes() != 4 || entries[0].ExecutionIdentity() != "a9e03c7a9a6a4b02febb1dc450d082eef00f22dccd11d99a6fd8548c695243c0" || entries[1].Path() != "added.txt" || entries[1].Kind() != "added" || entries[1].Status() != "supported" || entries[1].Reason() != "none" || entries[1].HeadSizeBytes() != 6 || entries[2].Path() != "removed.txt" || entries[2].Kind() != "removed" || entries[2].Status() != "unsupported" || entries[2].Reason() != "removed_file" || entries[2].HeadIdentity() != "" || entries[2].HeadSizeBytes() != 0 {
		t.Fatalf("entry getters/order changed: %#v", entries)
	}
	for i, entry := range entries {
		ranges := entry.Ranges()
		if i < 2 && (len(ranges) != 1 || ranges[0].StartLine() != 1 || ranges[0].EndLine() != 1) || i == 2 && len(ranges) != 0 {
			t.Fatalf("entry %d ranges=%v", i, ranges)
		}
	}
	ranges := entries[0].Ranges()
	ranges[0] = Range{}
	entries[0] = Entry{}
	if result.Entries()[0].Path() != "a.txt" || result.Entries()[0].Ranges()[0].StartLine() != 1 {
		t.Fatal("mutable entry/range getter")
	}
	payloadCopy := output.Payload()
	payloadCopy[0] = 'X'
	provenanceCopy := output.Provenance()
	provenanceCopy[0] = "bad"
	if string(output.Payload()) != oldCodeChangePayload || !slices.Equal(output.Provenance(), expectedProvenance) {
		t.Fatal("mutable artifact getter")
	}
	if fmt.Sprint(result) != "change model result" || fmt.Sprintf("%+v", result) != "change model result" || fmt.Sprintf("%#v", result) != "change.Result{<redacted>}" || fmt.Sprintf("%q", result) != `"change model result"` || fmt.Sprintf("%s", result) != "change model result" {
		t.Fatalf("result redaction changed: %#v", result)
	}
}

func TestOldCodeChangeNegativeControls(t *testing.T) {
	output, base, head, _, _ := realChangeFixture(t)
	payload := output.Payload()
	wrap := func(payload []byte, provenance []string, scope audit.ReviewScope, class artifact.Classification, protection artifact.Protection, origin artifact.Origin) artifact.Artifact {
		t.Helper()
		value, err := artifact.New(scope, artifact.KindChangeModel, "application/json", class, origin, protection, provenance, payload, output.CreatedAt(), output.ExpiresAt())
		if err != nil || value.Validate() != nil {
			t.Fatalf("invalid control envelope: %v", err)
		}
		return value
	}
	rewrap := func(payload []byte, provenance []string) artifact.Artifact {
		return wrap(payload, provenance, output.Scope(), output.Classification(), output.Protection(), output.Origin())
	}
	requireRejected := func(name string, value, baseValue, headValue artifact.Artifact, referencesOK bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if err := value.Validate(); err != nil {
				t.Fatalf("control envelope invalid: %v", err)
			}
			first, second, refsErr := ResultArtifactReferences(value)
			if referencesOK {
				if refsErr != nil || first != base.Identity() || second != head.Identity() {
					t.Fatalf("preliminary references=(%s,%s,%v)", first, second, refsErr)
				}
			} else if !errors.Is(refsErr, ErrInvalidResult) {
				t.Fatalf("preliminary references error=%v", refsErr)
			}
			if _, err := ParseResultArtifact(value, baseValue, headValue); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("full parse error=%v", err)
			}
		})
	}
	requireRejected("unknown field", rewrap(replaceOnce(t, payload, []byte(`"contract":`), []byte(`"unexpected":1,"contract":`)), output.Provenance()), base, head, false)
	requireRejected("reordered keys", rewrap(replaceOnce(t, payload, []byte(`"contract":"open-trestle/change-model-result","schema_version":1`), []byte(`"schema_version":1,"contract":"open-trestle/change-model-result"`)), output.Provenance()), base, head, false)
	requireRejected("trailing whitespace", rewrap(append(append([]byte(nil), payload...), ' '), output.Provenance()), base, head, false)
	requireRejected("trailing value", rewrap(append(append([]byte(nil), payload...), []byte(`{}`)...), output.Provenance()), base, head, false)
	requireRejected("wrong contract", rewrap(replaceOnce(t, payload, []byte(`open-trestle/change-model-result`), []byte(`open-trestle/other-result`)), output.Provenance()), base, head, false)
	requireRejected("wrong schema", rewrap(replaceOnce(t, payload, []byte(`"schema_version":1`), []byte(`"schema_version":3`)), output.Provenance()), base, head, false)
	identityField := []byte(`"identity":"` + "4c765836bb0d985a6a99596a3e8b3ef37083fe88cf1458f54717b34c3d471884" + `"`)
	bogusIdentity := replaceOnce(t, payload, identityField, []byte(`"identity":"`+strings.Repeat("f", 64)+`"`))
	requireRejected("wrong result identity", rewrap(bogusIdentity, output.Provenance()), base, head, true)
	missing := output.Provenance()
	for i, identity := range missing {
		if identity == base.Identity() {
			missing = append(missing[:i:i], missing[i+1:]...)
			break
		}
	}
	requireRejected("swapped source order", output, head, base, true)
	requireRejected("missing base provenance", rewrap(payload, missing), base, head, true)
	originalSnapshot, err := sourcehandler.ParseSnapshotArtifact(base)
	if err != nil {
		t.Fatal(err)
	}
	missingExecution := base.Provenance()
	for i, identity := range missingExecution {
		if identity == originalSnapshot.AcquisitionExecutionIdentity() {
			missingExecution = append(missingExecution[:i:i], missingExecution[i+1:]...)
			break
		}
	}
	if slices.Contains(missingExecution, originalSnapshot.AcquisitionExecutionIdentity()) || len(missingExecution) == 0 {
		t.Fatal("cannot remove source execution provenance without an invalid envelope")
	}
	noExecution, err := artifact.New(base.Scope(), base.Kind(), base.MediaType(), base.Classification(), base.Origin(), base.Protection(), missingExecution, base.Payload(), base.CreatedAt(), base.ExpiresAt())
	if err != nil || noExecution.Validate() != nil {
		t.Fatalf("source control envelope: %v", err)
	}
	if _, err := sourcehandler.ParseSnapshotArtifact(noExecution); err == nil {
		t.Fatal("missing source execution provenance accepted")
	}
	missingExecutionProvenance := output.Provenance()
	for i, identity := range missingExecutionProvenance {
		if identity == base.Identity() {
			missingExecutionProvenance[i] = noExecution.Identity()
		}
	}
	requireRejected("missing source execution provenance", rewrap(payload, missingExecutionProvenance), noExecution, head, true)
	requireRejected("wrong scope", wrap(payload, output.Provenance(), mustOtherScope(t), output.Classification(), output.Protection(), output.Origin()), base, head, true)
	requireRejected("wrong classification", wrap(payload, output.Provenance(), output.Scope(), artifact.ClassificationInternal, output.Protection(), output.Origin()), base, head, true)
	requireRejected("wrong protection", wrap(payload, output.Provenance(), output.Scope(), output.Classification(), artifact.ProtectionEnvelopeEncrypted, output.Origin()), base, head, true)
	requireRejected("wrong origin", wrap(payload, output.Provenance(), output.Scope(), output.Classification(), output.Protection(), artifact.OriginHost), base, head, false)
	alternate := alternateValidSnapshot(t, base)
	alternateProvenance := output.Provenance()
	for i, identity := range alternateProvenance {
		if identity == base.Identity() {
			alternateProvenance[i] = alternate.Identity()
		}
	}
	requireRejected("alternate source with unchanged wire", rewrap(payload, alternateProvenance), alternate, head, true)
	changedSnapshot, err := sourcehandler.ParseSnapshotArtifact(alternate)
	if err != nil {
		t.Fatal(err)
	}
	changedPayload := replaceOnce(t, payload, []byte(`"base_snapshot_artifact":"`+base.Identity()+`"`), []byte(`"base_snapshot_artifact":"`+alternate.Identity()+`"`))
	changedPayload = replaceOnce(t, changedPayload, []byte(`"base_snapshot_identity":"`+originalSnapshot.Identity()+`"`), []byte(`"base_snapshot_identity":"`+changedSnapshot.Identity()+`"`))
	withoutIdentity := replaceOnce(t, changedPayload, identityField, []byte(`"identity":""`))
	identitySum := sha256.Sum256(withoutIdentity)
	selfConsistent := replaceOnce(t, changedPayload, identityField, []byte(`"identity":"`+hex.EncodeToString(identitySum[:])+`"`))
	if !json.Valid(selfConsistent) {
		t.Fatal("recomputed change payload is not JSON")
	}
	changed := rewrap(selfConsistent, alternateProvenance)
	if refsBase, refsHead, err := ResultArtifactReferences(changed); err != nil || refsBase != alternate.Identity() || refsHead != head.Identity() {
		t.Fatalf("self-consistent references=(%s,%s,%v)", refsBase, refsHead, err)
	}
	if _, err := ParseResultArtifact(changed, alternate, head); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("repository mismatch after recomputed identity: %v", err)
	}
}

func replaceOnce(t *testing.T, payload, old, replacement []byte) []byte {
	t.Helper()
	if bytes.Count(payload, old) != 1 {
		t.Fatalf("expected one %q in canonical payload", old)
	}
	return bytes.Replace(payload, old, replacement, 1)
}

func mustOtherScope(t *testing.T) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "other-run")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func alternateValidSnapshot(t *testing.T, base artifact.Artifact) artifact.Artifact {
	t.Helper()
	original, err := sourcehandler.ParseSnapshotArtifact(base)
	if err != nil {
		t.Fatal(err)
	}
	otherRepo, err := evidence.NewRepositoryIdentity("github.com", []string{"other"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := sourceoutput.NewSnapshot("", original.AcquisitionRequestIdentity(), original.AcquisitionReceiptIdentity(), original.AcquisitionExecutionIdentity(), otherRepo.Identity(), original.RevisionIdentity(), original.SourceAdapterIdentity(), original.ManifestIdentity(), original.Files())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sourceoutput.EncodeSnapshot(alternate)
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(base.Scope(), base.Kind(), base.MediaType(), base.Classification(), base.Origin(), base.Protection(), base.Provenance(), payload, base.CreatedAt(), base.ExpiresAt())
	if err != nil || value.Validate() != nil {
		t.Fatalf("alternate artifact: %v", err)
	}
	parsed, err := sourcehandler.ParseSnapshotArtifact(value)
	if err != nil || parsed.Identity() != alternate.Identity() || parsed.ArtifactIdentity() != value.Identity() || parsed.RepositoryIdentity() != otherRepo.Identity() {
		t.Fatalf("alternate snapshot=(%#v,%v)", parsed, err)
	}
	return value
}
