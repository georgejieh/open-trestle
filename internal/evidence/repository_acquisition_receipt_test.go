package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNewRepositoryAcquisitionReceiptRecordsAcquiredManifest(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifest)
	manifest := mustReceiptManifest(t, receiptFileSpec{path: "main.go", content: []byte("main")})
	withNil, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, nil)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt(nil) error = %v", err)
	}
	withEmpty, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, map[string][]byte{})
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt(empty) error = %v", err)
	}
	if withNil != withEmpty || len(withNil.Identity()) != 64 || withNil.RequestIdentity() != request.Identity() || withNil.RepositoryIdentity() != request.RepositoryIdentity() || withNil.RevisionIdentity() != request.RevisionIdentity() || withNil.SourceAdapterIdentity() != request.SourceAdapterIdentity() {
		t.Fatalf("receipts = (%#v, %#v)", withNil, withEmpty)
	}
	if withNil.Artifact() != AcquisitionArtifactManifest || withNil.Effect() != AcquisitionEffectReadOnly || withNil.Outcome() != AcquisitionOutcomeAcquired || withNil.Reason() != AcquisitionReasonNone || !withNil.WasAttempted() || !withNil.HasManifest() || withNil.ManifestIdentity() != manifest.Identity() || withNil.ContentCoverage() != ContentCoverageNotRequested {
		t.Fatalf("receipt state = %#v", withNil)
	}
}

func TestNewRepositoryAcquisitionReceiptVerifiesCompleteContent(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	specs := []receiptFileSpec{
		{path: "binary.bin", content: []byte{'a', 0, 'b'}},
		{path: "empty", content: nil},
		{path: "invalid.txt", content: []byte{0xff, 0xfe}},
		{path: "main.go", content: []byte("package main\n")},
	}
	manifest := mustReceiptManifest(t, specs...)
	contents := make(map[string][]byte, len(specs))
	for _, spec := range specs {
		contents[spec.path] = append([]byte(nil), spec.content...)
	}
	receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, contents)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
	}
	if receipt.ContentCoverage() != ContentCoverageComplete || !receipt.HasManifest() || !receipt.WasAttempted() || receipt.ManifestIdentity() != manifest.Identity() {
		t.Fatalf("receipt = %#v", receipt)
	}
	identity := receipt.Identity()
	contents["main.go"][0] = 'P'
	contents["extra"] = []byte("extra")
	if receipt.Identity() != identity || receipt.ContentCoverage() != ContentCoverageComplete {
		t.Fatal("content mutation changed RepositoryAcquisitionReceipt")
	}
}

func TestNewRepositoryAcquisitionReceiptRecordsBlockedReasons(t *testing.T) {
	reasons := []RepositoryAcquisitionReason{
		AcquisitionReasonCapabilityUnavailable,
		AcquisitionReasonAuthorizationRequired,
		AcquisitionReasonPolicyBlocked,
		AcquisitionReasonAdapterUnavailable,
	}
	for _, artifact := range []RepositoryAcquisitionArtifact{AcquisitionArtifactManifest, AcquisitionArtifactManifestAndContent} {
		request := mustReceiptRequest(t, artifact)
		wantCoverage := ContentCoverageNotRequested
		if artifact == AcquisitionArtifactManifestAndContent {
			wantCoverage = ContentCoverageUnavailable
		}
		for _, reason := range reasons {
			t.Run(string(artifact)+"/"+string(reason), func(t *testing.T) {
				receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeBlocked, reason, RepositoryManifest{}, nil)
				if err != nil {
					t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
				}
				if receipt.WasAttempted() || receipt.HasManifest() || receipt.ManifestIdentity() != "" || receipt.ContentCoverage() != wantCoverage || receipt.Outcome() != AcquisitionOutcomeBlocked || receipt.Reason() != reason {
					t.Fatalf("receipt = %#v", receipt)
				}
			})
		}
	}
}

func TestNewRepositoryAcquisitionReceiptRecordsFailedReasons(t *testing.T) {
	reasons := []RepositoryAcquisitionReason{
		AcquisitionReasonAdapterFailure,
		AcquisitionReasonArtifactIncomplete,
		AcquisitionReasonResourceLimit,
	}
	for _, artifact := range []RepositoryAcquisitionArtifact{AcquisitionArtifactManifest, AcquisitionArtifactManifestAndContent} {
		request := mustReceiptRequest(t, artifact)
		wantCoverage := ContentCoverageNotRequested
		if artifact == AcquisitionArtifactManifestAndContent {
			wantCoverage = ContentCoverageUnavailable
		}
		for _, reason := range reasons {
			t.Run(string(artifact)+"/"+string(reason), func(t *testing.T) {
				receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeFailed, reason, RepositoryManifest{}, map[string][]byte{})
				if err != nil {
					t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
				}
				if !receipt.WasAttempted() || receipt.HasManifest() || receipt.ContentCoverage() != wantCoverage || receipt.Outcome() != AcquisitionOutcomeFailed || receipt.Reason() != reason {
					t.Fatalf("receipt = %#v", receipt)
				}
			})
		}
	}
}

func TestRepositoryAcquisitionReceiptCanonicalizesAbsentContent(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	testCases := []struct {
		outcome RepositoryAcquisitionOutcome
		reason  RepositoryAcquisitionReason
	}{
		{outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonPolicyBlocked},
		{outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonAdapterFailure},
	}
	for _, testCase := range testCases {
		withNil, err := NewRepositoryAcquisitionReceipt(request, testCase.outcome, testCase.reason, RepositoryManifest{}, nil)
		if err != nil {
			t.Fatalf("NewRepositoryAcquisitionReceipt(nil) error = %v", err)
		}
		withEmpty, err := NewRepositoryAcquisitionReceipt(request, testCase.outcome, testCase.reason, RepositoryManifest{}, map[string][]byte{})
		if err != nil || withEmpty != withNil {
			t.Fatalf("receipts = (%#v, %#v, %v)", withNil, withEmpty, err)
		}
	}
}

func TestNewRepositoryAcquisitionReceiptRejectsInvalidOutcomeReasonMatrix(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifest)
	manifest := mustReceiptManifest(t)
	testCases := []struct {
		name     string
		outcome  RepositoryAcquisitionOutcome
		reason   RepositoryAcquisitionReason
		manifest RepositoryManifest
	}{
		{name: "zero outcome"},
		{name: "unknown outcome", outcome: RepositoryAcquisitionOutcome("complete")},
		{name: "acquired missing reason", outcome: AcquisitionOutcomeAcquired, manifest: manifest},
		{name: "acquired blocked reason", outcome: AcquisitionOutcomeAcquired, reason: AcquisitionReasonPolicyBlocked, manifest: manifest},
		{name: "blocked none", outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonNone},
		{name: "blocked failed reason", outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonAdapterFailure},
		{name: "failed none", outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonNone},
		{name: "failed blocked reason", outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonAuthorizationRequired},
		{name: "unknown reason", outcome: AcquisitionOutcomeFailed, reason: RepositoryAcquisitionReason("network_error")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := NewRepositoryAcquisitionReceipt(request, testCase.outcome, testCase.reason, testCase.manifest, nil)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("NewRepositoryAcquisitionReceipt() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
}

func TestNewRepositoryAcquisitionReceiptRejectsInvalidArtifactShape(t *testing.T) {
	manifestRequest := mustReceiptRequest(t, AcquisitionArtifactManifest)
	contentRequest := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	manifest := mustReceiptManifest(t, receiptFileSpec{path: "main.go", content: []byte("main")})
	testCases := []struct {
		name     string
		request  RepositoryAcquisitionRequest
		outcome  RepositoryAcquisitionOutcome
		reason   RepositoryAcquisitionReason
		manifest RepositoryManifest
		contents map[string][]byte
	}{
		{name: "acquired zero manifest", request: manifestRequest, outcome: AcquisitionOutcomeAcquired, reason: AcquisitionReasonNone},
		{name: "manifest with content", request: manifestRequest, outcome: AcquisitionOutcomeAcquired, reason: AcquisitionReasonNone, manifest: manifest, contents: map[string][]byte{"main.go": []byte("main")}},
		{name: "content missing map", request: contentRequest, outcome: AcquisitionOutcomeAcquired, reason: AcquisitionReasonNone, manifest: manifest},
		{name: "blocked manifest", request: manifestRequest, outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonPolicyBlocked, manifest: manifest},
		{name: "blocked content", request: contentRequest, outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonPolicyBlocked, contents: map[string][]byte{"main.go": []byte("main")}},
		{name: "failed manifest", request: manifestRequest, outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonAdapterFailure, manifest: manifest},
		{name: "failed content", request: contentRequest, outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonAdapterFailure, contents: map[string][]byte{"main.go": []byte("main")}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := NewRepositoryAcquisitionReceipt(testCase.request, testCase.outcome, testCase.reason, testCase.manifest, testCase.contents)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("NewRepositoryAcquisitionReceipt() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
}

func TestNewRepositoryAcquisitionReceiptRejectsInexactContent(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	manifest := mustReceiptManifest(t,
		receiptFileSpec{path: "a", content: []byte("a")},
		receiptFileSpec{path: "b", content: []byte("b")},
		receiptFileSpec{path: "c", content: []byte("c")},
	)
	valid := map[string][]byte{"a": []byte("a"), "b": []byte("b"), "c": []byte("c")}
	testCases := map[string]map[string][]byte{
		"missing first":  {"b": []byte("b"), "c": []byte("c")},
		"missing middle": {"a": []byte("a"), "c": []byte("c")},
		"missing last":   {"a": []byte("a"), "b": []byte("b")},
		"extra":          {"a": []byte("a"), "b": []byte("b"), "c": []byte("c"), "d": []byte("d")},
		"missing extra":  {"a": []byte("a"), "b": []byte("b"), "./c": []byte("c")},
		"wrong bytes":    {"a": []byte("A"), "b": []byte("b"), "c": []byte("c")},
		"extra bytes":    {"a": []byte("a\n"), "b": []byte("b"), "c": []byte("c")},
		"missing bytes":  {"a": []byte{}, "b": []byte("b"), "c": []byte("c")},
	}
	for name, contents := range testCases {
		t.Run(name, func(t *testing.T) {
			receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, contents)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("NewRepositoryAcquisitionReceipt() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
	if receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, valid); err != nil || receipt.Identity() == "" {
		t.Fatalf("valid receipt = (%#v, %v)", receipt, err)
	}
}

func TestNewRepositoryAcquisitionReceiptHandlesEmptyContent(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	emptyManifest := mustReceiptManifest(t)
	withNil, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, emptyManifest, nil)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt(empty nil) error = %v", err)
	}
	withMap, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, emptyManifest, map[string][]byte{})
	if err != nil || withMap != withNil || withNil.ContentCoverage() != ContentCoverageComplete {
		t.Fatalf("empty receipts = (%#v, %#v, %v)", withNil, withMap, err)
	}
	fileManifest := mustReceiptManifest(t, receiptFileSpec{path: "empty", content: nil})
	withNilValue, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, fileManifest, map[string][]byte{"empty": nil})
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt(nil value) error = %v", err)
	}
	withEmptyValue, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, fileManifest, map[string][]byte{"empty": []byte{}})
	if err != nil || withEmptyValue != withNilValue {
		t.Fatalf("empty-file receipts = (%#v, %#v, %v)", withNilValue, withEmptyValue, err)
	}
	if receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, fileManifest, map[string][]byte{}); err == nil || receipt.Identity() != "" {
		t.Fatalf("absent empty file = (%#v, %v), want zero error result", receipt, err)
	}
}

func TestRepositoryAcquisitionReceiptUsesCanonicalPreimage(t *testing.T) {
	manifest := mustReceiptManifest(t, receiptFileSpec{path: "main.go", content: []byte("main")})
	testCases := []struct {
		name       string
		request    RepositoryAcquisitionRequest
		outcome    RepositoryAcquisitionOutcome
		reason     RepositoryAcquisitionReason
		manifest   RepositoryManifest
		contents   map[string][]byte
		manifestID string
		coverage   RepositoryContentCoverage
	}{
		{name: "acquired", request: mustReceiptRequest(t, AcquisitionArtifactManifestAndContent), outcome: AcquisitionOutcomeAcquired, reason: AcquisitionReasonNone, manifest: manifest, contents: map[string][]byte{"main.go": []byte("main")}, manifestID: manifest.Identity(), coverage: ContentCoverageComplete},
		{name: "blocked", request: mustReceiptRequest(t, AcquisitionArtifactManifestAndContent), outcome: AcquisitionOutcomeBlocked, reason: AcquisitionReasonAuthorizationRequired, coverage: ContentCoverageUnavailable},
		{name: "failed", request: mustReceiptRequest(t, AcquisitionArtifactManifest), outcome: AcquisitionOutcomeFailed, reason: AcquisitionReasonAdapterFailure, coverage: ContentCoverageNotRequested},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := NewRepositoryAcquisitionReceipt(testCase.request, testCase.outcome, testCase.reason, testCase.manifest, testCase.contents)
			if err != nil {
				t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
			}
			preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-acquisition-receipt","schema_version":1,"request_identity":"%s","repository_identity":"%s","revision_identity":"%s","source_adapter_identity":"%s","artifact":"%s","effect":"read_only","outcome":"%s","reason":"%s","manifest_identity":"%s","content_coverage":"%s"}`, testCase.request.Identity(), testCase.request.RepositoryIdentity(), testCase.request.RevisionIdentity(), testCase.request.SourceAdapterIdentity(), testCase.request.Artifact(), testCase.outcome, testCase.reason, testCase.manifestID, testCase.coverage)
			digest := sha256.Sum256([]byte(preimage))
			if want := hex.EncodeToString(digest[:]); receipt.Identity() != want {
				t.Fatalf("Identity() = %q, want SHA-256 of %s", receipt.Identity(), preimage)
			}
		})
	}
}

func TestCanonicalRepositoryAcquisitionRequestPreservesPublicContract(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	canonical, err := canonicalRepositoryAcquisitionRequest(request)
	if err != nil {
		t.Fatalf("canonicalRepositoryAcquisitionRequest() error = %v", err)
	}
	if !repositoryAcquisitionRequestsEqual(canonical, request) || canonical.Identity() != request.Identity() || !reflect.DeepEqual(canonical.RequiredCapabilities(), request.RequiredCapabilities()) {
		t.Fatalf("canonical request = %#v, want %#v", canonical, request)
	}
}

func TestCanonicalRepositoryAcquisitionRequestRejectsForgedRetainedChildren(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	forgeries := []RepositoryAcquisitionRequest{}
	forged := request
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = request
	forged.repository = RepositoryIdentity{}
	forgeries = append(forgeries, forged)
	forged = request
	forged.repository.name = "other"
	forgeries = append(forgeries, forged)
	forged = request
	forged.revision = RevisionIdentity{}
	forgeries = append(forgeries, forged)
	forged = request
	forged.revision.digest = "1123456789abcdef0123456789abcdef01234567"
	forgeries = append(forgeries, forged)
	changedRevision, err := NewRevisionIdentity(RevisionKindGitCommit, RevisionAlgorithmSHA1, "1123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	forged = request
	forged.revision = changedRevision
	forgeries = append(forgeries, forged)
	forged = request
	forged.adapter = SourceAdapterIdentity{}
	forgeries = append(forgeries, forged)
	forged = request
	forged.adapter.capabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	forgeries = append(forgeries, forged)
	forged = request
	forged.requiredCapabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	forgeries = append(forgeries, forged)
	for _, forgedRequest := range forgeries {
		if canonical, err := canonicalRepositoryAcquisitionRequest(forgedRequest); err == nil || canonical.Identity() != "" {
			t.Fatalf("canonicalRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", canonical, err)
		}
		if receipt, err := NewRepositoryAcquisitionReceipt(forgedRequest, AcquisitionOutcomeBlocked, AcquisitionReasonPolicyBlocked, RepositoryManifest{}, nil); err == nil || receipt.Identity() != "" {
			t.Fatalf("NewRepositoryAcquisitionReceipt() = (%#v, %v), want zero error result", receipt, err)
		}
	}
}

func TestRepositoryAcquisitionRequestRetainsDefensiveChildren(t *testing.T) {
	repository := mustAcquisitionRepository(t)
	revision := mustAcquisitionRevision(t, RevisionAlgorithmSHA1)
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	request := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent)
	identity := request.Identity()
	repository.namespace[0] = "changed"
	adapter.capabilities[0] = SourceCapabilityReadDiff
	if request.Identity() != identity {
		t.Fatal("child mutation changed RepositoryAcquisitionRequest")
	}
	if _, err := canonicalRepositoryAcquisitionRequest(request); err != nil {
		t.Fatalf("canonicalRepositoryAcquisitionRequest() error = %v", err)
	}
}

func TestNewRepositoryAcquisitionReceiptRejectsForgedManifest(t *testing.T) {
	request := mustReceiptRequest(t, AcquisitionArtifactManifest)
	manifest := mustReceiptManifest(t,
		receiptFileSpec{path: "a", content: []byte("a")},
		receiptFileSpec{path: "b", content: []byte("b")},
	)
	forgeries := []RepositoryManifest{}
	forged := manifest
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = manifest
	forged.files = append([]RepositoryFile{}, manifest.files...)
	forged.files[0], forged.files[1] = forged.files[1], forged.files[0]
	forgeries = append(forgeries, forged)
	forged = manifest
	forged.totalSizeBytes++
	forgeries = append(forgeries, forged)
	for _, forgedManifest := range forgeries {
		receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, forgedManifest, nil)
		if err == nil || receipt.Identity() != "" {
			t.Fatalf("NewRepositoryAcquisitionReceipt() = (%#v, %v), want zero error result", receipt, err)
		}
	}
}

func TestRepositoryAcquisitionReceiptAtManifestLimit(t *testing.T) {
	const fileLimit = 65_536
	files := make([]RepositoryFile, fileLimit)
	contents := make(map[string][]byte, fileLimit)
	for i := range files {
		path := fmt.Sprintf("files/%05d", i)
		file, err := NewRepositoryFile(path, nil)
		if err != nil {
			t.Fatalf("NewRepositoryFile(%d) error = %v", i, err)
		}
		files[i] = file
		contents[path] = nil
	}
	manifest, err := NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	request := mustReceiptRequest(t, AcquisitionArtifactManifestAndContent)
	receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, contents)
	if err != nil || receipt.ContentCoverage() != ContentCoverageComplete || receipt.ManifestIdentity() != manifest.Identity() {
		t.Fatalf("boundary receipt = (%#v, %v)", receipt, err)
	}
}

func TestRepositoryAcquisitionReceiptZeroValueIsEmpty(t *testing.T) {
	var receipt RepositoryAcquisitionReceipt
	if receipt.Identity() != "" || receipt.RequestIdentity() != "" || receipt.RepositoryIdentity() != "" || receipt.RevisionIdentity() != "" || receipt.SourceAdapterIdentity() != "" || receipt.Artifact() != "" || receipt.Effect() != "" || receipt.Outcome() != "" || receipt.Reason() != "" || receipt.WasAttempted() || receipt.HasManifest() || receipt.ManifestIdentity() != "" || receipt.ContentCoverage() != "" {
		t.Fatalf("zero RepositoryAcquisitionReceipt = %#v", receipt)
	}
}

type receiptFileSpec struct {
	path    string
	content []byte
}

func mustReceiptManifest(t *testing.T, specs ...receiptFileSpec) RepositoryManifest {
	t.Helper()
	files := make([]RepositoryFile, len(specs))
	for i, spec := range specs {
		file, err := NewRepositoryFile(spec.path, spec.content)
		if err != nil {
			t.Fatalf("NewRepositoryFile() error = %v", err)
		}
		files[i] = file
	}
	manifest, err := NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	return manifest
}

func mustReceiptRequest(t *testing.T, artifact RepositoryAcquisitionArtifact) RepositoryAcquisitionRequest {
	t.Helper()
	capabilities := []SourceAdapterCapability{SourceCapabilityReadManifest}
	if artifact == AcquisitionArtifactManifestAndContent {
		capabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	}
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, capabilities)
	return mustAcquisitionRequest(t, repository, revision, adapter, artifact)
}
