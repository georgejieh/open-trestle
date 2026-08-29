package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestBindRepositoryAcquisitionEvidence(t *testing.T) {
	for _, algorithm := range []RevisionAlgorithm{RevisionAlgorithmSHA1, RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			fixture := mustAcquisitionEvidenceFixture(t, algorithm, acquisitionEvidenceFile{path: "run.sh", mode: GitTreeModeExecutable, content: []byte("#!/bin/sh\n")}, acquisitionEvidenceFile{path: "source.go", mode: GitTreeModeRegular, content: []byte("package source\n")})
			binding, err := fixture.bind()
			if err != nil {
				t.Fatalf("BindRepositoryAcquisitionEvidence() error = %v", err)
			}
			if binding.BindingStatus() != RepositoryAcquisitionEvidenceStatusSupplied || binding.RequestIdentity() != fixture.request.Identity() || binding.ReceiptIdentity() != fixture.receipt.Identity() || binding.RepositoryIdentity() != fixture.request.RepositoryIdentity() || binding.RevisionIdentity() != fixture.graphFixture.revision.Identity() || binding.SourceAdapterIdentity() != fixture.request.SourceAdapterIdentity() || binding.ManifestIdentity() != fixture.manifest.Identity() || binding.GitCommitIdentity() != fixture.graphFixture.commit.Identity() || binding.GitTreeGraphIdentity() != fixture.graph.Identity() || binding.CorrespondenceIdentity() != fixture.correspondence.Identity() {
				t.Fatalf("binding = %#v", binding)
			}
		})
	}
}

func TestBindRepositoryAcquisitionEvidenceAcceptsEmptyRepository(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1)
	binding, err := fixture.bind()
	if err != nil || binding.ManifestIdentity() != fixture.manifest.Identity() {
		t.Fatalf("empty binding = (%#v, %v)", binding, err)
	}
}

func TestBindRepositoryAcquisitionEvidenceAcceptsIndependentBuffersAndMapOrder(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "a", mode: GitTreeModeRegular, content: []byte("first")}, acquisitionEvidenceFile{path: "b", mode: GitTreeModeRegular, content: []byte("second")})
	contents := map[string][]byte{"b": append([]byte{}, fixture.receiptContents["b"]...), "a": append([]byte{}, fixture.receiptContents["a"]...)}
	blobs := make(map[string][]byte, len(fixture.graphFixture.blobs))
	for digest, content := range fixture.graphFixture.blobs {
		blobs[digest] = append([]byte{}, content...)
	}
	fixture.receiptContents = contents
	fixture.graphFixture.blobs = blobs
	binding, err := fixture.bind()
	if err != nil || binding.Identity() == "" {
		t.Fatalf("independent buffers = (%#v, %v)", binding, err)
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsOtherReceiptStates(t *testing.T) {
	base := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	manifestRequest, err := NewRepositoryAcquisitionRequest(base.request.repository, base.request.revision, base.request.adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	manifestReceipt, err := NewRepositoryAcquisitionReceipt(manifestRequest, AcquisitionOutcomeAcquired, AcquisitionReasonNone, base.manifest, nil)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
	}
	blockedReceipt, err := NewRepositoryAcquisitionReceipt(base.request, AcquisitionOutcomeBlocked, AcquisitionReasonPolicyBlocked, RepositoryManifest{}, nil)
	if err != nil {
		t.Fatalf("blocked receipt error = %v", err)
	}
	failedReceipt, err := NewRepositoryAcquisitionReceipt(base.request, AcquisitionOutcomeFailed, AcquisitionReasonAdapterFailure, RepositoryManifest{}, nil)
	if err != nil {
		t.Fatalf("failed receipt error = %v", err)
	}
	testCases := []struct {
		name    string
		request RepositoryAcquisitionRequest
		receipt RepositoryAcquisitionReceipt
	}{
		{name: "manifest only", request: manifestRequest, receipt: manifestReceipt},
		{name: "blocked", request: base.request, receipt: blockedReceipt},
		{name: "failed", request: base.request, receipt: failedReceipt},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base
			fixture.request = testCase.request
			fixture.receipt = testCase.receipt
			if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
				t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
			}
		})
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsForgedRequestAndReceipt(t *testing.T) {
	base := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	testCases := []struct {
		name   string
		mutate func(*acquisitionEvidenceFixture)
	}{
		{name: "request identity", mutate: func(f *acquisitionEvidenceFixture) { f.request.identity = strings.Repeat("0", 64) }},
		{name: "request repository child", mutate: func(f *acquisitionEvidenceFixture) { f.request.repository.name = "other" }},
		{name: "request revision child", mutate: func(f *acquisitionEvidenceFixture) {
			f.request.revision.digest = "1123456789abcdef0123456789abcdef01234567"
		}},
		{name: "request adapter child", mutate: func(f *acquisitionEvidenceFixture) { f.request.adapter.version = "1.2.4" }},
		{name: "request capabilities", mutate: func(f *acquisitionEvidenceFixture) {
			f.request.requiredCapabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
		}},
		{name: "receipt identity", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.identity = strings.Repeat("0", 64) }},
		{name: "receipt request", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.requestIdentity = strings.Repeat("0", 64) }},
		{name: "receipt repository", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.repositoryIdentity = strings.Repeat("0", 64) }},
		{name: "receipt revision", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.revisionIdentity = strings.Repeat("0", 64) }},
		{name: "receipt adapter", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.sourceAdapterIdentity = strings.Repeat("0", 64) }},
		{name: "receipt artifact", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.artifact = AcquisitionArtifactManifest }},
		{name: "receipt effect", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.effect = RepositoryAcquisitionEffect("write") }},
		{name: "receipt outcome", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.outcome = AcquisitionOutcomeFailed }},
		{name: "receipt reason", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.reason = AcquisitionReasonAdapterFailure }},
		{name: "receipt manifest", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.manifestIdentity = strings.Repeat("0", 64) }},
		{name: "receipt coverage", mutate: func(f *acquisitionEvidenceFixture) { f.receipt.contentCoverage = ContentCoverageUnavailable }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base.clone()
			testCase.mutate(&fixture)
			if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
				t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
			}
		})
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsReceiptContentMismatch(t *testing.T) {
	base := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	testCases := []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{name: "missing", mutate: func(contents map[string][]byte) { delete(contents, "file") }},
		{name: "extra", mutate: func(contents map[string][]byte) { contents["extra"] = nil }},
		{name: "changed", mutate: func(contents map[string][]byte) { contents["file"][0] ^= 1 }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base.clone()
			testCase.mutate(fixture.receiptContents)
			if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
				t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
			}
		})
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsReceiptAndGitManifestMismatch(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	changedContent := []byte("changed")
	fixture.manifest = mustRepositoryManifestForTest(t, manifestFileSpec{path: "file", content: changedContent})
	fixture.receiptContents = map[string][]byte{"file": changedContent}
	var err error
	fixture.receipt, err = NewRepositoryAcquisitionReceipt(fixture.request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, fixture.manifest, fixture.receiptContents)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
	}
	if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
		t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsRevisionAndGitChainMismatch(t *testing.T) {
	base := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	testCases := []struct {
		name   string
		mutate func(*acquisitionEvidenceFixture)
	}{
		{name: "supplied revision", mutate: func(f *acquisitionEvidenceFixture) {
			f.graphFixture.revision.digest = "1123456789abcdef0123456789abcdef01234567"
		}},
		{name: "commit bytes", mutate: func(f *acquisitionEvidenceFixture) {
			f.graphFixture.commitContent[len(f.graphFixture.commitContent)-2] ^= 1
		}},
		{name: "root bytes", mutate: func(f *acquisitionEvidenceFixture) {
			f.graphFixture.rootContent[len(f.graphFixture.rootContent)-1] ^= 1
		}},
		{name: "blob bytes", mutate: func(f *acquisitionEvidenceFixture) {
			for digest := range f.graphFixture.blobs {
				f.graphFixture.blobs[digest][0] ^= 1
				break
			}
		}},
		{name: "graph", mutate: func(f *acquisitionEvidenceFixture) { f.graph.identity = strings.Repeat("0", 64) }},
		{name: "correspondence", mutate: func(f *acquisitionEvidenceFixture) { f.correspondence.identity = strings.Repeat("0", 64) }},
		{name: "manifest", mutate: func(f *acquisitionEvidenceFixture) { f.manifest.identity = strings.Repeat("0", 64) }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base.clone()
			testCase.mutate(&fixture)
			if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
				t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
			}
		})
	}
}

func TestBindRepositoryAcquisitionEvidenceAcceptsInheritedBoundaries(t *testing.T) {
	files := make([]acquisitionEvidenceFile, maxRepositoryManifestFiles)
	for i := range files {
		files[i] = acquisitionEvidenceFile{path: fmt.Sprintf("f%05d", i), mode: GitTreeModeRegular}
	}
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, files...)
	binding, err := fixture.bind()
	if err != nil || binding.ManifestIdentity() != fixture.manifest.Identity() {
		t.Fatalf("file-count boundary = (%#v, %v)", binding, err)
	}

	maxPath := strings.Repeat("x", maxRepositoryFilePathBytes)
	fixture = mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: maxPath, mode: GitTreeModeRegular})
	binding, err = fixture.bind()
	if err != nil || binding.ManifestIdentity() != fixture.manifest.Identity() {
		t.Fatalf("path boundary = (%#v, %v)", binding, err)
	}
}

func TestBindRepositoryAcquisitionEvidenceRejectsOverBoundReceiptContentWithoutAllocation(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular})
	size := int(maxRepositoryAcquisitionEvidenceContentBytes + 1)
	digest := strings.Repeat("0", sha256HexLength)
	identity, err := repositoryFileIdentity("file", digest, size)
	if err != nil {
		t.Fatalf("repositoryFileIdentity() error = %v", err)
	}
	file := RepositoryFile{identity: identity, path: "file", digest: digest, sizeBytes: size}
	fixture.manifest, err = NewRepositoryManifest([]RepositoryFile{file})
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	fixture.receipt.manifestIdentity = fixture.manifest.Identity()
	fixture.receiptContents = map[string][]byte{"file": nil}
	if binding, err := fixture.bind(); err == nil || binding.Identity() != "" {
		t.Fatalf("BindRepositoryAcquisitionEvidence() = (%#v, %v)", binding, err)
	}
}

func TestCheckedRepositoryAcquisitionEvidenceContentAdd(t *testing.T) {
	limit := int(maxRepositoryAcquisitionEvidenceContentBytes)
	if got, err := checkedRepositoryAcquisitionEvidenceContentAdd(0, limit); err != nil || got != maxRepositoryAcquisitionEvidenceContentBytes {
		t.Fatalf("checkedRepositoryAcquisitionEvidenceContentAdd() = (%d, %v)", got, err)
	}
	if got, err := checkedRepositoryAcquisitionEvidenceContentAdd(maxRepositoryAcquisitionEvidenceContentBytes, 0); err != nil || got != maxRepositoryAcquisitionEvidenceContentBytes {
		t.Fatalf("limit plus zero = (%d, %v)", got, err)
	}
	for _, values := range []struct {
		total int64
		size  int
	}{{total: maxRepositoryAcquisitionEvidenceContentBytes, size: 1}, {total: -1, size: 0}, {total: 0, size: -1}} {
		if _, err := checkedRepositoryAcquisitionEvidenceContentAdd(values.total, values.size); err == nil {
			t.Fatalf("checkedRepositoryAcquisitionEvidenceContentAdd(%d, %d) succeeded", values.total, values.size)
		}
	}
}

func TestRepositoryAcquisitionEvidenceBindingIdentityPreimage(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	binding, err := fixture.bind()
	if err != nil {
		t.Fatalf("BindRepositoryAcquisitionEvidence() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-acquisition-evidence-binding","schema_version":1,"binding_status":"supplied_evidence_bound","request_identity":"%s","receipt_identity":"%s","repository_identity":"%s","revision_identity":"%s","source_adapter_identity":"%s","manifest_identity":"%s","git_commit_identity":"%s","git_tree_graph_identity":"%s","correspondence_identity":"%s"}`, fixture.request.Identity(), fixture.receipt.Identity(), fixture.request.RepositoryIdentity(), fixture.request.RevisionIdentity(), fixture.request.SourceAdapterIdentity(), fixture.manifest.Identity(), fixture.graphFixture.commit.Identity(), fixture.graph.Identity(), fixture.correspondence.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if binding.Identity() != hex.EncodeToString(digest[:]) {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", binding.Identity(), preimage)
	}
}

func TestRepositoryAcquisitionEvidenceBindingDoesNotRetainInputs(t *testing.T) {
	fixture := mustAcquisitionEvidenceFixture(t, RevisionAlgorithmSHA1, acquisitionEvidenceFile{path: "file", mode: GitTreeModeRegular, content: []byte("content")})
	binding, err := fixture.bind()
	if err != nil {
		t.Fatalf("BindRepositoryAcquisitionEvidence() error = %v", err)
	}
	identity := binding.Identity()
	fixture.receiptContents["file"][0] = 'X'
	for digest := range fixture.graphFixture.blobs {
		fixture.graphFixture.blobs[digest][0] = 'Y'
	}
	fixture.graph.entries[0].path[0] = 'Z'
	fixture.manifest.files[0].path = "changed"
	if binding.Identity() != identity || binding.BindingStatus() != RepositoryAcquisitionEvidenceStatusSupplied {
		t.Fatal("input mutation changed RepositoryAcquisitionEvidenceBinding")
	}
}

func TestRepositoryAcquisitionEvidenceBindingZeroValueIsEmpty(t *testing.T) {
	var binding RepositoryAcquisitionEvidenceBinding
	if binding.Identity() != "" || binding.RequestIdentity() != "" || binding.ReceiptIdentity() != "" || binding.RepositoryIdentity() != "" || binding.RevisionIdentity() != "" || binding.SourceAdapterIdentity() != "" || binding.ManifestIdentity() != "" || binding.GitCommitIdentity() != "" || binding.GitTreeGraphIdentity() != "" || binding.CorrespondenceIdentity() != "" || binding.BindingStatus() != "" {
		t.Fatalf("zero RepositoryAcquisitionEvidenceBinding = %#v", binding)
	}
}

type acquisitionEvidenceFile struct {
	path    string
	mode    GitTreeMode
	content []byte
}

type acquisitionEvidenceFixture struct {
	graphFixture    graphFixture
	graph           GitTreeGraph
	manifest        RepositoryManifest
	correspondence  GitManifestCorrespondence
	request         RepositoryAcquisitionRequest
	receipt         RepositoryAcquisitionReceipt
	receiptContents map[string][]byte
}

func mustAcquisitionEvidenceFixture(t *testing.T, algorithm RevisionAlgorithm, specs ...acquisitionEvidenceFile) acquisitionEvidenceFixture {
	t.Helper()
	entries := make([]graphTestEntry, len(specs))
	blobs := make(map[string][]byte, len(specs))
	manifestSpecs := make([]manifestFileSpec, len(specs))
	contents := make(map[string][]byte, len(specs))
	for i, spec := range specs {
		digest := gitObjectDigestForTest("blob", spec.content, algorithm)
		entries[i] = graphTestEntry{mode: spec.mode, name: []byte(spec.path), digest: digest}
		blobs[digest] = append([]byte{}, spec.content...)
		manifestSpecs[i] = manifestFileSpec{path: spec.path, content: spec.content}
		contents[spec.path] = append([]byte{}, spec.content...)
	}
	rootContent := graphTreeContentForTest(t, algorithm, entries...)
	graphFixture := mustGraphFixture(t, algorithm, rootContent, nil, blobs)
	graph := mustVerifyGraphFixture(t, graphFixture)
	manifest := mustRepositoryManifestForTest(t, manifestSpecs...)
	correspondence, err := verifyManifestCorrespondence(graphFixture, graph, manifest)
	if err != nil {
		t.Fatalf("VerifyGitManifestCorrespondence() error = %v", err)
	}
	repository := mustAcquisitionRepository(t)
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	request, err := NewRepositoryAcquisitionRequest(repository, graphFixture.revision, adapter, AcquisitionArtifactManifestAndContent, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	receipt, err := NewRepositoryAcquisitionReceipt(request, AcquisitionOutcomeAcquired, AcquisitionReasonNone, manifest, contents)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
	}
	return acquisitionEvidenceFixture{graphFixture: graphFixture, graph: graph, manifest: manifest, correspondence: correspondence, request: request, receipt: receipt, receiptContents: contents}
}

func (f acquisitionEvidenceFixture) clone() acquisitionEvidenceFixture {
	cloned := f
	cloned.graphFixture = f.graphFixture.clone()
	cloned.graph.entries = cloneGitTreeGraphEntries(f.graph.entries)
	cloned.manifest.files = append([]RepositoryFile{}, f.manifest.files...)
	cloned.receiptContents = make(map[string][]byte, len(f.receiptContents))
	for path, content := range f.receiptContents {
		cloned.receiptContents[path] = append([]byte{}, content...)
	}
	return cloned
}

func (f acquisitionEvidenceFixture) bind() (RepositoryAcquisitionEvidenceBinding, error) {
	return BindRepositoryAcquisitionEvidence(f.request, f.receipt, f.receiptContents, f.graphFixture.revision, f.graphFixture.commitVerification, f.graphFixture.commitContent, f.graphFixture.commit, f.graphFixture.rootVerification, f.graphFixture.rootContent, f.graphFixture.rootTree, f.graphFixture.childTrees, f.graphFixture.blobs, f.graph, f.manifest, f.correspondence)
}
