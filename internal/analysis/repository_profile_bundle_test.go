package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewRepositoryProfileBundleBindsAcceptedAuthorities(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t,
		classificationFileSpec{path: "main.go", content: []byte("package main\n")},
	)
	bundle, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle() error = %v", err)
	}
	if len(bundle.Identity()) != 64 || bundle.ManifestIdentity() != authorities.manifest.Identity() || bundle.RepositoryProfileIdentity() != authorities.profile.Identity() || bundle.ClassificationReceiptIdentity() != authorities.classification.Identity() || bundle.ClassificationSummaryIdentity() != authorities.summary.Identity() || bundle.ClassifierVersion() != fileClassificationVersion {
		t.Fatalf("bundle binding = (%q, %q, %q, %q, %q, %q)", bundle.Identity(), bundle.ManifestIdentity(), bundle.RepositoryProfileIdentity(), bundle.ClassificationReceiptIdentity(), bundle.ClassificationSummaryIdentity(), bundle.ClassifierVersion())
	}
	repeated, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary)
	if err != nil || repeated != bundle {
		t.Fatalf("repeated bundle = (%#v, %v), want %#v", repeated, err, bundle)
	}
}

func TestRepositoryProfileBundleIdentityUsesCanonicalPreimage(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t,
		classificationFileSpec{path: "main.go", content: []byte("package main\n")},
	)
	bundle, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-profile-bundle","schema_version":1,"manifest_identity":"%s","repository_profile_identity":"%s","classification_receipt_identity":"%s","classification_summary_identity":"%s","classifier":"exact-path-and-nul-signals","classifier_version":"1"}`, authorities.manifest.Identity(), authorities.profile.Identity(), authorities.classification.Identity(), authorities.summary.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); bundle.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", bundle.Identity(), preimage)
	}
}

func TestNewRepositoryProfileBundleAcceptsEmptyAuthorityChain(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t)
	first, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle(first) error = %v", err)
	}
	second, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle(second) error = %v", err)
	}
	if first != second || len(first.Identity()) != 64 {
		t.Fatalf("empty bundles = (%#v, %#v), want equal identities", first, second)
	}
}

func TestNewRepositoryProfileBundleRejectsNoncanonicalEmptyProfile(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t)
	forgedProfile := authorities.profile
	forgedProfile.extensionFacts = nil
	bundle, err := NewRepositoryProfileBundle(authorities.manifest, forgedProfile, authorities.classification, authorities.summary)
	if err == nil || bundle.Identity() != "" {
		t.Fatalf("NewRepositoryProfileBundle() = (%#v, %v), want zero error result", bundle, err)
	}
}

func TestNewRepositoryProfileBundleRejectsZeroAuthorities(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	testCases := []struct {
		name           string
		manifest       evidence.RepositoryManifest
		profile        RepositoryProfile
		classification RepositoryClassificationReceipt
		summary        RepositoryClassificationSummary
	}{
		{name: "zero manifest", profile: authorities.profile, classification: authorities.classification, summary: authorities.summary},
		{name: "zero profile", manifest: authorities.manifest, classification: authorities.classification, summary: authorities.summary},
		{name: "zero classification", manifest: authorities.manifest, profile: authorities.profile, summary: authorities.summary},
		{name: "zero summary", manifest: authorities.manifest, profile: authorities.profile, classification: authorities.classification},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle, err := NewRepositoryProfileBundle(testCase.manifest, testCase.profile, testCase.classification, testCase.summary)
			if err == nil || bundle.Identity() != "" {
				t.Fatalf("NewRepositoryProfileBundle() = (%#v, %v), want zero error result", bundle, err)
			}
		})
	}
}

func TestNewRepositoryProfileBundleRejectsCrossBoundAuthorities(t *testing.T) {
	first := mustRepositoryProfileBundleAuthorities(t, classificationFileSpec{path: "a.go", content: []byte("a")})
	second := mustRepositoryProfileBundleAuthorities(t, classificationFileSpec{path: "b.go", content: []byte("b")})
	testCases := []struct {
		name           string
		profile        RepositoryProfile
		classification RepositoryClassificationReceipt
		summary        RepositoryClassificationSummary
	}{
		{name: "profile", profile: second.profile, classification: first.classification, summary: first.summary},
		{name: "classification", profile: first.profile, classification: second.classification, summary: first.summary},
		{name: "summary", profile: first.profile, classification: first.classification, summary: second.summary},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle, err := NewRepositoryProfileBundle(first.manifest, testCase.profile, testCase.classification, testCase.summary)
			if err == nil || bundle.Identity() != "" {
				t.Fatalf("NewRepositoryProfileBundle() = (%#v, %v), want zero error result", bundle, err)
			}
		})
	}
}

func TestNewRepositoryProfileBundleRejectsForgedAuthorities(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	forgedProfileIdentity := authorities.profile
	forgedProfileIdentity.identity = strings.Repeat("a", 64)
	forgedProfileFacts := authorities.profile
	forgedProfileFacts.fileCount++
	forgedProfileExtension := authorities.profile
	forgedProfileExtension.extensionFacts = append([]FileExtensionFact{}, forgedProfileExtension.extensionFacts...)
	forgedProfileExtension.extensionFacts[0].fileCount++
	forgedClassification := cloneRepositoryClassificationReceipt(authorities.classification)
	forgedClassification.identity = strings.Repeat("b", 64)
	wrongClassificationVersion := cloneRepositoryClassificationReceipt(authorities.classification)
	wrongClassificationVersion.classifierVersion = "2"
	forgedSummaryIdentity := authorities.summary
	forgedSummaryIdentity.identity = strings.Repeat("c", 64)
	forgedSummaryCounts := authorities.summary
	forgedSummaryCounts.nulFreeFileCount++
	wrongSummaryVersion := authorities.summary
	wrongSummaryVersion.classifierVersion = "2"
	testCases := []struct {
		name           string
		profile        RepositoryProfile
		classification RepositoryClassificationReceipt
		summary        RepositoryClassificationSummary
	}{
		{name: "profile identity", profile: forgedProfileIdentity, classification: authorities.classification, summary: authorities.summary},
		{name: "profile facts", profile: forgedProfileFacts, classification: authorities.classification, summary: authorities.summary},
		{name: "profile extension", profile: forgedProfileExtension, classification: authorities.classification, summary: authorities.summary},
		{name: "classification identity", profile: authorities.profile, classification: forgedClassification, summary: authorities.summary},
		{name: "classification version", profile: authorities.profile, classification: wrongClassificationVersion, summary: authorities.summary},
		{name: "summary identity", profile: authorities.profile, classification: authorities.classification, summary: forgedSummaryIdentity},
		{name: "summary counts", profile: authorities.profile, classification: authorities.classification, summary: forgedSummaryCounts},
		{name: "summary version", profile: authorities.profile, classification: authorities.classification, summary: wrongSummaryVersion},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle, err := NewRepositoryProfileBundle(authorities.manifest, testCase.profile, testCase.classification, testCase.summary)
			if err == nil || bundle.Identity() != "" {
				t.Fatalf("NewRepositoryProfileBundle() = (%#v, %v), want zero error result", bundle, err)
			}
		})
	}
}

func TestRepositoryProfileBundleAcceptsStructurallyValidSignalChain(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	file, _ := authorities.manifest.File("main.go")
	changedChild, err := newFileClassificationReceipt(authorities.manifest.Identity(), file, FileContentContainsNUL)
	if err != nil {
		t.Fatalf("newFileClassificationReceipt() error = %v", err)
	}
	classification := cloneRepositoryClassificationReceipt(authorities.classification)
	classification.files[0] = changedChild
	classification = mustRebuildRepositoryClassificationReceipt(t, classification)
	summary, err := NewRepositoryClassificationSummary(authorities.manifest, classification)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	bundle, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, classification, summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle() error = %v", err)
	}
	if bundle.ClassificationReceiptIdentity() != classification.Identity() || bundle.ClassificationSummaryIdentity() != summary.Identity() || bundle.Identity() == "" {
		t.Fatalf("bundle = %#v, want structurally bound signal chain", bundle)
	}
}

func TestRepositoryProfileBundleDoesNotMutateAuthorities(t *testing.T) {
	authorities := mustRepositoryProfileBundleAuthorities(t,
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "b.go", content: []byte("b")},
	)
	manifestIdentity := authorities.manifest.Identity()
	profileIdentity := authorities.profile.Identity()
	classificationIdentity := authorities.classification.Identity()
	summaryIdentity := authorities.summary.Identity()
	if _, err := NewRepositoryProfileBundle(authorities.manifest, authorities.profile, authorities.classification, authorities.summary); err != nil {
		t.Fatalf("NewRepositoryProfileBundle() error = %v", err)
	}
	if authorities.manifest.Identity() != manifestIdentity || authorities.profile.Identity() != profileIdentity || authorities.classification.Identity() != classificationIdentity || authorities.summary.Identity() != summaryIdentity {
		t.Fatal("bundle construction mutated an accepted authority")
	}
}

func TestRepositoryProfileBundleAtFileLimit(t *testing.T) {
	const fileLimit = 65_536
	files := make([]evidence.RepositoryFile, fileLimit)
	contents := make(map[string][]byte, fileLimit)
	for i := range files {
		filePath := fmt.Sprintf("files/%05d", i)
		file, err := evidence.NewRepositoryFile(filePath, nil)
		if err != nil {
			t.Fatalf("NewRepositoryFile(%d) error = %v", i, err)
		}
		files[i] = file
		contents[filePath] = nil
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	classification, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	summary, err := NewRepositoryClassificationSummary(manifest, classification)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	first, err := NewRepositoryProfileBundle(manifest, profile, classification, summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle(first) error = %v", err)
	}
	second, err := NewRepositoryProfileBundle(manifest, profile, classification, summary)
	if err != nil || second != first {
		t.Fatalf("NewRepositoryProfileBundle(second) = (%#v, %v), want %#v", second, err, first)
	}
	if first.ManifestIdentity() != manifest.Identity() || first.RepositoryProfileIdentity() != profile.Identity() || first.ClassificationReceiptIdentity() != classification.Identity() || first.ClassificationSummaryIdentity() != summary.Identity() {
		t.Fatalf("boundary bundle = %#v", first)
	}
	missing := cloneRepositoryClassificationReceipt(classification)
	missing.files = missing.files[:fileLimit-1]
	missing = mustRebuildRepositoryClassificationReceipt(t, missing)
	if result, err := NewRepositoryProfileBundle(manifest, profile, missing, summary); err == nil || result.Identity() != "" {
		t.Fatalf("missing classification = (%#v, %v), want zero error result", result, err)
	}
	extra := cloneRepositoryClassificationReceipt(classification)
	extra.files = append(extra.files, extra.files[fileLimit-1])
	extra = mustRebuildRepositoryClassificationReceipt(t, extra)
	if result, err := NewRepositoryProfileBundle(manifest, profile, extra, summary); err == nil || result.Identity() != "" {
		t.Fatalf("extra classification = (%#v, %v), want zero error result", result, err)
	}
	staleManifest, err := evidence.NewRepositoryManifest(files[:fileLimit-1])
	if err != nil {
		t.Fatalf("NewRepositoryManifest(stale) error = %v", err)
	}
	staleProfile, err := NewRepositoryProfile(staleManifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile(stale) error = %v", err)
	}
	if result, err := NewRepositoryProfileBundle(manifest, staleProfile, classification, summary); err == nil || result.Identity() != "" {
		t.Fatalf("stale profile = (%#v, %v), want zero error result", result, err)
	}
	staleSummary := summary
	staleSummary.fileCount--
	if result, err := NewRepositoryProfileBundle(manifest, profile, classification, staleSummary); err == nil || result.Identity() != "" {
		t.Fatalf("stale summary = (%#v, %v), want zero error result", result, err)
	}
}

type repositoryProfileBundleAuthorities struct {
	manifest       evidence.RepositoryManifest
	profile        RepositoryProfile
	classification RepositoryClassificationReceipt
	summary        RepositoryClassificationSummary
}

func mustRepositoryProfileBundleAuthorities(t *testing.T, specs ...classificationFileSpec) repositoryProfileBundleAuthorities {
	t.Helper()
	manifest, classification := mustRepositoryClassification(t, specs...)
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	summary, err := NewRepositoryClassificationSummary(manifest, classification)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	return repositoryProfileBundleAuthorities{
		manifest:       manifest,
		profile:        profile,
		classification: classification,
		summary:        summary,
	}
}
