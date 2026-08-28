package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestBuildGoChangeImpactProfileMatchesManualPipeline(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() { println(1) }\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	profile, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}
	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("ResolveGoChangeSymbols() error = %v", err)
	}
	manual, err := NewChangeImpactProfile(change, symbols)
	if err != nil || manual.Identity() != profile.Identity() {
		t.Fatalf("manual profile = (%q, %v), built %q", manual.Identity(), err, profile.Identity())
	}
	if receipt.ChangeIdentity() != change.Identity() || receipt.ProfileIdentity() != profile.Identity() || receipt.ResolverVersion() != goChangeImpactResolverVersion {
		t.Fatalf("receipt binding = (%q, %q, %q)", receipt.ChangeIdentity(), receipt.ProfileIdentity(), receipt.ResolverVersion())
	}
	files := receipt.Files()
	if len(files) != 1 || files[0].Path() != "main.go" || files[0].Outcome() != GoImpactOutcomeAnalyzed || files[0].Reason() != GoImpactReasonNone || files[0].SymbolCount() != 1 {
		t.Fatalf("Files() = %#v", files)
	}
}

func TestBuildGoChangeImpactProfileRecordsCanonicalCoverage(t *testing.T) {
	alpha := []byte("package worker\n\nfunc First() {\n\tone := 1\n\tprintln(one)\n}\n\nfunc Second() {}\n")
	zeta := []byte("package worker\n\nfunc Zeta() {}\n")
	notes := []byte("notes\n")
	change := mustCombinedAnalysisChange(t,
		mustChangedSymbolChange(t, "zeta.go", zeta, []evidence.SourceRange{mustAnalysisRange(t, "zeta.go", 3, 3)}),
		mustChangedSymbolChange(t, "notes.txt", notes, []evidence.SourceRange{mustAnalysisRange(t, "notes.txt", 1, 1)}),
		mustChangedSymbolChange(t, "alpha.go", alpha, []evidence.SourceRange{
			mustAnalysisRange(t, "alpha.go", 4, 4),
			mustAnalysisRange(t, "alpha.go", 6, 6),
			mustAnalysisRange(t, "alpha.go", 8, 8),
		}),
	)
	profile, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"zeta.go": zeta, "alpha.go": alpha})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}
	if len(profile.Symbols()) != 3 {
		t.Fatalf("profile has %d Symbols, want 3", len(profile.Symbols()))
	}
	files := receipt.Files()
	if len(files) != 3 || files[0].Path() != "alpha.go" || files[0].SymbolCount() != 2 || files[1].Path() != "notes.txt" || files[1].Outcome() != GoImpactOutcomeUnsupported || files[2].Path() != "zeta.go" || files[2].SymbolCount() != 1 {
		t.Fatalf("Files() = %#v", files)
	}
	if files[1].Reason() != GoImpactReasonUnsupportedLanguage || files[1].SymbolCount() != 0 {
		t.Fatalf("unsupported coverage = %#v", files[1])
	}
}

func TestBuildGoChangeImpactProfileRecordsDeletionOnlyCoverage(t *testing.T) {
	active := []byte("package worker\n\nfunc Active() {}\n")
	change := mustCombinedAnalysisChange(t,
		mustDeletionChange(t, "deleted.go"),
		mustChangedSymbolChange(t, "active.go", active, []evidence.SourceRange{mustAnalysisRange(t, "active.go", 3, 3)}),
	)
	profile, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"active.go": active, "deleted.go": nil})
	if err != nil || len(profile.Symbols()) != 1 {
		t.Fatalf("BuildGoChangeImpactProfile() = (%q, %#v, %v)", profile.Identity(), receipt, err)
	}
	deleted, ok := receipt.File("deleted.go")
	if !ok || deleted.Outcome() != GoImpactOutcomeNotApplicable || deleted.Reason() != GoImpactReasonNoPositiveHeadHunks || deleted.SymbolCount() != 0 {
		t.Fatalf("deleted coverage = (%#v, %t)", deleted, ok)
	}
}

func TestBuildGoChangeImpactProfileRecordsUnsupportedOnlyChange(t *testing.T) {
	text := []byte("notes\n")
	change := mustChangedSymbolChange(t, "notes.txt", text, []evidence.SourceRange{mustAnalysisRange(t, "notes.txt", 1, 1)})
	profile, receipt, err := BuildGoChangeImpactProfile(change, nil)
	if err != nil || len(profile.Symbols()) != 0 || profile.Symbols() == nil {
		t.Fatalf("BuildGoChangeImpactProfile() = (%#v, %#v, %v)", profile, receipt, err)
	}
	coverage, ok := receipt.File("notes.txt")
	if !ok || coverage.Outcome() != GoImpactOutcomeUnsupported || coverage.Reason() != GoImpactReasonUnsupportedLanguage {
		t.Fatalf("coverage = (%#v, %t)", coverage, ok)
	}
}

func TestGoChangeImpactReceiptIdentityUsesCanonicalPreimage(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {}\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	profile, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/go-change-impact-receipt","schema_version":1,"resolver":"go-stdlib-enclosing-symbols","resolver_version":"1","change_identity":"%s","profile_identity":"%s","files":[{"path":"main.go","outcome":"analyzed","reason":"none","symbol_count":1}]}`, change.Identity(), profile.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); receipt.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", receipt.Identity(), preimage)
	}
}

func TestBuildGoChangeImpactProfileIsDeterministicAndImmutable(t *testing.T) {
	alpha := []byte("package worker\n\nfunc Alpha() {}\n")
	zeta := []byte("package worker\n\nfunc Zeta() {}\n")
	change := mustCombinedAnalysisChange(t,
		mustChangedSymbolChange(t, "zeta.go", zeta, []evidence.SourceRange{mustAnalysisRange(t, "zeta.go", 3, 3)}),
		mustChangedSymbolChange(t, "alpha.go", alpha, []evidence.SourceRange{mustAnalysisRange(t, "alpha.go", 3, 3)}),
	)
	first, firstReceipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"zeta.go": zeta, "alpha.go": alpha})
	if err != nil {
		t.Fatalf("first build error = %v", err)
	}
	second, secondReceipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"alpha.go": append([]byte(nil), alpha...), "zeta.go": append([]byte(nil), zeta...)})
	if err != nil || second.Identity() != first.Identity() || secondReceipt.Identity() != firstReceipt.Identity() {
		t.Fatalf("second build = (%q, %q, %v), want (%q, %q)", second.Identity(), secondReceipt.Identity(), err, first.Identity(), firstReceipt.Identity())
	}
	files := firstReceipt.Files()
	files[0] = GoImpactFileCoverage{}
	for i := range alpha {
		alpha[i] = 'x'
	}
	if got := firstReceipt.Files(); got[0].Path() != "alpha.go" || firstReceipt.Identity() != secondReceipt.Identity() {
		t.Fatal("caller mutation changed receipt")
	}
}

func TestGoChangeImpactReceiptIdentityBindsVersionAndContent(t *testing.T) {
	firstSource := []byte("package worker\n\nfunc Process() { println(1) }\n")
	secondSource := []byte("package worker\n\nfunc Process() { println(2) }\n")
	firstChange := mustChangedSymbolChange(t, "main.go", firstSource, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	secondChange := mustChangedSymbolChange(t, "main.go", secondSource, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	firstProfile, firstReceipt, err := BuildGoChangeImpactProfile(firstChange, map[string][]byte{"main.go": firstSource})
	if err != nil {
		t.Fatalf("first build error = %v", err)
	}
	secondProfile, secondReceipt, err := BuildGoChangeImpactProfile(secondChange, map[string][]byte{"main.go": secondSource})
	if err != nil || secondProfile.Identity() == firstProfile.Identity() || secondReceipt.Identity() == firstReceipt.Identity() {
		t.Fatalf("second build = (%q, %q, %v)", secondProfile.Identity(), secondReceipt.Identity(), err)
	}
	otherVersion, err := newGoChangeImpactReceipt(firstChange, firstProfile, "2")
	if err != nil || otherVersion.Identity() == firstReceipt.Identity() || otherVersion.ProfileIdentity() != firstProfile.Identity() {
		t.Fatalf("other version = (%q, %q, %v)", otherVersion.Identity(), otherVersion.ProfileIdentity(), err)
	}
}

func TestBuildGoChangeImpactProfileMaintainsCoverageInvariant(t *testing.T) {
	source := []byte("package worker\n\nfunc First() {}\n\nfunc Second() {}\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{
		mustAnalysisRange(t, "main.go", 3, 3),
		mustAnalysisRange(t, "main.go", 5, 5),
	})
	profile, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}
	total := 0
	for _, file := range receipt.Files() {
		total += file.SymbolCount()
	}
	if total != len(profile.Symbols()) {
		t.Fatalf("coverage total = %d, profile Symbols = %d", total, len(profile.Symbols()))
	}
	for _, symbol := range profile.Symbols() {
		file, ok := receipt.File(symbol.Path())
		if !ok || file.Outcome() != GoImpactOutcomeAnalyzed {
			t.Fatalf("Symbol %q coverage = (%#v, %t)", symbol.Identity(), file, ok)
		}
	}
}

func TestBuildGoChangeImpactProfileHandlesMaximumFileCount(t *testing.T) {
	const fileCount = 1024
	changes := make([]evidence.Change, 0, fileCount)
	contents := make(map[string][]byte, fileCount)
	for i := fileCount - 1; i >= 0; i-- {
		path := fmt.Sprintf("pkg/%04d.go", i)
		source := []byte(fmt.Sprintf("package worker\n\nfunc F%04d() {}\n", i))
		contents[path] = source
		changes = append(changes, mustChangedSymbolChange(t, path, source, []evidence.SourceRange{mustAnalysisRange(t, path, 3, 3)}))
	}
	change := mustCombinedAnalysisChange(t, changes...)
	profile, receipt, err := BuildGoChangeImpactProfile(change, contents)
	if err != nil || len(profile.Symbols()) != fileCount || len(receipt.Files()) != fileCount {
		t.Fatalf("BuildGoChangeImpactProfile() = (%d Symbols, %d files, %v)", len(profile.Symbols()), len(receipt.Files()), err)
	}
	files := receipt.Files()
	if files[0].Path() != "pkg/0000.go" || files[fileCount-1].Path() != "pkg/1023.go" {
		t.Fatalf("boundary files = (%q, %q)", files[0].Path(), files[fileCount-1].Path())
	}
}

func TestBuildGoChangeImpactProfileFailsAtomically(t *testing.T) {
	valid := []byte("package worker\n\nfunc Process() {}\n")
	validChange := mustChangedSymbolChange(t, "main.go", valid, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	malformed := []byte("package worker\n\nfunc Broken( {\n")
	unsupported := []byte("package worker\n\ntype T struct{}\nfunc (**T) Bad() {}\n")
	nul := []byte("package worker\x00\n")
	invalidUTF8 := []byte{'p', 'a', 'c', 'k', 'a', 'g', 'e', ' ', 0xff, '\n'}
	oversized := append([]byte("package worker\n"), bytes.Repeat([]byte{' '}, maxGoSourceBytes)...)
	testCases := []struct {
		name     string
		change   evidence.Change
		contents map[string][]byte
	}{
		{name: "zero change"},
		{name: "missing", change: validChange},
		{name: "extra", change: validChange, contents: map[string][]byte{"main.go": valid, "extra.go": valid}},
		{name: "wrong digest", change: validChange, contents: map[string][]byte{"main.go": []byte("package other\n")}},
		{name: "wrong count", change: mustResolverChange(t, "main.go", valid, mustAnalysisRange(t, "main.go", 3, 3), physicalGoLineCount(valid)+1), contents: map[string][]byte{"main.go": valid}},
		{name: "malformed", change: mustChangedSymbolChange(t, "bad.go", malformed, []evidence.SourceRange{mustAnalysisRange(t, "bad.go", 3, 3)}), contents: map[string][]byte{"bad.go": malformed}},
		{name: "unsupported receiver", change: mustChangedSymbolChange(t, "bad.go", unsupported, []evidence.SourceRange{mustAnalysisRange(t, "bad.go", 4, 4)}), contents: map[string][]byte{"bad.go": unsupported}},
		{name: "NUL", change: mustChangedSymbolChange(t, "nul.go", nul, []evidence.SourceRange{mustAnalysisRange(t, "nul.go", 1, 1)}), contents: map[string][]byte{"nul.go": nul}},
		{name: "invalid UTF-8", change: mustChangedSymbolChange(t, "utf.go", invalidUTF8, []evidence.SourceRange{mustAnalysisRange(t, "utf.go", 1, 1)}), contents: map[string][]byte{"utf.go": invalidUTF8}},
		{name: "oversized", change: mustChangedSymbolChange(t, "large.go", oversized, []evidence.SourceRange{mustAnalysisRange(t, "large.go", 1, 1)}), contents: map[string][]byte{"large.go": oversized}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			profile, receipt, err := BuildGoChangeImpactProfile(testCase.change, testCase.contents)
			if err == nil || profile.Identity() != "" || receipt.Identity() != "" {
				t.Fatalf("BuildGoChangeImpactProfile() = (%#v, %#v, %v), want zero error result", profile, receipt, err)
			}
		})
	}
}

func TestGoChangeImpactReceiptRejectsForgedProfiles(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {}\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	profile, _, err := BuildGoChangeImpactProfile(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}

	forgedIdentity := profile
	forgedIdentity.identity = strings.Repeat("0", 64)
	forgedSymbols := profile
	forgedSymbols.symbols = nil
	forgedOrder := profile
	forgedOrder.symbols = append([]Symbol(nil), profile.symbols...)
	forgedOrder.symbols = append(forgedOrder.symbols, forgedOrder.symbols[0])
	forgedIndex := profile
	forgedIndex.symbolsByIdentity = nil
	forgedPosition := profile
	forgedPosition.symbolsByIdentity = map[string]int{profile.symbols[0].Identity(): 99}
	for _, forged := range []ChangeImpactProfile{forgedIdentity, forgedSymbols, forgedOrder, forgedIndex, forgedPosition} {
		receipt, err := newGoChangeImpactReceipt(change, forged, goChangeImpactResolverVersion)
		if err == nil || receipt.Identity() != "" {
			t.Fatalf("newGoChangeImpactReceipt(forged) = (%#v, %v), want zero error result", receipt, err)
		}
	}
}

func TestGoChangeImpactReceiptAccessorsAreExact(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {}\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	_, receipt, err := BuildGoChangeImpactProfile(change, map[string][]byte{"main.go": source})
	if err != nil {
		t.Fatalf("BuildGoChangeImpactProfile() error = %v", err)
	}
	for _, path := range []string{"", "missing.go", "./main.go", "../main.go"} {
		if file, ok := receipt.File(path); ok || file != (GoImpactFileCoverage{}) {
			t.Fatalf("File(%q) = (%#v, %t)", path, file, ok)
		}
	}
}
