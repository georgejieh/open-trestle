package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestReviewDebugOutputChangeCoversEveryFile(t *testing.T) {
	base := map[string][]byte{
		"a.go":      []byte("package a\nfunc first() {}\n"),
		"b.go":      []byte("package b\nfunc clean() int { return 1 }\n"),
		"c.go":      []byte("package c\nfunc second() {}\n"),
		"notes.txt": []byte("old\n"),
	}
	head := map[string][]byte{
		"a.go":      []byte("package a\nimport \"fmt\"\nfunc first() { fmt.Println(\"debug\") }\n"),
		"b.go":      []byte("package b\nfunc clean() int { return 2 }\n"),
		"c.go":      []byte("package c\nimport \"fmt\"\nfunc second() { fmt.Println(\"debug\") }\n"),
		"notes.txt": []byte("new\n"),
	}
	change := mustDebugOutputChange(t, base, head)
	limits := standardDebugOutputChangeLimitsForTest()
	result, err := ReviewDebugOutputChange(change, head, limits)
	if err != nil {
		t.Fatal(err)
	}
	findings := result.Findings()
	items := result.EvidenceItems()
	files := result.Files()
	if result.Identity() == "" || result.ChangeIdentity() != change.Identity() || result.RuleVersion() != "1" || len(findings) != 2 || len(items) != 2 || len(files) != 4 || result.Identity() != expectedDebugOutputChangeResultIdentity(result, limits) {
		t.Fatalf("result = %#v", result)
	}
	if findings[0].SourceRange().Path() != "a.go" || findings[1].SourceRange().Path() != "c.go" || items[0].SourceRange() != findings[0].SourceRange() || items[1].SourceRange() != findings[1].SourceRange() {
		t.Fatalf("findings/items = %#v %#v", findings, items)
	}
	for _, path := range []string{"a.go", "b.go", "c.go"} {
		coverage, ok := result.File(path)
		if !ok || coverage.Outcome() != DebugOutputChangeOutcomeAnalyzed || coverage.Reason() != DebugOutputChangeReasonNone {
			t.Fatalf("coverage %q = (%#v, %v)", path, coverage, ok)
		}
	}
	if coverage, ok := result.File("notes.txt"); !ok || coverage.Outcome() != DebugOutputChangeOutcomeNotApplicable || coverage.Reason() != DebugOutputChangeReasonUnsupportedLanguage || coverage.MatchCount() != 0 {
		t.Fatalf("notes coverage = (%#v, %v)", coverage, ok)
	}
	if coverage, _ := result.File("a.go"); coverage.MatchCount() != 1 {
		t.Fatalf("a.go coverage = %#v", coverage)
	}
	if coverage, _ := result.File("b.go"); coverage.MatchCount() != 0 {
		t.Fatalf("b.go coverage = %#v", coverage)
	}
}

func TestReviewDebugOutputChangeIsDeterministicAcrossMapOrder(t *testing.T) {
	base := map[string][]byte{"a.go": []byte("package a\nfunc f() {}\n"), "b.go": []byte("package b\nfunc g() {}\n")}
	head := map[string][]byte{"a.go": []byte("package a\nimport \"fmt\"\nfunc f() { fmt.Println(\"debug\") }\n"), "b.go": []byte("package b\nfunc g() { println(1) }\n")}
	change := mustDebugOutputChange(t, base, head)
	limits := standardDebugOutputChangeLimitsForTest()
	first, err := ReviewDebugOutputChange(change, map[string][]byte{"b.go": head["b.go"], "a.go": head["a.go"]}, limits)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReviewDebugOutputChange(change, map[string][]byte{"a.go": head["a.go"], "b.go": head["b.go"]}, limits)
	if err != nil || first.Identity() != second.Identity() || !equalFindingIDs(first.Findings(), second.Findings()) || !equalEvidenceIDs(first.EvidenceItems(), second.EvidenceItems()) {
		t.Fatalf("results = (%#v, %#v, %v)", first, second, err)
	}
}

func TestReviewDebugOutputChangeRejectsIncompleteOrMismatchedContent(t *testing.T) {
	base := map[string][]byte{"a.go": []byte("package a\nfunc f() {}\n"), "b.go": []byte("package b\nfunc g() {}\n")}
	head := map[string][]byte{"a.go": []byte("package a\nfunc f() { println(1) }\n"), "b.go": []byte("package b\nfunc g() { println(2) }\n")}
	change := mustDebugOutputChange(t, base, head)
	limits := standardDebugOutputChangeLimitsForTest()
	for _, test := range []struct {
		name     string
		contents map[string][]byte
	}{
		{name: "missing", contents: map[string][]byte{"a.go": head["a.go"]}},
		{name: "extra", contents: map[string][]byte{"a.go": head["a.go"], "b.go": head["b.go"], "extra": []byte("secret canary")}},
		{name: "one byte", contents: map[string][]byte{"a.go": append([]byte(nil), head["a.go"]...), "b.go": []byte("package b\nfunc g() { println(3) }\n")}},
		{name: "LF CRLF", contents: map[string][]byte{"a.go": []byte(strings.ReplaceAll(string(head["a.go"]), "\n", "\r\n")), "b.go": head["b.go"]}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := ReviewDebugOutputChange(change, test.contents, limits)
			if err == nil || result.Identity() != "" || result.Findings() != nil || result.EvidenceItems() != nil || result.Files() != nil || strings.Contains(err.Error(), "secret canary") {
				t.Fatalf("result = (%#v, %v)", result, err)
			}
		})
	}
}

func TestReviewDebugOutputChangeRejectsLineMapPastHeadEOF(t *testing.T) {
	headContent := []byte("package p\n")
	baseDigest := digestHex([]byte("base line one\nbase line two\n"))
	headDigest := digestHex(headContent)
	changedRange, err := evidence.NewSourceRange("file.go", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	fileChange, err := evidence.NewFileChange("file.go", baseDigest, headDigest, []evidence.SourceRange{changedRange})
	if err != nil {
		t.Fatal(err)
	}
	hunk, err := evidence.NewHunk(fileChange, 2, 1, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	lineMap, err := evidence.NewLineMap(fileChange, 2, 2, []evidence.Hunk{hunk})
	if err != nil {
		t.Fatal(err)
	}
	change, err := evidence.NewChange([]evidence.FileChange{fileChange}, []evidence.LineMap{lineMap})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ReviewDebugOutputChange(change, map[string][]byte{"file.go": headContent}, standardDebugOutputChangeLimitsForTest())
	if err == nil || result.Identity() != "" || result.Files() != nil {
		t.Fatalf("result = (%#v, %v)", result, err)
	}
}

func TestReviewDebugOutputChangeSanitizesParseErrors(t *testing.T) {
	canary := "UNIQUE_PARSE_CANARY_7319"
	base := map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}
	head := map[string][]byte{"file.go": []byte("package p\nfunc f " + canary + "\n")}
	change := mustDebugOutputChange(t, base, head)
	result, err := ReviewDebugOutputChange(change, head, standardDebugOutputChangeLimitsForTest())
	if err == nil || result.Identity() != "" || strings.Contains(err.Error(), canary) {
		t.Fatalf("result = (%#v, %v)", result, err)
	}
}

func TestReviewDebugOutputChangeRecordsDeletionOnlyAndNonGo(t *testing.T) {
	base := map[string][]byte{"deleted.go": []byte("package p\nfunc old() {}\n"), "file.txt": []byte("old\n")}
	head := map[string][]byte{"deleted.go": {}, "file.txt": []byte("new\n")}
	change := mustDebugOutputChange(t, base, head)
	result, err := ReviewDebugOutputChange(change, head, standardDebugOutputChangeLimitsForTest())
	if err != nil || len(result.Findings()) != 0 {
		t.Fatalf("result = (%#v, %v)", result, err)
	}
	deleted, ok := result.File("deleted.go")
	if !ok || deleted.Outcome() != DebugOutputChangeOutcomeNotApplicable || deleted.Reason() != DebugOutputChangeReasonNoPositiveHeadRanges || deleted.HeadDigest() == "" {
		t.Fatalf("deleted coverage = (%#v, %v)", deleted, ok)
	}
	nonGo, ok := result.File("file.txt")
	if !ok || nonGo.Reason() != DebugOutputChangeReasonUnsupportedLanguage {
		t.Fatalf("non-Go coverage = (%#v, %v)", nonGo, ok)
	}
}

func TestReviewDebugOutputChangeEnforcesLimitsWithoutPartialOutput(t *testing.T) {
	base := map[string][]byte{"a.go": []byte("package a\nfunc f() {}\n"), "b.go": []byte("package b\nfunc g() {}\n")}
	head := map[string][]byte{"a.go": []byte("package a\nimport \"fmt\"\nfunc f() { fmt.Println(\"debug\") }\n"), "b.go": []byte("package b\nfunc g() { println(1) }\n")}
	change := mustDebugOutputChange(t, base, head)
	standard := standardDebugOutputChangeLimitsForTest()
	total := len(head["a.go"]) + len(head["b.go"])
	passing := standard
	passing.MaxFiles = 2
	passing.MaxBytesPerFile = len(head["a.go"])
	passing.MaxTotalBytes = int64(total)
	passing.MaxFindings = 1
	if result, err := ReviewDebugOutputChange(change, head, passing); err != nil || result.Identity() == "" {
		t.Fatalf("boundary result = (%#v, %v)", result, err)
	}
	for _, test := range []struct {
		name   string
		limits DebugOutputChangeLimits
	}{
		{name: "files", limits: alterDebugLimits(passing, func(limits *DebugOutputChangeLimits) { limits.MaxFiles = 1 })},
		{name: "file bytes", limits: alterDebugLimits(passing, func(limits *DebugOutputChangeLimits) { limits.MaxBytesPerFile-- })},
		{name: "total bytes", limits: alterDebugLimits(passing, func(limits *DebugOutputChangeLimits) { limits.MaxTotalBytes-- })},
		{name: "findings", limits: alterDebugLimits(passing, func(limits *DebugOutputChangeLimits) { limits.MaxFindings = 0 })},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := ReviewDebugOutputChange(change, head, test.limits)
			if !errors.Is(err, DebugOutputChangeResourceLimit) || result.Identity() != "" || result.Findings() != nil {
				t.Fatalf("limited result = (%#v, %v)", result, err)
			}
		})
	}
}

func TestReviewDebugOutputChangeDoesNotRetainSource(t *testing.T) {
	canary := "UNIQUE_SOURCE_CANARY_91827"
	base := map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}
	headSource := []byte("package p\nimport \"fmt\"\nfunc f() { fmt.Println(\"debug\"); _ = \"" + canary + "\" }\n")
	head := map[string][]byte{"file.go": headSource}
	change := mustDebugOutputChange(t, base, head)
	result, err := ReviewDebugOutputChange(change, head, standardDebugOutputChangeLimitsForTest())
	if err != nil {
		t.Fatal(err)
	}
	headSource[0] = 'X'
	serialized, _ := json.Marshal(struct {
		Identity string                  `json:"identity"`
		Findings []Finding               `json:"findings"`
		Evidence []evidence.EvidenceItem `json:"evidence"`
	}{result.Identity(), result.Findings(), result.EvidenceItems()})
	if strings.Contains(string(serialized), canary) || strings.Contains(fmt.Sprintf("%#v", result), canary) {
		t.Fatal("result retained source canary")
	}
}

func mustDebugOutputChange(t *testing.T, base, head map[string][]byte) evidence.Change {
	t.Helper()
	paths := make([]string, 0, len(base))
	for path := range base {
		paths = append(paths, path)
	}
	fileChanges := make([]evidence.FileChange, 0, len(paths))
	lineMaps := make([]evidence.LineMap, 0, len(paths))
	for _, path := range paths {
		patch, err := evidence.GenerateUnifiedFileDiff(path, base[path], head[path])
		if err != nil {
			t.Fatalf("GenerateUnifiedFileDiff(%q) error = %v", path, err)
		}
		fileChange, lineMap, err := evidence.ParseUnifiedFileDiff(path, base[path], head[path], patch)
		if err != nil {
			t.Fatalf("ParseUnifiedFileDiff(%q) error = %v", path, err)
		}
		fileChanges = append(fileChanges, fileChange)
		lineMaps = append(lineMaps, lineMap)
	}
	change, err := evidence.NewChange(fileChanges, lineMaps)
	if err != nil {
		t.Fatal(err)
	}
	return change
}

func standardDebugOutputChangeLimitsForTest() DebugOutputChangeLimits {
	return DebugOutputChangeLimits{MaxFiles: 16, MaxBytesPerFile: 1 << 20, MaxTotalBytes: 8 << 20, MaxFindings: 128}
}

func alterDebugLimits(limits DebugOutputChangeLimits, alter func(*DebugOutputChangeLimits)) DebugOutputChangeLimits {
	alter(&limits)
	return limits
}

func equalFindingIDs(first, second []Finding) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].ID() != second[index].ID() {
			return false
		}
	}
	return true
}

func equalEvidenceIDs(first, second []evidence.EvidenceItem) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].ID() != second[index].ID() {
			return false
		}
	}
	return true
}

func expectedDebugOutputChangeResultIdentity(result DebugOutputChangeResult, limits DebugOutputChangeLimits) string {
	type fileWire struct {
		Path       string                   `json:"path"`
		Outcome    DebugOutputChangeOutcome `json:"outcome"`
		Reason     DebugOutputChangeReason  `json:"reason"`
		HeadDigest string                   `json:"head_digest"`
		MatchCount int                      `json:"match_count"`
	}
	files := result.Files()
	findings := result.Findings()
	items := result.EvidenceItems()
	preimage := struct {
		Contract        string     `json:"contract"`
		SchemaVersion   int        `json:"schema_version"`
		Rule            string     `json:"rule"`
		RuleVersion     string     `json:"rule_version"`
		ChangeIdentity  string     `json:"change_identity"`
		MaxFiles        int        `json:"max_files"`
		MaxBytesPerFile int        `json:"max_bytes_per_file"`
		MaxTotalBytes   int64      `json:"max_total_bytes"`
		MaxFindings     int        `json:"max_findings"`
		Files           []fileWire `json:"files"`
		FindingIDs      []string   `json:"finding_ids"`
		EvidenceIDs     []string   `json:"evidence_ids"`
	}{"open-trestle/debug-output-change-review", 1, staticDebugRuleID, "1", result.ChangeIdentity(), limits.MaxFiles, limits.MaxBytesPerFile, limits.MaxTotalBytes, limits.MaxFindings, make([]fileWire, len(files)), make([]string, len(findings)), make([]string, len(items))}
	for i, file := range files {
		preimage.Files[i] = fileWire{file.Path(), file.Outcome(), file.Reason(), file.HeadDigest(), file.MatchCount()}
	}
	for i, finding := range findings {
		preimage.FindingIDs[i] = finding.ID()
	}
	for i, item := range items {
		preimage.EvidenceIDs[i] = item.ID()
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
