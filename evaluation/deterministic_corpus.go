package evaluation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	internalanalysis "github.com/georgejieh/open-trestle/internal/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

const (
	corpusRoot                 = "testdata/deterministic-corpus-v1"
	maximumCorpusDocumentBytes = 1 << 20
	maximumCorpusReportBytes   = 1 << 20
)

var ErrInvalidDeterministicCorpus = errors.New("invalid deterministic corpus")

//go:embed testdata/deterministic-corpus-v1
var deterministicCorpusFiles embed.FS

type corpusBounds struct {
	MaximumCases           int `json:"maximum_cases"`
	MaximumFiles           int `json:"maximum_files"`
	MaximumTotalBytes      int `json:"maximum_total_bytes"`
	MaximumFileBytes       int `json:"maximum_file_bytes"`
	MaximumLabelsPerTarget int `json:"maximum_labels_per_target"`
}

type corpusTarget struct {
	Key       string `json:"key"`
	Version   int    `json:"version"`
	Family    string `json:"family"`
	MatchUnit string `json:"match_unit"`
}

type corpusOrigin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type corpusFixtureFile struct {
	Side   string `json:"side"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type corpusCaseManifest struct {
	ID           string              `json:"id"`
	Files        []corpusFixtureFile `json:"files"`
	LabelsPath   string              `json:"labels_path"`
	LabelsSHA256 string              `json:"labels_sha256"`
	LabelsBytes  int                 `json:"labels_bytes"`
}

type corpusManifest struct {
	Contract       string               `json:"contract"`
	SchemaVersion  int                  `json:"schema_version"`
	CorpusIdentity string               `json:"corpus_identity"`
	CorpusVersion  int                  `json:"corpus_version"`
	License        string               `json:"license"`
	ReviewState    string               `json:"review_state"`
	Bounds         corpusBounds         `json:"bounds"`
	Targets        []corpusTarget       `json:"targets"`
	Origin         corpusOrigin         `json:"origin"`
	Cases          []corpusCaseManifest `json:"cases"`
}

type corpusAdjudication struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	CorpusIdentity        string   `json:"corpus_identity"`
	ReviewState           string   `json:"review_state"`
	Method                string   `json:"method"`
	Decision              string   `json:"decision"`
	ResolvedDisagreements []string `json:"resolved_disagreements"`
	ReviewerIdentifier    string   `json:"reviewer_identifier,omitempty"`
	ReviewDate            string   `json:"review_date,omitempty"`
}

type corpusRange struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

type corpusChange struct {
	Path   string        `json:"path"`
	Ranges []corpusRange `json:"ranges"`
}

type corpusLabel struct {
	Path           string `json:"path,omitempty"`
	StartLine      int    `json:"start_line,omitempty"`
	EndLine        int    `json:"end_line,omitempty"`
	Signal         string `json:"signal,omitempty"`
	Kind           string `json:"kind,omitempty"`
	QualifiedName  string `json:"qualified_name,omitempty"`
	DeclarationKey string `json:"declaration_key,omitempty"`
	ChangeKind     string `json:"change_kind,omitempty"`
	Line           int    `json:"line,omitempty"`
	Column         int    `json:"column,omitempty"`
}

type expectedCoverage struct {
	Path    string `json:"path"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

type corpusCaseTarget struct {
	Key              string             `json:"key"`
	Expected         []corpusLabel      `json:"expected"`
	ExpectedCoverage []expectedCoverage `json:"expected_coverage"`
}

type corpusCaseLabels struct {
	SchemaVersion int                `json:"schema_version"`
	CaseID        string             `json:"case_id"`
	Changes       []corpusChange     `json:"changes"`
	Targets       []corpusCaseTarget `json:"targets"`
}

type deterministicCorpusCase struct {
	manifest corpusCaseManifest
	labels   corpusCaseLabels
	base     map[string][]byte
	head     map[string][]byte
}

type deterministicCorpus struct {
	manifest             corpusManifest
	adjudication         corpusAdjudication
	adjudicationIdentity string
	cases                []deterministicCorpusCase
	fixtureFileCount     uint32
	fixtureByteCount     uint64
	changedFileCount     uint32
	changedRangeCount    uint32
}

func decodeStrictJSON(encoded []byte, maximum int, destination any) error {
	if len(encoded) == 0 || len(encoded) > maximum || rejectDuplicateKeys(encoded) != nil {
		return ErrInvalidDeterministicCorpus
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidDeterministicCorpus
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var scan func() error
	scan = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := value.(string)
				if !ok {
					return ErrInvalidDeterministicCorpus
				}
				if _, ok := seen[key]; ok {
					return ErrInvalidDeterministicCorpus
				}
				seen[key] = struct{}{}
				if err := scan(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := scan(); err != nil {
					return err
				}
			}
		default:
			return ErrInvalidDeterministicCorpus
		}
		_, err = decoder.Token()
		return err
	}
	return scan()
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validCorpusDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value != strings.Repeat("0", 64)
}

func validCorpusPath(value string) bool {
	return value != "" && len(value) <= 4096 && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\")
}

func deriveManifestIdentity(encoded []byte) (string, error) {
	var value map[string]any
	if decodeStrictJSON(encoded, maximumCorpusDocumentBytes, &value) != nil {
		return "", ErrInvalidDeterministicCorpus
	}
	if _, ok := value["corpus_identity"].(string); !ok {
		return "", ErrInvalidDeterministicCorpus
	}
	value["corpus_identity"] = ""
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidDeterministicCorpus
	}
	return digestBytes(canonical), nil
}

func readBoundedFile(fsys fs.FS, name string, maximum int) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, ErrInvalidDeterministicCorpus
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(value) > maximum {
		return nil, ErrInvalidDeterministicCorpus
	}
	return value, nil
}

func loadDeterministicCorpus(fsys fs.FS, root string) (deterministicCorpus, error) {
	manifestBytes, err := readBoundedFile(fsys, root+"/manifest.json", maximumCorpusDocumentBytes)
	if err != nil {
		return deterministicCorpus{}, err
	}
	var manifest corpusManifest
	if decodeStrictJSON(manifestBytes, maximumCorpusDocumentBytes, &manifest) != nil {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	identity, err := deriveManifestIdentity(manifestBytes)
	if err != nil || identity != manifest.CorpusIdentity || validateManifest(manifest) != nil {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	adjudicationBytes, err := readBoundedFile(fsys, root+"/adjudication.json", maximumCorpusDocumentBytes)
	if err != nil {
		return deterministicCorpus{}, err
	}
	var adjudication corpusAdjudication
	if decodeStrictJSON(adjudicationBytes, maximumCorpusDocumentBytes, &adjudication) != nil || validateAdjudication(adjudication, identity) != nil {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	corpus := deterministicCorpus{
		manifest: manifest, adjudication: adjudication, adjudicationIdentity: digestBytes(adjudicationBytes),
		cases: make([]deterministicCorpusCase, len(manifest.Cases)), fixtureFileCount: 2,
		fixtureByteCount: uint64(len(manifestBytes) + len(adjudicationBytes)),
	}
	expectedPaths := map[string]struct{}{root + "/manifest.json": {}, root + "/adjudication.json": {}, root + "/" + manifest.Origin.Path: {}}
	origin, err := readBoundedFile(fsys, root+"/"+manifest.Origin.Path, manifest.Bounds.MaximumFileBytes)
	if err != nil || len(origin) != manifest.Origin.Bytes || digestBytes(origin) != manifest.Origin.SHA256 {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	corpus.fixtureFileCount++
	corpus.fixtureByteCount += uint64(len(origin))
	for index, caseManifest := range manifest.Cases {
		loaded, err := loadCorpusCase(fsys, root, manifest, caseManifest, expectedPaths)
		if err != nil {
			return deterministicCorpus{}, err
		}
		corpus.cases[index] = loaded
		corpus.fixtureFileCount += uint32(len(caseManifest.Files) + 1)
		corpus.fixtureByteCount += uint64(caseManifest.LabelsBytes)
		for _, file := range caseManifest.Files {
			corpus.fixtureByteCount += uint64(file.Bytes)
		}
		corpus.changedFileCount += uint32(len(loaded.labels.Changes))
		for _, change := range loaded.labels.Changes {
			corpus.changedRangeCount += uint32(len(change.Ranges))
		}
	}
	actualPaths := map[string]struct{}{}
	if fs.WalkDir(fsys, root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			actualPaths[name] = struct{}{}
		}
		return nil
	}) != nil || len(actualPaths) != len(expectedPaths) {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	for name := range actualPaths {
		if _, ok := expectedPaths[name]; !ok {
			return deterministicCorpus{}, ErrInvalidDeterministicCorpus
		}
	}
	if corpus.fixtureFileCount > uint32(manifest.Bounds.MaximumFiles) || corpus.fixtureByteCount > uint64(manifest.Bounds.MaximumTotalBytes) {
		return deterministicCorpus{}, ErrInvalidDeterministicCorpus
	}
	return corpus, nil
}

func validateManifest(manifest corpusManifest) error {
	expectedBounds := corpusBounds{MaximumCases: 8, MaximumFiles: 128, MaximumTotalBytes: 1 << 20, MaximumFileBytes: 128 << 10, MaximumLabelsPerTarget: 1024}
	expectedTargets := []corpusTarget{
		{Key: "changed_declaration", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,declaration_key,change_kind"},
		{Key: "contains_nul", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,signal"},
		{Key: "go_changed_symbol", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,kind,qualified_name,start_line,end_line"},
		{Key: "go_test_path", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,signal"},
		{Key: "public_api_change", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,declaration_key,change_kind"},
		{Key: "static_debug_output", Version: 1, Family: "finding_rule", MatchUnit: "case_id,path,start_line,end_line"},
		{Key: "syntactic_reference_candidate", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,declaration_key,path,line,column"},
		{Key: "vendor_path", Version: 1, Family: "structural_analyzer", MatchUnit: "case_id,path,signal"},
	}
	expectedCases := []string{"classification_boundaries", "coverage_and_removal", "debug_direct_and_multiline", "debug_near_misses", "go_symbol_boundaries", "semantic_api_and_references"}
	if manifest.Contract != "open-trestle/deterministic-corpus-manifest" || manifest.SchemaVersion != 1 || manifest.CorpusVersion != 1 || manifest.License != "Apache-2.0" || manifest.ReviewState != "pending" || !validCorpusDigest(manifest.CorpusIdentity) || manifest.Bounds != expectedBounds || len(manifest.Cases) != len(expectedCases) || len(manifest.Targets) != len(expectedTargets) || manifest.Origin.Path != "ORIGIN.md" || !validCorpusDigest(manifest.Origin.SHA256) || manifest.Origin.Bytes <= 0 || manifest.Origin.Bytes > manifest.Bounds.MaximumFileBytes {
		return ErrInvalidDeterministicCorpus
	}
	for index, target := range manifest.Targets {
		if target != expectedTargets[index] {
			return ErrInvalidDeterministicCorpus
		}
	}
	for index, item := range manifest.Cases {
		if item.ID != expectedCases[index] || item.LabelsPath != "cases/"+item.ID+"/labels.json" || !validCorpusDigest(item.LabelsSHA256) || item.LabelsBytes <= 0 || item.LabelsBytes > manifest.Bounds.MaximumFileBytes || len(item.Files) == 0 {
			return ErrInvalidDeterministicCorpus
		}
		previous := ""
		for _, file := range item.Files {
			key := file.Side + "/" + file.Path
			if (file.Side != "base" && file.Side != "head") || !validCorpusPath(file.Path) || key <= previous || !validCorpusDigest(file.SHA256) || file.Bytes < 0 || file.Bytes > manifest.Bounds.MaximumFileBytes {
				return ErrInvalidDeterministicCorpus
			}
			previous = key
		}
	}
	return nil
}

func validateAdjudication(value corpusAdjudication, corpusIdentity string) error {
	if value.Contract != "open-trestle/deterministic-corpus-adjudication" || value.SchemaVersion != 1 || value.CorpusIdentity != corpusIdentity || value.ReviewState != "pending" || value.Method != "independent_human_review" || value.Decision != "pending" || value.ResolvedDisagreements == nil || len(value.ResolvedDisagreements) != 0 || value.ReviewerIdentifier != "" || value.ReviewDate != "" {
		return ErrInvalidDeterministicCorpus
	}
	return nil
}

func loadCorpusCase(fsys fs.FS, root string, manifest corpusManifest, item corpusCaseManifest, expectedPaths map[string]struct{}) (deterministicCorpusCase, error) {
	loaded := deterministicCorpusCase{manifest: item, base: map[string][]byte{}, head: map[string][]byte{}}
	for _, descriptor := range item.Files {
		name := root + "/cases/" + item.ID + "/" + descriptor.Side + "/" + descriptor.Path
		if _, exists := expectedPaths[name]; exists {
			return deterministicCorpusCase{}, ErrInvalidDeterministicCorpus
		}
		expectedPaths[name] = struct{}{}
		content, err := readBoundedFile(fsys, name, manifest.Bounds.MaximumFileBytes)
		if err != nil || len(content) != descriptor.Bytes || digestBytes(content) != descriptor.SHA256 {
			return deterministicCorpusCase{}, ErrInvalidDeterministicCorpus
		}
		if descriptor.Side == "base" {
			loaded.base[descriptor.Path] = content
		} else {
			loaded.head[descriptor.Path] = content
		}
	}
	labelName := root + "/" + item.LabelsPath
	expectedPaths[labelName] = struct{}{}
	labelBytes, err := readBoundedFile(fsys, labelName, manifest.Bounds.MaximumFileBytes)
	if err != nil || len(labelBytes) != item.LabelsBytes || digestBytes(labelBytes) != item.LabelsSHA256 || decodeStrictJSON(labelBytes, manifest.Bounds.MaximumFileBytes, &loaded.labels) != nil || validateCaseLabels(manifest, loaded) != nil {
		return deterministicCorpusCase{}, ErrInvalidDeterministicCorpus
	}
	return loaded, nil
}

func validateCaseLabels(manifest corpusManifest, item deterministicCorpusCase) error {
	labels := item.labels
	if labels.SchemaVersion != 1 || labels.CaseID != item.manifest.ID || labels.Changes == nil || labels.Targets == nil || len(labels.Targets) == 0 {
		return ErrInvalidDeterministicCorpus
	}
	previous := ""
	for _, change := range labels.Changes {
		if !validCorpusPath(change.Path) || change.Path <= previous {
			return ErrInvalidDeterministicCorpus
		}
		base, baseOK := item.base[change.Path]
		head, headOK := item.head[change.Path]
		if !baseOK || !headOK || bytes.Equal(base, head) {
			return ErrInvalidDeterministicCorpus
		}
		patch, err := evidence.GenerateUnifiedFileDiff(change.Path, base, head)
		if err != nil {
			return ErrInvalidDeterministicCorpus
		}
		fileChange, _, err := evidence.ParseUnifiedFileDiff(change.Path, base, head, patch)
		if err != nil || !equalCorpusRanges(change.Ranges, fileChange.ChangedRanges()) {
			return ErrInvalidDeterministicCorpus
		}
		previous = change.Path
	}
	if len(item.base) != len(item.head) {
		return ErrInvalidDeterministicCorpus
	}
	changedPaths := make(map[string]struct{}, len(labels.Changes))
	for _, change := range labels.Changes {
		changedPaths[change.Path] = struct{}{}
	}
	for filePath, baseContent := range item.base {
		headContent, ok := item.head[filePath]
		_, changed := changedPaths[filePath]
		if !ok || bytes.Equal(baseContent, headContent) == changed {
			return ErrInvalidDeterministicCorpus
		}
	}
	knownTargets := map[string]corpusTarget{}
	for _, target := range manifest.Targets {
		knownTargets[target.Key] = target
	}
	previous = ""
	for _, target := range labels.Targets {
		if _, ok := knownTargets[target.Key]; !ok || target.Key <= previous || target.Expected == nil || target.ExpectedCoverage == nil || len(target.Expected) > manifest.Bounds.MaximumLabelsPerTarget || len(target.ExpectedCoverage) == 0 {
			return ErrInvalidDeterministicCorpus
		}
		previousKey := ""
		for _, label := range target.Expected {
			key, err := labelMatchKey(labels.CaseID, target.Key, label)
			if err != nil || key <= previousKey || !validTargetLabelSource(item, target.Key, label, changedPaths) {
				return ErrInvalidDeterministicCorpus
			}
			previousKey = key
		}
		coveragePaths := targetCoveragePaths(item, target.Key)
		if len(target.ExpectedCoverage) != len(coveragePaths) {
			return ErrInvalidDeterministicCorpus
		}
		for index, coverage := range target.ExpectedCoverage {
			if coverage.Path != coveragePaths[index] || !validCoveragePair(coverage.Outcome, coverage.Reason) {
				return ErrInvalidDeterministicCorpus
			}
		}
		previous = target.Key
	}
	return nil
}

func equalCorpusRanges(expected []corpusRange, observed []evidence.SourceRange) bool {
	if len(expected) != len(observed) {
		return false
	}
	for index := range expected {
		if expected[index].StartLine != observed[index].StartLine() || expected[index].EndLine != observed[index].EndLine() {
			return false
		}
	}
	return true
}

func targetCoveragePaths(item deterministicCorpusCase, target string) []string {
	paths := make([]string, 0)
	switch target {
	case "vendor_path", "go_test_path", "contains_nul":
		for filePath := range item.head {
			paths = append(paths, filePath)
		}
	case "syntactic_reference_candidate":
		for filePath := range item.head {
			if path.Ext(filePath) == ".go" {
				paths = append(paths, filePath)
			}
		}
	default:
		for _, change := range item.labels.Changes {
			paths = append(paths, change.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

func validTargetLabelSource(item deterministicCorpusCase, target string, label corpusLabel, changedPaths map[string]struct{}) bool {
	headContent, headExists := item.head[label.Path]
	_, changed := changedPaths[label.Path]
	switch target {
	case "vendor_path", "go_test_path", "contains_nul":
		return headExists
	case "static_debug_output":
		return changed && path.Ext(label.Path) == ".go" && validSourceRange(headContent, label.StartLine, label.EndLine) && overlapsChangedRange(item.labels.Changes, label.Path, label.StartLine, label.EndLine)
	case "go_changed_symbol":
		return changed && path.Ext(label.Path) == ".go" && validSourceRange(headContent, label.StartLine, label.EndLine) && overlapsChangedRange(item.labels.Changes, label.Path, label.StartLine, label.EndLine)
	case "changed_declaration", "public_api_change":
		_, baseExists := item.base[label.Path]
		return changed && (baseExists || headExists)
	case "syntactic_reference_candidate":
		return headExists && path.Ext(label.Path) == ".go" && validSourcePosition(headContent, label.Line, label.Column)
	default:
		return false
	}
}

func validSourceRange(content []byte, startLine, endLine int) bool {
	lineCount := physicalLineCountBytes(content)
	return startLine >= 1 && endLine >= startLine && endLine <= lineCount
}

func validSourcePosition(content []byte, line, column int) bool {
	lines := bytes.Split(content, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return line >= 1 && line <= len(lines) && column >= 1 && column <= len(lines[line-1])
}

func physicalLineCountBytes(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}

func overlapsChangedRange(changes []corpusChange, filePath string, startLine, endLine int) bool {
	for _, change := range changes {
		if change.Path != filePath {
			continue
		}
		for _, changedRange := range change.Ranges {
			if startLine <= changedRange.EndLine && endLine >= changedRange.StartLine {
				return true
			}
		}
	}
	return false
}

func validCoveragePair(outcome, reason string) bool {
	switch outcome {
	case "analyzed":
		return reason == "none"
	case "abstained":
		return reason == "parse_failure" || reason == "source_unavailable" || reason == "limit_exceeded"
	case "unsupported":
		return reason == "unsupported_language"
	case "not_applicable":
		return reason == "no_positive_head_ranges" || reason == "no_positive_head_hunks"
	default:
		return false
	}
}

func labelMatchKey(caseID, target string, label corpusLabel) (string, error) {
	if !validCorpusPath(label.Path) {
		return "", ErrInvalidDeterministicCorpus
	}
	prefix := caseID + "\x00" + label.Path + "\x00"
	switch target {
	case "static_debug_output":
		if label.StartLine < 1 || label.EndLine < label.StartLine || label.Signal != "" || label.Kind != "" || label.QualifiedName != "" || label.DeclarationKey != "" || label.ChangeKind != "" || label.Line != 0 || label.Column != 0 {
			return "", ErrInvalidDeterministicCorpus
		}
		return fmt.Sprintf("%s%09d\x00%09d", prefix, label.StartLine, label.EndLine), nil
	case "vendor_path", "go_test_path", "contains_nul":
		if label.Signal != target || label.StartLine != 0 || label.EndLine != 0 || label.Kind != "" || label.QualifiedName != "" || label.DeclarationKey != "" || label.ChangeKind != "" || label.Line != 0 || label.Column != 0 {
			return "", ErrInvalidDeterministicCorpus
		}
		return prefix + label.Signal, nil
	case "go_changed_symbol":
		if (label.Kind != "function" && label.Kind != "method") || label.QualifiedName == "" || label.StartLine < 1 || label.EndLine < label.StartLine || label.Signal != "" || label.DeclarationKey != "" || label.ChangeKind != "" || label.Line != 0 || label.Column != 0 {
			return "", ErrInvalidDeterministicCorpus
		}
		return fmt.Sprintf("%s%s\x00%s\x00%09d\x00%09d", prefix, label.Kind, label.QualifiedName, label.StartLine, label.EndLine), nil
	case "changed_declaration", "public_api_change":
		if label.DeclarationKey == "" || (label.ChangeKind != "added" && label.ChangeKind != "modified" && label.ChangeKind != "removed") || label.StartLine != 0 || label.EndLine != 0 || label.Signal != "" || label.Kind != "" || label.QualifiedName != "" || label.Line != 0 || label.Column != 0 {
			return "", ErrInvalidDeterministicCorpus
		}
		return prefix + label.DeclarationKey + "\x00" + label.ChangeKind, nil
	case "syntactic_reference_candidate":
		if label.DeclarationKey == "" || label.Line < 1 || label.Column < 1 || label.StartLine != 0 || label.EndLine != 0 || label.Signal != "" || label.Kind != "" || label.QualifiedName != "" || label.ChangeKind != "" {
			return "", ErrInvalidDeterministicCorpus
		}
		return fmt.Sprintf("%s%s\x00%09d\x00%09d", prefix, label.DeclarationKey, label.Line, label.Column), nil
	default:
		return "", ErrInvalidDeterministicCorpus
	}
}

type setScore[T ~string] struct {
	Expected          uint32
	Observed          uint32
	TruePositive      uint32
	FalsePositive     uint32
	FalseNegative     uint32
	Precision         [2]uint32
	Recall            [2]uint32
	FalsePositiveKeys []T
	FalseNegativeKeys []T
}

func scoreCanonicalSets[T ~string](expected, observed []T) setScore[T] {
	expectedSet := map[T]struct{}{}
	observedSet := map[T]struct{}{}
	for _, value := range expected {
		expectedSet[value] = struct{}{}
	}
	for _, value := range observed {
		observedSet[value] = struct{}{}
	}
	result := setScore[T]{Expected: uint32(len(expectedSet)), Observed: uint32(len(observedSet))}
	for value := range expectedSet {
		if _, ok := observedSet[value]; ok {
			result.TruePositive++
		} else {
			result.FalseNegativeKeys = append(result.FalseNegativeKeys, value)
		}
	}
	for value := range observedSet {
		if _, ok := expectedSet[value]; !ok {
			result.FalsePositiveKeys = append(result.FalsePositiveKeys, value)
		}
	}
	sort.Slice(result.FalsePositiveKeys, func(i, j int) bool { return result.FalsePositiveKeys[i] < result.FalsePositiveKeys[j] })
	sort.Slice(result.FalseNegativeKeys, func(i, j int) bool { return result.FalseNegativeKeys[i] < result.FalseNegativeKeys[j] })
	result.FalsePositive = uint32(len(result.FalsePositiveKeys))
	result.FalseNegative = uint32(len(result.FalseNegativeKeys))
	result.Precision = [2]uint32{result.TruePositive, result.TruePositive + result.FalsePositive}
	result.Recall = [2]uint32{result.TruePositive, result.TruePositive + result.FalseNegative}
	return result
}

type coverageObservation struct{ Path, Outcome, Reason string }
type abstentionReasonCount struct {
	Reason string `json:"reason"`
	Count  uint32 `json:"count"`
}
type coverageSummary struct {
	ApplicableUnits    uint32                  `json:"applicable_units"`
	AnalyzedUnits      uint32                  `json:"analyzed_units"`
	AbstainedUnits     uint32                  `json:"abstained_units"`
	UnsupportedUnits   uint32                  `json:"unsupported_units"`
	NotApplicableUnits uint32                  `json:"not_applicable_units"`
	Coverage           [2]uint32               `json:"-"`
	AbstentionRate     [2]uint32               `json:"-"`
	AbstentionReasons  []abstentionReasonCount `json:"abstention_reasons"`
}

func summarizeCoverage(values []coverageObservation) coverageSummary {
	result := coverageSummary{AbstentionReasons: []abstentionReasonCount{}}
	reasons := map[string]uint32{}
	for _, value := range values {
		switch value.Outcome {
		case "analyzed":
			result.AnalyzedUnits++
		case "abstained":
			result.AbstainedUnits++
			reasons[value.Reason]++
		case "unsupported":
			result.UnsupportedUnits++
		case "not_applicable":
			result.NotApplicableUnits++
		}
	}
	result.ApplicableUnits = result.AnalyzedUnits + result.AbstainedUnits
	result.Coverage = [2]uint32{result.AnalyzedUnits, result.ApplicableUnits}
	result.AbstentionRate = [2]uint32{result.AbstainedUnits, result.ApplicableUnits}
	keys := make([]string, 0, len(reasons))
	for key := range reasons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result.AbstentionReasons = append(result.AbstentionReasons, abstentionReasonCount{key, reasons[key]})
	}
	return result
}

func buildCorpusChange(item deterministicCorpusCase) (evidence.Change, map[string][]byte, error) {
	fileChanges := make([]evidence.FileChange, 0, len(item.labels.Changes))
	lineMaps := make([]evidence.LineMap, 0, len(item.labels.Changes))
	head := map[string][]byte{}
	for _, changed := range item.labels.Changes {
		baseContent, headContent := item.base[changed.Path], item.head[changed.Path]
		patch, err := evidence.GenerateUnifiedFileDiff(changed.Path, baseContent, headContent)
		if err != nil {
			return evidence.Change{}, nil, err
		}
		fileChange, lineMap, err := evidence.ParseUnifiedFileDiff(changed.Path, baseContent, headContent, patch)
		if err != nil {
			return evidence.Change{}, nil, err
		}
		fileChanges = append(fileChanges, fileChange)
		lineMaps = append(lineMaps, lineMap)
		head[changed.Path] = headContent
	}
	change, err := evidence.NewChange(fileChanges, lineMaps)
	return change, head, err
}

func semanticProfile(item deterministicCorpusCase) (semanticimpact.Profile, error) {
	changes := make([]semanticimpact.ChangedPath, 0, len(item.labels.Changes))
	for _, change := range item.labels.Changes {
		value, err := semanticimpact.NewChangedPath(change.Path)
		if err != nil {
			return semanticimpact.Profile{}, err
		}
		changes = append(changes, value)
	}
	baseFiles := []semanticimpact.File{}
	headFiles := []semanticimpact.File{}
	paths := make([]string, 0, len(item.base))
	for p := range item.base {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if path.Ext(p) != ".go" {
			continue
		}
		value, err := semanticimpact.NewFile(p, item.base[p])
		if err != nil {
			return semanticimpact.Profile{}, err
		}
		baseFiles = append(baseFiles, value)
	}
	paths = paths[:0]
	for p := range item.head {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if path.Ext(p) != ".go" {
			continue
		}
		value, err := semanticimpact.NewFile(p, item.head[p])
		if err != nil {
			return semanticimpact.Profile{}, err
		}
		headFiles = append(headFiles, value)
	}
	baseID := snapshotIdentity(item.base)
	headID := snapshotIdentity(item.head)
	changeID := digestBytes([]byte("open-trestle/deterministic-corpus-change/v1\x00" + item.manifest.ID))
	input, err := semanticimpact.NewInput(baseID, headID, changeID, changes, baseFiles, headFiles)
	if err != nil {
		return semanticimpact.Profile{}, err
	}
	return semanticimpact.AnalyzeGo(input)
}

func snapshotIdentity(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(digestBytes(files[p])))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type targetExecution struct {
	observed []string
	coverage []coverageObservation
}

func evaluateCaseTarget(item deterministicCorpusCase, target corpusCaseTarget) (targetExecution, error) {
	switch target.Key {
	case "static_debug_output":
		change, head, err := buildCorpusChange(item)
		if err != nil {
			return targetExecution{}, err
		}
		result, err := review.ReviewDebugOutputChange(change, head, review.DebugOutputChangeLimits{MaxFiles: 16, MaxBytesPerFile: 1 << 20, MaxTotalBytes: 8 << 20, MaxFindings: 128})
		if err != nil {
			return targetExecution{}, err
		}
		out := targetExecution{}
		for _, finding := range result.Findings() {
			r := finding.SourceRange()
			key, _ := labelMatchKey(item.manifest.ID, target.Key, corpusLabel{Path: r.Path(), StartLine: r.StartLine(), EndLine: r.EndLine()})
			out.observed = append(out.observed, key)
		}
		for _, file := range result.Files() {
			outcome, reason := string(file.Outcome()), string(file.Reason())
			out.coverage = append(out.coverage, coverageObservation{file.Path(), outcome, reason})
		}
		return out, nil
	case "vendor_path", "go_test_path", "contains_nul":
		paths := make([]string, 0, len(item.head))
		for p := range item.head {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		files := make([]evidence.RepositoryFile, 0, len(paths))
		for _, p := range paths {
			f, err := evidence.NewRepositoryFile(p, item.head[p])
			if err != nil {
				return targetExecution{}, err
			}
			files = append(files, f)
		}
		manifest, err := evidence.NewRepositoryManifest(files)
		if err != nil {
			return targetExecution{}, err
		}
		result, err := internalanalysis.ClassifyRepositoryManifest(manifest, item.head)
		if err != nil {
			return targetExecution{}, err
		}
		out := targetExecution{}
		for _, file := range result.Files() {
			positive := target.Key == "vendor_path" && file.IsVendorPath() || target.Key == "go_test_path" && file.IsGoTestPath() || target.Key == "contains_nul" && file.ContentSignal() == internalanalysis.FileContentContainsNUL
			if positive {
				key, _ := labelMatchKey(item.manifest.ID, target.Key, corpusLabel{Path: file.Path(), Signal: target.Key})
				out.observed = append(out.observed, key)
			}
			out.coverage = append(out.coverage, coverageObservation{file.Path(), "analyzed", "none"})
		}
		return out, nil
	case "go_changed_symbol":
		change, head, err := buildCorpusChange(item)
		if err != nil {
			return targetExecution{}, err
		}
		goHead := map[string][]byte{}
		for p, value := range head {
			if path.Ext(p) == ".go" {
				goHead[p] = value
			}
		}
		profile, receipt, err := internalanalysis.BuildGoChangeImpactProfile(change, goHead)
		if err != nil {
			return targetExecution{}, err
		}
		out := targetExecution{}
		for _, symbol := range profile.Symbols() {
			r := symbol.SourceRange()
			key, _ := labelMatchKey(item.manifest.ID, target.Key, corpusLabel{Path: symbol.Path(), Kind: string(symbol.Kind()), QualifiedName: symbol.QualifiedName(), StartLine: r.StartLine(), EndLine: r.EndLine()})
			out.observed = append(out.observed, key)
		}
		for _, file := range receipt.Files() {
			out.coverage = append(out.coverage, coverageObservation{file.Path(), string(file.Outcome()), string(file.Reason())})
		}
		return out, nil
	case "changed_declaration", "public_api_change", "syntactic_reference_candidate":
		profile, err := semanticProfile(item)
		if err != nil {
			return targetExecution{}, err
		}
		out := targetExecution{}
		if target.Key == "syntactic_reference_candidate" {
			references, err := indexReferences(item, profile)
			if err != nil {
				return targetExecution{}, err
			}
			for _, ref := range references {
				key, _ := labelMatchKey(item.manifest.ID, target.Key, ref)
				out.observed = append(out.observed, key)
			}
		} else {
			declarations := profile.Declarations()
			if target.Key == "public_api_change" {
				declarations = profile.PublicAPIChanges()
			}
			for _, declaration := range declarations {
				key, _ := labelMatchKey(item.manifest.ID, target.Key, corpusLabel{Path: declaration.Path(), DeclarationKey: declaration.Key(), ChangeKind: string(declaration.Change())})
				out.observed = append(out.observed, key)
			}
		}
		gaps := map[string]semanticimpact.Gap{}
		for _, gap := range profile.Gaps() {
			gaps[gap.Path()] = gap
		}
		coveragePaths := targetCoveragePaths(item, target.Key)
		for _, filePath := range coveragePaths {
			if gap, ok := gaps[filePath]; ok {
				outcome := "abstained"
				if gap.Reason() == semanticimpact.GapUnsupportedLanguage {
					outcome = "unsupported"
				}
				out.coverage = append(out.coverage, coverageObservation{filePath, outcome, string(gap.Reason())})
			} else {
				out.coverage = append(out.coverage, coverageObservation{filePath, "analyzed", "none"})
			}
		}
		return out, nil
	default:
		return targetExecution{}, ErrInvalidDeterministicCorpus
	}
}

func expectedKeys(caseID string, target corpusCaseTarget) ([]string, error) {
	values := make([]string, len(target.Expected))
	for i, label := range target.Expected {
		key, err := labelMatchKey(caseID, target.Key, label)
		if err != nil {
			return nil, err
		}
		values[i] = key
	}
	return values, nil
}
func coverageKey(path, outcome, reason string) string {
	return path + "\x00" + outcome + "\x00" + reason
}

type deterministicCaseResult struct {
	ID                    string `json:"id"`
	TargetKey             string `json:"target_key"`
	ExpectedCount         uint32 `json:"expected_count"`
	ObservedCount         uint32 `json:"observed_count"`
	TruePositiveCount     uint32 `json:"true_positive_count"`
	FalsePositiveCount    uint32 `json:"false_positive_count"`
	FalseNegativeCount    uint32 `json:"false_negative_count"`
	CoverageMismatchCount uint32 `json:"coverage_mismatch_count"`
}

type deterministicTargetResult struct {
	Key                   string                  `json:"key"`
	Version               int                     `json:"version"`
	Family                string                  `json:"family"`
	MatchUnit             string                  `json:"match_unit"`
	CaseCount             uint32                  `json:"case_count"`
	ExpectedCount         uint32                  `json:"expected_count"`
	ObservedCount         uint32                  `json:"observed_count"`
	TruePositiveCount     uint32                  `json:"true_positive_count"`
	FalsePositiveCount    uint32                  `json:"false_positive_count"`
	FalseNegativeCount    uint32                  `json:"false_negative_count"`
	PrecisionNumerator    uint32                  `json:"precision_numerator"`
	PrecisionDenominator  uint32                  `json:"precision_denominator"`
	RecallNumerator       uint32                  `json:"recall_numerator"`
	RecallDenominator     uint32                  `json:"recall_denominator"`
	ApplicableUnits       uint32                  `json:"applicable_units"`
	AnalyzedUnits         uint32                  `json:"analyzed_units"`
	AbstainedUnits        uint32                  `json:"abstained_units"`
	UnsupportedUnits      uint32                  `json:"unsupported_units"`
	NotApplicableUnits    uint32                  `json:"not_applicable_units"`
	CoverageNumerator     uint32                  `json:"coverage_numerator"`
	CoverageDenominator   uint32                  `json:"coverage_denominator"`
	AbstentionNumerator   uint32                  `json:"abstention_numerator"`
	AbstentionDenominator uint32                  `json:"abstention_denominator"`
	AbstentionReasons     []abstentionReasonCount `json:"abstention_reasons"`
}

type deterministicWorkload struct {
	FixtureFileCount       uint32 `json:"fixture_file_count"`
	FixtureByteCount       uint64 `json:"fixture_byte_count"`
	ChangedFileCount       uint32 `json:"changed_file_count"`
	ChangedRangeCount      uint32 `json:"changed_range_count"`
	PredictionCount        uint32 `json:"prediction_count"`
	MaximumCases           uint32 `json:"maximum_cases"`
	MaximumFiles           uint32 `json:"maximum_files"`
	MaximumTotalBytes      uint64 `json:"maximum_total_bytes"`
	MaximumFileBytes       uint64 `json:"maximum_file_bytes"`
	MaximumLabelsPerTarget uint32 `json:"maximum_labels_per_target"`
}

type DeterministicCorpusReport struct {
	identity                 string
	corpusIdentity           string
	labelSetIdentity         string
	adjudicationIdentity     string
	evaluatorIdentity        string
	staticDebugSuiteIdentity string
	reviewState              string
	executionStatus          string
	caseCount                uint32
	targetCount              uint32
	workload                 deterministicWorkload
	targets                  []deterministicTargetResult
	cases                    []deterministicCaseResult
}

func (r DeterministicCorpusReport) Identity() string              { return r.identity }
func (r DeterministicCorpusReport) ReviewState() string           { return r.reviewState }
func (r DeterministicCorpusReport) ExecutionStatus() string       { return r.executionStatus }
func (r DeterministicCorpusReport) CaseCount() uint32             { return r.caseCount }
func (r DeterministicCorpusReport) TargetCount() uint32           { return r.targetCount }
func (r DeterministicCorpusReport) ReleaseEvidenceEligible() bool { return false }
func (r DeterministicCorpusReport) Cases() []deterministicCaseResult {
	return append([]deterministicCaseResult(nil), r.cases...)
}
func (r DeterministicCorpusReport) Targets() []deterministicTargetResult {
	return append([]deterministicTargetResult(nil), r.targets...)
}

func deriveLabelSetIdentity(manifest corpusManifest) string {
	type row struct{ ID, Digest string }
	rows := make([]row, len(manifest.Cases))
	for i, c := range manifest.Cases {
		rows[i] = row{c.ID, c.LabelsSHA256}
	}
	encoded, _ := json.Marshal(struct {
		Contract string
		Version  int
		Rows     []row
	}{"open-trestle/deterministic-corpus-label-set", 1, rows})
	return digestBytes(encoded)
}
func deriveEvaluatorIdentity(targets []corpusTarget) string {
	encoded, _ := json.Marshal(struct {
		Contract string
		Version  int
		Targets  []corpusTarget
		APIs     []string
	}{"open-trestle/deterministic-corpus-evaluator", 1, targets, []string{"analysis.BuildGoChangeImpactProfile/v1", "analysis.ClassifyRepositoryManifest/v1", "review.ReviewDebugOutputChange/v1", "semanticimpact.AnalyzeGo/v1"}})
	return digestBytes(encoded)
}

func evaluateDeterministicCorpusCandidateUnchecked() (DeterministicCorpusReport, error) {
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		return DeterministicCorpusReport{}, err
	}
	staticReport, err := EvaluateStaticDebug()
	if err != nil {
		return DeterministicCorpusReport{}, err
	}
	report := DeterministicCorpusReport{corpusIdentity: corpus.manifest.CorpusIdentity, labelSetIdentity: deriveLabelSetIdentity(corpus.manifest), adjudicationIdentity: corpus.adjudicationIdentity, evaluatorIdentity: deriveEvaluatorIdentity(corpus.manifest.Targets), staticDebugSuiteIdentity: staticReport.SuiteIdentity(), reviewState: corpus.adjudication.ReviewState, caseCount: uint32(len(corpus.cases)), targetCount: uint32(len(corpus.manifest.Targets)), workload: deterministicWorkload{FixtureFileCount: corpus.fixtureFileCount, FixtureByteCount: corpus.fixtureByteCount, ChangedFileCount: corpus.changedFileCount, ChangedRangeCount: corpus.changedRangeCount, MaximumCases: uint32(corpus.manifest.Bounds.MaximumCases), MaximumFiles: uint32(corpus.manifest.Bounds.MaximumFiles), MaximumTotalBytes: uint64(corpus.manifest.Bounds.MaximumTotalBytes), MaximumFileBytes: uint64(corpus.manifest.Bounds.MaximumFileBytes), MaximumLabelsPerTarget: uint32(corpus.manifest.Bounds.MaximumLabelsPerTarget)}}
	targetByKey := map[string]int{}
	for i, target := range corpus.manifest.Targets {
		report.targets = append(report.targets, deterministicTargetResult{Key: target.Key, Version: target.Version, Family: target.Family, MatchUnit: target.MatchUnit, AbstentionReasons: []abstentionReasonCount{}})
		targetByKey[target.Key] = i
	}
	coverageByTarget := make([][]coverageObservation, len(report.targets))
	mismatch := false
	for _, item := range corpus.cases {
		for _, target := range item.labels.Targets {
			execution, err := evaluateCaseTarget(item, target)
			if err != nil {
				return DeterministicCorpusReport{}, fmt.Errorf("evaluate %s/%s: %w", item.manifest.ID, target.Key, err)
			}
			expected, err := expectedKeys(item.manifest.ID, target)
			if err != nil {
				return DeterministicCorpusReport{}, err
			}
			score := scoreCanonicalSets(expected, execution.observed)
			expectedCoverageKeys := make([]string, len(target.ExpectedCoverage))
			for i, value := range target.ExpectedCoverage {
				expectedCoverageKeys[i] = coverageKey(value.Path, value.Outcome, value.Reason)
			}
			observedCoverageKeys := make([]string, len(execution.coverage))
			for i, value := range execution.coverage {
				observedCoverageKeys[i] = coverageKey(value.Path, value.Outcome, value.Reason)
			}
			coverageScore := scoreCanonicalSets(expectedCoverageKeys, observedCoverageKeys)
			coverageMismatches := coverageScore.FalsePositive + coverageScore.FalseNegative
			row := deterministicCaseResult{item.manifest.ID, target.Key, score.Expected, score.Observed, score.TruePositive, score.FalsePositive, score.FalseNegative, coverageMismatches}
			report.cases = append(report.cases, row)
			index := targetByKey[target.Key]
			aggregate := &report.targets[index]
			aggregate.CaseCount++
			aggregate.ExpectedCount += score.Expected
			aggregate.ObservedCount += score.Observed
			aggregate.TruePositiveCount += score.TruePositive
			aggregate.FalsePositiveCount += score.FalsePositive
			aggregate.FalseNegativeCount += score.FalseNegative
			coverageByTarget[index] = append(coverageByTarget[index], execution.coverage...)
			report.workload.PredictionCount += score.Observed
			if score.FalsePositive > 0 || score.FalseNegative > 0 || coverageMismatches > 0 {
				mismatch = true
			}
		}
	}
	for index := range report.targets {
		target := &report.targets[index]
		target.PrecisionNumerator = target.TruePositiveCount
		target.PrecisionDenominator = target.TruePositiveCount + target.FalsePositiveCount
		target.RecallNumerator = target.TruePositiveCount
		target.RecallDenominator = target.TruePositiveCount + target.FalseNegativeCount
		coverage := summarizeCoverage(coverageByTarget[index])
		target.ApplicableUnits = coverage.ApplicableUnits
		target.AnalyzedUnits = coverage.AnalyzedUnits
		target.AbstainedUnits = coverage.AbstainedUnits
		target.UnsupportedUnits = coverage.UnsupportedUnits
		target.NotApplicableUnits = coverage.NotApplicableUnits
		target.CoverageNumerator = coverage.Coverage[0]
		target.CoverageDenominator = coverage.Coverage[1]
		target.AbstentionNumerator = coverage.AbstentionRate[0]
		target.AbstentionDenominator = coverage.AbstentionRate[1]
		target.AbstentionReasons = coverage.AbstentionReasons
	}
	sort.Slice(report.cases, func(i, j int) bool {
		if report.cases[i].ID != report.cases[j].ID {
			return report.cases[i].ID < report.cases[j].ID
		}
		return report.cases[i].TargetKey < report.cases[j].TargetKey
	})
	report.executionStatus = "matched"
	if mismatch {
		report.executionStatus = "mismatch"
	}
	report.identity = deriveDeterministicReportIdentity(report)
	return report, nil
}

// EvaluateDeterministicCorpusCandidate produces the pending embedded-corpus report.
func EvaluateDeterministicCorpusCandidate() (DeterministicCorpusReport, error) {
	report, err := evaluateDeterministicCorpusCandidateUnchecked()
	if err != nil || report.Validate() != nil {
		return DeterministicCorpusReport{}, ErrInvalidDeterministicCorpus
	}
	return report, nil
}

type deterministicReportWire struct {
	Contract                 string                      `json:"contract"`
	SchemaVersion            int                         `json:"schema_version"`
	Identity                 string                      `json:"identity"`
	CorpusIdentity           string                      `json:"corpus_identity"`
	LabelSetIdentity         string                      `json:"label_set_identity"`
	AdjudicationIdentity     string                      `json:"adjudication_identity"`
	EvaluatorIdentity        string                      `json:"evaluator_identity"`
	StaticDebugSuiteIdentity string                      `json:"static_debug_suite_identity"`
	ReviewState              string                      `json:"review_state"`
	ReleaseEvidenceEligible  bool                        `json:"release_evidence_eligible"`
	GoldenStatus             string                      `json:"golden_status"`
	ExecutionStatus          string                      `json:"execution_status"`
	CaseCount                uint32                      `json:"case_count"`
	TargetCount              uint32                      `json:"target_count"`
	Workload                 deterministicWorkload       `json:"workload"`
	Targets                  []deterministicTargetResult `json:"targets"`
	Cases                    []deterministicCaseResult   `json:"cases"`
}

func deterministicWire(report DeterministicCorpusReport) deterministicReportWire {
	return deterministicReportWire{Contract: "open-trestle/deterministic-corpus-candidate-result", SchemaVersion: 1, Identity: report.identity, CorpusIdentity: report.corpusIdentity, LabelSetIdentity: report.labelSetIdentity, AdjudicationIdentity: report.adjudicationIdentity, EvaluatorIdentity: report.evaluatorIdentity, StaticDebugSuiteIdentity: report.staticDebugSuiteIdentity, ReviewState: report.reviewState, ReleaseEvidenceEligible: false, GoldenStatus: "prohibited_pending_human_review", ExecutionStatus: report.executionStatus, CaseCount: report.caseCount, TargetCount: report.targetCount, Workload: report.workload, Targets: append([]deterministicTargetResult(nil), report.targets...), Cases: append([]deterministicCaseResult(nil), report.cases...)}
}
func deriveDeterministicReportIdentity(report DeterministicCorpusReport) string {
	wire := deterministicWire(report)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	return digestBytes(encoded)
}

func (r DeterministicCorpusReport) Validate() error {
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		return ErrInvalidDeterministicCorpus
	}
	staticReport, err := EvaluateStaticDebug()
	if err != nil {
		return ErrInvalidDeterministicCorpus
	}
	if !validCorpusDigest(r.identity) || r.corpusIdentity != corpus.manifest.CorpusIdentity || r.labelSetIdentity != deriveLabelSetIdentity(corpus.manifest) || r.adjudicationIdentity != corpus.adjudicationIdentity || r.evaluatorIdentity != deriveEvaluatorIdentity(corpus.manifest.Targets) || r.staticDebugSuiteIdentity != staticReport.SuiteIdentity() || r.reviewState != "pending" || (r.executionStatus != "matched" && r.executionStatus != "mismatch") || r.caseCount != uint32(len(corpus.cases)) || r.targetCount != uint32(len(corpus.manifest.Targets)) || len(r.targets) != len(corpus.manifest.Targets) || len(r.cases) == 0 {
		return ErrInvalidDeterministicCorpus
	}
	if r.workload.FixtureFileCount != corpus.fixtureFileCount || r.workload.FixtureByteCount != corpus.fixtureByteCount || r.workload.ChangedFileCount != corpus.changedFileCount || r.workload.ChangedRangeCount != corpus.changedRangeCount || r.workload.MaximumCases != uint32(corpus.manifest.Bounds.MaximumCases) || r.workload.MaximumFiles != uint32(corpus.manifest.Bounds.MaximumFiles) || r.workload.MaximumTotalBytes != uint64(corpus.manifest.Bounds.MaximumTotalBytes) || r.workload.MaximumFileBytes != uint64(corpus.manifest.Bounds.MaximumFileBytes) || r.workload.MaximumLabelsPerTarget != uint32(corpus.manifest.Bounds.MaximumLabelsPerTarget) {
		return ErrInvalidDeterministicCorpus
	}
	caseAggregates := make(map[string]deterministicTargetResult, len(r.targets))
	predictionCount := uint32(0)
	mismatch := false
	previousCase := ""
	for _, row := range r.cases {
		caseKey := row.ID + "\x00" + row.TargetKey
		if !validCaseID(row.ID) || !validCaseID(row.TargetKey) || caseKey <= previousCase || row.ExpectedCount != row.TruePositiveCount+row.FalseNegativeCount || row.ObservedCount != row.TruePositiveCount+row.FalsePositiveCount {
			return ErrInvalidDeterministicCorpus
		}
		agg := caseAggregates[row.TargetKey]
		agg.CaseCount++
		agg.ExpectedCount += row.ExpectedCount
		agg.ObservedCount += row.ObservedCount
		agg.TruePositiveCount += row.TruePositiveCount
		agg.FalsePositiveCount += row.FalsePositiveCount
		agg.FalseNegativeCount += row.FalseNegativeCount
		caseAggregates[row.TargetKey] = agg
		predictionCount += row.ObservedCount
		if row.FalsePositiveCount > 0 || row.FalseNegativeCount > 0 || row.CoverageMismatchCount > 0 {
			mismatch = true
		}
		previousCase = caseKey
	}
	if predictionCount != r.workload.PredictionCount || (r.executionStatus == "mismatch") != mismatch {
		return ErrInvalidDeterministicCorpus
	}
	for index, target := range r.targets {
		declared := corpus.manifest.Targets[index]
		agg := caseAggregates[target.Key]
		if target.Key != declared.Key || target.Version != declared.Version || target.Family != declared.Family || target.MatchUnit != declared.MatchUnit || target.CaseCount != agg.CaseCount || target.ExpectedCount != agg.ExpectedCount || target.ObservedCount != agg.ObservedCount || target.TruePositiveCount != agg.TruePositiveCount || target.FalsePositiveCount != agg.FalsePositiveCount || target.FalseNegativeCount != agg.FalseNegativeCount || target.PrecisionNumerator != target.TruePositiveCount || target.PrecisionDenominator != target.TruePositiveCount+target.FalsePositiveCount || target.RecallNumerator != target.TruePositiveCount || target.RecallDenominator != target.TruePositiveCount+target.FalseNegativeCount || target.ApplicableUnits != target.AnalyzedUnits+target.AbstainedUnits || target.CoverageNumerator != target.AnalyzedUnits || target.CoverageDenominator != target.ApplicableUnits || target.AbstentionNumerator != target.AbstainedUnits || target.AbstentionDenominator != target.ApplicableUnits {
			return ErrInvalidDeterministicCorpus
		}
		var abstained uint32
		previousReason := ""
		for _, reason := range target.AbstentionReasons {
			if reason.Reason <= previousReason || reason.Count == 0 || (reason.Reason != "parse_failure" && reason.Reason != "source_unavailable" && reason.Reason != "limit_exceeded") {
				return ErrInvalidDeterministicCorpus
			}
			abstained += reason.Count
			previousReason = reason.Reason
		}
		if abstained != target.AbstainedUnits {
			return ErrInvalidDeterministicCorpus
		}
	}
	if r.identity != deriveDeterministicReportIdentity(r) {
		return ErrInvalidDeterministicCorpus
	}
	expected, err := evaluateDeterministicCorpusCandidateUnchecked()
	if err != nil {
		return ErrInvalidDeterministicCorpus
	}
	actualWire, _ := json.Marshal(deterministicWire(r))
	expectedWire, _ := json.Marshal(deterministicWire(expected))
	if !bytes.Equal(actualWire, expectedWire) {
		return ErrInvalidDeterministicCorpus
	}
	return nil
}

func EncodeDeterministicCorpusReport(report DeterministicCorpusReport) ([]byte, error) {
	if report.Validate() != nil {
		return nil, ErrInvalidDeterministicCorpus
	}
	encoded, err := json.Marshal(deterministicWire(report))
	if err != nil || len(encoded) > maximumCorpusReportBytes {
		return nil, ErrInvalidDeterministicCorpus
	}
	return encoded, nil
}
func ParseDeterministicCorpusReport(encoded []byte) (DeterministicCorpusReport, error) {
	var wire deterministicReportWire
	if decodeStrictJSON(encoded, maximumCorpusReportBytes, &wire) != nil || wire.Contract != "open-trestle/deterministic-corpus-candidate-result" || wire.SchemaVersion != 1 || wire.ReleaseEvidenceEligible || wire.GoldenStatus != "prohibited_pending_human_review" {
		return DeterministicCorpusReport{}, ErrInvalidDeterministicCorpus
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(encoded, canonical) {
		return DeterministicCorpusReport{}, ErrInvalidDeterministicCorpus
	}
	report := DeterministicCorpusReport{identity: wire.Identity, corpusIdentity: wire.CorpusIdentity, labelSetIdentity: wire.LabelSetIdentity, adjudicationIdentity: wire.AdjudicationIdentity, evaluatorIdentity: wire.EvaluatorIdentity, staticDebugSuiteIdentity: wire.StaticDebugSuiteIdentity, reviewState: wire.ReviewState, executionStatus: wire.ExecutionStatus, caseCount: wire.CaseCount, targetCount: wire.TargetCount, workload: wire.Workload, targets: wire.Targets, cases: wire.Cases}
	if report.Validate() != nil {
		return DeterministicCorpusReport{}, ErrInvalidDeterministicCorpus
	}
	return report, nil
}

// indexReferences returns the repository index's reference candidates of
// each changed head declaration, from a graph of the case's head Go files
// analysed in memory.
func indexReferences(item deterministicCorpusCase, profile semanticimpact.Profile) ([]corpusLabel, error) {
	head := map[string][]byte{}
	for p, content := range item.head {
		if path.Ext(p) == ".go" || path.Base(p) == "go.mod" {
			head[p] = content
		}
	}
	analyzer, err := semanticimpact.NewGoSyntaxAnalyzer(syntaxanalysis.DefaultLimits())
	if err != nil {
		return nil, err
	}
	graph, err := repoindex.MemoryGraph(context.Background(), "head", head, analyzer)
	if err != nil {
		return nil, err
	}
	labels := []corpusLabel{}
	for _, declaration := range profile.Declarations() {
		if declaration.Change() == semanticimpact.ChangeRemoved {
			continue
		}
		for _, symbol := range graph.Definitions(declaration.Name()) {
			if symbol.Path != declaration.Path() || symbol.Range.Start.Line != declaration.StartLine() {
				continue
			}
			for _, use := range graph.References(symbol.ID) {
				labels = append(labels, corpusLabel{Path: use.Path, DeclarationKey: declaration.Key(), Line: use.Range.Start.Line, Column: use.Range.Start.Column})
			}
		}
	}
	return labels, nil
}
