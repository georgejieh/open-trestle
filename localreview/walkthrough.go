package localreview

import (
	"bytes"
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// The walkthrough is a verification-led summary of a direct review, built
// deterministically from the run's own recorded artifacts: what was verified
// (the deterministic checks that ran and what the independent verifier
// confirmed or rejected), a per-file change summary from the diff and the
// semantic-impact profile, and missing verification (changed functions no
// test file references). No model writes any of it.

// Walkthrough bounds keep the result within its output limits.
const (
	maxWalkthroughFiles               = 64
	maxWalkthroughDeclarationsPerFile = 16
	maxWalkthroughDeclarations        = 128
	maxWalkthroughMissing             = 32
	maxWalkthroughNameBytes           = 256
	maxWalkthroughPathBytes           = 4096
)

// Secret-scan states: every prepared model request was scanned (with the
// receipts' totals), no model request was prepared, or a receipt could not be
// read. Local-only requests are scanned as well as remote ones.
const (
	SecretScanScanned    = "scanned"
	SecretScanNotRun     = "not_run"
	SecretScanUnreadable = "unavailable"
)

// Walkthrough is the result's walkthrough (schema version 6, direct runs).
type Walkthrough struct {
	Verified WalkthroughVerified `json:"verified"`
	Files    []WalkthroughFile   `json:"files"`
	// FilesNotListed counts changed files past the listing bound.
	FilesNotListed int `json:"files_not_listed,omitempty"`
	// MissingVerification lists changed functions and methods that no test
	// file references. It is an informational class, never a defect, and
	// never changes the result's status or CI disposition.
	MissingVerification []MissingVerification `json:"missing_verification"`
	// MissingVerificationNotListed counts notes past the listing bound.
	MissingVerificationNotListed int `json:"missing_verification_not_listed,omitempty"`
	// MissingVerificationIncomplete is set when the semantic-impact scan did
	// not read every Go file, so a test it did not read may reference a
	// listed function.
	MissingVerificationIncomplete bool `json:"missing_verification_incomplete,omitempty"`
}

// WalkthroughVerified is what the review verified.
type WalkthroughVerified struct {
	SecretScan     WalkthroughSecretScan     `json:"secret_scan"`
	StaticChecks   []WalkthroughStaticCheck  `json:"static_checks"`
	StyleDetection WalkthroughStyleDetection `json:"style_detection"`
	SemanticImpact WalkthroughSemanticImpact `json:"semantic_impact"`
	// Verifier is the independent verifier's account; absent when the run
	// recorded no verified set.
	Verifier *WalkthroughVerifier `json:"verifier,omitempty"`
}

// WalkthroughSecretScan reports the secret scan of the run's model requests
// (see the secret-scan states). Requests counts the scan receipts: one per
// prepared request, whether or not it was then sent.
type WalkthroughSecretScan struct {
	State         string `json:"state"`
	Requests      int    `json:"requests,omitempty"`
	ScannedBytes  int    `json:"scanned_bytes,omitempty"`
	Matches       int    `json:"matches,omitempty"`
	RedactedBytes int    `json:"redacted_bytes,omitempty"`
}

// WalkthroughStaticCheck is one deterministic check of the analysis task.
type WalkthroughStaticCheck struct {
	Key          string `json:"key"`
	State        string `json:"state"`
	CheckedFiles uint32 `json:"checked_files"`
	Matches      uint32 `json:"matches"`
}

// WalkthroughStyleDetection reports declared-style detection.
type WalkthroughStyleDetection struct {
	State           string `json:"state"`
	Recommendations int    `json:"recommendations"`
	Withheld        int    `json:"withheld"`
}

// WalkthroughSemanticImpact summarizes the Go semantic-impact profile.
type WalkthroughSemanticImpact struct {
	State            string `json:"state"`
	Declarations     int    `json:"declarations"`
	PublicAPIChanges int    `json:"public_api_changes"`
	References       int    `json:"references"`
	TestReferences   int    `json:"test_references"`
	Gaps             int    `json:"gaps"`
}

// WalkthroughVerifier is the independent verifier's account of the candidates.
type WalkthroughVerifier struct {
	Candidates   uint16 `json:"candidates"`
	Verified     uint16 `json:"verified"`
	Rejected     uint16 `json:"rejected"`
	Inconclusive uint16 `json:"inconclusive"`
	Independence string `json:"independence"`
}

// WalkthroughFile is one changed file. Line counts are absent when the diff
// could not count them (binary or non-UTF-8 content, or past its bounds).
type WalkthroughFile struct {
	Path                  string                   `json:"path"`
	Change                string                   `json:"change"`
	RenamedFrom           string                   `json:"renamed_from,omitempty"`
	AddedLines            *uint32                  `json:"added_lines,omitempty"`
	RemovedLines          *uint32                  `json:"removed_lines,omitempty"`
	Declarations          []WalkthroughDeclaration `json:"declarations,omitempty"`
	DeclarationsNotListed int                      `json:"declarations_not_listed,omitempty"`
	// SemanticGap names why a Go file has no structural summary.
	SemanticGap string `json:"semantic_gap,omitempty"`
}

// WalkthroughDeclaration is one added, removed or changed Go declaration.
type WalkthroughDeclaration struct {
	Change          string `json:"change"`
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	PublicAPIChange bool   `json:"public_api_change,omitempty"`
}

// MissingVerification is one changed function or method that no test file
// references.
type MissingVerification struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Change string `json:"change"`
}

// walkthroughInputs is what readResult recorded for the walkthrough.
type walkthroughInputs struct {
	recorded     recordedChange
	analysis     *analysishandler.Result
	lines        changeLines
	style        StyleAdvice
	receipts     []string // sanitized egress receipt artifact identities
	verifier     *WalkthroughVerifier
	receiptError bool
}

// buildWalkthrough assembles the walkthrough from recorded artifacts. readReceipt
// reads one sanitized egress receipt's scan totals.
func buildWalkthrough(in walkthroughInputs, readReceipt func(string) (review.ScanCompletion, int, error)) *Walkthrough {
	w := &Walkthrough{Files: []WalkthroughFile{}, MissingVerification: []MissingVerification{}}
	w.Verified.StaticChecks = []WalkthroughStaticCheck{}
	w.Verified.SecretScan = secretScanSummary(in, readReceipt)
	w.Verified.StyleDetection = WalkthroughStyleDetection{State: "ran", Recommendations: len(in.style.Recommendations), Withheld: len(in.style.Withheld)}
	if in.style.Unavailable {
		w.Verified.StyleDetection = WalkthroughStyleDetection{State: "unavailable"}
	}
	w.Verified.Verifier = in.verifier
	w.Verified.SemanticImpact.State = "unavailable"
	var profile semanticimpact.Profile
	if in.analysis != nil {
		for _, check := range in.analysis.Checks() {
			w.Verified.StaticChecks = append(w.Verified.StaticChecks, WalkthroughStaticCheck{Key: check.Key(), State: check.State().String(), CheckedFiles: check.CheckedFiles(), Matches: check.MatchCount()})
		}
		profile = in.analysis.SemanticImpact()
		tests := 0
		for _, reference := range profile.References() {
			if reference.AffectedTest() {
				tests++
			}
		}
		w.Verified.SemanticImpact = WalkthroughSemanticImpact{State: "ran", Declarations: len(profile.Declarations()), PublicAPIChanges: len(profile.PublicAPIChanges()), References: len(profile.References()), TestReferences: tests, Gaps: len(profile.Gaps())}
	}
	w.Files, w.FilesNotListed = walkthroughFiles(in.recorded, in.lines, profile, in.analysis != nil)
	if in.analysis != nil {
		w.MissingVerification, w.MissingVerificationNotListed, w.MissingVerificationIncomplete = missingVerification(profile)
	}
	return w
}

func secretScanSummary(in walkthroughInputs, readReceipt func(string) (review.ScanCompletion, int, error)) WalkthroughSecretScan {
	if in.receiptError {
		return WalkthroughSecretScan{State: SecretScanUnreadable}
	}
	if len(in.receipts) == 0 {
		// No model request was prepared, so none was scanned or sent.
		return WalkthroughSecretScan{State: SecretScanNotRun}
	}
	summary := WalkthroughSecretScan{State: SecretScanScanned}
	for _, id := range in.receipts {
		scan, redacted, err := readReceipt(id)
		if err != nil || !scan.Complete {
			return WalkthroughSecretScan{State: SecretScanUnreadable}
		}
		summary.Requests++
		summary.ScannedBytes += scan.ScannedByteCount
		summary.Matches += scan.MatchCount
		summary.RedactedBytes += redacted
	}
	return summary
}

// walkthroughFiles lists the changed files in path order: renames (a removed
// file whose exact content is an added file) as one entry, line counts from
// the change-line accounting, and for Go files their changed declarations.
func walkthroughFiles(recorded recordedChange, lines changeLines, profile semanticimpact.Profile, hasProfile bool) ([]WalkthroughFile, int) {
	entries := recorded.change.Entries()
	addedByDigest := map[string]string{}
	for _, entry := range entries {
		if entry.Kind() == string(evidence.RepositoryFileDeltaAdded) && entry.HeadDigest() != "" {
			if _, seen := addedByDigest[entry.HeadDigest()]; seen {
				addedByDigest[entry.HeadDigest()] = ""
			} else {
				addedByDigest[entry.HeadDigest()] = entry.Path()
			}
		}
	}
	renamedTo, renamedFrom := map[string]string{}, map[string]string{}
	for _, entry := range entries {
		if entry.Kind() != string(evidence.RepositoryFileDeltaRemoved) || entry.BaseDigest() == "" {
			continue
		}
		if target := addedByDigest[entry.BaseDigest()]; target != "" && renamedFrom[target] == "" {
			renamedTo[entry.Path()], renamedFrom[target] = target, entry.Path()
		}
	}
	declarations := map[string][]semanticimpact.Declaration{}
	gaps := map[string]string{}
	if hasProfile {
		for _, declaration := range profile.Declarations() {
			declarations[declaration.Path()] = append(declarations[declaration.Path()], declaration)
		}
		for _, gap := range profile.Gaps() {
			if path.Ext(gap.Path()) == ".go" && gaps[gap.Path()] == "" {
				gaps[gap.Path()] = string(gap.Reason())
			}
		}
	}
	files := []WalkthroughFile{}
	notListed, listedDeclarations := 0, 0
	for _, entry := range entries {
		if renamedTo[entry.Path()] != "" {
			continue
		}
		if len(files) == maxWalkthroughFiles || len(entry.Path()) > maxWalkthroughPathBytes {
			notListed++
			continue
		}
		file := WalkthroughFile{Path: entry.Path(), Change: entry.Kind()}
		if from := renamedFrom[entry.Path()]; from != "" {
			zero := uint32(0)
			file.Change, file.RenamedFrom, file.AddedLines, file.RemovedLines = "renamed", from, &zero, &zero
		} else if accounting, ok := lines.paths[entry.Path()]; ok && accounting.known {
			added, removed := accounting.added, accounting.removed
			file.AddedLines, file.RemovedLines = &added, &removed
		}
		if path.Ext(entry.Path()) == ".go" && file.Change != "renamed" {
			file.SemanticGap = gaps[entry.Path()]
			for _, declaration := range declarations[entry.Path()] {
				name := declarationName(declaration)
				if len(file.Declarations) == maxWalkthroughDeclarationsPerFile || listedDeclarations == maxWalkthroughDeclarations || len(name) > maxWalkthroughNameBytes {
					file.DeclarationsNotListed++
					continue
				}
				listedDeclarations++
				file.Declarations = append(file.Declarations, WalkthroughDeclaration{Change: string(declaration.Change()), Kind: declaration.Kind(), Name: name, PublicAPIChange: declaration.PublicAPIChange()})
			}
		}
		files = append(files, file)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, notListed
}

// missingVerification lists added or changed functions and methods outside
// test files that no test file references, in path and name order. The
// semantic-impact references are syntactic candidates (identifier matches),
// so a listed function has no test reference at all, while an unlisted one
// may be referenced by a test of another declaration with the same name.
func missingVerification(profile semanticimpact.Profile) ([]MissingVerification, int, bool) {
	tested := map[string]bool{}
	for _, reference := range profile.References() {
		if reference.AffectedTest() {
			tested[reference.DeclarationIdentity()] = true
		}
	}
	notes := []MissingVerification{}
	notListed := 0
	for _, declaration := range profile.Declarations() {
		if declaration.Kind() != "function" && declaration.Kind() != "method" || declaration.Change() == semanticimpact.ChangeRemoved || strings.HasSuffix(declaration.Path(), "_test.go") || tested[declaration.Identity()] {
			continue
		}
		name := declarationName(declaration)
		if len(notes) == maxWalkthroughMissing || len(name) > maxWalkthroughNameBytes {
			notListed++
			continue
		}
		notes = append(notes, MissingVerification{Path: declaration.Path(), Kind: declaration.Kind(), Name: name, Change: string(declaration.Change())})
	}
	incomplete := false
	for _, gap := range profile.Gaps() {
		if gap.Reason() == semanticimpact.GapLimitExceeded || gap.Reason() == semanticimpact.GapSourceUnavailable {
			incomplete = true
		}
	}
	return notes, notListed, incomplete
}

// declarationName renders a declaration: a method with its receiver, such as
// "(*Calc).Divide", and anything else by its name.
func declarationName(declaration semanticimpact.Declaration) string {
	if declaration.Kind() == "method" {
		if rest, ok := strings.CutPrefix(declaration.Key(), "method:"); ok {
			if dot := strings.LastIndex(rest, "."); dot > 0 {
				return "(" + rest[:dot] + ")." + rest[dot+1:]
			}
		}
	}
	return declaration.Name()
}

// walkthroughOmittedLimitation records a walkthrough dropped because the
// result would not fit its output bound with it.
const walkthroughOmittedLimitation = "walkthrough_omitted_output_limit"

// readAnalysis reads a recorded deterministic analysis for a recorded change.
func (s *Session) readAnalysis(ctx context.Context, scope audit.ReviewScope, recorded recordedChange, analysisID string, at time.Time) (analysishandler.Result, error) {
	value, err := s.store.Get(ctx, scope, analysisID, at)
	if err != nil {
		return analysishandler.Result{}, err
	}
	analysis, err := analysishandler.ParseResultArtifact(value, recorded.artifact, recorded.base, recorded.head)
	if err != nil || analysis.ChangeIdentity() != recorded.change.Identity() {
		return analysishandler.Result{}, errInvalidWalkthrough
	}
	return analysis, nil
}

// withWalkthrough adds a direct run's walkthrough. When the result would
// exceed its JSON or text bound with it, the walkthrough is left out and the
// result records walkthrough_omitted_output_limit; it is never truncated.
func (s *Session) withWalkthrough(ctx context.Context, scope audit.ReviewScope, result Result, walk walkthroughInputs, lines changeLines) Result {
	walk.lines = lines
	if set := result.diagnostics; set.VerifiedSetIdentity() != "" {
		walk.verifier = &WalkthroughVerifier{Candidates: set.CandidateCount(), Verified: set.VerifiedCount(), Rejected: set.RejectedCount(), Inconclusive: set.InconclusiveCount(), Independence: result.wire.Independence}
	}
	readReceipt := func(id string) (review.ScanCompletion, int, error) {
		value, err := s.store.Get(ctx, scope, id, s.options.Clock.Now())
		if err != nil {
			return review.ScanCompletion{}, 0, err
		}
		receipt, err := review.ParseSanitizedEgressReceipt(value.Payload())
		if err != nil {
			return review.ScanCompletion{}, 0, err
		}
		return receipt.Initial(), receipt.RedactedByteCount(), nil
	}
	with := result
	with.wire.Walkthrough = buildWalkthrough(walk, readReceipt)
	var text bytes.Buffer
	if _, err := EncodeResult(with); err == nil && RenderResultWithOptions(&text, with, maximalText) == nil {
		return with
	}
	result.wire.Limitations = append(append([]string{}, result.wire.Limitations...), walkthroughOmittedLimitation)
	return result
}

var errInvalidWalkthrough = errors.New("invalid walkthrough")

// clone copies the walkthrough so a report never aliases a sealed result.
func (w *Walkthrough) clone() *Walkthrough {
	if w == nil {
		return nil
	}
	value := *w
	value.Verified.StaticChecks = append([]WalkthroughStaticCheck{}, w.Verified.StaticChecks...)
	if w.Verified.Verifier != nil {
		verifier := *w.Verified.Verifier
		value.Verified.Verifier = &verifier
	}
	value.Files = make([]WalkthroughFile, 0, len(w.Files))
	for _, file := range w.Files {
		file.Declarations = append([]WalkthroughDeclaration(nil), file.Declarations...)
		if file.AddedLines != nil {
			added := *file.AddedLines
			file.AddedLines = &added
		}
		if file.RemovedLines != nil {
			removed := *file.RemovedLines
			file.RemovedLines = &removed
		}
		value.Files = append(value.Files, file)
	}
	value.MissingVerification = append([]MissingVerification{}, w.MissingVerification...)
	return &value
}

// validate checks a parsed walkthrough's closed values and bounds.
func (w *Walkthrough) validate() error {
	if w == nil {
		return nil
	}
	if w.Files == nil || w.MissingVerification == nil || w.Verified.StaticChecks == nil || len(w.Files) > maxWalkthroughFiles || len(w.MissingVerification) > maxWalkthroughMissing || w.FilesNotListed < 0 || w.MissingVerificationNotListed < 0 {
		return errInvalidWalkthrough
	}
	switch w.Verified.SecretScan.State {
	case SecretScanScanned, SecretScanNotRun, SecretScanUnreadable:
	default:
		return errInvalidWalkthrough
	}
	if w.Verified.StyleDetection.State != "ran" && w.Verified.StyleDetection.State != "unavailable" || w.Verified.SemanticImpact.State != "ran" && w.Verified.SemanticImpact.State != "unavailable" {
		return errInvalidWalkthrough
	}
	text := func(value string, limit int) bool {
		return value != "" && len(value) <= limit && utf8.ValidString(value)
	}
	declarations := 0
	for _, file := range w.Files {
		switch file.Change {
		case "added", "modified", "removed", "renamed":
		default:
			return errInvalidWalkthrough
		}
		if !text(file.Path, maxWalkthroughPathBytes) || file.RenamedFrom != "" && !text(file.RenamedFrom, maxWalkthroughPathBytes) || (file.Change == "renamed") != (file.RenamedFrom != "") || len(file.Declarations) > maxWalkthroughDeclarationsPerFile || file.DeclarationsNotListed < 0 {
			return errInvalidWalkthrough
		}
		for _, declaration := range file.Declarations {
			if !text(declaration.Name, maxWalkthroughNameBytes) || declaration.Change != "added" && declaration.Change != "modified" && declaration.Change != "removed" || !validDeclarationKind(declaration.Kind) {
				return errInvalidWalkthrough
			}
			declarations++
		}
	}
	for _, note := range w.MissingVerification {
		if !text(note.Path, maxWalkthroughPathBytes) || !text(note.Name, maxWalkthroughNameBytes) || note.Kind != "function" && note.Kind != "method" || note.Change != "added" && note.Change != "modified" {
			return errInvalidWalkthrough
		}
	}
	if declarations > maxWalkthroughDeclarations {
		return errInvalidWalkthrough
	}
	return nil
}

func validDeclarationKind(kind string) bool {
	switch kind {
	case "function", "method", "type", "var", "const":
		return true
	}
	return false
}
