package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type localGitReviewStatus string

const (
	localGitReviewStatusFindings     localGitReviewStatus = "findings"
	localGitReviewStatusInconclusive localGitReviewStatus = "inconclusive"
	localGitReviewStatusNoChange     localGitReviewStatus = "no_change"
	localGitReviewStatusPartial      localGitReviewStatus = "partial"
	localGitReviewStatusUnsupported  localGitReviewStatus = "unsupported"
)

type localGitReviewLimitsResult struct {
	MaxFiles        int   `json:"max_files"`
	MaxBytesPerFile int   `json:"max_bytes_per_file"`
	MaxTotalBytes   int64 `json:"max_total_bytes"`
	MaxFindings     int   `json:"max_findings"`
}

type localGitReviewFileResult struct {
	Path       string `json:"path"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
	HeadDigest string `json:"head_digest"`
	MatchCount int    `json:"match_count"`
}

type localGitReviewFindingResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Path        string   `json:"path"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type localGitReviewEvidenceResult struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type localGitReviewResult struct {
	Contract                string                         `json:"contract"`
	SchemaVersion           int                            `json:"schema_version"`
	Status                  localGitReviewStatus           `json:"status"`
	ReviewExecutionIdentity string                         `json:"review_execution_identity"`
	ReviewPresent           bool                           `json:"review_present"`
	ReviewResultIdentity    string                         `json:"review_result_identity"`
	RuleVersion             string                         `json:"rule_version"`
	Limits                  localGitReviewLimitsResult     `json:"limits"`
	Change                  localGitChangeResult           `json:"change"`
	Files                   []localGitReviewFileResult     `json:"files"`
	Findings                []localGitReviewFindingResult  `json:"findings"`
	Evidence                []localGitReviewEvidenceResult `json:"evidence"`
}

func runLocalGitReview(args []string, stdout, stderr io.Writer) int {
	return runLocalGitReviewWithOpener(args, stdout, stderr, openLocalGitRoot)
}

func runLocalGitReviewWithOpener(args []string, stdout, stderr io.Writer, opener localGitRootOpener) int {
	options, repository, baseRevision, headRevision, err := parseLocalGitChangeOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "local-git review: %v\n", err)
		writeLocalGitReviewUsage(stderr)
		return 2
	}
	handle, err := opener(options.objectsRoot)
	if err != nil {
		fmt.Fprintln(stderr, "open object root: unavailable")
		return 1
	}
	if handle.close == nil {
		if handle.root != nil {
			_ = handle.root.Close()
		}
		fmt.Fprintln(stderr, "open object root: invalid root handle")
		return 1
	}
	if handle.root == nil {
		closeErr := handle.close()
		fmt.Fprint(stderr, "open object root: invalid root handle")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	encoded, resultCode, reviewErr := buildLocalGitReviewResult(handle.root, repository, baseRevision, headRevision)
	closeErr := handle.close()
	if reviewErr != nil {
		fmt.Fprint(stderr, "review local Git: failed")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintln(stderr, "close object root: failed")
		return 1
	}
	written, err := stdout.Write(encoded)
	if err == nil && written != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintln(stderr, "write result: failed")
		return 1
	}
	return resultCode
}

func buildLocalGitReviewResult(root *os.Root, repository evidence.RepositoryIdentity, baseRevision, headRevision evidence.RevisionIdentity) ([]byte, int, error) {
	store, err := scm.NewLocalGitObjectStore(root, repository)
	if err != nil {
		return nil, 0, err
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		return nil, 0, err
	}
	baseRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, baseRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return nil, 0, err
	}
	headRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, headRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return nil, 0, err
	}
	limits := localGitReviewLimits()
	execution, err := scm.ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, limits)
	if err != nil {
		return nil, 0, err
	}
	result, resultCode, err := newLocalGitReviewResult(execution, limits)
	if err != nil {
		return nil, 0, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, 0, fmt.Errorf("encode local Git review result: %w", err)
	}
	return append(encoded, '\n'), resultCode, nil
}

func newLocalGitReviewResult(execution scm.LocalGitDebugOutputReviewExecution, limits review.DebugOutputChangeLimits) (localGitReviewResult, int, error) {
	if execution.Identity() == "" {
		return localGitReviewResult{}, 0, fmt.Errorf("local Git debug-output review execution is required")
	}
	changeResult, _, err := newLocalGitChangeResult(execution.ChangeExecution())
	if err != nil {
		return localGitReviewResult{}, 0, err
	}
	result := localGitReviewResult{
		Contract: "open-trestle/local-git-review-result", SchemaVersion: 1,
		ReviewExecutionIdentity: execution.Identity(), ReviewPresent: execution.HasReview(),
		Limits: localGitReviewLimitsResult{
			MaxFiles: limits.MaxFiles, MaxBytesPerFile: limits.MaxBytesPerFile,
			MaxTotalBytes: limits.MaxTotalBytes, MaxFindings: limits.MaxFindings,
		},
		Change:   changeResult,
		Files:    make([]localGitReviewFileResult, 0),
		Findings: make([]localGitReviewFindingResult, 0),
		Evidence: make([]localGitReviewEvidenceResult, 0),
	}
	if !execution.HasReview() {
		if execution.Result().Identity() != "" || execution.ChangeExecution().HasChange() {
			return localGitReviewResult{}, 0, fmt.Errorf("absent local Git review result is inconsistent")
		}
		if changeResult.Status == localGitChangeStatusNoChange {
			result.Status = localGitReviewStatusNoChange
		} else {
			result.Status = localGitReviewStatusUnsupported
		}
		return result, 3, nil
	}
	staticResult := execution.Result()
	if staticResult.Identity() == "" || staticResult.ChangeIdentity() != execution.ChangeExecution().Change().Identity() {
		return localGitReviewResult{}, 0, fmt.Errorf("local Git review result does not match change")
	}
	findings := staticResult.Findings()
	items := staticResult.EvidenceItems()
	files := staticResult.Files()
	if err := validateLocalGitReviewEvidence(findings, items); err != nil || len(files) != changeResult.SupportedFileCount {
		return localGitReviewResult{}, 0, fmt.Errorf("local Git review result counts do not agree")
	}
	result.ReviewResultIdentity = staticResult.Identity()
	result.RuleVersion = staticResult.RuleVersion()
	result.Files = make([]localGitReviewFileResult, len(files))
	for index, file := range files {
		result.Files[index] = localGitReviewFileResult{
			Path: file.Path(), Outcome: string(file.Outcome()), Reason: string(file.Reason()),
			HeadDigest: file.HeadDigest(), MatchCount: file.MatchCount(),
		}
	}
	result.Evidence = make([]localGitReviewEvidenceResult, len(items))
	for index, item := range items {
		sourceRange := item.SourceRange()
		result.Evidence[index] = localGitReviewEvidenceResult{
			ID: item.ID(), Kind: string(item.Kind()), Digest: item.Digest(), Path: sourceRange.Path(),
			StartLine: sourceRange.StartLine(), EndLine: sourceRange.EndLine(),
		}
	}
	result.Findings = make([]localGitReviewFindingResult, len(findings))
	for index, finding := range findings {
		sourceRange := finding.SourceRange()
		result.Findings[index] = localGitReviewFindingResult{
			ID: finding.ID(), Title: finding.Title(), Severity: string(finding.Severity()),
			Path: sourceRange.Path(), StartLine: sourceRange.StartLine(), EndLine: sourceRange.EndLine(),
			EvidenceIDs: finding.EvidenceIDs(),
		}
	}
	switch {
	case changeResult.UnsupportedFileCount > 0:
		result.Status = localGitReviewStatusPartial
		return result, 3, nil
	case len(findings) > 0:
		result.Status = localGitReviewStatusFindings
		return result, 0, nil
	default:
		result.Status = localGitReviewStatusInconclusive
		return result, 3, nil
	}
}

func validateLocalGitReviewEvidence(findings []review.Finding, items []evidence.EvidenceItem) error {
	if len(findings) != len(items) {
		return fmt.Errorf("finding and evidence counts differ")
	}
	findingIDs := make(map[string]struct{}, len(findings))
	evidenceIDs := make(map[string]struct{}, len(items))
	for index, finding := range findings {
		item := items[index]
		if _, exists := findingIDs[finding.ID()]; exists {
			return fmt.Errorf("duplicate finding identity")
		}
		if _, exists := evidenceIDs[item.ID()]; exists {
			return fmt.Errorf("duplicate evidence identity")
		}
		ids := finding.EvidenceIDs()
		if len(ids) != 1 || ids[0] != item.ID() || finding.SourceRange() != item.SourceRange() {
			return fmt.Errorf("finding and evidence binding differs")
		}
		findingIDs[finding.ID()] = struct{}{}
		evidenceIDs[item.ID()] = struct{}{}
	}
	return nil
}

func localGitReviewLimits() review.DebugOutputChangeLimits {
	return review.DebugOutputChangeLimits{
		MaxFiles: 64, MaxBytesPerFile: 1 << 20,
		MaxTotalBytes: 64 << 20, MaxFindings: 1024,
	}
}

func writeLocalGitReviewUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git review --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --base-revision-digest FULL_LOWERCASE_HEX --head-revision-digest FULL_LOWERCASE_HEX")
}
