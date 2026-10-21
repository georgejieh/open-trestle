package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// RunProgress binds read-only coverage to one canonical receipt revision.
type RunProgress struct {
	Run      controlplane.ReviewRunReceipt `json:"run"`
	Progress ProgressCoverage              `json:"progress"`
}

// MarshalJSON preserves the canonical run receipt inside a progress document.
func (p RunProgress) MarshalJSON() ([]byte, error) {
	encoded, err := controlplane.EncodeReviewRunReceipt(p.Run)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Run      json.RawMessage  `json:"run"`
		Progress ProgressCoverage `json:"progress"`
	}{encoded, p.Progress})
}

type ProgressCoverage struct {
	Change        ChangeProgress        `json:"change"`
	Deterministic DeterministicProgress `json:"deterministic"`
	Context       ContextProgress       `json:"context"`
	Verification  VerificationProgress  `json:"verification"`
}
type ChangeProgress struct {
	State            string `json:"state"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	Files            *int   `json:"files,omitempty"`
	Ranges           *int   `json:"ranges,omitempty"`
}
type DeterministicProgress struct {
	State            string `json:"state"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	ApplicableFiles  *int   `json:"applicable_files,omitempty"`
	ApplicableRanges *int   `json:"applicable_ranges,omitempty"`
	CheckedFiles     *int   `json:"checked_files,omitempty"`
	CheckedRanges    *int   `json:"checked_ranges,omitempty"`
	Observations     *int   `json:"observations,omitempty"`
}
type ContextProgress struct {
	State            string `json:"state"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	Analyzed         *int   `json:"analyzed,omitempty"`
	Selected         *int   `json:"selected,omitempty"`
	Omitted          *int   `json:"omitted,omitempty"`
}
type VerificationProgress struct {
	State            string `json:"state"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	Candidates       *int   `json:"candidates,omitempty"`
	Verified         *int   `json:"verified,omitempty"`
	Rejected         *int   `json:"rejected,omitempty"`
	Inconclusive     *int   `json:"inconclusive,omitempty"`
}

// GetRunProgress reads immutable evidence counts without publishing diagnostics.
func (c *Client) GetRunProgress(ctx context.Context, scope audit.ReviewScope) (RunProgress, error) {
	if scope.Validate() != nil || c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return RunProgress{}, ErrInvalidClient
	}
	requestURL := *c.baseURL
	requestURL.Path = runPath(scope) + "/progress"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return RunProgress{}, ErrInvalidClient
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("User-Agent", "open-trestle-client/1")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRejected) {
			return RunProgress{}, ErrRedirectRejected
		}
		return RunProgress{}, fmt.Errorf("Open Trestle API request: %w", err)
	}
	defer response.Body.Close()
	encoded, tooLarge, err := readClientBody(response.Body)
	if err != nil || tooLarge {
		return RunProgress{}, ErrInvalidResponse
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return RunProgress{}, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK {
		record, err := parseClientResponse(encoded)
		if err != nil || record.Error == nil {
			return RunProgress{}, ErrInvalidResponse
		}
		return RunProgress{}, &APIError{statusCode: response.StatusCode, requestID: record.RequestID, code: record.Error.Code, message: record.Error.Message}
	}
	return parseRunProgress(encoded, scope)
}
func parseRunProgress(encoded []byte, scope audit.ReviewScope) (RunProgress, error) {
	var envelope struct {
		Contract      string           `json:"contract"`
		SchemaVersion int              `json:"schema_version"`
		RequestID     string           `json:"request_id"`
		Run           json.RawMessage  `json:"run"`
		Progress      ProgressCoverage `json:"progress"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Contract != "open-trestle/run-progress-response" || envelope.SchemaVersion != 1 || !validResponseValue(envelope.RequestID, 128) {
		return RunProgress{}, ErrInvalidResponse
	}
	receipt, err := controlplane.ParseReviewRunReceipt(envelope.Run)
	if err != nil || receipt.Scope().Identity() != scope.Identity() {
		return RunProgress{}, ErrInvalidResponse
	}
	p := envelope.Progress
	if !validProgressAxis(receipt, controlplane.TaskBuildChange, p.Change.State, p.Change.ArtifactIdentity, p.Change.Files, p.Change.Ranges) ||
		!validProgressAxis(receipt, controlplane.TaskInspectDeterministic, p.Deterministic.State, p.Deterministic.ArtifactIdentity, p.Deterministic.ApplicableFiles, p.Deterministic.ApplicableRanges, p.Deterministic.CheckedFiles, p.Deterministic.CheckedRanges, p.Deterministic.Observations) ||
		!validProgressAxis(receipt, controlplane.TaskAssembleContext, p.Context.State, p.Context.ArtifactIdentity, p.Context.Analyzed, p.Context.Selected, p.Context.Omitted) ||
		!validProgressAxis(receipt, controlplane.TaskVerifyCandidates, p.Verification.State, p.Verification.ArtifactIdentity, p.Verification.Candidates, p.Verification.Verified, p.Verification.Rejected, p.Verification.Inconclusive) {
		return RunProgress{}, ErrInvalidResponse
	}
	if progressAvailable(p.Change.State) && (p.Change.Files == nil || p.Change.Ranges == nil || *p.Change.Files > 4096 || *p.Change.Ranges > 1000000) {
		return RunProgress{}, ErrInvalidResponse
	}
	d := p.Deterministic
	checkCount := 0
	for _, v := range []*int{d.ApplicableFiles, d.ApplicableRanges, d.CheckedFiles, d.CheckedRanges} {
		if v != nil {
			checkCount++
		}
	}
	if checkCount != 0 && checkCount != 4 || d.State == "partial" && checkCount != 4 {
		return RunProgress{}, ErrInvalidResponse
	}
	if checkCount == 4 && (*d.ApplicableFiles > 4096 || *d.ApplicableRanges > 1000000 || *d.CheckedFiles > *d.ApplicableFiles || *d.CheckedRanges > *d.ApplicableRanges || *d.ApplicableFiles > *d.ApplicableRanges || *d.CheckedFiles > *d.CheckedRanges) {
		return RunProgress{}, ErrInvalidResponse
	}
	if d.Observations != nil && *d.Observations > 8192 {
		return RunProgress{}, ErrInvalidResponse
	}
	if progressAvailable(p.Context.State) && (p.Context.Analyzed == nil || p.Context.Selected == nil || p.Context.Omitted == nil || *p.Context.Analyzed != *p.Context.Selected+*p.Context.Omitted || *p.Context.Analyzed > 65664 || *p.Context.Selected > 32) {
		return RunProgress{}, ErrInvalidResponse
	}
	v := p.Verification
	if progressAvailable(v.State) && (v.Candidates == nil || v.Verified == nil || v.Rejected == nil || v.Inconclusive == nil || *v.Candidates > 16 || *v.Candidates != *v.Verified+*v.Rejected+*v.Inconclusive) {
		return RunProgress{}, ErrInvalidResponse
	}
	return RunProgress{Run: receipt, Progress: p}, nil
}
func progressAvailable(state string) bool { return state == "available" || state == "partial" }
func validProgressAxis(receipt controlplane.ReviewRunReceipt, kind controlplane.TaskKind, state, id string, counts ...*int) bool {
	if state != "not_run" && state != "unavailable" && !progressAvailable(state) || state == "partial" && kind != controlplane.TaskInspectDeterministic {
		return false
	}
	completed := false
	output := ""
	for _, task := range receipt.Tasks() {
		if task.Kind() == kind && task.Status() == controlplane.TaskRuntimeSucceeded {
			if completed {
				return false
			}
			completed = true
			output = task.OutputIdentity()
		}
	}
	if id != "" {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 32 || strings.Trim(id, "0") == "" || hex.EncodeToString(decoded) != id || !completed {
			return false
		}
		if kind != controlplane.TaskAssembleContext && id != output {
			return false
		}
	}
	if progressAvailable(state) && (id == "" || !completed) || state == "not_run" && (completed || id != "") {
		return false
	}
	for _, count := range counts {
		if count != nil && (!progressAvailable(state) || *count < 0 || *count > 1<<30) {
			return false
		}
	}
	return true
}
