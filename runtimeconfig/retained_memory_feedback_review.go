package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// LoadProtectedFeedbackReview checks the scope and canonical diagnostic lineage
// of operator-supplied completed review output. It does not attest authorship.
func LoadProtectedFeedbackReview(ctx context.Context, path, tenant, repositoryID string, repository evidence.RepositoryIdentity, policy RuntimePolicy) (diagnostics.Set, evidence.RevisionIdentity, error) {
	fail := func() (diagnostics.Set, evidence.RevisionIdentity, error) {
		return diagnostics.Set{}, evidence.RevisionIdentity{}, ErrInvalidRetainedMemoryInput
	}
	if ctx == nil || ctx.Err() != nil || path == "" || policy.Validate() != nil {
		return fail()
	}
	opener := func(name string) (protectedConfigurationFile, error) { return fileauthority.OpenReadOnly(name) }
	encoded, err := readProtectedConfiguration(ctx, path, 256<<10, opener)
	if err != nil || !utf8.Valid(encoded) || validateUniqueJSONKeys(encoded) != nil {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return fail()
	}
	keys := strings.Fields("contract schema_version status ci_disposition run_status failure review_run_id scope_identity request_identity plan_identity output_identity repository_identity base_revision_identity head_revision_identity inventory_identity runtime_policy_identity context_identity generation_request_identity verification_request_identity verification_context_identity candidate_batch_identity candidate_ids readiness_identity generation_route_record_identity verification_route_record_identity independence limitations comprehensive_clearance usage_known actual_cost_micro_usd lease_renewals tasks audit diagnostics")
	// A version 4 result differs from version 1 only by finding_guidance; the
	// feedback review reads neither its categories nor its fix text.
	_, guided := fields["finding_guidance"]
	if guided {
		keys = append(keys, "finding_guidance")
	}
	if len(fields) != len(keys) {
		return fail()
	}
	for _, key := range keys {
		if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fail()
		}
	}
	var wire struct {
		Contract            string          `json:"contract"`
		Version             int             `json:"schema_version"`
		Status              string          `json:"status"`
		RunStatus           string          `json:"run_status"`
		Run                 string          `json:"review_run_id"`
		Scope               string          `json:"scope_identity"`
		Repository          string          `json:"repository_identity"`
		Head                string          `json:"head_revision_identity"`
		Policy              string          `json:"runtime_policy_identity"`
		VerificationContext string          `json:"verification_context_identity"`
		Comprehensive       bool            `json:"comprehensive_clearance"`
		Diagnostics         json.RawMessage `json:"diagnostics"`
	}
	if json.Unmarshal(encoded, &wire) != nil || wire.Contract != "open-trestle/local-git-model-review-result" || (wire.Version != 1 || guided) && (wire.Version != 4 || !guided) || wire.RunStatus != "succeeded" || wire.Comprehensive || wire.Repository != repository.Identity() || wire.Policy != policy.Identity() {
		return fail()
	}
	if wire.Status != "findings" && wire.Status != "incomplete" && wire.Status != "no_candidates" {
		return fail()
	}
	set, err := diagnostics.ParseSet(wire.Diagnostics)
	if err != nil || set.Validate() != nil || set.SchemaVersion() == 6 || set.Scope().TenantID() != tenant || set.Scope().RepositoryID() != repositoryID || set.Scope().ReviewRunID() != wire.Run || set.Scope().Identity() != wire.Scope || set.VerificationContextIdentity() != wire.VerificationContext {
		return fail()
	}
	algorithm := evidence.RevisionAlgorithmSHA1
	if len(set.HeadRevision()) == 64 {
		algorithm = evidence.RevisionAlgorithmSHA256
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, set.HeadRevision())
	if err != nil || head.Identity() != wire.Head || ctx.Err() != nil {
		return fail()
	}
	again, err := readProtectedConfiguration(ctx, path, 256<<10, opener)
	if err != nil || !bytes.Equal(encoded, again) || ctx.Err() != nil {
		return fail()
	}
	return set, head, nil
}

// LoadProtectedFindingFeedback selects advisory decisions from actual findings.
// Existing path/text entries remain preferences, not policy or suppressions.
func LoadProtectedFindingFeedback(ctx context.Context, path string, set diagnostics.Set) ([]RetainedMemoryFeedback, error) {
	if ctx == nil || ctx.Err() != nil || set.Validate() != nil {
		return nil, ErrInvalidRetainedMemoryInput
	}
	opener := func(name string) (protectedConfigurationFile, error) { return fileauthority.OpenReadOnly(name) }
	encoded, err := readProtectedConfiguration(ctx, path, retainedRawLimit, opener)
	if err != nil || len(encoded) == 0 || !utf8.Valid(encoded) {
		return nil, ErrInvalidRetainedMemoryInput
	}
	scanner := retainedFeedbackScanner{encoded: encoded, ctx: ctx, review: &set}
	feedback, ok := scanner.parse()
	scanner.space()
	if !ok || scanner.offset != len(encoded) || ctx.Err() != nil || !validRetainedFeedback(feedback) {
		return nil, ErrInvalidRetainedMemoryInput
	}
	return feedback, nil
}

func feedbackDecisionText(set diagnostics.Set, path string, start uint32, decision, text string) (string, bool) {
	if decision != "confirm" && decision != "dismiss" && decision != "advisory" || start == 0 {
		return "", false
	}
	var selected diagnostics.Finding
	count := 0
	for _, finding := range set.Findings() {
		if finding.Path() == path && finding.StartLine() == start {
			selected = finding
			count++
		}
	}
	if count != 1 {
		return "", false
	}
	value := fmt.Sprintf("Operator advisory %s; not verified human adjudication or suppression. Review %s; diagnostic set %s; finding %s.\n%s", decision, set.Scope().ReviewRunID(), set.Identity(), selected.Identity(), text)
	return value, validRetainedFeedbackText(value)
}
