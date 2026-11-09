package github

import (
	"context"
	"net/http"
	"net/url"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// ResolveMergeBase reads the merge base GitHub uses for a pull request diff
// (merge-base...head) from one compare page. Only merge_base_commit.sha is
// read; the rest of the bounded response is ignored. A compare that is not
// found while both commits exist means the commits share no history.
func (a *Adapter) ResolveMergeBase(ctx context.Context, request scm.MergeBaseRequest) scm.MergeBaseResult {
	unavailable := func(reason evidence.RepositoryAcquisitionReason) scm.MergeBaseResult {
		return scm.MergeBaseResult{Outcome: scm.MergeBaseUnavailable, Reason: reason}
	}
	if nilInterface(ctx) || a == nil || a.Validate() != nil {
		return unavailable(evidence.AcquisitionReasonPolicyBlocked)
	}
	if ctx.Err() != nil {
		return unavailable(evidence.AcquisitionReasonAdapterUnavailable)
	}
	repository := request.Repository()
	namespace := repository.Namespace()
	base, head := request.Base(), request.Head()
	if request.Adapter().Identity() != a.identity.Identity() || repository.Authority() != a.repositoryAuthority || len(namespace) != 1 || !validRepositorySlug(namespace[0]) || !validRepositorySlug(repository.Name()) ||
		!validObjectID(base.Digest(), len(base.Digest())) || !validObjectID(head.Digest(), len(base.Digest())) {
		return unavailable(evidence.AcquisitionReasonPolicyBlocked)
	}
	if a.installationBroker != nil {
		op, err := a.installationBroker.beginSource(ctx, repository)
		if err != nil {
			return unavailable(brokerAcquisitionFailure(err).reason)
		}
		defer op.Close()
		ctx = op.Context()
	}
	owner, name := url.PathEscape(namespace[0]), url.PathEscape(repository.Name())
	body, status, headers, failure := a.apiGet(ctx, "/repos/"+owner+"/"+name+"/compare/"+base.Digest()+"..."+head.Digest(), url.Values{"per_page": {"1"}}, maximumMetadataBytes)
	if failure != nil {
		return unavailable(failure.reason)
	}
	if status == http.StatusNotFound {
		for _, commit := range []string{base.Digest(), head.Digest()} {
			if _, missing := a.loadCommit(ctx, namespace[0], repository.Name(), commit); missing != nil {
				return unavailable(missing.reason)
			}
		}
		return scm.MergeBaseResult{Outcome: scm.MergeBaseNone, Reason: evidence.AcquisitionReasonNone}
	}
	if status != http.StatusOK {
		return unavailable(classifyStatus(status, headers).reason)
	}
	var wire struct {
		MergeBaseCommit struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	if decodeJSON(body, &wire) != nil || !validObjectID(wire.MergeBaseCommit.SHA, len(base.Digest())) {
		return unavailable(evidence.AcquisitionReasonArtifactIncomplete)
	}
	mergeBase, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, base.Algorithm(), wire.MergeBaseCommit.SHA)
	if err != nil {
		return unavailable(evidence.AcquisitionReasonArtifactIncomplete)
	}
	return scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, MergeBase: mergeBase, Reason: evidence.AcquisitionReasonNone}
}

var _ scm.MergeBaseResolver = (*Adapter)(nil)
