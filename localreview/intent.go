package localreview

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

var errCommitIntentScope = errors.New("commit intent outside the session repository")

// commitIntentSource reads the commit messages of a direct review's range,
// base..head, from the session's own verified Git object store: the objects
// source acquisition read. The text is untrusted repository data; the context
// handler carries it as the packet's stated_intent, never as instructions.
type commitIntentSource struct {
	objects    *scm.LocalGitObjectStore
	repository evidence.RepositoryIdentity
}

// commitIntentSourceIdentity versions the reader and its bounds; it is bound
// into the context handler identity, so a change here fails planned runs
// closed.
var commitIntentSourceIdentity = digest("open-trestle/local-git-commit-intent/v1:range-walk-1024:message-prefix-4096")

func (commitIntentSource) Identity() string { return commitIntentSourceIdentity }

func (s commitIntentSource) StatedIntent(ctx context.Context, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.StatedIntent, error) {
	if s.objects == nil || repository.Identity() != s.repository.Identity() {
		return review.StatedIntent{}, errCommitIntentScope
	}
	commits, err := s.objects.ReadCommitRange(ctx, base, head)
	if err != nil {
		return review.StatedIntent{}, err
	}
	values := make([]review.IntentCommit, len(commits.Commits))
	for index, commit := range commits.Commits {
		values[index] = review.IntentCommit{CommitID: commit.Revision.Digest(), Message: commit.Message, MessageBytes: commit.MessageBytes}
	}
	return review.NewStatedIntent(values, commits.Incomplete)
}
