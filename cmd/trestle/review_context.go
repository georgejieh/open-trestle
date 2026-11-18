package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/reviewcontext"
)

// reviewIndexBudget bounds the time a review spends building the index of
// its base and head. A build cut by it keeps what it analysed, and the next
// review continues from there.
const reviewIndexBudget = 2 * time.Minute

// reviewIndexContext is the repository index a direct review reads its
// context from. It is built before the review starts; during the review it
// only loads and plans.
type reviewIndexContext struct {
	mu         sync.Mutex
	session    *indexSession
	base, head evidence.RevisionIdentity
	// state is review.ContextIndexOverBudget when the build of either commit
	// did not finish within the budget.
	state string
}

var reviewIndexContextIdentity = func() string {
	digest := sha256.Sum256(fmt.Appendf(nil, "open-trestle/review-index-context/v1:%+v", reviewcontext.DefaultLimits()))
	return hex.EncodeToString(digest[:])
}()

func (c *reviewIndexContext) Identity() string { return reviewIndexContextIdentity }

func (c *reviewIndexContext) close() {
	if c != nil && c.session != nil {
		c.session.close()
	}
}

// prepareReviewIndex builds or refreshes the index of a review's base and
// head within reviewIndexBudget, saying so once when either commit is new
// to the index. It returns nil when the checkout has no usable index; the
// review then records the index as unavailable.
func prepareReviewIndex(ctx context.Context, checkout string, base, head evidence.RevisionIdentity, stderr io.Writer) *reviewIndexContext {
	session, err := openIndexSessionAt(ctx, checkout, "")
	if err != nil {
		return nil
	}
	c := &reviewIndexContext{session: session, base: base, head: head, state: review.ContextIndexUsed}
	pending := []evidence.RevisionIdentity{}
	for _, revision := range []evidence.RevisionIdentity{base, head} {
		snapshot, err := session.index.Snapshot(ctx, session.algorithm, revision.Digest())
		if err != nil || !snapshotComplete(snapshot) {
			pending = append(pending, revision)
		}
	}
	if len(pending) == 0 {
		return c
	}
	fmt.Fprintf(stderr, "Indexing the repository for review context (up to %s; later reviews reuse the index).\n", reviewIndexBudget)
	deadline := time.Now().Add(reviewIndexBudget)
	for _, revision := range slices.Compact(pending) {
		remaining := time.Until(deadline)
		if remaining <= 0 || !c.build(ctx, revision, remaining) {
			c.state = review.ContextIndexOverBudget
		}
	}
	return c
}

// build indexes one commit within a time limit and reports whether every
// file was reached.
func (c *reviewIndexContext) build(ctx context.Context, revision evidence.RevisionIdentity, limit time.Duration) bool {
	b, tree, pool, err := c.session.builder(revision)
	if err != nil {
		return false
	}
	defer pool.Close()
	b.Limits = repoindex.DefaultBuildLimits()
	b.Limits.MaxDuration = limit
	buildCtx, cancel := context.WithTimeout(ctx, limit+30*time.Second)
	defer cancel()
	snapshot, err := b.Build(buildCtx, tree)
	return err == nil && snapshotComplete(snapshot)
}

func snapshotComplete(s repoindex.Snapshot) bool {
	for _, f := range s.Files {
		switch f.Status {
		case repoindex.StatusTimeLimit, repoindex.StatusFileLimit, repoindex.StatusByteLimit, repoindex.StatusStoreLimit, repoindex.StatusFailed:
			return false
		}
	}
	return !s.Coverage.TreeTruncated
}

// ContextPlan loads the indexed base and head and plans their context. A
// commit the build did not reach is over budget; a partial build is used
// and the plan says it is incomplete.
func (c *reviewIndexContext) ContextPlan(ctx context.Context, _ evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.ContextPlan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if base != c.base || head != c.head {
		return review.ContextPlan{}, errors.New("the review range is not the prepared one")
	}
	headGraph, err := c.session.index.Load(ctx, c.session.algorithm, head.Digest())
	if errors.Is(err, repoindex.ErrNotIndexed) {
		return review.UnavailableContextPlan(review.ContextIndexOverBudget), nil
	}
	if err != nil {
		return review.ContextPlan{}, err
	}
	baseGraph, err := c.session.index.Load(ctx, c.session.algorithm, base.Digest())
	if errors.Is(err, repoindex.ErrNotIndexed) {
		return review.UnavailableContextPlan(review.ContextIndexOverBudget), nil
	}
	if err != nil {
		return review.ContextPlan{}, err
	}
	changes, err := c.session.changes(ctx, head, baseGraph, headGraph)
	if err != nil {
		return review.ContextPlan{}, err
	}
	plan := reviewcontext.Plan(headGraph, baseGraph, changes, reviewcontext.DefaultLimits())
	plan.Complete = plan.Complete && c.state == review.ContextIndexUsed
	// The checks come from the base tree: the author of a change controls
	// the head, and could otherwise claim a check that never ran.
	if profile, err := repositoryProfile(ctx, c.session, baseGraph); err == nil {
		plan.Checks = profile.EnforcedClasses()
	}
	return plan, nil
}
