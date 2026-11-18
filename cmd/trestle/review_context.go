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

// maxReviewIndexTime bounds the time a review spends building the index of
// its base and head; a review also gives it at most a quarter of its own
// timeout. A build cut by the bound keeps what it analysed, and the next
// review continues from there.
const maxReviewIndexTime = 2 * time.Minute

// reviewIndexContext is the repository index a direct review reads its
// context from. It is built before the review starts; during the review it
// only loads and plans, once for all the members of a review set.
type reviewIndexContext struct {
	session    *indexSession
	base, head evidence.RevisionIdentity
	// state is review.ContextIndexOverBudget when the build of either commit
	// was cut by its time bound.
	state string
	once  sync.Once
	plan  review.ContextPlan
	err   error
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

// reviewIndexTime is the build's share of a review timeout.
func reviewIndexTime(timeout time.Duration) time.Duration {
	return min(maxReviewIndexTime, timeout/4)
}

// prepareReviewIndex builds or refreshes the index of a review's base and
// head under its own deadline, so that the review keeps the rest of its
// time, and says so once when either commit is new to the index. It returns
// nil when the objects have no usable index; the review then plans from
// its own snapshots.
func prepareReviewIndex(ctx context.Context, session *indexSession, base, head evidence.RevisionIdentity, timeout time.Duration, stderr io.Writer) *reviewIndexContext {
	if session == nil {
		return nil
	}
	c := &reviewIndexContext{session: session, base: base, head: head, state: review.ContextIndexUsed}
	pending := []evidence.RevisionIdentity{}
	for _, revision := range slices.Compact([]evidence.RevisionIdentity{base, head}) {
		snapshot, err := session.index.Snapshot(ctx, session.algorithm, revision.Digest())
		if err != nil || needsBuild(snapshot) {
			pending = append(pending, revision)
		}
	}
	if len(pending) == 0 {
		return c
	}
	limit := reviewIndexTime(timeout)
	fmt.Fprintf(stderr, "Indexing the repository for review context (up to %s; later reviews reuse the index).\n", limit.Round(time.Second))
	build, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	deadline, _ := build.Deadline()
	for _, revision := range pending {
		if !c.build(build, revision, time.Until(deadline)) {
			c.state = review.ContextIndexOverBudget
		}
	}
	return c
}

// build indexes one commit within a time limit and reports whether the
// build reached every file it could.
func (c *reviewIndexContext) build(ctx context.Context, revision evidence.RevisionIdentity, limit time.Duration) bool {
	if limit <= 0 {
		return false
	}
	b, tree, pool, err := c.session.builder(revision)
	if err != nil {
		return false
	}
	defer pool.Close()
	b.Limits = repoindex.DefaultBuildLimits()
	b.Limits.MaxDuration = limit
	snapshot, err := b.Build(ctx, tree)
	return err == nil && !needsBuild(snapshot)
}

// needsBuild reports a snapshot that a build can still extend: one cut by
// its time limit. Lasting limits, such as the file and byte limits and
// files whose analysis failed, leave it ready and incomplete.
func needsBuild(s repoindex.Snapshot) bool {
	return slices.ContainsFunc(s.Files, func(f repoindex.FileEntry) bool { return f.Status == repoindex.StatusTimeLimit })
}

// ContextPlan loads the indexed base and head and plans their context, once.
// A commit the build did not reach is over budget; a partial build is used
// and the plan says it is incomplete.
func (c *reviewIndexContext) ContextPlan(ctx context.Context, _ evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.ContextPlan, error) {
	if base != c.base || head != c.head {
		return review.ContextPlan{}, errors.New("the review range is not the prepared one")
	}
	c.once.Do(func() { c.plan, c.err = c.load(ctx) })
	return c.plan, c.err
}

func (c *reviewIndexContext) load(ctx context.Context) (review.ContextPlan, error) {
	headGraph, err := c.session.index.Load(ctx, c.session.algorithm, c.head.Digest())
	if errors.Is(err, repoindex.ErrNotIndexed) {
		return review.UnavailableContextPlan(review.ContextIndexOverBudget), nil
	}
	if err != nil {
		return review.ContextPlan{}, err
	}
	baseGraph, err := c.session.index.Load(ctx, c.session.algorithm, c.base.Digest())
	if errors.Is(err, repoindex.ErrNotIndexed) {
		return review.UnavailableContextPlan(review.ContextIndexOverBudget), nil
	}
	if err != nil {
		return review.ContextPlan{}, err
	}
	changes, err := c.session.changes(ctx, c.head, baseGraph, headGraph)
	if err != nil {
		return review.ContextPlan{}, err
	}
	plan, err := reviewcontext.Plan(ctx, headGraph, baseGraph, changes, reviewcontext.DefaultLimits())
	if err != nil {
		return review.ContextPlan{}, err
	}
	plan.Complete = plan.Complete && c.state == review.ContextIndexUsed
	// The checks come from the base tree: the author of a change controls
	// the head, and could otherwise claim a check that never ran.
	if profile, err := repositoryProfile(ctx, c.session, baseGraph); err == nil {
		plan.Checks = profile.EnforcedClasses()
	}
	return plan, nil
}

// openReviewIndexSession opens the index a review uses: the checkout's, or
// for an objects root the one kept for that object store.
func openReviewIndexSession(ctx context.Context, options localModelReviewOptions, base evidence.RevisionIdentity) *indexSession {
	var session *indexSession
	var err error
	if options.checkout != "" {
		session, err = openIndexSessionAt(ctx, options.checkout, "")
	} else {
		session, err = openIndexSessionForObjects(options.objects, string(base.Algorithm()), defaultSetupDirectory(options.objects))
	}
	if err != nil {
		return nil
	}
	return session
}
