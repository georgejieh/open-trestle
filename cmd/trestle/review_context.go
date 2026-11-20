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
	"github.com/georgejieh/open-trestle/syntaxanalysis"
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

// reviewIndexAnalyzer is the analyzer of a review's index build: the
// build's syntax workers. Tests replace it to slow the build down.
var reviewIndexAnalyzer = func(workers syntaxanalysis.Analyzer) syntaxanalysis.Analyzer { return workers }

// prepareReviewIndex builds or refreshes the index of a review's base and
// head within a share of the time left before ctx's deadline, so that the
// review keeps the rest of it, and says so once when either commit is new
// to the index. It returns nil when the objects have no usable index; the
// review then plans from its own snapshots.
func prepareReviewIndex(ctx context.Context, session *indexSession, base, head evidence.RevisionIdentity, stderr io.Writer) *reviewIndexContext {
	if session == nil {
		return nil
	}
	c := &reviewIndexContext{session: session, base: base, head: head, state: review.ContextIndexUsed}
	build, cancel := review.WithContextPlanDeadline(ctx)
	defer cancel()
	build, cancelMax := context.WithTimeout(build, maxReviewIndexTime)
	defer cancelMax()
	pending := []evidence.RevisionIdentity{}
	for _, revision := range slices.Compact([]evidence.RevisionIdentity{base, head}) {
		snapshot, err := session.index.Snapshot(build, session.algorithm, revision.Digest())
		if err != nil || needsBuild(snapshot) {
			pending = append(pending, revision)
		}
	}
	if len(pending) == 0 {
		return c
	}
	deadline, _ := build.Deadline()
	fmt.Fprintf(stderr, "Indexing the repository for review context (up to %s; later reviews reuse the index).\n", time.Until(deadline).Round(time.Second))
	if !c.build(build, pending) {
		c.state = review.ContextIndexOverBudget
	}
	return c
}

// build indexes the commits before ctx's deadline with one pool of syntax
// workers and reports whether each build reached every file it could.
func (c *reviewIndexContext) build(ctx context.Context, revisions []evidence.RevisionIdentity) bool {
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) <= 0 {
		return false
	}
	b, tree, pool, err := c.session.builder(revisions[0])
	if err != nil {
		return false
	}
	defer pool.Close()
	trees := []*repoindex.GitTree{tree}
	for _, revision := range revisions[1:] {
		tree, err := repoindex.NewGitTree(c.session.store, revision)
		if err != nil {
			return false
		}
		trees = append(trees, tree)
	}
	b.Analyzer = reviewIndexAnalyzer(pool)
	b.Limits = repoindex.DefaultBuildLimits()
	complete := true
	for _, tree := range trees {
		b.Limits.MaxDuration = time.Until(deadline)
		if b.Limits.MaxDuration <= 0 {
			return false
		}
		snapshot, err := b.Build(ctx, tree)
		complete = complete && err == nil && !needsBuild(snapshot)
	}
	return complete
}

// needsBuild reports a snapshot that a build can still extend: one cut by
// its time limit. Lasting limits, such as the file and byte limits and
// files whose analysis failed, leave it ready and incomplete.
func needsBuild(s repoindex.Snapshot) bool {
	return slices.ContainsFunc(s.Files, func(f repoindex.FileEntry) bool { return f.Status == repoindex.StatusTimeLimit })
}

// ContextPlan loads the indexed base and head and plans their context, once,
// within a share of the time left before ctx's deadline. A commit the build
// did not reach, or a plan that ran out of time, is over budget; a partial
// build is used and the plan says it is incomplete.
func (c *reviewIndexContext) ContextPlan(ctx context.Context, _ evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.ContextPlan, error) {
	if base != c.base || head != c.head {
		return review.ContextPlan{}, errors.New("the review range is not the prepared one")
	}
	c.once.Do(func() {
		bounded, cancel := review.WithContextPlanDeadline(ctx)
		defer cancel()
		c.plan, c.err = c.load(bounded)
		// load leaves out the checks when reading them fails, so a plan
		// that ran past the bound is abandoned even when it returned.
		if review.ContextPlanAbandoned(ctx, bounded) {
			c.plan, c.err = review.UnavailableContextPlan(review.ContextIndexOverBudget), nil
		}
	})
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

// dependents lists the files that depend on the change, from the indexed
// base and head, or reports false when the review has no index or either
// commit is not indexed.
func (c *reviewIndexContext) dependents(ctx context.Context) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	headGraph, err := c.session.index.Load(ctx, c.session.algorithm, c.head.Digest())
	if err != nil {
		return nil, false
	}
	baseGraph, err := c.session.index.Load(ctx, c.session.algorithm, c.base.Digest())
	if err != nil {
		return nil, false
	}
	changes, err := c.session.changes(ctx, c.head, baseGraph, headGraph)
	if err != nil {
		return nil, false
	}
	result := repoindex.Dependents(headGraph, baseGraph, changes, repoindex.DefaultDependentsLimits())
	paths := slices.Clone(result.TestFiles)
	for _, file := range result.Files {
		paths = append(paths, file.Path)
	}
	slices.Sort(paths)
	return slices.Compact(paths), true
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
