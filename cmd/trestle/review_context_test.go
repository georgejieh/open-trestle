package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

const indexingLine = "Indexing the repository for review context"

type reviewContextRepo struct {
	checkout   string
	base, head evidence.RevisionIdentity
}

func writeRepoFiles(t *testing.T, checkout string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(checkout, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func revisionOf(t *testing.T, checkout, ref string) evidence.RevisionIdentity {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm("sha1"), checkoutGit(t, checkout, "rev-parse", ref))
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

// newReviewContextRepo commits base, then head on top of it, and points HOME
// at a private folder so the index is kept there.
func newReviewContextRepo(t *testing.T, base, head map[string]string) reviewContextRepo {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init", "-q", "-b", "main")
	writeRepoFiles(t, checkout, base)
	checkoutGit(t, checkout, "add", ".")
	checkoutGit(t, checkout, "commit", "-q", "-m", "base")
	writeRepoFiles(t, checkout, head)
	checkoutGit(t, checkout, "add", ".")
	checkoutGit(t, checkout, "commit", "-q", "-m", "head")
	return reviewContextRepo{checkout: checkout, base: revisionOf(t, checkout, "HEAD~1"), head: revisionOf(t, checkout, "HEAD")}
}

func manyGoFiles(count int, changed string) map[string]string {
	files := map[string]string{}
	for i := range count {
		files[fmt.Sprintf("p/f%03d.go", i)] = fmt.Sprintf("package p\n\nfunc F%03d(x int) int { return x%s }\n", i, changed)
	}
	return files
}

func (r reviewContextRepo) open(t *testing.T) *indexSession {
	t.Helper()
	session := openReviewIndexSession(context.Background(), localModelReviewOptions{checkout: r.checkout}, r.base)
	if session == nil {
		t.Fatal("the index session did not open")
	}
	t.Cleanup(session.close)
	return session
}

// prepare prepares the index as a review with the timeout would.
func (r reviewContextRepo) prepare(t *testing.T, session *indexSession, timeout time.Duration) (*reviewIndexContext, string) {
	t.Helper()
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := prepareReviewIndex(ctx, session, r.base, r.head, &stderr)
	if c == nil {
		t.Fatal("prepareReviewIndex returned no context")
	}
	return c, stderr.String()
}

func (r reviewContextRepo) plan(c *reviewIndexContext) (review.ContextPlan, error) {
	return c.ContextPlan(context.Background(), evidence.RepositoryIdentity{}, r.base, r.head)
}

// A build cut by its time bound is over budget but still plans from what it
// kept, and the next prepare with time to spare finishes it.
func TestReviewIndexPartialBuildContinues(t *testing.T) {
	repo := newReviewContextRepo(t, manyGoFiles(60, ""), manyGoFiles(60, "+1"))
	session := repo.open(t)

	c, _ := repo.prepare(t, session, 8*time.Millisecond)
	if c.state != review.ContextIndexOverBudget {
		t.Fatalf("state after a 2ms build = %q", c.state)
	}
	plan, err := repo.plan(c)
	if err != nil {
		t.Fatal(err)
	}
	switch plan.State {
	case review.ContextIndexUsed:
		if plan.Complete {
			t.Fatalf("a partial build planned as complete: %+v", plan)
		}
	case review.ContextIndexOverBudget:
	default:
		t.Fatalf("plan state = %q", plan.State)
	}

	c, stderr := repo.prepare(t, session, 10*time.Minute)
	if !strings.Contains(stderr, indexingLine) {
		t.Fatalf("the continued build said nothing: %q", stderr)
	}
	if c.state != review.ContextIndexUsed {
		t.Fatalf("state after a full build = %q", c.state)
	}
	plan, err = repo.plan(c)
	if err != nil || plan.State != review.ContextIndexUsed || !plan.Complete {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

// With nothing stored the plan says over budget.
func TestReviewIndexOverBudgetWithoutSnapshot(t *testing.T) {
	repo := newReviewContextRepo(t, map[string]string{"a.go": "package p\n"}, map[string]string{"b.go": "package p\n"})
	session := repo.open(t)
	c := &reviewIndexContext{session: session, base: repo.base, head: repo.head, state: review.ContextIndexOverBudget}
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if c.build(expired, []evidence.RevisionIdentity{repo.head}) {
		t.Fatal("a build with no time reported success")
	}
	plan, err := repo.plan(c)
	if err != nil || plan.State != review.ContextIndexOverBudget || plan.Complete {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

// A snapshot that only lasting limits left incomplete needs no build.
func TestReviewIndexLastingLimitNeedsNoBuild(t *testing.T) {
	repo := newReviewContextRepo(t, manyGoFiles(3, ""), manyGoFiles(3, "+1"))
	session := repo.open(t)
	for _, revision := range []evidence.RevisionIdentity{repo.base, repo.head} {
		b, tree, pool, err := session.builder(revision)
		if err != nil {
			t.Fatal(err)
		}
		b.Limits = repoindex.DefaultBuildLimits()
		b.Limits.MaxFiles = 1
		snapshot, err := b.Build(context.Background(), tree)
		pool.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(snapshot.Files, func(f repoindex.FileEntry) bool { return f.Status == repoindex.StatusFileLimit }) {
			t.Fatal("the build did not hit the file limit")
		}
		if needsBuild(snapshot) {
			t.Fatal("a file limit asks for another build")
		}
	}
	c, stderr := repo.prepare(t, session, time.Minute)
	if stderr != "" || c.state != review.ContextIndexUsed {
		t.Fatalf("prepare printed %q with state %q", stderr, c.state)
	}
}

func TestReviewIndexSaysSoOnlyOnFirstUse(t *testing.T) {
	repo := newReviewContextRepo(t, map[string]string{"a.go": "package p\n"}, map[string]string{"b.go": "package p\n"})
	session := repo.open(t)
	_, first := repo.prepare(t, session, time.Minute)
	if strings.Count(first, indexingLine) != 1 || strings.Count(first, "\n") != 1 {
		t.Fatalf("first prepare printed %q", first)
	}
	if _, second := repo.prepare(t, session, time.Minute); second != "" {
		t.Fatalf("second prepare printed %q", second)
	}
}

func TestReviewContextPlanRejectsOtherRevisions(t *testing.T) {
	repo := newReviewContextRepo(t, map[string]string{"a.go": "package p\n"}, map[string]string{"b.go": "package p\n"})
	session := repo.open(t)
	c, _ := repo.prepare(t, session, time.Minute)
	for _, pair := range [][2]evidence.RevisionIdentity{{repo.head, repo.base}, {repo.base, repo.base}, {repo.head, repo.head}} {
		if _, err := c.ContextPlan(context.Background(), evidence.RepositoryIdentity{}, pair[0], pair[1]); err == nil {
			t.Fatal("a range other than the prepared one was planned")
		}
	}
}

func TestReviewContextPlanIsComputedOnce(t *testing.T) {
	repo := newReviewContextRepo(t, manyGoFiles(2, ""), manyGoFiles(2, "+1"))
	session := repo.open(t)
	c, _ := repo.prepare(t, session, time.Minute)
	first, err := repo.plan(c)
	if err != nil || first.State != review.ContextIndexUsed {
		t.Fatalf("plan = %+v, %v", first, err)
	}
	if err := os.RemoveAll(session.index.Directory()); err != nil {
		t.Fatal(err)
	}
	second, err := repo.plan(c)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("second plan = %+v, %v", second, err)
	}
}

// The checks come from the base commit, so a workflow the change adds does
// not claim a check that never ran.
func TestReviewContextChecksComeFromTheBase(t *testing.T) {
	workflow := func(step string) string {
		return "on: pull_request\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + step + "\n"
	}
	repo := newReviewContextRepo(t,
		map[string]string{"a.go": "package p\n", ".github/workflows/ci.yml": workflow("golangci-lint run")},
		map[string]string{".github/workflows/format.yml": workflow("prettier --check .")})
	session := repo.open(t)
	c, _ := repo.prepare(t, session, time.Minute)
	plan, err := repo.plan(c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Checks, "lint") || slices.Contains(plan.Checks, "formatting") {
		t.Fatalf("checks = %v", plan.Checks)
	}
}

// An objects root has no checkout; its index is kept for the object store.
func TestReviewIndexSessionOpensOnAnObjectsRoot(t *testing.T) {
	repo := newReviewContextRepo(t, manyGoFiles(2, ""), manyGoFiles(2, "+1"))
	objects := filepath.Join(repo.checkout, ".git", "objects")
	session := openReviewIndexSession(context.Background(), localModelReviewOptions{objects: objects}, repo.base)
	if session == nil {
		t.Fatal("no session opened on the objects root")
	}
	defer session.close()
	if session.checkout != "" {
		t.Fatalf("checkout = %q", session.checkout)
	}
	c, stderr := repo.prepare(t, session, time.Minute)
	if !strings.Contains(stderr, indexingLine) || c.state != review.ContextIndexUsed {
		t.Fatalf("prepare printed %q with state %q", stderr, c.state)
	}
	plan, err := repo.plan(c)
	if err != nil || plan.State != review.ContextIndexUsed || !plan.Complete {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

// stalledAnalyzer analyses nothing until its context ends, as a build of a
// repository too large for the time would.
type stalledAnalyzer struct{ calls *atomic.Int64 }

func (stalledAnalyzer) Supports(syntaxanalysis.Language) bool { return true }

func (a stalledAnalyzer) Analyze(ctx context.Context, _ syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	a.calls.Add(1)
	<-ctx.Done()
	return syntaxanalysis.FileAnalysis{}, ctx.Err()
}

// A review with a short timeout reaches its model call when indexing would
// outlast the whole review: the build gives up at its share of the time.
func TestReviewWithAStalledIndexBuildReachesTheModel(t *testing.T) {
	calls := &atomic.Int64{}
	previous := reviewIndexAnalyzer
	reviewIndexAnalyzer = func(syntaxanalysis.Analyzer) syntaxanalysis.Analyzer { return stalledAnalyzer{calls: calls} }
	t.Cleanup(func() { reviewIndexAnalyzer = previous })
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "wait"})
	args := replaceLocalGitChangeValue(f.args, "--timeout", "4s")
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(args, &stdout, &stderr) }()
	select {
	case <-f.generation.entered:
	case code := <-done:
		t.Fatalf("entrypoint returned %d before reaching the model wait", code)
	case <-time.After(4 * time.Second):
		t.Fatal("the model wait was not reached within the review timeout")
	}
	if calls.Load() == 0 {
		t.Fatal("the index build did not run")
	}
	select {
	case code := <-done:
		var result localModelReceipt
		if code != 3 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Status != "canceled" || !strings.Contains(stderr.String(), indexingLine) {
			t.Fatalf("exit=%d stdout=%s stderr=%q", code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the review did not stop at its deadline")
	}
}
