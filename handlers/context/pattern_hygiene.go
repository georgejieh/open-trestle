package context

import (
	"context"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/patternhygiene"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// Pattern-hygiene bounds. A directory past a bound is not compared at all, so
// a partial count can never invent an increase.
const (
	maximumHygieneDirectories    = 32
	maximumHygieneDirectoryFiles = 128
	maximumHygieneBaseBytes      = 8 << 20
	maximumHygieneFileBytes      = 1 << 20
)

// ChangeIntentSource reads the author-stated intent of one reviewed change,
// for example the commit messages of base..head. Its identity is bound into
// the handler identity. What it returns is untrusted repository data.
type ChangeIntentSource interface {
	Identity() string
	StatedIntent(ctx context.Context, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.StatedIntent, error)
}

// hygieneExcludedPath skips vendored and dependency trees, which a change
// copies rather than writes.
func hygieneExcludedPath(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		switch segment {
		case "vendor", "node_modules", "third_party":
			return true
		}
	}
	return false
}

// patternHygieneReport builds the deterministic pattern-hygiene report of a
// change from the acquired snapshots: the head contents already loaded for
// context assembly and, for the changed files' directories, the base files.
func (h *Handler) patternHygieneReport(ctx context.Context, scope audit.ReviewScope, at time.Time, base sourceoutput.Snapshot, change changecodec.Result, contents map[string][]byte, expires *time.Time) (patternhygiene.Report, controlplane.RunFailure) {
	var input patternhygiene.Input
	directories := map[string]bool{}
	for _, entry := range change.Entries() {
		if hygieneExcludedPath(entry.Path()) {
			continue
		}
		changed := patternhygiene.Change{Path: entry.Path()}
		for _, value := range entry.Ranges() {
			changed.Added = append(changed.Added, patternhygiene.LineRange{Start: value.StartLine(), End: value.EndLine()})
		}
		input.Changes = append(input.Changes, changed)
		if _, ok := patternhygiene.LanguageOf(entry.Path()); ok {
			directories[path.Dir(entry.Path())] = true
		} else if content, ok := contents[entry.Path()]; ok && patternhygiene.RuleFile(entry.Path()) && len(changed.Added) > 0 {
			input.Head = append(input.Head, patternhygiene.File{Path: entry.Path(), Content: content})
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Strings(ordered)
	unread := map[string]bool{}
	for index, directory := range ordered {
		if index >= maximumHygieneDirectories {
			unread[directory] = true
		}
	}
	inScope := func(filePath string) (string, bool) {
		directory := path.Dir(filePath)
		if _, ok := patternhygiene.LanguageOf(filePath); !ok || !directories[directory] || unread[directory] || hygieneExcludedPath(filePath) {
			return directory, false
		}
		return directory, true
	}
	headPaths := make([]string, 0, len(contents))
	for filePath := range contents {
		headPaths = append(headPaths, filePath)
	}
	sort.Strings(headPaths)
	headCounts := map[string]int{}
	for _, filePath := range headPaths {
		directory, ok := inScope(filePath)
		if !ok || len(contents[filePath]) > maximumHygieneFileBytes {
			continue
		}
		if headCounts[directory]++; headCounts[directory] > maximumHygieneDirectoryFiles {
			unread[directory] = true
			continue
		}
		input.Head = append(input.Head, patternhygiene.File{Path: filePath, Content: contents[filePath]})
	}
	baseCounts := map[string]int{}
	loaded := 0
	for _, reference := range base.Files() {
		if ctx.Err() != nil {
			return patternhygiene.Report{}, controlplane.RunFailureCanceled
		}
		directory, ok := inScope(reference.Path())
		if !ok || reference.SizeBytes() > maximumHygieneFileBytes {
			continue
		}
		if baseCounts[directory]++; baseCounts[directory] > maximumHygieneDirectoryFiles || loaded+reference.SizeBytes() > maximumHygieneBaseBytes {
			unread[directory] = true
			continue
		}
		value, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			return patternhygiene.Report{}, readFailure(ctx, err)
		}
		file, err := sourceoutput.ParseFileArtifact(value, base, reference)
		if err != nil || file.RepositoryFile().Digest() != reference.Digest() {
			return patternhygiene.Report{}, controlplane.RunFailureInvalidInput
		}
		input.Base = append(input.Base, patternhygiene.File{Path: reference.Path(), Content: file.Content()})
		loaded += reference.SizeBytes()
		if value.ExpiresAt().Before(*expires) {
			*expires = value.ExpiresAt()
		}
	}
	for directory := range unread {
		input.Unread = append(input.Unread, directory)
	}
	sort.Strings(input.Unread)
	report := patternhygiene.Analyze(input)
	for _, file := range input.Base {
		clear(file.Content)
	}
	return report, 0
}
