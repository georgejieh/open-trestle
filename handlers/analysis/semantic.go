package analysis

import (
	"context"
	"errors"
	"path"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

const (
	maximumSemanticSourceBytes  = 64 << 20
	maximumSemanticFilesPerSide = 4096
)

func buildSemanticProfile(ctx context.Context, store artifact.Store, scope audit.ReviewScope, at time.Time, base, head source.Snapshot, change changehandler.Result) (semanticimpact.Profile, time.Time, error) {
	changed := make([]semanticimpact.ChangedPath, 0, len(change.Entries()))
	changedGo := map[string]bool{}
	for _, entry := range change.Entries() {
		value, err := semanticimpact.NewChangedPath(entry.Path())
		if err != nil {
			return semanticimpact.Profile{}, time.Time{}, err
		}
		changed = append(changed, value)
		if path.Ext(entry.Path()) == ".go" {
			changedGo[entry.Path()] = true
		}
	}
	loaded := 0
	expires := at.Add(100 * 365 * 24 * time.Hour)
	gaps := map[string]semanticimpact.Gap{}
	limitGapRecorded := false
	recordLimit := func(filePath string) {
		if changedGo[filePath] || !limitGapRecorded {
			gap, _ := semanticimpact.NewCoverageGap(filePath, semanticimpact.GapLimitExceeded)
			gaps[filePath] = gap
			limitGapRecorded = true
		}
	}
	load := func(snapshot source.Snapshot, baseSide bool) ([]semanticimpact.File, error) {
		files := []semanticimpact.File{}
		for _, ref := range snapshot.Files() {
			if path.Ext(ref.Path()) != ".go" || (baseSide && !changedGo[ref.Path()]) {
				continue
			}
			if len(files) >= maximumSemanticFilesPerSide || loaded+ref.SizeBytes() > maximumSemanticSourceBytes {
				recordLimit(ref.Path())
				continue
			}
			value, err := store.Get(ctx, scope, ref.ArtifactIdentity(), at)
			if err != nil {
				if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrArtifactExpired) {
					gap, _ := semanticimpact.NewCoverageGap(ref.Path(), semanticimpact.GapSourceUnavailable)
					gaps[ref.Path()] = gap
					continue
				}
				return nil, err
			}
			decoded, err := source.ParseFileArtifact(value, snapshot, ref)
			if err != nil {
				return nil, err
			}
			content := decoded.Content()
			semanticFile, err := semanticimpact.NewFile(ref.Path(), content)
			clear(content)
			if err != nil {
				recordLimit(ref.Path())
				continue
			}
			loaded += ref.SizeBytes()
			if value.ExpiresAt().Before(expires) {
				expires = value.ExpiresAt()
			}
			files = append(files, semanticFile)
		}
		return files, nil
	}
	baseFiles, err := load(base, true)
	if err != nil {
		return semanticimpact.Profile{}, time.Time{}, err
	}
	headFiles, err := load(head, false)
	if err != nil {
		return semanticimpact.Profile{}, time.Time{}, err
	}
	coverage := make([]semanticimpact.Gap, 0, len(gaps))
	for _, gap := range gaps {
		coverage = append(coverage, gap)
	}
	input, err := semanticimpact.NewInputWithCoverageGaps(base.Identity(), head.Identity(), change.Identity(), changed, baseFiles, headFiles, coverage)
	if err != nil {
		return semanticimpact.Profile{}, time.Time{}, err
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	return profile, expires, err
}
