package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// ReviewSnapshot binds a review to immutable local source identity.
type ReviewSnapshot struct {
	workspace string
	revision  string
	identity  string
	ranges    []evidence.SourceRange
}

// NewReviewSnapshot creates a content-addressed local review snapshot.
func NewReviewSnapshot(workspace, revision string, ranges []evidence.SourceRange) (ReviewSnapshot, error) {
	if workspace == "" {
		return ReviewSnapshot{}, fmt.Errorf("workspace identity is required")
	}
	if len(revision) != sha256.Size*2 || revision != strings.ToLower(revision) {
		return ReviewSnapshot{}, fmt.Errorf("revision must be a lowercase SHA-256 digest")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return ReviewSnapshot{}, fmt.Errorf("invalid revision digest: %w", err)
	}
	if len(ranges) == 0 {
		return ReviewSnapshot{}, fmt.Errorf("at least one source range is required")
	}
	for i, sourceRange := range ranges {
		if _, err := evidence.NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine()); err != nil {
			return ReviewSnapshot{}, fmt.Errorf("validate source range %d: %w", i, err)
		}
	}
	canonical := struct {
		Workspace string           `json:"workspace"`
		Revision  string           `json:"revision"`
		Ranges    []canonicalRange `json:"ranges"`
	}{
		Workspace: workspace,
		Revision:  revision,
		Ranges:    make([]canonicalRange, len(ranges)),
	}
	for i, sourceRange := range ranges {
		canonical.Ranges[i] = canonicalRange{
			Path:      sourceRange.Path(),
			StartLine: sourceRange.StartLine(),
			EndLine:   sourceRange.EndLine(),
		}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	digest := sha256.Sum256(encoded)

	return ReviewSnapshot{
		workspace: workspace,
		revision:  revision,
		identity:  hex.EncodeToString(digest[:]),
		ranges:    append([]evidence.SourceRange(nil), ranges...),
	}, nil
}

type canonicalRange struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// Validate verifies the snapshot fields and content-derived identity.
func (s ReviewSnapshot) Validate() error {
	rebuilt, err := NewReviewSnapshot(s.workspace, s.revision, s.ranges)
	if err != nil {
		return err
	}
	if rebuilt.identity != s.identity {
		return fmt.Errorf("review snapshot identity does not match its contents")
	}
	return nil
}

// Workspace returns the local workspace identity.
func (s ReviewSnapshot) Workspace() string {
	return s.workspace
}

// Revision returns the immutable source revision.
func (s ReviewSnapshot) Revision() string {
	return s.revision
}

// Identity returns the snapshot's canonical SHA-256 identity.
func (s ReviewSnapshot) Identity() string {
	return s.identity
}

// Ranges returns a copy of the snapshot's source ranges.
func (s ReviewSnapshot) Ranges() []evidence.SourceRange {
	return append([]evidence.SourceRange(nil), s.ranges...)
}

// ReviewRequest identifies a local review operation and its snapshot.
type ReviewRequest struct {
	id       string
	snapshot ReviewSnapshot
}

// NewReviewRequest creates a local review request.
func NewReviewRequest(id string, snapshot ReviewSnapshot) (ReviewRequest, error) {
	if id == "" {
		return ReviewRequest{}, fmt.Errorf("review request identity is required")
	}
	if err := snapshot.Validate(); err != nil {
		return ReviewRequest{}, fmt.Errorf("review snapshot is invalid: %w", err)
	}
	return ReviewRequest{id: id, snapshot: snapshot}, nil
}

// ID returns the review request identity.
func (r ReviewRequest) ID() string {
	return r.id
}

// Snapshot returns the immutable review snapshot.
func (r ReviewRequest) Snapshot() ReviewSnapshot {
	return r.snapshot
}
