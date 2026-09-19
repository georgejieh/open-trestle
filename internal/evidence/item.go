package evidence

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EvidenceKind identifies the origin of immutable review evidence.
type EvidenceKind string

const (
	// EvidenceKindSource identifies evidence bound to a source range.
	EvidenceKindSource EvidenceKind = "source"
)

// EvidenceItem binds a content digest to a source range.
type EvidenceItem struct {
	id          string
	kind        EvidenceKind
	digest      string
	sourceRange SourceRange
}

// NewEvidenceItem creates a content-addressed evidence item.
func NewEvidenceItem(id string, kind EvidenceKind, digest string, sourceRange SourceRange) (EvidenceItem, error) {
	if id == "" {
		return EvidenceItem{}, fmt.Errorf("evidence identity is required")
	}
	if kind != EvidenceKindSource {
		return EvidenceItem{}, fmt.Errorf("unsupported evidence kind: %q", kind)
	}
	if len(digest) != sha256HexLength || digest != strings.ToLower(digest) {
		return EvidenceItem{}, fmt.Errorf("evidence digest must be a lowercase SHA-256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return EvidenceItem{}, fmt.Errorf("invalid evidence digest: %w", err)
	}
	if sourceRange.Path() == "" {
		return EvidenceItem{}, fmt.Errorf("evidence source range is required")
	}
	return EvidenceItem{id: id, kind: kind, digest: digest, sourceRange: sourceRange}, nil
}

const sha256HexLength = 64

// ID returns the evidence identity.
func (i EvidenceItem) ID() string {
	return i.id
}

// Kind returns the evidence origin.
func (i EvidenceItem) Kind() EvidenceKind {
	return i.kind
}

// Digest returns the lowercase SHA-256 content digest.
func (i EvidenceItem) Digest() string {
	return i.digest
}

// SourceRange returns the evidence source range.
func (i EvidenceItem) SourceRange() SourceRange {
	return i.sourceRange
}
