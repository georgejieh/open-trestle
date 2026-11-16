package github

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

type locatedFindingStub struct {
	path       string
	start, end int
	side       review.LineSide
}

func (f locatedFindingStub) Path() string          { return f.path }
func (f locatedFindingStub) StartLine() int        { return f.start }
func (f locatedFindingStub) EndLine() int          { return f.end }
func (f locatedFindingStub) Side() review.LineSide { return f.side }

func TestPublicationNeverAnchorsBaseLinesOnTheHeadSide(t *testing.T) {
	head := locatedFindingStub{path: "calc.go", start: 4, end: 6}
	base := locatedFindingStub{path: "calc.go", start: 4, end: 6, side: review.LineSideBase}
	// Head locations keep their historical text, so head-only payloads keep
	// their bytes.
	if got := findingLocation(head); got != "`calc.go:4-6`" {
		t.Fatalf("head location = %q", got)
	}
	if got := findingLocation(base); got != "`calc.go` removed base lines 4-6" {
		t.Fatalf("base location = %q", got)
	}
	comment, err := inlineReviewComment(head, "body")
	if err != nil || comment.Side != "RIGHT" || comment.StartSide != "RIGHT" || comment.StartLine != 4 || comment.Line != 6 {
		t.Fatalf("head comment = %+v, %v", comment, err)
	}
	if comment, err := inlineReviewComment(base, "body"); !errors.Is(err, ErrInvalidPublicationConfig) || comment.Path != "" {
		t.Fatalf("base-side finding anchored inline: %+v, %v", comment, err)
	}
}
