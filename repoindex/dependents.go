package repoindex

import (
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// LineRange is an inclusive range of 1-based lines.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Change is one changed file of a review: the head lines that were added
// or replaced and the base lines that were removed or replaced.
type Change struct {
	// Path is the head path, empty when the file was deleted.
	Path string
	// BasePath is the base path, empty when the file was added. It differs
	// from Path for a file moved and edited.
	BasePath  string
	HeadLines []LineRange
	BaseLines []LineRange
	// Approximation, when set, says why the lines are wider than the
	// change, such as a diff past its budget; it becomes a gap and makes
	// the result incomplete.
	Approximation string
}

// DependentsLimits bound the reverse closure.
type DependentsLimits struct {
	// MaxDepth is how many reference steps the closure follows from the
	// changed definitions.
	MaxDepth int
	// MaxDependents bounds the dependents reported.
	MaxDependents int
	// MaxCandidates bounds the reference candidates followed for one
	// definition, so that a common name does not flood the result.
	MaxCandidates int
	// MaxWork bounds the references checked for the whole closure.
	MaxWork int
}

// DefaultDependentsLimits returns the limits used unless configured.
func DefaultDependentsLimits() DependentsLimits {
	return DependentsLimits{MaxDepth: 3, MaxDependents: 1000, MaxCandidates: 2000, MaxWork: 2_000_000}
}

// withDefaults replaces each limit that is not positive by its default.
func (l DependentsLimits) withDefaults() DependentsLimits {
	d := DefaultDependentsLimits()
	for _, pair := range []struct{ value, fallback *int }{{&l.MaxDepth, &d.MaxDepth}, {&l.MaxDependents, &d.MaxDependents}, {&l.MaxCandidates, &d.MaxCandidates}, {&l.MaxWork, &d.MaxWork}} {
		if *pair.value <= 0 {
			*pair.value = *pair.fallback
		}
	}
	return l
}

// ChangedDefinition is a definition enclosing changed lines. Side is head
// for a definition of the head snapshot and base for one that the change
// removed or replaced; a base definition's ID is meaningless in the head.
type ChangedDefinition struct {
	Symbol
	Side string `json:"side"`
}

// Dependent is a definition, or the top level of a file, that holds a
// reference candidate of a changed definition or of another dependent.
type Dependent struct {
	// Symbol is nil for a reference at the top level of a file.
	Symbol *Symbol `json:"symbol,omitempty"`
	Path   string  `json:"path"`
	Role   Role    `json:"role"`
	// Depth is 1 for a reference to a changed definition, 2 for a
	// reference to a dependent of depth 1, and so on.
	Depth int `json:"depth"`
	// Via is the referenced name and Line the line of the reference.
	Via   syntaxanalysis.Text `json:"via"`
	Line  int                 `json:"line"`
	Scope Scope               `json:"scope"`
}

// DependentFile is a file holding a changed definition (depth 0) or a
// dependent, at the smallest depth found.
type DependentFile struct {
	Path  string `json:"path"`
	Role  Role   `json:"role"`
	Depth int    `json:"depth"`
}

// DependentsCut records what the limits left out.
type DependentsCut struct {
	// NotExpanded counts dependents at the depth limit whose own
	// references were not followed.
	NotExpanded int `json:"not_expanded"`
	// DependentsDropped counts candidates past MaxDependents.
	DependentsDropped int `json:"dependents_dropped"`
	// CandidatesCut counts definitions whose candidates passed
	// MaxCandidates; their remaining candidates were not followed.
	CandidatesCut int `json:"candidates_cut"`
	// WorkCut counts definitions whose references were not all checked
	// because MaxWork was spent.
	WorkCut int `json:"work_cut"`
}

// ChangeGap says why a changed file is not fully covered.
type ChangeGap struct {
	Path   string `json:"path"`
	Side   string `json:"side"`
	Reason string `json:"reason"`
}

// DependentsResult is the reverse closure of a change.
type DependentsResult struct {
	// Coverage is the head graph's, with Complete also false when a change
	// was approximated or a limit cut the closure: a dependent the index
	// does not cover is not found.
	Coverage   GraphCoverage       `json:"coverage"`
	Changed    []ChangedDefinition `json:"changed"`
	Dependents []Dependent         `json:"dependents"`
	Files      []DependentFile     `json:"files"`
	TestFiles  []string            `json:"test_files"`
	Cut        DependentsCut       `json:"cut"`
	Gaps       []ChangeGap         `json:"gaps"`
}

// Dependents computes the definitions enclosing a change's lines and the
// reverse closure of the definitions and files that hold reference
// candidates of them, breadth first, within the limits. base, which may be
// nil, supplies the definitions the change removed or replaced.
func Dependents(head, base *Graph, changes []Change, limits DependentsLimits) DependentsResult {
	c := newClosure(head, base, limits.withDefaults())
	for _, change := range changes {
		c.seed(change)
	}
	c.expand()
	return c.finish()
}
