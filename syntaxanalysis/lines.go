package syntaxanalysis

import "sort"

// LineIndex converts byte offsets of one source to positions.
type LineIndex struct{ starts []int }

// NewLineIndex indexes the line starts of content.
func NewLineIndex(content []byte) LineIndex {
	starts := []int{0}
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return LineIndex{starts: starts}
}

// Position returns the 1-based line and byte column of an offset.
func (l LineIndex) Position(offset int) Position {
	line := sort.Search(len(l.starts), func(i int) bool { return l.starts[i] > offset }) - 1
	return Position{Line: line + 1, Column: offset - l.starts[line] + 1}
}

// Range returns the range of a span.
func (l LineIndex) Range(s Span) Range {
	return Range{StartByte: s.Start, EndByte: s.End, Start: l.Position(s.Start), End: l.Position(s.End)}
}
