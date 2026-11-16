package review

import "github.com/georgejieh/open-trestle/internal/evidence"

// LineSide names the coordinate space of a finding location or an evidence
// binding. Head lines are lines of the reviewed head file; base lines are lines
// of the base file that a removed_lines source binds. The two are different
// coordinate spaces: a range on one side never contains a range on the other,
// even when the path and the line numbers are equal.
type LineSide uint8

const (
	// LineSideHead is the zero value: head lines of the reviewed snapshot.
	LineSideHead LineSide = iota
	// LineSideBase is base lines bound by a removed_lines source.
	LineSideBase
)

// String returns the recorded token: "head" or "base".
func (s LineSide) String() string {
	switch s {
	case LineSideHead:
		return "head"
	case LineSideBase:
		return "base"
	default:
		return ""
	}
}

// recordedLineSide is the omitempty wire token of a side: head is absent so
// head-only records keep their historical bytes.
func recordedLineSide(side LineSide) string {
	if side == LineSideBase {
		return "base"
	}
	return ""
}

// parseRecordedLineSide accepts only an absent side or "base".
func parseRecordedLineSide(value string) (LineSide, bool) {
	switch value {
	case "":
		return LineSideHead, true
	case "base":
		return LineSideBase, true
	default:
		return 0, false
	}
}

func validLineSide(side LineSide) bool {
	return side == LineSideHead || side == LineSideBase
}

// bindingCovers reports whether an evidence binding contains a location on
// the same side.
func bindingCovers(binding candidateEvidenceBinding, side LineSide, location evidence.SourceRange) bool {
	return binding.side == side && rangeContains(binding.sourceRange, location)
}

// hasBaseSide reports whether any binding records base lines.
func hasBaseSide(bindings []candidateEvidenceBinding) bool {
	for _, binding := range bindings {
		if binding.side == LineSideBase {
			return true
		}
	}
	return false
}
