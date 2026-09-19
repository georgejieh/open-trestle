package evidence

import (
	"bytes"
	"fmt"
)

// Bounds Myers search independently of the parser's byte and line limits.
const (
	maxUnifiedDiffGenerationEditDistance = 1024
	maxUnifiedDiffGenerationWork         = 8_388_608
	maxUnifiedDiffGenerationTraceCells   = 1_100_000
)

// UnifiedDiffGenerationError identifies an expected generation failure category.
type UnifiedDiffGenerationError string

const (
	UnifiedDiffGenerationNoChange           UnifiedDiffGenerationError = "no_change"
	UnifiedDiffGenerationUnsupportedContent UnifiedDiffGenerationError = "unsupported_content"
	UnifiedDiffGenerationResourceLimit      UnifiedDiffGenerationError = "resource_limit"
)

// Error returns the stable generation failure category.
func (e UnifiedDiffGenerationError) Error() string { return string(e) }

type unifiedDiffGenerationLimits struct {
	maxContentBytes int
	maxLines        int
	maxPatchBytes   int
	maxHunks        int
	maxEditDistance int
	maxWork         int
	maxTraceCells   int
}

type generatedDiffOperation struct {
	kind      byte
	baseIndex int
	headIndex int
}

type generatedMyersTraceRow struct {
	distance int
	values   []int
}

// GenerateUnifiedFileDiff builds one canonical bounded modified-file patch.
func GenerateUnifiedFileDiff(path string, baseContent, headContent []byte) ([]byte, error) {
	return generateUnifiedFileDiff(path, baseContent, headContent, standardUnifiedDiffGenerationLimits())
}

func standardUnifiedDiffGenerationLimits() unifiedDiffGenerationLimits {
	return unifiedDiffGenerationLimits{
		maxContentBytes: maxUnifiedDiffContentBytes,
		maxLines:        maxUnifiedDiffPhysicalLines,
		maxPatchBytes:   maxUnifiedDiffPatchBytes,
		maxHunks:        maxUnifiedDiffHunks,
		maxEditDistance: maxUnifiedDiffGenerationEditDistance,
		maxWork:         maxUnifiedDiffGenerationWork,
		maxTraceCells:   maxUnifiedDiffGenerationTraceCells,
	}
}

func generateUnifiedFileDiff(path string, baseContent, headContent []byte, limits unifiedDiffGenerationLimits) ([]byte, error) {
	if err := validateUnifiedDiffGenerationLimits(limits); err != nil {
		return nil, err
	}
	if len(path) > maxUnifiedDiffPathBytes || validateSourcePath(path) != nil {
		return nil, UnifiedDiffGenerationUnsupportedContent
	}
	if len(baseContent) > limits.maxContentBytes || len(headContent) > limits.maxContentBytes {
		return nil, UnifiedDiffGenerationResourceLimit
	}
	if bytes.IndexByte(baseContent, 0) >= 0 || bytes.IndexByte(headContent, 0) >= 0 {
		return nil, UnifiedDiffGenerationUnsupportedContent
	}
	if bytes.Equal(baseContent, headContent) {
		return nil, UnifiedDiffGenerationNoChange
	}
	baseBytes := append([]byte(nil), baseContent...)
	headBytes := append([]byte(nil), headContent...)
	base, err := newUnifiedContent(baseBytes)
	if err != nil || len(base.lines) > limits.maxLines {
		return nil, UnifiedDiffGenerationResourceLimit
	}
	head, err := newUnifiedContent(headBytes)
	if err != nil || len(head.lines) > limits.maxLines {
		return nil, UnifiedDiffGenerationResourceLimit
	}
	operations, err := buildGeneratedMyersOperations(base, head, limits)
	if err != nil {
		return nil, err
	}
	patch, err := renderGeneratedUnifiedDiff(path, base, head, operations, limits)
	if err != nil {
		return nil, err
	}
	if _, _, err := ParseUnifiedFileDiff(path, baseBytes, headBytes, patch); err != nil {
		return nil, fmt.Errorf("generated unified diff failed validation: %w", err)
	}
	return patch, nil
}

func validateUnifiedDiffGenerationLimits(limits unifiedDiffGenerationLimits) error {
	if limits.maxContentBytes <= 0 || limits.maxContentBytes > maxUnifiedDiffContentBytes || limits.maxLines <= 0 || limits.maxLines > maxUnifiedDiffPhysicalLines || limits.maxPatchBytes <= 0 || limits.maxPatchBytes > maxUnifiedDiffPatchBytes || limits.maxHunks <= 0 || limits.maxHunks > maxUnifiedDiffHunks || limits.maxEditDistance <= 0 || limits.maxEditDistance > maxUnifiedDiffGenerationEditDistance || limits.maxWork <= 0 || limits.maxWork > maxUnifiedDiffGenerationWork || limits.maxTraceCells <= 0 || limits.maxTraceCells > maxUnifiedDiffGenerationTraceCells {
		return UnifiedDiffGenerationResourceLimit
	}
	return nil
}

func buildGeneratedMyersOperations(base, head unifiedContent, limits unifiedDiffGenerationLimits) ([]generatedDiffOperation, error) {
	baseCount, headCount := len(base.lines), len(head.lines)
	maximum := baseCount + headCount
	if maximum < 0 || maximum > 2*maxUnifiedDiffPhysicalLines {
		return nil, UnifiedDiffGenerationResourceLimit
	}
	offset := maximum + 1
	frontier := make([]int, 2*maximum+3)
	trace := make([]generatedMyersTraceRow, 0, limits.maxEditDistance+1)
	work, traceCells := 0, 0
	for distance := 0; distance <= maximum && distance <= limits.maxEditDistance; distance++ {
		rowCells := 2*distance + 1
		if traceCells > limits.maxTraceCells-rowCells {
			return nil, UnifiedDiffGenerationResourceLimit
		}
		for diagonal := -distance; diagonal <= distance; diagonal += 2 {
			work++
			if work > limits.maxWork {
				return nil, UnifiedDiffGenerationResourceLimit
			}
			index := offset + diagonal
			var baseIndex int
			if diagonal == -distance || (diagonal != distance && frontier[index-1] < frontier[index+1]) {
				baseIndex = frontier[index+1]
			} else {
				baseIndex = frontier[index-1] + 1
			}
			headIndex := baseIndex - diagonal
			for baseIndex < baseCount && headIndex < headCount {
				work++
				if work > limits.maxWork {
					return nil, UnifiedDiffGenerationResourceLimit
				}
				if !sameUnifiedPhysicalLine(base, baseIndex, head, headIndex) {
					break
				}
				baseIndex++
				headIndex++
			}
			frontier[index] = baseIndex
			if baseIndex >= baseCount && headIndex >= headCount {
				trace = append(trace, copyGeneratedTraceRow(frontier, offset, distance))
				return backtrackGeneratedMyersOperations(base, head, trace), nil
			}
		}
		trace = append(trace, copyGeneratedTraceRow(frontier, offset, distance))
		traceCells += rowCells
	}
	return nil, UnifiedDiffGenerationResourceLimit
}

func copyGeneratedTraceRow(frontier []int, offset, distance int) generatedMyersTraceRow {
	values := make([]int, 2*distance+1)
	for diagonal := -distance; diagonal <= distance; diagonal++ {
		values[diagonal+distance] = frontier[offset+diagonal]
	}
	return generatedMyersTraceRow{distance: distance, values: values}
}

func generatedTraceValue(row generatedMyersTraceRow, diagonal int) int {
	return row.values[diagonal+row.distance]
}

func backtrackGeneratedMyersOperations(base, head unifiedContent, trace []generatedMyersTraceRow) []generatedDiffOperation {
	baseIndex, headIndex := len(base.lines), len(head.lines)
	reversed := make([]generatedDiffOperation, 0, baseIndex+headIndex)
	for distance := len(trace) - 1; distance > 0; distance-- {
		diagonal := baseIndex - headIndex
		previous := trace[distance-1]
		var previousDiagonal int
		if diagonal == -distance || (diagonal != distance && generatedTraceValue(previous, diagonal-1) < generatedTraceValue(previous, diagonal+1)) {
			previousDiagonal = diagonal + 1
		} else {
			previousDiagonal = diagonal - 1
		}
		previousBase := generatedTraceValue(previous, previousDiagonal)
		previousHead := previousBase - previousDiagonal
		for baseIndex > previousBase && headIndex > previousHead {
			baseIndex--
			headIndex--
			reversed = append(reversed, generatedDiffOperation{kind: ' ', baseIndex: baseIndex, headIndex: headIndex})
		}
		if baseIndex == previousBase {
			headIndex--
			reversed = append(reversed, generatedDiffOperation{kind: '+', baseIndex: baseIndex, headIndex: headIndex})
		} else {
			baseIndex--
			reversed = append(reversed, generatedDiffOperation{kind: '-', baseIndex: baseIndex, headIndex: headIndex})
		}
	}
	for baseIndex > 0 && headIndex > 0 {
		baseIndex--
		headIndex--
		reversed = append(reversed, generatedDiffOperation{kind: ' ', baseIndex: baseIndex, headIndex: headIndex})
	}
	for baseIndex > 0 {
		baseIndex--
		reversed = append(reversed, generatedDiffOperation{kind: '-', baseIndex: baseIndex, headIndex: 0})
	}
	for headIndex > 0 {
		headIndex--
		reversed = append(reversed, generatedDiffOperation{kind: '+', baseIndex: 0, headIndex: headIndex})
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed
}

type generatedPatchWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (w *generatedPatchWriter) write(parts ...[]byte) error {
	total := w.buffer.Len()
	for _, part := range parts {
		if len(part) > w.limit-total {
			return UnifiedDiffGenerationResourceLimit
		}
		total += len(part)
	}
	for _, part := range parts {
		_, _ = w.buffer.Write(part)
	}
	return nil
}

func renderGeneratedUnifiedDiff(path string, base, head unifiedContent, operations []generatedDiffOperation, limits unifiedDiffGenerationLimits) ([]byte, error) {
	writer := generatedPatchWriter{limit: limits.maxPatchBytes}
	if err := writer.write([]byte("--- a/"), []byte(path), []byte("\n+++ b/"), []byte(path), []byte("\n")); err != nil {
		return nil, err
	}
	baseCursor, headCursor, hunkCount := 1, 1, 0
	for index := 0; index < len(operations); {
		if operations[index].kind == ' ' {
			baseCursor++
			headCursor++
			index++
			continue
		}
		start := index
		baseStart, headStart := baseCursor, headCursor
		for index < len(operations) && operations[index].kind != ' ' {
			if operations[index].kind == '-' {
				baseCursor++
			} else {
				headCursor++
			}
			index++
		}
		baseLineCount := baseCursor - baseStart
		headLineCount := headCursor - headStart
		hunkCount++
		if hunkCount > limits.maxHunks {
			return nil, UnifiedDiffGenerationResourceLimit
		}
		baseHeaderStart, headHeaderStart := baseStart, headStart
		if baseLineCount == 0 {
			baseHeaderStart--
		}
		if headLineCount == 0 {
			headHeaderStart--
		}
		header := []byte(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", baseHeaderStart, baseLineCount, headHeaderStart, headLineCount))
		if err := writer.write(header); err != nil {
			return nil, err
		}
		for _, kind := range []byte{'-', '+'} {
			for _, operation := range operations[start:index] {
				if operation.kind != kind {
					continue
				}
				content := base
				lineIndex := operation.baseIndex
				if kind == '+' {
					content = head
					lineIndex = operation.headIndex
				}
				if err := writer.write([]byte{kind}, content.lines[lineIndex], []byte{'\n'}); err != nil {
					return nil, err
				}
				if !content.lineHasLF(lineIndex) {
					if err := writer.write([]byte(unifiedNoNewlineMarker), []byte{'\n'}); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if hunkCount == 0 {
		return nil, UnifiedDiffGenerationNoChange
	}
	return append([]byte(nil), writer.buffer.Bytes()...), nil
}
