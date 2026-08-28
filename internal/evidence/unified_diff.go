package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	// These limits bound memory and work for one untrusted text-file diff.
	maxUnifiedDiffContentBytes  = 1 << 20
	maxUnifiedHunkHeaderBytes   = 1024
	maxUnifiedDiffPatchBytes    = 2*maxUnifiedDiffContentBytes + 1024
	maxUnifiedDiffPathBytes     = 4096
	maxUnifiedDiffPhysicalLines = 100_000
	maxUnifiedDiffHunks         = 1024
	unifiedNoNewlineMarker      = `\ No newline at end of file`
)

// ParseUnifiedFileDiff verifies one modified-file patch against exact content.
func ParseUnifiedFileDiff(path string, baseContent, headContent, patch []byte) (FileChange, LineMap, error) {
	if err := validateUnifiedDiffInputs(path, baseContent, headContent, patch); err != nil {
		return FileChange{}, LineMap{}, err
	}
	base, err := newUnifiedContent(baseContent)
	if err != nil {
		return FileChange{}, LineMap{}, fmt.Errorf("base content: %w", err)
	}
	head, err := newUnifiedContent(headContent)
	if err != nil {
		return FileChange{}, LineMap{}, fmt.Errorf("head content: %w", err)
	}
	patchLines := bytes.Split(patch[:len(patch)-1], []byte{'\n'})
	parser := unifiedFileDiffParser{
		path:       path,
		base:       base,
		head:       head,
		patchLines: patchLines,
	}
	edits, err := parser.parse()
	if err != nil {
		return FileChange{}, LineMap{}, err
	}
	return buildUnifiedDiffEvidence(path, baseContent, headContent, base, head, edits)
}

func validateUnifiedDiffInputs(path string, baseContent, headContent, patch []byte) error {
	if len(path) > maxUnifiedDiffPathBytes {
		return fmt.Errorf("source path exceeds %d bytes", maxUnifiedDiffPathBytes)
	}
	if err := validateSourcePath(path); err != nil {
		return err
	}
	if len(baseContent) > maxUnifiedDiffContentBytes {
		return fmt.Errorf("base content exceeds %d bytes", maxUnifiedDiffContentBytes)
	}
	if len(headContent) > maxUnifiedDiffContentBytes {
		return fmt.Errorf("head content exceeds %d bytes", maxUnifiedDiffContentBytes)
	}
	if len(patch) == 0 {
		return fmt.Errorf("unified diff is required")
	}
	if len(patch) > maxUnifiedDiffPatchBytes {
		return fmt.Errorf("unified diff exceeds %d bytes", maxUnifiedDiffPatchBytes)
	}
	if patch[len(patch)-1] != '\n' {
		return fmt.Errorf("unified diff must end with LF")
	}
	if bytes.IndexByte(baseContent, 0) >= 0 || bytes.IndexByte(headContent, 0) >= 0 || bytes.IndexByte(patch, 0) >= 0 {
		return fmt.Errorf("binary content is not supported")
	}
	if bytes.Count(patch, []byte{'\n'}) > 2*maxUnifiedDiffPhysicalLines+2*maxUnifiedDiffHunks+2 {
		return fmt.Errorf("unified diff has too many physical lines")
	}
	return nil
}

type unifiedContent struct {
	lines      [][]byte
	terminalLF bool
}

func newUnifiedContent(content []byte) (unifiedContent, error) {
	if len(content) == 0 {
		return unifiedContent{}, nil
	}
	lineCount := bytes.Count(content, []byte{'\n'})
	terminalLF := content[len(content)-1] == '\n'
	if !terminalLF {
		lineCount++
	}
	if lineCount > maxUnifiedDiffPhysicalLines {
		return unifiedContent{}, fmt.Errorf("content has more than %d physical lines", maxUnifiedDiffPhysicalLines)
	}
	lines := bytes.Split(content, []byte{'\n'})
	if terminalLF {
		lines = lines[:len(lines)-1]
	}
	return unifiedContent{lines: lines, terminalLF: terminalLF}, nil
}

func (c unifiedContent) lineHasLF(index int) bool {
	return index < len(c.lines)-1 || c.terminalLF
}

type unifiedEdit struct {
	baseStart int
	baseCount int
	headStart int
	headCount int
}

type unifiedFileDiffParser struct {
	path       string
	base       unifiedContent
	head       unifiedContent
	patchLines [][]byte
	patchIndex int
	baseIndex  int
	headIndex  int
	hunkCount  int
	edits      []unifiedEdit
}

func (p *unifiedFileDiffParser) parse() ([]unifiedEdit, error) {
	if len(p.patchLines) < 3 {
		return nil, fmt.Errorf("unified diff must contain file headers and at least one hunk")
	}
	if !bytes.Equal(p.patchLines[0], []byte("--- a/"+p.path)) {
		return nil, fmt.Errorf("patch line 1: unsupported or mismatched base path")
	}
	if !bytes.Equal(p.patchLines[1], []byte("+++ b/"+p.path)) {
		return nil, fmt.Errorf("patch line 2: unsupported or mismatched head path")
	}
	p.patchIndex = 2
	for p.patchIndex < len(p.patchLines) {
		if p.hunkCount == maxUnifiedDiffHunks {
			return nil, p.lineError("unified diff has too many hunks")
		}
		if !bytes.HasPrefix(p.patchLines[p.patchIndex], []byte("@@")) {
			return nil, p.lineError("expected a unified hunk header")
		}
		header, err := parseUnifiedHunkHeader(p.patchLines[p.patchIndex])
		if err != nil {
			return nil, p.lineError(err.Error())
		}
		p.hunkCount++
		p.patchIndex++
		if err := p.parseHunk(header); err != nil {
			return nil, err
		}
	}
	if p.hunkCount == 0 || len(p.edits) == 0 {
		return nil, fmt.Errorf("unified diff must contain at least one edit")
	}
	if err := p.verifyUnchangedTail(); err != nil {
		return nil, err
	}
	return append([]unifiedEdit(nil), p.edits...), nil
}

type unifiedHunkHeader struct {
	baseStart  int
	baseCount  int
	headStart  int
	headCount  int
	baseCursor int
	headCursor int
}

func parseUnifiedHunkHeader(line []byte) (unifiedHunkHeader, error) {
	if len(line) > maxUnifiedHunkHeaderBytes {
		return unifiedHunkHeader{}, fmt.Errorf("hunk header exceeds %d bytes", maxUnifiedHunkHeaderBytes)
	}
	if !bytes.HasPrefix(line, []byte("@@ -")) {
		return unifiedHunkHeader{}, fmt.Errorf("invalid hunk header prefix")
	}
	index := len("@@ -")
	baseStart, index, err := parseUnifiedDecimal(line, index)
	if err != nil {
		return unifiedHunkHeader{}, fmt.Errorf("invalid base start: %w", err)
	}
	baseCount := 1
	if index < len(line) && line[index] == ',' {
		baseCount, index, err = parseUnifiedDecimal(line, index+1)
		if err != nil {
			return unifiedHunkHeader{}, fmt.Errorf("invalid base count: %w", err)
		}
	}
	if index+2 > len(line) || !bytes.Equal(line[index:index+2], []byte(" +")) {
		return unifiedHunkHeader{}, fmt.Errorf("invalid hunk coordinate separator")
	}
	index += 2
	headStart, index, err := parseUnifiedDecimal(line, index)
	if err != nil {
		return unifiedHunkHeader{}, fmt.Errorf("invalid head start: %w", err)
	}
	headCount := 1
	if index < len(line) && line[index] == ',' {
		headCount, index, err = parseUnifiedDecimal(line, index+1)
		if err != nil {
			return unifiedHunkHeader{}, fmt.Errorf("invalid head count: %w", err)
		}
	}
	if index+3 > len(line) || !bytes.Equal(line[index:index+3], []byte(" @@")) {
		return unifiedHunkHeader{}, fmt.Errorf("invalid hunk header suffix")
	}
	index += 3
	if index < len(line) {
		if line[index] != ' ' || index+1 == len(line) {
			return unifiedHunkHeader{}, fmt.Errorf("invalid hunk section")
		}
		section := line[index+1:]
		if !utf8.Valid(section) || bytes.Contains(section, []byte("@@")) {
			return unifiedHunkHeader{}, fmt.Errorf("invalid hunk section")
		}
		for _, value := range string(section) {
			if !unicode.IsPrint(value) {
				return unifiedHunkHeader{}, fmt.Errorf("invalid hunk section")
			}
		}
	}
	baseCursor, err := normalizeUnifiedStart(baseStart, baseCount)
	if err != nil {
		return unifiedHunkHeader{}, fmt.Errorf("invalid base coordinates: %w", err)
	}
	headCursor, err := normalizeUnifiedStart(headStart, headCount)
	if err != nil {
		return unifiedHunkHeader{}, fmt.Errorf("invalid head coordinates: %w", err)
	}
	if baseCount == 0 && headCount == 0 {
		return unifiedHunkHeader{}, fmt.Errorf("hunk cannot be empty on both sides")
	}
	return unifiedHunkHeader{
		baseStart: baseStart, baseCount: baseCount,
		headStart: headStart, headCount: headCount,
		baseCursor: baseCursor, headCursor: headCursor,
	}, nil
}

func parseUnifiedDecimal(line []byte, index int) (int, int, error) {
	start := index
	maxInt := int(^uint(0) >> 1)
	value := 0
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		digit := int(line[index] - '0')
		if value > (maxInt-digit)/10 {
			return 0, index, fmt.Errorf("decimal value overflows int")
		}
		value = value*10 + digit
		index++
	}
	if index == start {
		return 0, index, fmt.Errorf("decimal value is required")
	}
	if index-start > 1 && line[start] == '0' {
		return 0, index, fmt.Errorf("decimal value has a leading zero")
	}
	return value, index, nil
}

func normalizeUnifiedStart(rawStart, count int) (int, error) {
	maxInt := int(^uint(0) >> 1)
	if count == 0 {
		if rawStart == maxInt {
			return 0, fmt.Errorf("zero-count cursor overflows int")
		}
		return rawStart + 1, nil
	}
	if rawStart == 0 {
		return 0, fmt.Errorf("positive span must start on a positive line")
	}
	if _, err := hunkInclusiveEnd(rawStart, count); err != nil {
		return 0, err
	}
	return rawStart, nil
}

func (p *unifiedFileDiffParser) parseHunk(header unifiedHunkHeader) error {
	baseTarget := header.baseCursor - 1
	headTarget := header.headCursor - 1
	if baseTarget < p.baseIndex || headTarget < p.headIndex {
		return p.lineError("hunk overlaps or moves backward")
	}
	if baseTarget > len(p.base.lines) || headTarget > len(p.head.lines) {
		return p.lineError("hunk starts beyond content")
	}
	if baseTarget-p.baseIndex != headTarget-p.headIndex {
		return p.lineError("hunk has unequal omitted gaps")
	}
	for p.baseIndex < baseTarget {
		if !sameUnifiedPhysicalLine(p.base, p.baseIndex, p.head, p.headIndex) {
			return p.lineError("omitted content differs")
		}
		p.baseIndex++
		p.headIndex++
	}

	baseConsumed := 0
	headConsumed := 0
	bodyLines := 0
	editLines := 0
	var active *unifiedEdit
	additionSeen := false
	for p.patchIndex < len(p.patchLines) && !bytes.HasPrefix(p.patchLines[p.patchIndex], []byte("@@")) {
		line := p.patchLines[p.patchIndex]
		if len(line) == 0 {
			return p.lineError("empty hunk body record")
		}
		bodyLines++
		switch line[0] {
		case ' ':
			if active != nil {
				if err := p.appendEdit(*active); err != nil {
					return p.lineError(err.Error())
				}
				active = nil
				additionSeen = false
			}
			if baseConsumed == header.baseCount || headConsumed == header.headCount {
				return p.lineError("context exceeds hunk counts")
			}
			if err := p.matchContext(line[1:]); err != nil {
				return err
			}
			baseConsumed++
			headConsumed++
		case '-':
			if additionSeen {
				return p.lineError("deletion follows addition without context")
			}
			if baseConsumed == header.baseCount {
				return p.lineError("deletion exceeds base hunk count")
			}
			if active == nil {
				active = &unifiedEdit{baseStart: p.baseIndex + 1, headStart: p.headIndex + 1}
			}
			if err := p.matchDeletion(line[1:]); err != nil {
				return err
			}
			active.baseCount++
			baseConsumed++
			editLines++
		case '+':
			if headConsumed == header.headCount {
				return p.lineError("addition exceeds head hunk count")
			}
			if active == nil {
				active = &unifiedEdit{baseStart: p.baseIndex + 1, headStart: p.headIndex + 1}
			}
			additionSeen = true
			if err := p.matchAddition(line[1:]); err != nil {
				return err
			}
			active.headCount++
			headConsumed++
			editLines++
		case '\\':
			return p.lineError("unexpected no-newline marker")
		default:
			return p.lineError("invalid hunk body prefix")
		}
	}
	if active != nil {
		if err := p.appendEdit(*active); err != nil {
			return p.lineError(err.Error())
		}
	}
	if bodyLines == 0 {
		return p.lineError("hunk body is required")
	}
	if editLines == 0 {
		return p.lineError("hunk must contain an addition or deletion")
	}
	if baseConsumed != header.baseCount || headConsumed != header.headCount {
		return p.lineError("hunk body counts do not match header")
	}
	return nil
}

func (p *unifiedFileDiffParser) matchContext(content []byte) error {
	if p.baseIndex >= len(p.base.lines) || p.headIndex >= len(p.head.lines) {
		return p.lineError("context is beyond content")
	}
	if !bytes.Equal(content, p.base.lines[p.baseIndex]) || !bytes.Equal(content, p.head.lines[p.headIndex]) {
		return p.lineError("context does not match content")
	}
	baseMissingLF := !p.base.lineHasLF(p.baseIndex)
	headMissingLF := !p.head.lineHasLF(p.headIndex)
	if baseMissingLF != headMissingLF {
		return p.lineError("context has different newline state")
	}
	if err := p.consumeNoNewlineMarker(baseMissingLF); err != nil {
		return err
	}
	p.baseIndex++
	p.headIndex++
	return nil
}

func (p *unifiedFileDiffParser) matchDeletion(content []byte) error {
	if p.baseIndex >= len(p.base.lines) || !bytes.Equal(content, p.base.lines[p.baseIndex]) {
		return p.lineError("deletion does not match base content")
	}
	if err := p.consumeNoNewlineMarker(!p.base.lineHasLF(p.baseIndex)); err != nil {
		return err
	}
	p.baseIndex++
	return nil
}

func (p *unifiedFileDiffParser) matchAddition(content []byte) error {
	if p.headIndex >= len(p.head.lines) || !bytes.Equal(content, p.head.lines[p.headIndex]) {
		return p.lineError("addition does not match head content")
	}
	if err := p.consumeNoNewlineMarker(!p.head.lineHasLF(p.headIndex)); err != nil {
		return err
	}
	p.headIndex++
	return nil
}

func (p *unifiedFileDiffParser) consumeNoNewlineMarker(required bool) error {
	p.patchIndex++
	hasMarker := p.patchIndex < len(p.patchLines) && string(p.patchLines[p.patchIndex]) == unifiedNoNewlineMarker
	if required && !hasMarker {
		return p.lineError("missing no-newline marker")
	}
	if !required && hasMarker {
		return p.lineError("unexpected no-newline marker")
	}
	if hasMarker {
		p.patchIndex++
	}
	return nil
}

func (p *unifiedFileDiffParser) appendEdit(edit unifiedEdit) error {
	if edit.baseCount == 0 && edit.headCount == 0 {
		return fmt.Errorf("empty edit block")
	}
	if len(p.edits) == 0 {
		p.edits = append(p.edits, edit)
		return nil
	}
	last := &p.edits[len(p.edits)-1]
	if last.baseStart+last.baseCount == edit.baseStart && last.headStart+last.headCount == edit.headStart {
		last.baseCount += edit.baseCount
		last.headCount += edit.headCount
		return nil
	}
	p.edits = append(p.edits, edit)
	return nil
}

func (p *unifiedFileDiffParser) verifyUnchangedTail() error {
	if len(p.base.lines)-p.baseIndex != len(p.head.lines)-p.headIndex {
		return fmt.Errorf("omitted tail has unequal line counts")
	}
	for p.baseIndex < len(p.base.lines) {
		if !sameUnifiedPhysicalLine(p.base, p.baseIndex, p.head, p.headIndex) {
			return fmt.Errorf("omitted tail differs")
		}
		p.baseIndex++
		p.headIndex++
	}
	return nil
}

func sameUnifiedPhysicalLine(base unifiedContent, baseIndex int, head unifiedContent, headIndex int) bool {
	return bytes.Equal(base.lines[baseIndex], head.lines[headIndex]) && base.lineHasLF(baseIndex) == head.lineHasLF(headIndex)
}

func (p *unifiedFileDiffParser) lineError(message string) error {
	return fmt.Errorf("patch line %d: %s", p.patchIndex+1, message)
}

func buildUnifiedDiffEvidence(path string, baseBytes, headBytes []byte, base, head unifiedContent, edits []unifiedEdit) (FileChange, LineMap, error) {
	ranges := make([]SourceRange, 0, len(edits))
	for _, edit := range edits {
		if edit.headCount == 0 {
			continue
		}
		sourceRange, err := NewSourceRange(path, edit.headStart, edit.headStart+edit.headCount-1)
		if err != nil {
			return FileChange{}, LineMap{}, fmt.Errorf("create changed range: %w", err)
		}
		ranges = append(ranges, sourceRange)
	}
	change, err := NewFileChange(path, unifiedContentDigest(baseBytes), unifiedContentDigest(headBytes), ranges)
	if err != nil {
		return FileChange{}, LineMap{}, fmt.Errorf("create file change: %w", err)
	}
	hunks := make([]Hunk, len(edits))
	for i, edit := range edits {
		hunk, err := newHunkWithoutRangeCheck(change, edit.baseStart, edit.baseCount, edit.headStart, edit.headCount)
		if err != nil {
			return FileChange{}, LineMap{}, fmt.Errorf("create hunk %d: %w", i, err)
		}
		hunks[i] = hunk
	}
	lineMap, err := NewLineMap(change, len(base.lines), len(head.lines), hunks)
	if err != nil {
		return FileChange{}, LineMap{}, fmt.Errorf("create line map: %w", err)
	}
	return change, lineMap, nil
}

func unifiedContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
