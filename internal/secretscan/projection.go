package secretscan

import (
	"context"
	"fmt"
	"sort"
	"unicode/utf8"
)

type Projection struct {
	sources         [][]byte
	matches         []Match
	initial         ScanMetadata
	residual        ScanMetadata
	maskedByteCount int
	failure         FailureClass
	complete        bool
}

func (projection Projection) Complete() bool {
	return projection.complete && projection.failure == FailureNone
}
func (projection Projection) Sources() [][]byte      { return copiedSources(projection.sources) }
func (projection Projection) Matches() []Match       { return append([]Match(nil), projection.matches...) }
func (projection Projection) Initial() ScanMetadata  { return projection.initial }
func (projection Projection) Residual() ScanMetadata { return projection.residual }
func (projection Projection) MaskedByteCount() int   { return projection.maskedByteCount }
func (projection Projection) Failure() FailureClass  { return projection.failure }
func (projection Projection) String() string         { return "secret scan projection" }
func (projection Projection) GoString() string       { return "secretscan.Projection{<redacted>}" }
func (projection Projection) Format(state fmt.State, verb rune) {
	if verb == 'v' && state.Flag('#') {
		_, _ = fmt.Fprint(state, projection.GoString())
		return
	}
	_, _ = fmt.Fprint(state, projection.String())
}

type Projector struct {
	scanner sourceScanner
}

func newProjector(scanner sourceScanner) *Projector {
	return &Projector{scanner: scanner}
}

func (projector *Projector) Sanitize(ctx context.Context, sources [][]byte) Projection {
	if projector == nil || projector.scanner == nil {
		return Projection{failure: FailurePolicy}
	}
	if !validateSourceInputs(sources) {
		return Projection{failure: FailureInvalidInput}
	}
	ownedSources := copiedSources(sources)
	defer clearSources(ownedSources)
	initial := projector.scanner.scan(ctx, ownedSources)
	projection := Projection{initial: initial.metadata, failure: initial.failure}
	if !initial.Complete() {
		return projection
	}
	sanitized, masked, ok := maskSources(ownedSources, initial.matches)
	if !ok {
		return Projection{initial: initial.metadata, failure: FailurePolicy}
	}
	residual := projector.scanner.scan(ctx, sanitized)
	projection.residual = residual.metadata
	if !residual.Complete() {
		clearSources(sanitized)
		projection.failure = residual.failure
		return projection
	}
	if len(residual.matches) != 0 {
		clearSources(sanitized)
		projection.failure = FailurePolicy
		return projection
	}
	projection.sources = sanitized
	projection.matches = append([]Match(nil), initial.matches...)
	projection.maskedByteCount = masked
	projection.failure = FailureNone
	projection.complete = true
	return projection
}

type byteSpan struct {
	start int
	end   int
}

func maskSources(sources [][]byte, matches []Match) ([][]byte, int, bool) {
	sanitized := copiedSources(sources)
	spans := make([][]byteSpan, len(sources))
	for _, match := range matches {
		if match.SourceOrdinal < 0 || match.SourceOrdinal >= len(sources) {
			clearSources(sanitized)
			return nil, 0, false
		}
		source := sources[match.SourceOrdinal]
		if match.StartByte < 0 || match.EndByteExclusive <= match.StartByte || match.EndByteExclusive > len(source) ||
			!utf8.Valid(source) || !utf8Boundary(source, match.StartByte) || !utf8Boundary(source, match.EndByteExclusive) {
			clearSources(sanitized)
			return nil, 0, false
		}
		spans[match.SourceOrdinal] = append(spans[match.SourceOrdinal], byteSpan{start: match.StartByte, end: match.EndByteExclusive})
	}
	masked := 0
	for ordinal := range sanitized {
		intervals := spans[ordinal]
		sort.Slice(intervals, func(left, right int) bool {
			if intervals[left].start != intervals[right].start {
				return intervals[left].start < intervals[right].start
			}
			return intervals[left].end < intervals[right].end
		})
		merged := mergeSpans(intervals)
		for _, interval := range merged {
			for offset := interval.start; offset < interval.end; offset++ {
				if sanitized[ordinal][offset] == '\r' || sanitized[ordinal][offset] == '\n' {
					continue
				}
				sanitized[ordinal][offset] = '*'
				masked++
			}
		}
		if len(sanitized[ordinal]) != len(sources[ordinal]) || !utf8.Valid(sanitized[ordinal]) || !sameLineBreaks(sources[ordinal], sanitized[ordinal]) {
			clearSources(sanitized)
			return nil, 0, false
		}
	}
	return sanitized, masked, true
}

func mergeSpans(spans []byteSpan) []byteSpan {
	if len(spans) == 0 {
		return nil
	}
	merged := make([]byteSpan, 0, len(spans))
	current := spans[0]
	for _, next := range spans[1:] {
		if next.start <= current.end {
			if next.end > current.end {
				current.end = next.end
			}
			continue
		}
		merged = append(merged, current)
		current = next
	}
	return append(merged, current)
}

func sameLineBreaks(original []byte, sanitized []byte) bool {
	for index := range original {
		if (original[index] == '\r' || original[index] == '\n') != (sanitized[index] == '\r' || sanitized[index] == '\n') {
			return false
		}
		if original[index] == '\r' || original[index] == '\n' {
			if original[index] != sanitized[index] {
				return false
			}
		}
	}
	return true
}

func copiedSources(sources [][]byte) [][]byte {
	if sources == nil {
		return nil
	}
	copied := make([][]byte, len(sources))
	for index := range sources {
		if sources[index] != nil {
			copied[index] = make([]byte, len(sources[index]))
			copy(copied[index], sources[index])
		}
	}
	return copied
}

func clearSources(sources [][]byte) {
	for index := range sources {
		clear(sources[index])
	}
	clear(sources)
}
