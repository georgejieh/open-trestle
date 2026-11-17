package adapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"iter"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
	"github.com/rs/zerolog"
)

const (
	maximumMatches       = 8192
	maximumSources       = 256
	maximumSourceBytes   = 256 * 1024
	maximumRequestBytes  = 2 * 1024 * 1024
	internalScanDeadline = 5 * time.Second
)

// HostEngineScanDeadline bounds one scan in the WebAssembly guest. The guest
// runs the same Betterleaks code compiled to WebAssembly, on one thread, and
// takes up to five times as long as the native worker for the same request.
// Every request that the native worker completes, or stops at the match
// limit, within internalScanDeadline must end the same way in the guest, so
// the guest gets internalScanDeadline times that factor and a fifth more.
const HostEngineScanDeadline = 30 * time.Second

var ErrInitialization = errors.New("secret scanner initialization failed")

type detectorRuntime struct {
	run        func(context.Context, sources.Source) iter.Seq[detect.Result]
	totalBytes func() uint64
}

type Adapter struct {
	detector     *detect.Detector
	runtime      detectorRuntime
	deadline     time.Duration
	buildProfile string
	mu           sync.Mutex
}

// NewWithHostEngine returns an adapter whose regular expressions run in the
// host of a WebAssembly guest. engine must report regexabi.EngineVersion, and
// responses carry protocol.HostRE2BuildProfile.
func NewWithHostEngine(engine blregexp.Engine) (*Adapter, error) {
	return newWithEngine(engine, regexabi.EngineVersion, protocol.HostRE2BuildProfile, HostEngineScanDeadline)
}

func newWithEngine(engine blregexp.Engine, version, buildProfile string, deadline time.Duration) (adapter *Adapter, err error) {
	defer func() {
		if recover() != nil {
			adapter = nil
			err = ErrInitialization
		}
	}()

	logging.Logger = zerolog.Nop()
	if engine == nil || !protocol.KnownBuildProfile(buildProfile) {
		return nil, ErrInitialization
	}
	blregexp.SetEngine(engine)
	if blregexp.Version() != version {
		return nil, ErrInitialization
	}
	wantRulesetDigest := [sha256.Size]byte{
		0x27, 0xde, 0xd7, 0x83, 0xc8, 0x19, 0x40, 0xd1,
		0x3c, 0x22, 0xcc, 0x46, 0x55, 0x6a, 0x3f, 0x81,
		0x84, 0xba, 0xf3, 0x97, 0xbf, 0xf0, 0x8a, 0x69,
		0xfc, 0xfa, 0xe8, 0x79, 0x91, 0x92, 0x5f, 0x42,
	}
	if sha256.Sum256([]byte(config.DefaultConfig)) != wantRulesetDigest {
		return nil, ErrInitialization
	}

	cfg, configErr := config.Default()
	if configErr != nil || !rulesMatchPin(cfg) {
		return nil, ErrInitialization
	}
	detector := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{Enabled: false})
	if detector == nil {
		return nil, ErrInitialization
	}
	detector.MaxDecodeDepth = 0
	detector.MatchContext.Mode = 0
	detector.MatchContext.ColsBefore = 0
	detector.MatchContext.ColsAfter = 0
	detector.MatchContext.LinesBefore = 0
	detector.MatchContext.LinesAfter = 0
	detector.MinConfidence = ""
	detector.IgnoreGitleaksAllow = true
	detector.SkipFindingAppend = true

	return &Adapter{
		detector: detector,
		runtime: detectorRuntime{
			run:        detector.Run,
			totalBytes: detector.TotalBytes.Load,
		},
		deadline:     deadline,
		buildProfile: buildProfile,
	}, nil
}

func rulesMatchPin(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Rules) != protocol.RulesetRuleCount || len(pinnedRuleIDsV1) != protocol.RulesetRuleCount {
		return false
	}
	ids := make([]string, 0, len(cfg.Rules))
	for id := range cfg.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for index, id := range ids {
		if id != pinnedRuleIDsV1[index] {
			return false
		}
	}
	return true
}

func pinnedRuleIDSet() map[string]struct{} {
	ids := make(map[string]struct{}, len(pinnedRuleIDsV1))
	for _, id := range pinnedRuleIDsV1 {
		ids[id] = struct{}{}
	}
	return ids
}

func PinnedRuleIDs() map[string]struct{} {
	return pinnedRuleIDSet()
}

func (a *Adapter) Scan(ctx context.Context, request protocol.Request) protocol.Response {
	buildProfile := ""
	if a != nil {
		buildProfile = a.buildProfile
	}
	response := emptyResponse(request.RequestID, protocol.StatusScanFailed, buildProfile)
	if !validRequest(request) {
		response.Status = protocol.StatusInputRejected
		return response
	}
	if a == nil || a.runtime.run == nil || a.runtime.totalBytes == nil || a.deadline <= 0 || !protocol.KnownBuildProfile(a.buildProfile) {
		return response
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	scanCtx, cancelScan := context.WithTimeout(ctx, a.deadline)
	defer cancelScan()
	ruleIDs := pinnedRuleIDSet()
	matches := make([]protocol.Match, 0)
	hasFailure := false
	hasResourceExhaustion := false

	for _, requestSource := range request.Sources {
		source := newSingleFragmentSource(requestSource.Content)
		// The line index is built on the first finding of the source and
		// shared by all of them, so projection costs one pass over the
		// content however many findings it has.
		var lines *sourceLines
		beforeBytes := a.runtime.totalBytes()
		runCtx, cancelRun := context.WithCancel(scanCtx)
		for result := range a.runtime.run(runCtx, source) {
			if result.Err != nil {
				hasFailure = true
				continue
			}
			if hasFailure || hasResourceExhaustion {
				continue
			}
			if len(matches) == maximumMatches {
				hasResourceExhaustion = true
				cancelRun()
				continue
			}
			finding := result.Finding
			if lines == nil {
				lines = newSourceLines(requestSource.Content)
			}
			match, ok := lines.project(requestSource.Ordinal, findingCoordinates{
				RuleID:      finding.RuleID,
				StartLine:   finding.StartLine,
				EndLine:     finding.EndLine,
				StartColumn: finding.StartColumn,
				EndColumn:   finding.EndColumn,
			}, ruleIDs)
			if !ok {
				hasFailure = true
				continue
			}
			matches = append(matches, match)
		}
		cancelRun()
		afterBytes := a.runtime.totalBytes()
		if !source.completed.Load() || afterBytes < beforeBytes || afterBytes-beforeBytes != uint64(len(requestSource.Content)) {
			hasFailure = true
		}
		if hasResourceExhaustion {
			break
		}
	}
	if scanCtx.Err() != nil && !hasResourceExhaustion {
		hasFailure = true
	}

	if hasResourceExhaustion {
		response.Status = protocol.StatusResourceExhausted
		return response
	}
	if hasFailure {
		return response
	}

	sort.Slice(matches, func(i, j int) bool { return matchLess(matches[i], matches[j]) })
	for index := 1; index < len(matches); index++ {
		if !matchLess(matches[index-1], matches[index]) {
			return response
		}
	}
	response.Status = protocol.StatusComplete
	response.Matches = matches
	return response
}

func emptyResponse(requestID, status, buildProfile string) protocol.Response {
	return protocol.Response{
		SchemaVersion:   1,
		RequestID:       requestID,
		Status:          status,
		Scanner:         protocol.ScannerName,
		ScannerVersion:  protocol.ScannerVersion,
		ScannerCommit:   protocol.ScannerCommit,
		RulesetIdentity: protocol.RulesetIdentity,
		BuildProfile:    buildProfile,
		Matches:         []protocol.Match{},
	}
}

func validRequest(request protocol.Request) bool {
	if request.SchemaVersion != 1 || !validRequestID(request.RequestID) || request.Sources == nil || len(request.Sources) == 0 || len(request.Sources) > maximumSources {
		return false
	}
	total := 0
	for index, source := range request.Sources {
		if source.Ordinal != index || source.Content == nil || len(source.Content) > maximumSourceBytes || !utf8.Valid(source.Content) {
			return false
		}
		total += len(source.Content)
		if total > maximumRequestBytes {
			return false
		}
	}
	return true
}

func validRequestID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	for _, value := range []byte(id) {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}

type findingCoordinates struct {
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
}

// sourceLines is one source's content with its UTF-8 validity and the byte
// offset of every line start, computed once for all of its findings.
type sourceLines struct {
	content []byte
	valid   bool
	starts  []int
}

func newSourceLines(content []byte) *sourceLines {
	return &sourceLines{content: content, valid: utf8.Valid(content), starts: lineStartOffsets(content)}
}

func projectFinding(sourceOrdinal int, content []byte, finding findingCoordinates, ruleIDs map[string]struct{}) (protocol.Match, bool) {
	return newSourceLines(content).project(sourceOrdinal, finding, ruleIDs)
}

func (lines *sourceLines) project(sourceOrdinal int, finding findingCoordinates, ruleIDs map[string]struct{}) (protocol.Match, bool) {
	content := lines.content
	if !lines.valid || finding.StartLine < 1 || finding.EndLine < 1 || finding.StartColumn < 1 || finding.EndColumn < 1 {
		return protocol.Match{}, false
	}
	if _, known := ruleIDs[finding.RuleID]; !known {
		return protocol.Match{}, false
	}
	lineStarts := lines.starts
	if finding.StartLine > len(lineStarts) || finding.EndLine > len(lineStarts) {
		return protocol.Match{}, false
	}
	start := lineStarts[finding.StartLine-1] + finding.StartColumn - 1
	end := lineStarts[finding.EndLine-1] + finding.EndColumn
	if start < 0 || start >= end || end > len(content) || !utf8Boundary(content, start) || !utf8Boundary(content, end) {
		return protocol.Match{}, false
	}
	startLine, startColumn := startCoordinate(lineStarts, start)
	endLine, endColumn := endCoordinate(lineStarts, end)
	if startLine != finding.StartLine || startColumn != finding.StartColumn || endLine != finding.EndLine || endColumn != finding.EndColumn {
		return protocol.Match{}, false
	}
	match := protocol.Match{
		SourceOrdinal:    sourceOrdinal,
		RuleID:           finding.RuleID,
		StartByte:        start,
		EndByteExclusive: end,
	}
	match.OccurrenceID = protocol.OccurrenceID(match)
	return match, true
}

func lineStartOffsets(content []byte) []int {
	starts := []int{0}
	for index, value := range content {
		if value == '\n' {
			starts = append(starts, index+1)
		}
	}
	return starts
}

func startCoordinate(lineStarts []int, offset int) (int, int) {
	line := coordinateLine(lineStarts, offset)
	return line + 1, offset - lineStarts[line] + 1
}

func endCoordinate(lineStarts []int, offset int) (int, int) {
	line := coordinateLine(lineStarts, offset)
	return line + 1, offset - lineStarts[line]
}

func coordinateLine(lineStarts []int, offset int) int {
	index := sort.Search(len(lineStarts), func(index int) bool { return lineStarts[index] >= offset })
	if index < len(lineStarts) && lineStarts[index] == offset {
		return index
	}
	return index - 1
}

func utf8Boundary(content []byte, offset int) bool {
	return offset == 0 || offset == len(content) || utf8.RuneStart(content[offset])
}

func matchLess(left, right protocol.Match) bool {
	if left.SourceOrdinal != right.SourceOrdinal {
		return left.SourceOrdinal < right.SourceOrdinal
	}
	if left.StartByte != right.StartByte {
		return left.StartByte < right.StartByte
	}
	if left.EndByteExclusive != right.EndByteExclusive {
		return left.EndByteExclusive < right.EndByteExclusive
	}
	if left.RuleID != right.RuleID {
		return left.RuleID < right.RuleID
	}
	return left.OccurrenceID < right.OccurrenceID
}
