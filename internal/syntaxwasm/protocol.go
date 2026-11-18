package syntaxwasm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Constants shared with shim/analyze.c.
const (
	shimABIVersion = 1
	resultMagic    = 0x3153544f

	statusOK             = 0
	statusBadLanguage    = 1
	statusNoQuery        = 2
	statusQueryError     = 3
	statusQueryPredicate = 4
	statusParseFailed    = 5
	statusQueryLoaded    = 6
	statusStopped        = 7

	flagMatchLimit   = 1
	flagResultLimit  = 2
	flagErrorLimit   = 4
	flagTreeHasError = 8

	regionError   = 0
	regionMissing = 1

	// maxResultBytes bounds one result buffer copied out of the guest.
	maxResultBytes = 64 << 20
	// maxCapturesPerMatch bounds the captures of one match; query packs
	// use a handful.
	maxCapturesPerMatch = 64
)

// errProtocol marks a result buffer that breaks the shim's layout. The
// guest is untrusted, so such a result is discarded with its instance.
var errProtocol = errors.New("syntax module returned a malformed result")

type reader struct {
	data []byte
	at   int
}

func (r *reader) u32() (uint32, error) {
	if len(r.data)-r.at < 4 {
		return 0, errProtocol
	}
	v := binary.LittleEndian.Uint32(r.data[r.at:])
	r.at += 4
	return v, nil
}

func (r *reader) bytes() ([]byte, error) {
	n, err := r.u32()
	if err != nil || uint64(n) > uint64(len(r.data)-r.at) {
		return nil, errProtocol
	}
	out := r.data[r.at : r.at+int(n)]
	r.at += int(n)
	return out, nil
}

func (r *reader) remaining() int { return len(r.data) - r.at }

// newReader checks the buffer header and positions the reader after it.
func newReader(data []byte) (*reader, error) {
	r := &reader{data: data}
	magic, err := r.u32()
	if err != nil || magic != resultMagic {
		return nil, errProtocol
	}
	length, err := r.u32()
	if err != nil || uint64(length) != uint64(len(data)) {
		return nil, errProtocol
	}
	return r, nil
}

// decodeDescribe returns the language names a module describes. Each comes
// with its grammar's ABI version, which ts_parser_set_language checks.
func decodeDescribe(data []byte) ([]string, error) {
	r, err := newReader(data)
	if err != nil {
		return nil, err
	}
	count, err := r.u32()
	if err != nil || count == 0 || uint64(count)*8 > uint64(r.remaining()) {
		return nil, errProtocol
	}
	out := make([]string, 0, count)
	for range count {
		if _, err := r.u32(); err != nil {
			return nil, err
		}
		name, err := r.bytes()
		if err != nil || len(name) == 0 || len(name) > 64 {
			return nil, errProtocol
		}
		out = append(out, string(name))
	}
	if r.remaining() != 0 {
		return nil, errProtocol
	}
	return out, nil
}

type queryInfo struct {
	patterns uint32
	captures []string
}

// queryError reports a query the guest refused to compile, with the byte
// offset and error kind the runtime gave. It is a defect in a query pack.
type queryError struct {
	status, offset, kind uint32
}

func (e queryError) Error() string {
	return fmt.Sprintf("syntax query was rejected with status %d at byte %d, error kind %d", e.status, e.offset, e.kind)
}

func decodeQueryInfo(data []byte) (queryInfo, error) {
	r, err := newReader(data)
	if err != nil {
		return queryInfo{}, err
	}
	status, err := r.u32()
	if err != nil {
		return queryInfo{}, err
	}
	if status != statusOK {
		e := queryError{status: status}
		if status == statusQueryError || status == statusQueryPredicate {
			e.offset, _ = r.u32()
			e.kind, _ = r.u32()
		}
		return queryInfo{}, e
	}
	if _, err := r.u32(); err != nil {
		return queryInfo{}, err
	}
	if _, err := r.u32(); err != nil {
		return queryInfo{}, err
	}
	patterns, err := r.u32()
	if err != nil {
		return queryInfo{}, err
	}
	count, err := r.u32()
	if err != nil || uint64(count)*4 > uint64(r.remaining()) {
		return queryInfo{}, errProtocol
	}
	info := queryInfo{patterns: patterns, captures: make([]string, 0, count)}
	for range count {
		name, err := r.bytes()
		if err != nil || len(name) == 0 || len(name) > 128 {
			return queryInfo{}, errProtocol
		}
		info.captures = append(info.captures, string(name))
	}
	if r.remaining() != 0 {
		return queryInfo{}, errProtocol
	}
	return info, nil
}

type capture struct {
	index      uint32
	start, end int
}

type match struct {
	captures []capture
}

type region struct {
	start, end int
}

type analysisResult struct {
	flags   uint32
	matches []match
	regions []region
}

// decodeAnalysis decodes an ot_analyze result. Every count is checked
// against the bytes that remain before anything is allocated, and every
// capture index and byte offset against the query and the source size.
func decodeAnalysis(data []byte, info queryInfo, sourceSize int) (analysisResult, uint32, error) {
	r, err := newReader(data)
	if err != nil {
		return analysisResult{}, 0, err
	}
	status, err := r.u32()
	if err != nil {
		return analysisResult{}, 0, err
	}
	if status != statusOK {
		if r.remaining() != 0 {
			return analysisResult{}, 0, errProtocol
		}
		return analysisResult{}, status, nil
	}
	var result analysisResult
	if result.flags, err = r.u32(); err != nil {
		return analysisResult{}, 0, err
	}
	matchCount, err := r.u32()
	if err != nil {
		return analysisResult{}, 0, err
	}
	regionCount, err := r.u32()
	if err != nil {
		return analysisResult{}, 0, err
	}
	if uint64(matchCount)*8+uint64(regionCount)*12 > uint64(r.remaining()) {
		return analysisResult{}, 0, errProtocol
	}
	offset := func() (int, error) {
		v, err := r.u32()
		if err != nil || uint64(v) > uint64(sourceSize) {
			return 0, errProtocol
		}
		return int(v), nil
	}
	result.matches = make([]match, 0, matchCount)
	for range matchCount {
		pattern, err := r.u32()
		if err != nil || pattern >= info.patterns {
			return analysisResult{}, 0, errProtocol
		}
		count, err := r.u32()
		if err != nil || count == 0 || count > maxCapturesPerMatch || uint64(count)*12 > uint64(r.remaining()) {
			return analysisResult{}, 0, errProtocol
		}
		m := match{captures: make([]capture, 0, count)}
		for range count {
			index, err := r.u32()
			if err != nil || uint64(index) >= uint64(len(info.captures)) {
				return analysisResult{}, 0, errProtocol
			}
			start, err := offset()
			if err != nil {
				return analysisResult{}, 0, err
			}
			end, err := offset()
			if err != nil || end < start {
				return analysisResult{}, 0, errProtocol
			}
			m.captures = append(m.captures, capture{index: index, start: start, end: end})
		}
		result.matches = append(result.matches, m)
	}
	if uint64(regionCount)*12 != uint64(r.remaining()) {
		return analysisResult{}, 0, errProtocol
	}
	result.regions = make([]region, 0, regionCount)
	for range regionCount {
		start, err := offset()
		if err != nil {
			return analysisResult{}, 0, err
		}
		end, err := offset()
		if err != nil || end < start {
			return analysisResult{}, 0, errProtocol
		}
		kind, err := r.u32()
		if err != nil || (kind != regionError && kind != regionMissing) {
			return analysisResult{}, 0, errProtocol
		}
		result.regions = append(result.regions, region{start: start, end: end})
	}
	return result, statusOK, nil
}
