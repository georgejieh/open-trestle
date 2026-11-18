package syntaxwasm

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func buffer(words ...uint32) []byte {
	out := make([]byte, 0, 8+4*len(words))
	out = binary.LittleEndian.AppendUint32(out, resultMagic)
	out = binary.LittleEndian.AppendUint32(out, uint32(8+4*len(words)))
	for _, w := range words {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	return out
}

var testQuery = queryInfo{patterns: 2, captures: []string{"name", "definition.function"}}

func TestDecodeAnalysisAcceptsAWellFormedResult(t *testing.T) {
	data := buffer(statusOK, flagTreeHasError, 1, 1, 1, 2, 0, 4, 9, 1, 0, 12, 3, 5, regionMissing)
	result, status, err := decodeAnalysis(data, testQuery, 20)
	if err != nil || status != statusOK || len(result.matches) != 1 || len(result.regions) != 1 {
		t.Fatalf("result = %+v, %d, %v", result, status, err)
	}
	if c := result.matches[0].captures[1]; c.index != 1 || c.start != 0 || c.end != 12 {
		t.Fatalf("capture = %+v", c)
	}
}

func TestDecodeAnalysisRejectsMalformedResults(t *testing.T) {
	cases := map[string][]byte{
		"empty":                nil,
		"bad magic":            append([]byte{1, 2, 3, 4}, buffer(statusOK)[4:]...),
		"length mismatch":      append(buffer(statusOK, 0, 0, 0), 0),
		"huge match count":     buffer(statusOK, 0, 0xffffffff, 0),
		"huge region count":    buffer(statusOK, 0, 0, 0x40000000),
		"pattern out of range": buffer(statusOK, 0, 1, 0, 2, 1, 0, 0, 1),
		"capture out of range": buffer(statusOK, 0, 1, 0, 0, 1, 2, 0, 1),
		"zero captures":        buffer(statusOK, 0, 1, 0, 0, 0),
		"too many captures":    buffer(statusOK, 0, 1, 0, 0, maxCapturesPerMatch+1),
		"offset past source":   buffer(statusOK, 0, 1, 0, 0, 1, 0, 0, 21),
		"end before start":     buffer(statusOK, 0, 1, 0, 0, 1, 0, 5, 4),
		"bad region kind":      buffer(statusOK, 0, 0, 1, 0, 1, 7),
		"trailing bytes":       buffer(statusOK, 0, 0, 0, 0),
		"truncated capture":    buffer(statusOK, 0, 1, 0, 0, 1, 0, 0),
		"status with payload":  buffer(statusNoQuery, 1),
	}
	for name, data := range cases {
		if _, _, err := decodeAnalysis(data, testQuery, 20); !errors.Is(err, errProtocol) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
	if _, status, err := decodeAnalysis(buffer(statusStopped), testQuery, 20); err != nil || status != statusStopped {
		t.Fatalf("stopped status = %d, %v", status, err)
	}
}

func TestDecodeQueryInfo(t *testing.T) {
	// Names are length-prefixed without padding, so build one by hand.
	data := buffer(statusOK, 0, 0, 3, 1)
	data = binary.LittleEndian.AppendUint32(data, 4)
	data = append(data, "name"...)
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))
	info, err := decodeQueryInfo(data)
	if err != nil || info.patterns != 3 || len(info.captures) != 1 || info.captures[0] != "name" {
		t.Fatalf("info = %+v, %v", info, err)
	}
	var qe queryError
	if _, err := decodeQueryInfo(buffer(statusQueryError, 17, 2)); !errors.As(err, &qe) || qe.offset != 17 || qe.kind != 2 {
		t.Fatalf("query error = %v", err)
	}
	if _, err := decodeQueryInfo(buffer(statusOK, 0, 0, 1, 0xffffffff)); !errors.Is(err, errProtocol) {
		t.Fatal("huge capture count accepted")
	}
}

func TestCaptureRolesRefuseUnknownNames(t *testing.T) {
	roles, err := captureRoles([]string{"definition.class", "reference.call", "name", "_anchor", "match.require", "import.source"})
	if err != nil || roles[0].definition != syntaxanalysis.KindClass || roles[1].reference != syntaxanalysis.ReferenceCall || roles[3].kind != roleIgnored || roles[4].text != "require" {
		t.Fatalf("roles = %+v, %v", roles, err)
	}
	for _, bad := range []string{"definition.lambda", "reference.read", "named", "match.", "local.scope"} {
		if _, err := captureRoles([]string{bad}); !errors.Is(err, errQueryPack) {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestRawFileNeedsExactlyOneRecordCapture(t *testing.T) {
	roles, _ := captureRoles([]string{"definition.function", "reference.call", "name", "match.require"})
	content := []byte("require(x)")
	for _, m := range []match{
		{captures: []capture{{index: 2, start: 0, end: 7}}},
		{captures: []capture{{index: 0, start: 0, end: 9}, {index: 1, start: 0, end: 9}}},
	} {
		if _, _, err := rawFile(content, analysisResult{matches: []match{m}}, roles); !errors.Is(err, errQueryPack) {
			t.Fatalf("match %+v accepted", m)
		}
	}
	kept, _, err := rawFile(content, analysisResult{matches: []match{
		{captures: []capture{{index: 1, start: 0, end: 10}, {index: 2, start: 0, end: 7}, {index: 3, start: 0, end: 7}}},
		{captures: []capture{{index: 1, start: 0, end: 10}, {index: 2, start: 0, end: 7}, {index: 3, start: 8, end: 9}}},
	}}, roles)
	if err != nil || len(kept.References) != 1 {
		t.Fatalf("match filter kept %+v, %v", kept.References, err)
	}
}
