package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestInvestigationProposalCanonicalizesModelWhitespaceAndOrder(t *testing.T) {
	ref := strings.Repeat("a", 64)
	first := []byte(`{"schema_version":1,"tool_calls":[{"call_id":"read-1","tool":"snapshot.read","snapshot_ref":"` + ref + `","file_ref":"` + ref + `","start_line":2,"end_line":2}]}`)
	second := []byte(" \n" + `{"tool_calls":[{"end_line":2,"start_line":2,"file_ref":"` + ref + `","snapshot_ref":"` + ref + `","tool":"snapshot.read","call_id":"read-1"}],"schema_version":1}` + "\n")
	a, err := ParseInvestigationProposal(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseInvestigationProposal(second)
	if err != nil {
		t.Fatal("model order/whitespace incorrectly treated as host canonical artifact")
	}
	ca, err := EncodeInvestigationProposal(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := EncodeInvestigationProposal(b)
	if err != nil || !bytes.Equal(ca, cb) {
		t.Fatal("equivalent untrusted proposals did not canonicalize")
	}
	ca[0] = 'x'
	again, err := EncodeInvestigationProposal(a)
	if err != nil || !bytes.Equal(again, cb) {
		t.Fatal("proposal canonical output is mutable")
	}
}
func TestInvestigationProposalStrictDenials(t *testing.T) {
	ref := strings.Repeat("a", 64)
	base := `{"schema_version":1,"tool_calls":[{"call_id":"read-1","tool":"snapshot.read","snapshot_ref":"` + ref + `","file_ref":"` + ref + `","start_line":2,"end_line":2}]}`
	cases := map[string][]byte{
		"mixed":              []byte(strings.Replace(base, `"schema_version":1`, `"candidates":[],"schema_version":1`, 1)),
		"duplicate root":     []byte(strings.Replace(base, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"duplicate call key": []byte(strings.Replace(base, `"start_line":2`, `"start_line":2,"start_line":2`, 1)),
		"case":               []byte(strings.Replace(base, `"start_line":2`, `"Start_line":2`, 1)),
		"null":               []byte(strings.Replace(base, `"start_line":2`, `"start_line":null`, 1)),
		"unknown field":      []byte(strings.Replace(base, `"start_line":2`, `"path":"notes.txt","start_line":2`, 1)),
		"unknown tool":       []byte(strings.Replace(base, `snapshot.read`, `shell`, 1)),
		"traversal ref":      []byte(strings.Replace(base, `"file_ref":"`+ref+`"`, `"file_ref":"../private"`, 1)),
		"newline ref":        []byte(strings.Replace(base, `"file_ref":"`+ref+`"`, `"file_ref":"`+ref+`\n"`, 1)),
		"newline call":       []byte(strings.Replace(base, `"call_id":"read-1"`, `"call_id":"read-1\n"`, 1)),
		"fraction":           []byte(strings.Replace(base, `"start_line":2`, `"start_line":2.5`, 1)),
		"numeric string":     []byte(strings.Replace(base, `"start_line":2`, `"start_line":"2"`, 1)),
		"exponent":           []byte(strings.Replace(base, `"start_line":2`, `"start_line":2e0`, 1)),
		"integer overflow":   []byte(strings.Replace(base, `"start_line":2`, `"start_line":18446744073709551616`, 1)),
		"malformed":          []byte(base[:len(base)-1]),
		"two documents":      []byte(base + base),
		"invalid UTF-8":      bytes.Replace([]byte(base), []byte("read-1"), []byte{'r', 0xff}, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, []byte(base)) {
				t.Fatal("mutation missed input")
			}
			if _, err := ParseInvestigationProposal(raw); err == nil {
				t.Fatal("unsafe model proposal admitted")
			}
		})
	}
}

func TestInvestigationProposalToolsAccessorsAndIdentity(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, test := range []struct{ tool, call, extra string }{
		{"snapshot.list", "list-a", ``},
		{"snapshot.read", "read-a", `,"file_ref":"` + b + `","start_line":1,"end_line":1000000`},
		{"snapshot.search", "search-a", `,"file_refs":["` + b + `","` + a + `"],"literal":"héllo<&>"`},
	} {
		t.Run(test.tool, func(t *testing.T) {
			raw := []byte(`{"schema_version":1,"tool_calls":[{"call_id":"` + test.call + `","tool":"` + test.tool + `","snapshot_ref":"` + a + `"` + test.extra + `}]}`)
			value, err := ParseInvestigationProposal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if value.Validate() != nil || value.Tool() != test.tool || value.CallID() != test.call || value.SnapshotRef() != a {
				t.Fatal("proposal accessors lost admitted syntax")
			}
			if test.tool == "snapshot.read" && (value.FileRef() != b || value.StartLine() != 1 || value.EndLine() != 1000000) {
				t.Fatal("read range changed")
			}
			if test.tool == "snapshot.search" {
				refs := value.FileRefs()
				if len(refs) != 2 || refs[0] != b || refs[1] != a || value.Literal() != "héllo<&>" {
					t.Fatal("search order or literal changed")
				}
				refs[0] = a
				if value.FileRefs()[0] != b {
					t.Fatal("reference accessor aliases state")
				}
			}
			encoded, err := EncodeInvestigationProposal(value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.HasSuffix(encoded, []byte("\n")) || len(encoded) > 64<<10 {
				t.Fatal("canonical proposal is not bounded")
			}
			sum := sha256.Sum256(encoded)
			if value.Identity() != hex.EncodeToString(sum[:]) {
				t.Fatal("proposal identity is not canonical-byte SHA-256")
			}
			roundtrip, err := ParseInvestigationProposal(encoded)
			if err != nil || roundtrip.Identity() != value.Identity() {
				t.Fatal("canonical proposal failed roundtrip")
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
				out := fmt.Sprintf(verb, value)
				if strings.Contains(out, test.call) || strings.Contains(out, a) || strings.Contains(out, "héllo") {
					t.Fatal("formatting exposed untrusted proposal data")
				}
			}
		})
	}
}
func TestInvestigationProposalZeroAndForgedValuesRefuse(t *testing.T) {
	if (InvestigationProposal{}).Validate() == nil {
		t.Fatal("zero proposal validated")
	}
	if _, err := EncodeInvestigationProposal(InvestigationProposal{}); err == nil {
		t.Fatal("zero proposal encoded")
	}
	raw := []byte(`{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.list","snapshot_ref":"` + strings.Repeat("a", 64) + `"}]}`)
	value, err := ParseInvestigationProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	value.identity = strings.Repeat("f", 64)
	if value.Validate() == nil {
		t.Fatal("forged identity validated")
	}
	if _, err := EncodeInvestigationProposal(value); err == nil {
		t.Fatal("forged proposal encoded")
	}
}
func TestInvestigationProposalInputAndFieldBounds(t *testing.T) {
	ref := strings.Repeat("a", 64)
	list := `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.list","snapshot_ref":"` + ref + `"}]}`
	padded := append([]byte(list), bytes.Repeat([]byte{' '}, (64<<10)-len(list))...)
	if _, err := ParseInvestigationProposal(padded); err != nil {
		t.Fatal("exact input byte boundary refused")
	}
	if _, err := ParseInvestigationProposal(append(padded, ' ')); err == nil {
		t.Fatal("input byte cap ignored")
	}
	read := `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.read","snapshot_ref":"` + ref + `","file_ref":"` + ref + `","start_line":1,"end_line":2}]}`
	search := `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.search","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":"x"}]}`
	cases := map[string]string{
		"empty": "", "version": strings.Replace(list, `"schema_version":1`, `"schema_version":2`, 1),
		"missing":              strings.Replace(list, `"call_id":"a",`, ``, 1),
		"zero calls":           `{"schema_version":1,"tool_calls":[]}`,
		"multiple calls":       strings.Replace(list, `}]}`, `},{"call_id":"b","tool":"snapshot.list","snapshot_ref":"`+ref+`"}]}`, 1),
		"zero ref":             strings.Replace(list, ref, strings.Repeat("0", 64), 1),
		"uppercase ref":        strings.Replace(list, ref, strings.Repeat("A", 64), 1),
		"short ref":            strings.Replace(list, ref, strings.Repeat("a", 63), 1),
		"long call":            strings.Replace(list, `"call_id":"a"`, `"call_id":"`+strings.Repeat("a", 65)+`"`, 1),
		"bad call alphabet":    strings.Replace(list, `"call_id":"a"`, `"call_id":"a/b"`, 1),
		"list has read args":   strings.Replace(list, `"tool":"snapshot.list"`, `"tool":"snapshot.list","start_line":1`, 1),
		"read has search args": strings.Replace(read, `"start_line":1`, `"literal":"x","start_line":1`, 1),
		"search has read args": strings.Replace(search, `"literal":"x"`, `"literal":"x","file_ref":"`+ref+`"`, 1),
		"unordered read":       strings.Replace(read, `"start_line":1`, `"start_line":3`, 1),
		"zero line":            strings.Replace(read, `"start_line":1`, `"start_line":0`, 1),
		"line ceiling":         strings.Replace(read, `"end_line":2`, `"end_line":1000001`, 1),
		"duplicate refs":       strings.Replace(search, `"file_refs":["`+ref+`"]`, `"file_refs":["`+ref+`","`+ref+`"]`, 1),
		"empty refs":           strings.Replace(search, `"file_refs":["`+ref+`"]`, `"file_refs":[]`, 1),
		"empty literal":        strings.Replace(search, `"literal":"x"`, `"literal":""`, 1),
		"newline literal":      strings.Replace(search, `"literal":"x"`, `"literal":"a\nb"`, 1),
		"CR literal":           strings.Replace(search, `"literal":"x"`, `"literal":"a\rb"`, 1),
		"NUL literal":          strings.Replace(search, `"literal":"x"`, `"literal":"a\u0000b"`, 1),
		"byte literal cap":     strings.Replace(search, `"literal":"x"`, `"literal":"`+strings.Repeat("é", 129)+`"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInvestigationProposal([]byte(raw)); err == nil {
				t.Fatal("proposal field boundary ignored")
			}
		})
	}
	callBoundary := strings.Replace(list, `"call_id":"a"`, `"call_id":"`+strings.Repeat("a", 64)+`"`, 1)
	if _, err := ParseInvestigationProposal([]byte(callBoundary)); err != nil {
		t.Fatal("exact call-ID byte boundary refused")
	}
	literalBoundary := strings.Replace(search, `"literal":"x"`, `"literal":"`+strings.Repeat("é", 128)+`"`, 1)
	if _, err := ParseInvestigationProposal([]byte(literalBoundary)); err != nil {
		t.Fatal("exact literal byte boundary refused")
	}
	refs := []string{}
	for i := 1; i <= 65; i++ {
		refs = append(refs, fmt.Sprintf(`"%064x"`, i))
	}
	for _, count := range []int{64, 65} {
		raw := strings.Replace(search, `"file_refs":["`+ref+`"]`, `"file_refs":[`+strings.Join(refs[:count], ",")+`]`, 1)
		value, err := ParseInvestigationProposal([]byte(raw))
		if (err == nil) != (count == 64) {
			t.Fatal("search file count boundary incorrect")
		}
		if err == nil {
			encoded, err := EncodeInvestigationProposal(value)
			if err != nil || len(encoded) > 64<<10 {
				t.Fatal("maximum admitted canonical output exceeded byte cap")
			}
		}
	}
}

func TestInvestigationProposalUnicodeEscapesRemainExact(t *testing.T) {
	ref := strings.Repeat("a", 64)
	prefix := `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.search","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":`
	for _, bad := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, `"\ud800\u0061"`} {
		if _, err := ParseInvestigationProposal([]byte(prefix + bad + `}]}`)); err == nil {
			t.Fatal("invalid surrogate normalized into literal")
		}
	}
	value, err := ParseInvestigationProposal([]byte(prefix + `"\ud83d\ude00"}]}`))
	if err != nil || value.Literal() != "😀" {
		t.Fatal("valid surrogate pair did not preserve Unicode scalar")
	}
	value, err = ParseInvestigationProposal([]byte(prefix + `"\\ud800"}]}`))
	if err != nil || value.Literal() != `\ud800` {
		t.Fatal("escaped backslash was treated as Unicode syntax")
	}
}

func TestInvestigationProposalUnicodeBackslashParity(t *testing.T) {
	ref := strings.Repeat("a", 64)
	prefix := `{"schema_version":1,"tool_calls":[{"tool":"snapshot.search","call_id":"a","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":`
	for slashes := 1; slashes <= 8; slashes++ {
		t.Run(fmt.Sprintf("slashes-%d", slashes), func(t *testing.T) {
			raw := []byte(prefix + `"` + strings.Repeat(`\`, slashes) + `ud800"}]}`)
			parsed, err := ParseInvestigationProposal(raw)
			if validProposalUnicode(raw) != (slashes%2 == 0) {
				t.Fatal("Unicode scan changed escaped-backslash parity")
			}
			if slashes%2 == 1 {
				if err == nil {
					t.Fatal("unpaired surrogate admitted")
				}
				return
			}
			if err != nil || parsed.Literal() != strings.Repeat(`\`, slashes/2)+"ud800" {
				t.Fatal("literal escaped backslash was refused or changed")
			}
			encoded, err := EncodeInvestigationProposal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseInvestigationProposal(encoded)
			if err != nil || again.Identity() != parsed.Identity() {
				t.Fatal("escaped-backslash canonical roundtrip changed")
			}
		})
	}
}

func TestInvestigationProposalOversizedFieldAllocation(t *testing.T) {
	ref := strings.Repeat("a", 64)
	raw := []byte(`{"schema_version":1,"tool_calls":[{"call_id":"` + strings.Repeat("a", 60000) + `","tool":"snapshot.list","snapshot_ref":"` + ref + `"}]}`)
	if len(raw) != 60155 || len(raw) > 64<<10 {
		t.Fatal("allocation fixture changed or exceeds the aggregate cap")
	}
	if value, err := ParseInvestigationProposal(raw); err == nil || value.Identity() != "" {
		t.Fatal("oversized field returned usable proposal")
	}
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = ParseInvestigationProposal(raw)
		}
	})
	t.Logf("input=%d allocated_bytes_per_op=%d", len(raw), result.AllocedBytesPerOp())
	// This ceiling covers only this invalid field, not all parser or process memory.
	if result.AllocedBytesPerOp() > 4096 {
		t.Fatal("oversized field materialized before refusal")
	}
}

func TestInvestigationProposalRawAndEscapedFieldBounds(t *testing.T) {
	ref := strings.Repeat("a", 64)
	base := `{"schema_version":1,"tool_calls":[{"tool":"snapshot.search","call_id":"a","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":"x"}]}`
	for name, raw := range map[string]string{
		"root key":                   strings.Replace(base, `"schema_version"`, `"`+strings.Repeat("x", 60000)+`"`, 1),
		"call key":                   strings.Replace(base, `"call_id"`, `"`+strings.Repeat("x", 60000)+`"`, 1),
		"tool":                       strings.Replace(base, `snapshot.search`, strings.Repeat("x", 60000), 1),
		"snapshot ref":               strings.Replace(base, `"snapshot_ref":"`+ref+`"`, `"snapshot_ref":"`+strings.Repeat("a", 60000)+`"`, 1),
		"file ref":                   strings.Replace(base, `"file_refs":["`+ref+`"]`, `"file_refs":["`+strings.Repeat("a", 60000)+`"]`, 1),
		"literal":                    strings.Replace(base, `"literal":"x"`, `"literal":"`+strings.Repeat("x", 60000)+`"`, 1),
		"escaped call":               strings.Replace(base, `"call_id":"a"`, `"call_id":"`+strings.Repeat(`\u0061`, 65)+`"`, 1),
		"escaped ref":                strings.Replace(base, `"file_refs":["`+ref+`"]`, `"file_refs":["`+strings.Repeat(`\u0061`, 65)+`"]`, 1),
		"escaped multibyte literal":  strings.Replace(base, `"literal":"x"`, `"literal":"`+strings.Repeat(`\u00e9`, 129)+`"`, 1),
		"escaped surrogate literal":  strings.Replace(base, `"literal":"x"`, `"literal":"`+strings.Repeat(`\ud83d\ude00`, 65)+`"`, 1),
		"escaped duplicate root key": strings.Replace(base, `"schema_version":1`, `"schema_version":1,"\u0073chema_version":1`, 1),
		"escaped duplicate call key": strings.Replace(base, `"call_id":"a"`, `"call_id":"a","\u0063all_id":"a"`, 1),
		"escaped duplicate ref":      strings.Replace(base, `"file_refs":["`+ref+`"]`, `"file_refs":["`+ref+`","`+strings.Repeat(`\u0061`, 64)+`"]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if len(raw) > 64<<10 || raw == base {
				t.Fatal("field fixture missed its mutation or aggregate cap")
			}
			if value, err := ParseInvestigationProposal([]byte(raw)); err == nil || value.Identity() != "" {
				t.Fatal("invalid raw or escaped field returned usable syntax")
			}
		})
	}
}

func TestInvestigationProposalEscapedKeysAndBoundedValuesCanonicalize(t *testing.T) {
	ref, escapedRef := strings.Repeat("a", 64), strings.Repeat(`\u0061`, 64)
	for _, literal := range []struct{ plain, escaped string }{
		{strings.Repeat("é", 128), strings.Repeat(`\u00e9`, 128)},
		{strings.Repeat("😀", 64), strings.Repeat(`\uD83D\uDE00`, 64)},
		{"a/b", `a\/b`},
	} {
		plain := []byte(`{"schema_version":1,"tool_calls":[{"tool":"snapshot.search","call_id":"` + ref + `","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":"` + literal.plain + `"}]}`)
		escaped := []byte(" \n\t" + `{
			"\u0074ool_calls" : [ {
				"literal" : "` + literal.escaped + `",
				"file_refs" : [ "` + escapedRef + `" ],
				"\u0073napshot_ref" : "` + escapedRef + `",
				"call_id" : "` + escapedRef + `",
				"tool" : "snapshot\u002esearch"
			} ], "\u0073chema_version" : 1
		}` + "\r\n ")
		a, err := ParseInvestigationProposal(plain)
		if err != nil {
			t.Fatal("plain boundary fixture refused")
		}
		b, err := ParseInvestigationProposal(escaped)
		if err != nil || a.Identity() != b.Identity() || b.Literal() != literal.plain {
			t.Fatal("model whitespace, shuffled keys or equivalent bounded escapes changed admission")
		}
		first, err := EncodeInvestigationProposal(a)
		if err != nil {
			t.Fatal(err)
		}
		second, err := EncodeInvestigationProposal(b)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatal("equivalent escaped proposal canonical bytes changed")
		}
	}
}
