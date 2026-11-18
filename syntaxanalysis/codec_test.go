package syntaxanalysis

import (
	"errors"
	"math/rand"
	"reflect"
	"testing"
)

func codecSample(t *testing.T) FileAnalysis {
	t.Helper()
	content := "class Box:\n    def put(self, item):\n        helper(item)\n        store.save(item)\nimport os\n\x01bad"
	source := mustSource(t, content)
	raw := RawFile{
		Definitions: []RawDefinition{
			{Kind: KindClass, Name: spanOf(t, content, "Box", 0), Node: Span{Start: 0, End: 82}, Exported: true},
			{Kind: KindFunction, Name: spanOf(t, content, "put", 0), Node: Span{Start: 15, End: 82}, Container: spanOf(t, content, "put", 0)},
		},
		References: []RawReference{
			{Kind: ReferenceCall, Name: spanOf(t, content, "helper", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "save", 0), Qualifier: spanOf(t, content, "store", 0)},
			{Kind: ReferenceType, Name: spanOf(t, content, "store", 0)},
		},
		Imports: []RawImport{{Source: spanOf(t, content, "os", 0), Node: spanOf(t, content, "import os", 0)}},
		Gaps:    []RawGap{{Reason: GapParseError, Span: spanOf(t, content, "\x01bad", 0)}, {Reason: GapLimitExceeded, Limit: LimitMatches}},
	}
	a := Assemble(source, "test", raw, DefaultLimits())
	if len(a.Definitions) != 2 || len(a.References) != 3 || len(a.Imports) != 1 || len(a.Gaps) != 2 {
		t.Fatalf("sample analysis is incomplete: %d %d %d %d", len(a.Definitions), len(a.References), len(a.Imports), len(a.Gaps))
	}
	return a
}

func TestBinaryEncodingRoundTrips(t *testing.T) {
	a := codecSample(t)
	encoded, err := EncodeBinary(a)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBinary(encoded, "other/path.py")
	if err != nil {
		t.Fatal(err)
	}
	a.Path = "other/path.py"
	if !reflect.DeepEqual(decoded, a) {
		t.Fatalf("decoded analysis differs:\n%#v\n%#v", decoded.References, a.References)
	}
	if decoded.References[2].Qualifier.value != decoded.References[1].Name.value || decoded.Definitions[1].Name.value != decoded.Definitions[1].Container.value {
		t.Fatal("equal names must share one text value")
	}
	empty := WholeFileGap(mustSource(t, ""), "test", GapUnsupportedLanguage, "")
	encoded, err = EncodeBinary(empty)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeBinary(encoded, empty.Path); err != nil || !reflect.DeepEqual(decoded, empty) {
		t.Fatalf("whole-file gap = %v, %v", decoded, err)
	}
}

func TestBinaryEncodingRefusesInvalidAnalyses(t *testing.T) {
	a := codecSample(t)
	for name, mutate := range map[string]func(*FileAnalysis){
		"digest":    func(a *FileAnalysis) { a.ContentSHA256 = "zz" },
		"language":  func(a *FileAnalysis) { a.Language = "cobol" },
		"kind":      func(a *FileAnalysis) { a.Definitions[0].Kind = "lambda" },
		"reference": func(a *FileAnalysis) { a.References[0].Kind = "read" },
		"gap":       func(a *FileAnalysis) { a.Gaps[0].Reason = "other" },
	} {
		b := a
		b.Definitions = append([]Definition(nil), a.Definitions...)
		b.References = append([]Reference(nil), a.References...)
		b.Gaps = append([]Gap(nil), a.Gaps...)
		mutate(&b)
		if _, err := EncodeBinary(b); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: invalid analysis encoded", name)
		}
	}
}

func TestBinaryDecodingRejectsMalformedInput(t *testing.T) {
	encoded, err := EncodeBinary(codecSample(t))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(encoded); n++ {
		if _, err := DecodeBinary(encoded[:n], "a.py"); err == nil {
			t.Fatalf("truncation at %d decoded", n)
		}
	}
	if _, err := DecodeBinary(append(append([]byte(nil), encoded...), 0), "a.py"); err == nil {
		t.Fatal("trailing byte decoded")
	}
	if _, err := DecodeBinary(encoded, "../a.py"); err == nil {
		t.Fatal("unsafe path accepted")
	}
	random := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		mutated := append([]byte(nil), encoded...)
		for j := 0; j < 1+random.Intn(4); j++ {
			mutated[random.Intn(len(mutated))] = byte(random.Intn(256))
		}
		decoded, err := DecodeBinary(mutated, "a.py")
		if err != nil {
			continue
		}
		for k, d := range decoded.Definitions {
			if d.Parent < -1 || d.Parent >= k || d.Name.Empty() || !d.Kind.Valid() {
				t.Fatalf("mutation %d decoded an invalid definition", i)
			}
		}
		for _, r := range decoded.References {
			if r.Enclosing < -1 || r.Enclosing >= len(decoded.Definitions) || r.Name.Empty() {
				t.Fatalf("mutation %d decoded an invalid reference", i)
			}
		}
	}
}
