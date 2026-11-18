package semanticimpact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var _ syntaxanalysis.Analyzer = GoSyntaxAnalyzer{}

const syntaxFixture = `package shapes

import (
	"fmt"
	str "strings"
)

const Pi = 3.14

var registry = map[string]Shape{}

type Shape interface {
	fmt.Stringer
	Area() float64
}

type Circle struct {
	Base
	Radius float64
}

func (c *Circle) Area() float64 { return Pi * c.Radius * c.Radius }

func (c Circle) String() string { return fmt.Sprintf("circle %v", str.TrimSpace("r")) }

func New(r float64) *Circle {
	c := &Circle{Radius: r}
	registry["c"] = c
	return c
}
`

func goSyntax(t *testing.T, content string, limits syntaxanalysis.Limits) syntaxanalysis.FileAnalysis {
	t.Helper()
	analyzer, err := NewGoSyntaxAnalyzer(limits)
	if err != nil {
		t.Fatal(err)
	}
	source, err := syntaxanalysis.NewSource("shapes/shapes.go", syntaxanalysis.LanguageGo, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analyzer.Analyze(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return analysis
}

func TestGoSyntaxAnalyzerRecords(t *testing.T) {
	a := goSyntax(t, syntaxFixture, syntaxanalysis.DefaultLimits())
	if !a.Complete() || a.Analyzer != GoSyntaxAnalyzerIdentity {
		t.Fatalf("gaps = %+v", a.Gaps)
	}
	definitions := []string{}
	for i, d := range a.Definitions {
		entry := fmt.Sprintf("%s %s parent=%d exported=%v", d.Kind, a.QualifiedName(i).Untrusted(), d.Parent, d.Exported)
		if !d.Container.Empty() {
			entry += " container=" + d.Container.Untrusted()
		}
		definitions = append(definitions, entry)
	}
	want := []string{
		"constant Pi parent=-1 exported=true",
		"variable registry parent=-1 exported=false",
		"interface Shape parent=-1 exported=true",
		"method Shape.Area parent=2 exported=true",
		"struct Circle parent=-1 exported=true",
		"field Circle.Radius parent=4 exported=true",
		"method Area parent=-1 exported=true container=Circle",
		"method String parent=-1 exported=true container=Circle",
		"function New parent=-1 exported=true",
	}
	if strings.Join(definitions, "\n") != strings.Join(want, "\n") {
		t.Fatalf("definitions:\n%s", strings.Join(definitions, "\n"))
	}
	imports := []string{}
	for _, i := range a.Imports {
		imports = append(imports, i.Source.Untrusted()+"="+i.Alias.Untrusted())
	}
	if strings.Join(imports, ",") != "fmt=,strings=str" {
		t.Fatalf("imports = %v", imports)
	}
	references := []string{}
	for _, r := range a.References {
		entry := string(r.Kind) + " " + r.Name.Untrusted()
		if !r.Qualifier.Empty() {
			entry = string(r.Kind) + " " + r.Qualifier.Untrusted() + "." + r.Name.Untrusted()
		}
		if r.Enclosing >= 0 {
			entry += " in " + a.QualifiedName(r.Enclosing).Untrusted()
		}
		references = append(references, entry)
	}
	for _, expected := range []string{
		"type string in registry", "type Shape in registry", "inherit fmt.Stringer in Shape", "type float64 in Shape.Area",
		"inherit Base in Circle", "type Circle in Area", "call fmt.Sprintf in String", "call str.TrimSpace in String",
		"construct Circle in New",
	} {
		found := false
		for _, r := range references {
			found = found || r == expected
		}
		if !found {
			t.Fatalf("reference %q missing from:\n%s", expected, strings.Join(references, "\n"))
		}
	}
}

func TestGoSyntaxAnalyzerReportsParseErrorsAndKeepsTheRest(t *testing.T) {
	content := "package p\n\nfunc Good() { helper() }\n\nfunc Broken( {\n\nfunc helper() {}\n"
	a := goSyntax(t, content, syntaxanalysis.DefaultLimits())
	if a.Complete() {
		t.Fatal("broken file must have a parse_error gap")
	}
	for _, g := range a.Gaps {
		if g.Reason != syntaxanalysis.GapParseError || !g.HasRange {
			t.Fatalf("gap = %+v", g)
		}
	}
	if len(a.Definitions) == 0 || a.Definitions[0].Name.Untrusted() != "Good" {
		t.Fatalf("definitions = %+v", a.Definitions)
	}
}

func TestGoSyntaxAnalyzerLimits(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.MaxFileBytes = 16
	a := goSyntax(t, syntaxFixture, limits)
	if len(a.Gaps) != 1 || a.Gaps[0].Limit != syntaxanalysis.LimitFileSize || len(a.Definitions) != 0 {
		t.Fatalf("analysis = %+v", a)
	}
	if _, err := NewGoSyntaxAnalyzer(syntaxanalysis.Limits{}); !errors.Is(err, syntaxanalysis.ErrInvalidInput) {
		t.Fatal("zero limits accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	analyzer, _ := NewGoSyntaxAnalyzer(syntaxanalysis.DefaultLimits())
	source, _ := syntaxanalysis.NewSource("a.go", syntaxanalysis.LanguageGo, []byte("package a"))
	if _, err := analyzer.Analyze(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}
