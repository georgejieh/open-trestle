package semanticimpact

import (
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// referenceList lists an analysis's references as "kind qualifier.name",
// with the qualifier left out when there is none.
func referenceList(a syntaxanalysis.FileAnalysis) []string {
	out := []string{}
	for _, r := range a.References {
		entry := string(r.Kind) + " " + r.Name.Untrusted()
		if !r.Qualifier.Empty() {
			entry = string(r.Kind) + " " + r.Qualifier.Untrusted() + "." + r.Name.Untrusted()
		}
		out = append(out, entry)
	}
	return out
}

func requireReferences(t *testing.T, a syntaxanalysis.FileAnalysis, present, absent []string) {
	t.Helper()
	got := referenceList(a)
	for _, want := range present {
		if !slices.Contains(got, want) {
			t.Errorf("reference %q missing", want)
		}
	}
	for _, unwanted := range absent {
		if slices.Contains(got, unwanted) {
			t.Errorf("reference %q recorded", unwanted)
		}
	}
	if t.Failed() {
		t.Fatalf("references:\n%s", strings.Join(got, "\n"))
	}
}

const valueFixture = `package shapes

import (
	"os"
	"example.com/geo"
)

const Max = 10

var limit = Max

var parser = Parse

type Kind int

const KindCircle Kind = 1

type Circle struct {
	Radius float64
}

func (c *Circle) Area() float64 { return c.Radius * c.Radius }

func Parse(s string) *Circle { return &Circle{Radius: float64(len(s))} }

func register(f func(string) *Circle) {}

func Map[K comparable, V any](m map[K]V) {}

func Use(x any, s *Circle) {
	register(Parse)
	h := Parse
	_ = h
	_ = limit + Max
	limit++
	_ = s.Radius
	_ = s.Area
	_ = os.Args
	_ = geo.Point{X: 1}
	_ = []Circle{{Radius: 2}}
	_ = map[string]*Circle{"a": {Radius: 3}}
	_ = map[Kind]string{KindCircle: "circle"}
	_ = make([]*Circle, 0)
	_ = new(Circle)
	_ = []Circle(nil)
	Map[string, Circle](nil)
	c := Circle{}
	_ = c.Radius
	switch x.(type) {
	case Kind:
	}
	tests := []struct{ name string }{{name: "a"}}
	for _, tt := range tests {
		_ = tt.name
	}
}
`

func TestGoSyntaxAnalyzerRecordsValueUses(t *testing.T) {
	a := goSyntax(t, valueFixture, syntaxanalysis.DefaultLimits())
	if !a.Complete() {
		t.Fatalf("gaps = %+v", a.Gaps)
	}
	requireReferences(t, a, []string{
		// Function values, package-level reads and writes.
		"value Max", "value Parse", "value limit",
		// Field reads and a method value, qualified by the declared type.
		"value Circle.Radius", "value Circle.Area",
		// A variable of an imported package.
		"value os.Args",
		// Composite literal keys, with elided literal types.
		"value geo.Point.X", "value Circle.Radius",
		// A map key is a value.
		"value KindCircle",
		// Type positions.
		"type Circle", "type string", "type Kind",
		// A call stays a call.
		"call register", "call Map",
	}, []string{
		"value register", "value Map", "value Circle", "value Kind", "call Parse",
		// The field of an anonymous test table type is no definition.
		"value tt.name", "value name",
	})
	starts := map[int]bool{}
	for _, r := range a.References {
		if starts[r.Range.StartByte] {
			t.Fatalf("two references at byte %d:\n%s", r.Range.StartByte, strings.Join(referenceList(a), "\n"))
		}
		starts[r.Range.StartByte] = true
	}
}

const skipFixture = `package skip

import alias "example.com/lib"

var Shared = 1

type T struct {
	Field int
}

func (t T) Method(param int) (result int) {
	local := param
	var declared = local
	for i, v := range []int{declared} {
		result += i + v
	}
	f := func(inner int) int { return inner }
	result += f(local)
outer:
	for {
		break outer
	}
	_ = nil
	_ = true
	_ = alias.Value
	return result + t.Field + Shared
}
`

func TestGoSyntaxAnalyzerSkipsNamesThatAreNoUses(t *testing.T) {
	a := goSyntax(t, skipFixture, syntaxanalysis.DefaultLimits())
	requireReferences(t, a, []string{"value Shared", "value T.Field", "value alias.Value"}, []string{
		// Parameters, results, locals, range variables and a local function.
		"value param", "value result", "value local", "value declared", "value i", "value v", "value inner", "value f", "call f",
		// A label.
		"value outer",
		// Definitions, field and method names, and the package and import names.
		"value T", "value Field", "value Method", "value skip", "value alias",
		// The blank identifier and the predeclared values.
		"value _", "value nil", "value true",
	})
}

func TestGoSyntaxAnalyzerValueUsesRespectTheRecordLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("package p\n\nvar X = 1\n\nfunc f() {\n")
	for range 64 {
		b.WriteString("\t_ = X\n")
	}
	b.WriteString("}\n")
	limits := syntaxanalysis.DefaultLimits()
	limits.MaxRecords = 16
	a := goSyntax(t, b.String(), limits)
	if len(a.Definitions)+len(a.References)+len(a.Imports) > limits.MaxRecords {
		t.Fatalf("%d records kept", len(a.Definitions)+len(a.References)+len(a.Imports))
	}
	found := false
	for _, g := range a.Gaps {
		found = found || g.Reason == syntaxanalysis.GapLimitExceeded && g.Limit == syntaxanalysis.LimitRecords
	}
	if !found {
		t.Fatalf("no records gap: %+v", a.Gaps)
	}
}
