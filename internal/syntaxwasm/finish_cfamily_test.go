package syntaxwasm

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

type flags struct {
	kind     syntaxanalysis.DefinitionKind
	exported bool
}

func definitionFlags(a syntaxanalysis.FileAnalysis) map[string]flags {
	out := map[string]flags{}
	for i, d := range a.Definitions {
		out[a.QualifiedName(i).Untrusted()] = flags{d.Kind, d.Exported}
	}
	return out
}

func TestMemberAccessFollowsTheLabels(t *testing.T) {
	a := testAnalyzer(t)
	source := `class A {
  // public: in a comment is not a label
  int a;
public:
  int b;
private: /* comment */
  int c;
  const char *s = "public:";
  const char *r = R"x(public: )x";
  int big = 1'000;
protected:
  int d;
public:
  struct Inner { int e; };
  void f() { int local = 0; }
  int g;
};
struct B { int h; private: int i; public: int j; };
`
	got := definitionFlags(analyze(t, a, "access.hpp", []byte(source)))
	want := map[string]bool{
		"A": true, "A.a": false, "A.b": true, "A.c": false, "A.s": false, "A.r": false, "A.big": false,
		"A.d": false, "A.Inner": true, "A.Inner.e": true, "A.f": true, "A.g": true,
		"B": true, "B.h": true, "B.i": false, "B.j": true,
	}
	for name, exported := range want {
		if f, ok := got[name]; !ok || f.exported != exported {
			t.Errorf("%s: got %+v (present %v), want exported=%v", name, f, ok, exported)
		}
	}
	if _, ok := got["A.f.local"]; ok {
		t.Error("a local variable was recorded")
	}
}

func TestLinkageAndConstants(t *testing.T) {
	a := testAnalyzer(t)
	source := `static int s;
int g;
const int k = 1;
extern const int ek;
int *const p = 0;
const int *q = 0;
constexpr int ce = 1;
int n = 1, *const m = &n;
const char *a1, b1 = 0;
namespace { int hidden; }
struct W { static const int sc = 1; static int sv; const int ic = 2; };
`
	got := definitionFlags(analyze(t, a, "linkage.cpp", []byte(source)))
	want := map[string]flags{
		"s": {syntaxanalysis.KindVariable, false}, "g": {syntaxanalysis.KindVariable, true},
		"k": {syntaxanalysis.KindConstant, false}, "ek": {syntaxanalysis.KindConstant, true},
		"p": {syntaxanalysis.KindConstant, false}, "q": {syntaxanalysis.KindVariable, true},
		"ce": {syntaxanalysis.KindConstant, false}, "n": {syntaxanalysis.KindVariable, true},
		"m": {syntaxanalysis.KindConstant, false}, "a1": {syntaxanalysis.KindVariable, true},
		"b1":               {syntaxanalysis.KindConstant, false},
		"namespace.hidden": {syntaxanalysis.KindVariable, false},
		"W.sc":             {syntaxanalysis.KindConstant, false}, "W.sv": {syntaxanalysis.KindField, false},
		"W.ic": {syntaxanalysis.KindField, false},
	}
	for name, w := range want {
		if f, ok := got[name]; !ok || f != w {
			t.Errorf("%s: got %+v (present %v), want %+v", name, f, ok, w)
		}
	}

	// C gives a const global external linkage.
	gotC := definitionFlags(analyze(t, a, "linkage.c", []byte("const int k = 1;\nstatic const int sk = 2;\n")))
	if gotC["k"] != (flags{syntaxanalysis.KindConstant, true}) || gotC["sk"] != (flags{syntaxanalysis.KindConstant, false}) {
		t.Errorf("C constants: %+v", gotC)
	}
}

func TestLocalDeclarationsInConditionalsAreNotFileScope(t *testing.T) {
	a := testAnalyzer(t)
	source := `#ifdef A
int top;
#endif
int f(void)
{
#ifdef B
	int inner;
	void helper(void);
#else
	int other;
#endif
	return 0;
}
`
	got := definitionFlags(analyze(t, a, "cond.c", []byte(source)))
	for _, name := range []string{"inner", "helper", "other", "f.inner", "f.helper", "f.other"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was recorded", name)
		}
	}
	if _, ok := got["top"]; !ok {
		t.Error("the declaration in a conditional at file scope is missing")
	}
}

func TestMacroInvocationsAreNotDefinitionsOrTypes(t *testing.T) {
	a := testAnalyzer(t)
	source := `TEST(Suite, Case) { int x = 1; }
class W {
  DECLARE(int, width)
  explicit W(int);
  W(const W &) = default;
};
void g() { std::vector<int> v(n); Foo f(a, b); }
`
	analysis := analyze(t, a, "macros.cpp", []byte(source))
	for i, d := range analysis.Definitions {
		if name := analysis.QualifiedName(i).Untrusted(); name == "TEST" || name == "W.DECLARE" || name == "x" {
			t.Errorf("%s (%s) was recorded as a definition", name, d.Kind)
		}
	}
	for _, r := range analysis.References {
		switch r.Name.Untrusted() {
		case "Suite", "Case", "n", "a", "b":
			t.Errorf("%s %s was recorded", r.Kind, r.Name.Untrusted())
		}
	}
}

func TestClassBodiesAreReadOnce(t *testing.T) {
	a := testAnalyzer(t)
	var b strings.Builder
	b.WriteString("class Big {\npublic:\n")
	for i := range 20000 {
		fmt.Fprintf(&b, "  int member_%d;\n", i)
	}
	b.WriteString("};\n")
	started := time.Now()
	got := analyze(t, a, "big.hpp", []byte(b.String()))
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("a class with 20000 members took %v", elapsed)
	}
	flags := definitionFlags(got)
	if f := flags["Big.member_19999"]; !f.exported || f.kind != syntaxanalysis.KindField {
		t.Fatalf("last member: %+v", f)
	}
}

func TestLocalSpansDropLocalsWhereverDeclarationsSit(t *testing.T) {
	a := testAnalyzer(t)
	source := `#if A
int first(void);
#elif B
int second(void);
int counter;
#endif
class Box {
  friend void swap(Box &, Box &);
  friend bool operator==(const Box &, const Box &) { return true; }
  int size;
};
void run() {
  if (int found = lookup()) { use(found); }
  while (auto *next = advance()) { int inner = 1; }
  auto task = [] { int captured = 2; return captured; };
}
TEST(Box, Works) {
  int expected = 3;
}
`
	got := definitionFlags(analyze(t, a, "locals.cpp", []byte(source)))
	for _, name := range []string{"first", "second", "counter", "Box", "Box.size", "run"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s is missing from %v", name, got)
		}
	}
	for _, name := range []string{"Box.swap", "swap", "run.found", "run.next", "run.inner", "run.task", "run.captured", "expected"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was recorded", name)
		}
	}
}
