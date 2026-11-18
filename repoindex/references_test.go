package repoindex

import (
	"fmt"
	"strings"
	"testing"
)

// usesOf lists the candidates of the definition with a qualified name in a
// file as "path:line scope kind".
func usesOf(g *Graph, name, qualified, inPath string) string {
	out := []string{}
	for _, d := range g.Definitions(name) {
		if d.Path != inPath || d.QualifiedName.Untrusted() != qualified {
			continue
		}
		for _, u := range g.References(d.ID) {
			out = append(out, fmt.Sprintf("%s:%d %s %s", u.Path, u.Range.Start.Line, u.Scope, u.Kind))
		}
	}
	return strings.Join(out, ", ")
}

func TestGoValueUsesReachTheirDefinitions(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod": "module example.com/app\n",
		"lib/lib.go": "package lib\n\nconst Limit = 3\n\nfunc Handler() int { return Limit }\n\n" +
			"type Config struct {\n\tName string\n}\n\ntype Other struct {\n\tName string\n}\n\ntype Wrapper struct {\n\tConfig\n}\n",
		"lib/use.go": "package lib\n\nfunc use(w Wrapper) int {\n\th := Handler\n\t_ = h\n\to := Other{Name: \"o\"}\n\treturn Limit + len(o.Name) + len(w.Name)\n}\n\n" +
			"func shadow() int {\n\tLimit, Handler := 1, 2\n\tName := Limit\n\treturn Name + Handler\n}\n",
		"app/app.go": "package app\n\nimport (\n\t\"net/http\"\n\n\t\"example.com/app/lib\"\n)\n\n" +
			"func Run(c *lib.Config, s *http.Server) int {\n\tf := lib.Handler\n\t_ = f\n" +
			"\tcfg := lib.Config{Name: \"x\"}\n\treturn lib.Limit + len(c.Name) + len(cfg.Name) + len(s.Name)\n}\n",
	})
	for _, c := range []struct{ name, qualified, want string }{
		{"Limit", "Limit", "app/app.go:13 import value, lib/lib.go:5 file value, lib/use.go:7 package value"},
		{"Handler", "Handler", "app/app.go:10 import value, lib/use.go:4 package value"},
		// A key, a parameter's and a variable's field and a field promoted
		// through an embedded type; not the field of an outside type.
		{"Name", "Config.Name", "app/app.go:12 import value, app/app.go:13 import value, app/app.go:13 import value, lib/use.go:7 package value"},
		{"Name", "Other.Name", "lib/use.go:6 package value, lib/use.go:7 package value"},
	} {
		if got := usesOf(g, c.name, c.qualified, "lib/lib.go"); got != c.want {
			t.Errorf("%s: got %s, want %s", c.qualified, got, c.want)
		}
	}
}
