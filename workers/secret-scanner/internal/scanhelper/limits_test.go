package scanhelper

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/workerio"
)

// TestFrameLimitsEqualTheProtocolLimits requires the helper's frame limits to
// equal the protocol's, which the parent session enforces through its copy
// of the protocol. The protocol keeps them unexported, so they are read from
// its source.
func TestFrameLimitsEqualTheProtocolLimits(t *testing.T) {
	limits := protocolConstants(t, "maxRequestFrameBytes", "maxResponseFrameBytes")
	if limits["maxRequestFrameBytes"] != workerio.MaximumRequestFrameBytes {
		t.Fatalf("request frame limit %d, protocol %d", workerio.MaximumRequestFrameBytes, limits["maxRequestFrameBytes"])
	}
	if limits["maxResponseFrameBytes"] != MaximumResponseFrameBytes {
		t.Fatalf("response frame limit %d, protocol %d", MaximumResponseFrameBytes, limits["maxResponseFrameBytes"])
	}
}

func protocolConstants(t *testing.T, names ...string) map[string]int64 {
	t.Helper()
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, filepath.Join("..", "protocol", "protocol.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	values := map[string]int64{}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for index, name := range value.Names {
				if !wanted[name.Name] || index >= len(value.Values) {
					continue
				}
				expression := value.Values[index]
				var source strings.Builder
				if err := printer.Fprint(&source, files, expression); err != nil {
					t.Fatal(err)
				}
				evaluated, err := types.Eval(token.NewFileSet(), nil, token.NoPos, source.String())
				if err != nil || evaluated.Value == nil {
					t.Fatalf("%s = %s is not a constant expression: %v", name.Name, source.String(), err)
				}
				number, exact := constant.Int64Val(evaluated.Value)
				if !exact {
					t.Fatalf("%s is not an integer", name.Name)
				}
				values[name.Name] = number
			}
		}
	}
	if len(values) != len(names) {
		t.Fatalf("found %v in the protocol source, want %s", values, strings.Join(names, ", "))
	}
	return values
}
