// Package filterpatterns lists, without running anything, the regular
// expressions that filter expressions compile lazily through matchesAny and
// findMatch. Together with the patterns that Compile sees while a ruleset
// loads, they are every pattern a scan of that ruleset can compile.
package filterpatterns

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
)

// Collect returns the joined pattern of every matchesAny and findMatch call in
// the global prefilter and filter and in every rule filter of cfg, in the form
// the expression runtime compiles it. A pattern argument that is not a string
// literal or a list of string literals is an error, so the result is complete
// or there is no result.
func Collect(cfg *config.Config) ([]string, error) {
	expressions := []string{cfg.Prefilter, cfg.Filter}
	for _, rule := range cfg.Rules {
		expressions = append(expressions, rule.Filter)
	}
	visitor := &collector{}
	for _, expression := range expressions {
		if expression == "" {
			continue
		}
		text := expression
		if exprruntime.NeedsCELCompat(expression) {
			rewritten, err := exprruntime.RewriteCELCompat(expression)
			if err != nil {
				return nil, err
			}
			text = rewritten
		}
		tree, err := parser.Parse(text)
		if err != nil {
			return nil, err
		}
		ast.Walk(&tree.Node, visitor)
		if visitor.err != nil {
			return nil, visitor.err
		}
	}
	return visitor.patterns, nil
}

type collector struct {
	patterns []string
	err      error
}

func (c *collector) Visit(node *ast.Node) {
	call, ok := (*node).(*ast.CallNode)
	if !ok || c.err != nil {
		return
	}
	name := calleeName(call.Callee)
	if name != "matchesAny" && name != "findMatch" {
		return
	}
	if len(call.Arguments) != 2 {
		c.err = fmt.Errorf("%s: %d arguments, want 2", name, len(call.Arguments))
		return
	}
	var literals []string
	switch argument := call.Arguments[1].(type) {
	case *ast.StringNode:
		literals = []string{argument.Value}
	case *ast.ArrayNode:
		for _, element := range argument.Nodes {
			literal, ok := element.(*ast.StringNode)
			if !ok {
				c.err = fmt.Errorf("%s: pattern list holds a value that is not a string literal", name)
				return
			}
			literals = append(literals, literal.Value)
		}
	default:
		c.err = fmt.Errorf("%s: pattern argument is not a string literal", name)
		return
	}
	if len(literals) == 0 {
		return
	}
	// The expression runtime joins the patterns of one call this way before
	// it compiles them (getOrCompileJoinedRegex).
	parts := make([]string, len(literals))
	for index, literal := range literals {
		parts[index] = "(?:" + literal + ")"
	}
	c.patterns = append(c.patterns, strings.Join(parts, "|"))
}

func calleeName(node ast.Node) string {
	switch callee := node.(type) {
	case *ast.IdentifierNode:
		return callee.Value
	case *ast.MemberNode:
		if property, ok := callee.Property.(*ast.StringNode); ok {
			return property.Value
		}
	}
	return ""
}
