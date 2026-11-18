package repoprofile

import "strings"

const maxYAMLDepth = 24

type yamlKind uint8

const (
	yamlScalar yamlKind = iota
	yamlSequence
	yamlMapping
)

// yamlNode is a node of the YAML subset the profile reads: block and flow
// collections, plain and quoted scalars and block scalars. Anchors, aliases,
// tags and multi-document streams are not interpreted, so what they hide is
// simply not found. The accessors accept a nil node.
type yamlNode struct {
	kind  yamlKind
	value string
	items []*yamlNode // sequence items, or mapping values parallel to keys
	keys  []string
}

func (n *yamlNode) get(key string) *yamlNode {
	if n == nil || n.kind != yamlMapping {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.items[i]
		}
	}
	return nil
}

func (n *yamlNode) str() string {
	if n == nil || n.kind != yamlScalar {
		return ""
	}
	return n.value
}

func (n *yamlNode) seq() []*yamlNode {
	if n == nil || n.kind != yamlSequence {
		return nil
	}
	return n.items
}

type yamlLine struct {
	indent int
	text   string
}

type yamlParser struct {
	lines []yamlLine
	pos   int
}

// parseYAML parses text up to the line bounds; what it cannot parse ends the
// enclosing collection.
func parseYAML(text string) *yamlNode {
	p := &yamlParser{}
	scanLines(text, func(line string) {
		line = strings.TrimRight(line, " \t\r")
		body := strings.TrimLeft(line, " ")
		if body == "" || body[0] == '#' || body == "---" {
			return
		}
		p.lines = append(p.lines, yamlLine{len(line) - len(body), body})
	})
	return p.block(0, 0)
}

func (p *yamlParser) block(minIndent, depth int) *yamlNode {
	if p.pos >= len(p.lines) || depth > maxYAMLDepth {
		return nil
	}
	l := p.lines[p.pos]
	if l.indent < minIndent {
		return nil
	}
	switch {
	case isSeqItem(l.text):
		return p.sequence(l.indent, depth)
	case isKeyLine(l.text):
		return p.mapping(l.indent, depth)
	}
	p.pos++
	return parseFlow(stripComment(l.text), 0)
}

func (p *yamlParser) sequence(indent, depth int) *yamlNode {
	n := &yamlNode{kind: yamlSequence}
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.indent != indent || !isSeqItem(l.text) {
			break
		}
		rest := strings.TrimLeft(l.text[1:], " ")
		var item *yamlNode
		switch {
		case rest == "" || rest[0] == '#':
			p.pos++
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				item = p.block(indent+1, depth+1)
			}
		case isSeqItem(rest) || isKeyLine(rest):
			p.lines[p.pos] = yamlLine{indent + len(l.text) - len(rest), rest}
			item = p.block(indent+1, depth+1)
		default:
			p.pos++
			item = p.value(rest, indent, depth)
		}
		n.items = append(n.items, item)
	}
	return n
}

func (p *yamlParser) mapping(indent, depth int) *yamlNode {
	n := &yamlNode{kind: yamlMapping}
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		key, rest, ok := splitKey(l.text)
		if l.indent != indent || !ok {
			break
		}
		p.pos++
		n.keys = append(n.keys, key)
		n.items = append(n.items, p.value(rest, indent, depth))
	}
	return n
}

// value parses what follows a key or a sequence dash at indent.
func (p *yamlParser) value(rest string, indent, depth int) *yamlNode {
	rest = stripComment(rest)
	switch {
	case rest == "":
		if p.pos < len(p.lines) {
			l := p.lines[p.pos]
			if l.indent > indent || l.indent == indent && isSeqItem(l.text) {
				return p.block(indent, depth+1)
			}
		}
		return &yamlNode{}
	case rest[0] == '|' || rest[0] == '>':
		return p.blockScalar(rest[0], indent)
	case rest[0] == '[' || rest[0] == '{':
		return parseFlow(rest, 0)
	}
	n := &yamlNode{value: unquote(rest)}
	if rest[0] != '"' && rest[0] != '\'' {
		for p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
			n.value += " " + stripComment(p.lines[p.pos].text)
			p.pos++
		}
	}
	return n
}

// blockScalar reads the lines indented deeper than indent. A literal scalar
// keeps its line breaks, a folded one joins its lines with spaces.
func (p *yamlParser) blockScalar(style byte, indent int) *yamlNode {
	var parts []string
	for p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
		parts = append(parts, p.lines[p.pos].text)
		p.pos++
	}
	separator := "\n"
	if style == '>' {
		separator = " "
	}
	return &yamlNode{value: strings.Join(parts, separator)}
}

func isSeqItem(text string) bool { return text == "-" || strings.HasPrefix(text, "- ") }

func isKeyLine(text string) bool {
	_, _, ok := splitKey(text)
	return ok
}

// splitKey splits "key: rest". A plain key ends at the first colon followed
// by a space or the end of the text.
func splitKey(text string) (key, rest string, ok bool) {
	if text == "" || strings.IndexByte("[{|>&*!?%@`", text[0]) >= 0 {
		return "", "", false
	}
	if text[0] == '"' || text[0] == '\'' {
		end := closingQuote(text)
		if end < 0 || end+1 >= len(text) || text[end+1] != ':' || end+2 < len(text) && text[end+2] != ' ' {
			return "", "", false
		}
		return unquote(text[:end+1]), strings.TrimSpace(text[end+2:]), true
	}
	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == ':' && (i+1 == len(text) || text[i+1] == ' '):
			return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), i > 0
		case text[i] == '#' && i > 0 && text[i-1] == ' ':
			return "", "", false
		}
	}
	return "", "", false
}

// closingQuote returns the index of the quote that closes the quoted text
// starting at text[0], or -1.
func closingQuote(text string) int {
	q := text[0]
	for i := 1; i < len(text); i++ {
		switch {
		case q == '"' && text[i] == '\\':
			i++
		case text[i] == q && q == '\'' && i+1 < len(text) && text[i+1] == '\'':
			i++
		case text[i] == q:
			return i
		}
	}
	return -1
}

// stripComment removes a trailing " #" comment outside quotes.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case (c == '"' || c == '\'') && (i == 0 || strings.IndexByte(" [{,", s[i-1]) >= 0):
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return s
}

var doubleQuoted = strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\n`, "\n", `\t`, "\t")

func unquote(s string) string {
	if len(s) >= 2 && s[0] == s[len(s)-1] {
		switch s[0] {
		case '"':
			return doubleQuoted.Replace(s[1 : len(s)-1])
		case '\'':
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
	}
	return s
}

// parseFlow parses a flow sequence or mapping, or a scalar.
func parseFlow(s string, depth int) *yamlNode {
	s = strings.TrimSpace(s)
	if depth <= maxYAMLDepth && len(s) >= 2 {
		inner := s[1 : len(s)-1]
		switch {
		case s[0] == '[' && s[len(s)-1] == ']':
			n := &yamlNode{kind: yamlSequence}
			for _, part := range splitFlow(inner) {
				n.items = append(n.items, parseFlow(part, depth+1))
			}
			return n
		case s[0] == '{' && s[len(s)-1] == '}':
			n := &yamlNode{kind: yamlMapping}
			for _, part := range splitFlow(inner) {
				key, rest, ok := splitKey(part)
				if !ok {
					key, rest = part, ""
				}
				n.keys = append(n.keys, key)
				n.items = append(n.items, parseFlow(rest, depth+1))
			}
			return n
		}
	}
	return &yamlNode{value: unquote(s)}
}

// splitFlow splits the inside of a flow collection at its top-level commas.
func splitFlow(s string) []string {
	var parts []string
	var quote byte
	nesting, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '{':
			nesting++
		case c == ']' || c == '}':
			nesting--
		case c == ',' && nesting == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	var kept []string
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			kept = append(kept, strings.TrimSpace(part))
		}
	}
	return kept
}
