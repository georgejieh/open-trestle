package syntaxwasm

import (
	"bytes"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishHTML keeps the construction records of custom elements and the
// imports that point at a resource. The query records every tag name and
// every src, href and action value, because it cannot test their text. The
// href of a base element sets the base for other addresses and is not a
// target, so it is dropped too.
func finishHTML(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	references := a.References[:0]
	for _, r := range a.References {
		if htmlCustomElement(r.Name.Untrusted()) {
			references = append(references, r)
		}
	}
	a.References = references
	imports := a.Imports[:0]
	for _, i := range a.Imports {
		if htmlResource(i.Source.Untrusted()) && htmlTagBefore(content, i.Range.StartByte) != "base" {
			imports = append(imports, i)
		}
	}
	a.Imports = imports
}

// htmlCustomElement reports whether a tag name is a valid custom element
// name: it starts with a letter and contains a hyphen, and it is not one of
// the hyphenated names that SVG and MathML reserve.
func htmlCustomElement(name string) bool {
	if name == "" || !strings.Contains(name, "-") {
		return false
	}
	if c := name[0] | 0x20; c < 'a' || c > 'z' {
		return false
	}
	switch strings.ToLower(name) {
	case "annotation-xml", "color-profile", "font-face", "font-face-src", "font-face-uri", "font-face-format", "font-face-name", "missing-glyph":
		return false
	}
	return true
}

// htmlResource reports whether an attribute value names a resource, as
// opposed to a fragment of the same page or a scheme that runs code or
// opens another application.
func htmlResource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value[0] == '#' {
		return false
	}
	lower := strings.ToLower(value)
	for _, scheme := range []string{"javascript:", "data:", "mailto:", "tel:", "sms:", "blob:", "about:"} {
		if strings.HasPrefix(lower, scheme) {
			return false
		}
	}
	return true
}

// htmlTagBefore returns the lower-case name of the tag that opens the last
// start tag before offset, which is the element that owns an attribute
// starting there.
func htmlTagBefore(content []byte, offset int) string {
	open := bytes.LastIndexByte(content[:offset], '<')
	if open < 0 {
		return ""
	}
	name := content[open+1 : offset]
	if end := bytes.IndexAny(name, " \t\r\n/>"); end >= 0 {
		name = name[:end]
	}
	return strings.ToLower(string(name))
}
