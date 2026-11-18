package syntaxwasm

import (
	"bytes"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// filterHTML keeps the construction records of custom elements and the
// imports that point at a resource. The query records every tag name and
// every src, href and action value, because it cannot test their text. The
// href of a base element sets the base for other addresses and is not a
// target, so it is dropped too. It runs before the records of inline
// scripts are added.
func filterHTML(content []byte, raw *syntaxanalysis.RawFile) {
	references := raw.References[:0]
	for _, r := range raw.References {
		if htmlCustomElement(string(content[r.Name.Start:r.Name.End])) {
			references = append(references, r)
		}
	}
	raw.References = references
	imports := raw.Imports[:0]
	for _, i := range raw.Imports {
		if htmlResource(string(content[i.Source.Start:i.Source.End])) && htmlTagBefore(content, i.Node.Start) != "base" {
			imports = append(imports, i)
		}
	}
	raw.Imports = imports
}

// htmlScriptLanguage returns the language of an inline script from its
// start tag: TypeScript or TSX for a lang attribute that names it, or a
// TypeScript type, and JavaScript for no type, a JavaScript type or module.
// Other types, such as JSON, import maps and templates, are not code to
// analyse.
func htmlScriptLanguage(tag []byte) (syntaxanalysis.Language, bool) {
	attributes := htmlAttributes(tag)
	if lang, ok := attributes["lang"]; ok {
		switch lang {
		case "ts", "typescript":
			return syntaxanalysis.LanguageTypeScript, true
		case "tsx":
			return syntaxanalysis.LanguageTSX, true
		case "", "js", "javascript", "jsx", "mjs":
			return syntaxanalysis.LanguageJavaScript, true
		}
		return "", false
	}
	switch attributes["type"] {
	case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript",
		"application/x-javascript", "application/x-ecmascript", "text/x-javascript", "text/x-ecmascript",
		"text/jscript", "text/livescript", "text/jsx", "text/babel":
		return syntaxanalysis.LanguageJavaScript, true
	case "text/typescript", "application/typescript":
		return syntaxanalysis.LanguageTypeScript, true
	}
	return "", false
}

// htmlAttributes reads the attributes of a start tag, with lower-case
// names and trimmed lower-case values. The first occurrence of a name
// wins, as in HTML.
func htmlAttributes(tag []byte) map[string]string {
	attributes := map[string]string{}
	i := 0
	if len(tag) > 0 && tag[0] == '<' {
		i = 1
		for i < len(tag) && !htmlSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
			i++
		}
	}
	for i < len(tag) {
		for i < len(tag) && (htmlSpace(tag[i]) || tag[i] == '/') {
			i++
		}
		if i >= len(tag) || tag[i] == '>' {
			break
		}
		start := i
		for i < len(tag) && !htmlSpace(tag[i]) && tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		name := strings.ToLower(string(tag[start:i]))
		for i < len(tag) && htmlSpace(tag[i]) {
			i++
		}
		value := ""
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && htmlSpace(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '"' || tag[i] == '\'') {
				quote := tag[i]
				end := bytes.IndexByte(tag[i+1:], quote)
				if end < 0 {
					end = len(tag) - i - 1
				}
				value = string(tag[i+1 : i+1+end])
				i += end + 2
			} else {
				start := i
				for i < len(tag) && !htmlSpace(tag[i]) && tag[i] != '>' {
					i++
				}
				value = string(tag[start:i])
			}
		}
		if _, seen := attributes[name]; !seen && name != "" {
			attributes[name] = strings.ToLower(strings.TrimSpace(value))
		}
	}
	return attributes
}

func htmlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
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
