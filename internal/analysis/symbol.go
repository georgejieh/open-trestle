package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Bounds identity preimages derived from parser-controlled symbol names.
const maxSymbolQualifiedNameBytes = 4096

// Language identifies a supported source language.
type Language string

const (
	// LanguageGo identifies Go source.
	LanguageGo Language = "go"
)

// SymbolKind identifies a supported enclosing declaration.
type SymbolKind string

const (
	// SymbolKindFunction identifies a package-level function.
	SymbolKindFunction SymbolKind = "function"
	// SymbolKindMethod identifies a method declaration.
	SymbolKindMethod SymbolKind = "method"
)

// Symbol binds an enclosing declaration to exact head-side evidence.
type Symbol struct {
	identity           string
	lineMapIdentity    string
	fileChangeIdentity string
	path               string
	language           Language
	kind               SymbolKind
	qualifiedName      string
	sourceRange        evidence.SourceRange
}

// NewSymbol creates an immutable exact-head symbol descriptor.
func NewSymbol(lineMap evidence.LineMap, language Language, kind SymbolKind, qualifiedName string, sourceRange evidence.SourceRange) (Symbol, error) {
	if !isSHA256Identity(lineMap.Identity()) || !isSHA256Identity(lineMap.FileChangeIdentity()) || lineMap.Path() == "" {
		return Symbol{}, fmt.Errorf("line map is required")
	}
	if language != LanguageGo {
		return Symbol{}, fmt.Errorf("unsupported symbol language: %q", language)
	}
	if kind != SymbolKindFunction && kind != SymbolKindMethod {
		return Symbol{}, fmt.Errorf("unsupported symbol kind: %q", kind)
	}
	if len(qualifiedName) == 0 || strings.TrimSpace(qualifiedName) == "" {
		return Symbol{}, fmt.Errorf("qualified name is required")
	}
	if len(qualifiedName) > maxSymbolQualifiedNameBytes {
		return Symbol{}, fmt.Errorf("qualified name exceeds %d bytes", maxSymbolQualifiedNameBytes)
	}
	if !utf8.ValidString(qualifiedName) {
		return Symbol{}, fmt.Errorf("qualified name must be valid UTF-8")
	}
	for _, value := range qualifiedName {
		if !unicode.IsPrint(value) {
			return Symbol{}, fmt.Errorf("qualified name contains a non-printing character")
		}
	}
	validatedRange, err := evidence.NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
	if err != nil {
		return Symbol{}, fmt.Errorf("validate symbol range: %w", err)
	}
	if validatedRange.Path() != lineMap.Path() {
		return Symbol{}, fmt.Errorf("symbol range path does not match line map path")
	}
	if validatedRange.EndLine() > lineMap.HeadLineCount() {
		return Symbol{}, fmt.Errorf("symbol range exceeds head content")
	}
	canonical := struct {
		Contract           string     `json:"contract"`
		SchemaVersion      int        `json:"schema_version"`
		LineMapIdentity    string     `json:"line_map_identity"`
		FileChangeIdentity string     `json:"file_change_identity"`
		Path               string     `json:"path"`
		Language           Language   `json:"language"`
		Kind               SymbolKind `json:"kind"`
		QualifiedName      string     `json:"qualified_name"`
		StartLine          int        `json:"start_line"`
		EndLine            int        `json:"end_line"`
	}{
		Contract:           "open-trestle/symbol",
		SchemaVersion:      1,
		LineMapIdentity:    lineMap.Identity(),
		FileChangeIdentity: lineMap.FileChangeIdentity(),
		Path:               lineMap.Path(),
		Language:           language,
		Kind:               kind,
		QualifiedName:      qualifiedName,
		StartLine:          validatedRange.StartLine(),
		EndLine:            validatedRange.EndLine(),
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Symbol{}, fmt.Errorf("encode symbol identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return Symbol{
		identity:           hex.EncodeToString(digest[:]),
		lineMapIdentity:    lineMap.Identity(),
		fileChangeIdentity: lineMap.FileChangeIdentity(),
		path:               lineMap.Path(),
		language:           language,
		kind:               kind,
		qualifiedName:      qualifiedName,
		sourceRange:        validatedRange,
	}, nil
}

func isSHA256Identity(identity string) bool {
	if len(identity) != sha256.Size*2 || identity != strings.ToLower(identity) {
		return false
	}
	_, err := hex.DecodeString(identity)
	return err == nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (s Symbol) Identity() string {
	return s.identity
}

// LineMapIdentity returns the exact head-side line-map identity.
func (s Symbol) LineMapIdentity() string {
	return s.lineMapIdentity
}

// FileChangeIdentity returns the owning file-change identity.
func (s Symbol) FileChangeIdentity() string {
	return s.fileChangeIdentity
}

// Path returns the workspace-relative source path.
func (s Symbol) Path() string {
	return s.path
}

// Language returns the source language.
func (s Symbol) Language() Language {
	return s.language
}

// Kind returns the declaration kind.
func (s Symbol) Kind() SymbolKind {
	return s.kind
}

// QualifiedName returns the exact parser-provided symbol name.
func (s Symbol) QualifiedName() string {
	return s.qualifiedName
}

// SourceRange returns the physical head-side declaration range.
func (s Symbol) SourceRange() evidence.SourceRange {
	return s.sourceRange
}
