package semanticimpact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumFiles          = 4096
	maximumChangedPaths   = 4096
	maximumFileBytes      = 2 << 20
	maximumTotalBytes     = 128 << 20
	maximumDeclarations   = 8192
	maximumReferences     = 32768
	maximumGaps           = 4096
	maximumSourcePosition = maximumFileBytes + 1
)

var (
	ErrInvalidInput = errors.New("invalid semantic impact input")
	ErrImpactLimit  = errors.New("semantic impact limit exceeded")
)

type Grade string

const (
	GradeStructural         Grade = "structural"
	GradeSyntacticCandidate Grade = "syntactic_candidate"
)

type Change string

const (
	ChangeAdded    Change = "added"
	ChangeModified Change = "modified"
	ChangeRemoved  Change = "removed"
)

type GapReason string

const (
	GapUnsupportedLanguage GapReason = "unsupported_language"
	GapParseFailure        GapReason = "parse_failure"
	GapSourceUnavailable   GapReason = "source_unavailable"
	GapLimitExceeded       GapReason = "limit_exceeded"
)

type File struct {
	filePath, digest string
	content          []byte
}

func NewFile(filePath string, content []byte) (File, error) {
	if !validPath(filePath) || len(content) > maximumFileBytes {
		return File{}, ErrInvalidInput
	}
	sum := sha256.Sum256(content)
	return File{filePath: filePath, digest: hex.EncodeToString(sum[:]), content: append([]byte(nil), content...)}, nil
}
func (f File) Path() string    { return f.filePath }
func (f File) Digest() string  { return f.digest }
func (f File) Content() []byte { return append([]byte(nil), f.content...) }

type ChangedPath struct{ filePath string }

func NewChangedPath(filePath string) (ChangedPath, error) {
	if !validPath(filePath) {
		return ChangedPath{}, ErrInvalidInput
	}
	return ChangedPath{filePath: filePath}, nil
}
func (c ChangedPath) Path() string { return c.filePath }

type Input struct {
	baseSnapshotIdentity, headSnapshotIdentity, changeModelIdentity, identity string
	changes                                                                   []ChangedPath
	coverageGaps                                                              []Gap
	baseFiles, headFiles                                                      []File
}

func NewInput(baseSnapshotIdentity, headSnapshotIdentity, changeModelIdentity string, changes []ChangedPath, baseFiles, headFiles []File) (Input, error) {
	return NewInputWithCoverageGaps(baseSnapshotIdentity, headSnapshotIdentity, changeModelIdentity, changes, baseFiles, headFiles, nil)
}
func NewInputWithCoverageGaps(baseSnapshotIdentity, headSnapshotIdentity, changeModelIdentity string, changes []ChangedPath, baseFiles, headFiles []File, coverageGaps []Gap) (Input, error) {
	if !validDigest(baseSnapshotIdentity) || !validDigest(headSnapshotIdentity) || !validDigest(changeModelIdentity) || len(changes) > maximumChangedPaths || len(baseFiles) > maximumFiles || len(headFiles) > maximumFiles {
		return Input{}, ErrInvalidInput
	}
	if len(coverageGaps) > maximumGaps {
		return Input{}, ErrImpactLimit
	}
	cc := append([]ChangedPath(nil), changes...)
	bf := append([]File(nil), baseFiles...)
	hf := append([]File(nil), headFiles...)
	cg := append([]Gap(nil), coverageGaps...)
	slices.SortFunc(cc, func(a, b ChangedPath) int { return strings.Compare(a.filePath, b.filePath) })
	slices.SortFunc(bf, func(a, b File) int { return strings.Compare(a.filePath, b.filePath) })
	slices.SortFunc(hf, func(a, b File) int { return strings.Compare(a.filePath, b.filePath) })
	slices.SortFunc(cg, func(a, b Gap) int {
		if c := strings.Compare(a.filePath, b.filePath); c != 0 {
			return c
		}
		return strings.Compare(string(a.reason), string(b.reason))
	})
	lastGap := ""
	for _, g := range cg {
		key := g.filePath + "\x00" + string(g.reason)
		if key <= lastGap || !validPath(g.filePath) || (g.reason != GapLimitExceeded && g.reason != GapSourceUnavailable) || g.detail == "" || len(g.detail) > 128 || g.identity != newGap(g.filePath, g.reason, g.detail).identity {
			return Input{}, ErrInvalidInput
		}
		lastGap = key
	}
	total := 0
	seen := map[string]bool{}
	for _, c := range cc {
		if !validPath(c.filePath) || seen[c.filePath] {
			return Input{}, ErrInvalidInput
		}
		seen[c.filePath] = true
	}
	for _, set := range [][]File{bf, hf} {
		seen = map[string]bool{}
		for _, f := range set {
			if !validPath(f.filePath) || len(f.content) > maximumFileBytes || seen[f.filePath] {
				return Input{}, ErrInvalidInput
			}
			if len(f.content) > maximumTotalBytes-total {
				return Input{}, ErrImpactLimit
			}
			seen[f.filePath] = true
			total += len(f.content)
		}
	}
	for _, set := range [][]File{bf, hf} {
		for _, f := range set {
			if !validFile(f) {
				return Input{}, ErrInvalidInput
			}
		}
	}
	bf = cloneFiles(bf)
	hf = cloneFiles(hf)
	wire := struct {
		Base, Head, Change                  string
		Changes, BaseFiles, HeadFiles, Gaps []string
	}{Base: baseSnapshotIdentity, Head: headSnapshotIdentity, Change: changeModelIdentity}
	for _, c := range cc {
		wire.Changes = append(wire.Changes, c.filePath)
	}
	for _, f := range bf {
		wire.BaseFiles = append(wire.BaseFiles, f.filePath+":"+f.digest)
	}
	for _, f := range hf {
		wire.HeadFiles = append(wire.HeadFiles, f.filePath+":"+f.digest)
	}
	for _, g := range cg {
		wire.Gaps = append(wire.Gaps, g.identity)
	}
	return Input{baseSnapshotIdentity: baseSnapshotIdentity, headSnapshotIdentity: headSnapshotIdentity, changeModelIdentity: changeModelIdentity, identity: hashJSON(wire), changes: cc, coverageGaps: cg, baseFiles: bf, headFiles: hf}, nil
}

func cloneFiles(in []File) []File {
	out := make([]File, len(in))
	for i, f := range in {
		out[i] = File{filePath: f.filePath, digest: f.digest, content: append([]byte(nil), f.content...)}
	}
	return out
}
func validFile(f File) bool {
	if !validPath(f.filePath) || len(f.content) > maximumFileBytes || !validDigest(f.digest) {
		return false
	}
	sum := sha256.Sum256(f.content)
	return f.digest == hex.EncodeToString(sum[:])
}
func validPath(v string) bool {
	return v != "" && len(v) <= 4096 && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl) && !strings.HasPrefix(v, "/") && path.Clean(v) == v && v != "." && !strings.HasPrefix(v, "../")
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return v != strings.Repeat("0", 64)
}
func hashJSON(v any) string {
	encoded, _ := json.Marshal(v)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

type Declaration struct {
	identity, key, name, kind, filePath, syntaxDigest, apiDigest string
	change                                                       Change
	exported, publicAPIChange                                    bool
	startLine, endLine                                           int
}

func (d Declaration) Identity() string      { return d.identity }
func (d Declaration) Key() string           { return d.key }
func (d Declaration) Name() string          { return d.name }
func (d Declaration) Kind() string          { return d.kind }
func (d Declaration) Path() string          { return d.filePath }
func (d Declaration) Change() Change        { return d.change }
func (d Declaration) Exported() bool        { return d.exported }
func (d Declaration) StartLine() int        { return d.startLine }
func (d Declaration) EndLine() int          { return d.endLine }
func (d Declaration) Grade() Grade          { return GradeStructural }
func (d Declaration) SyntaxDigest() string  { return d.syntaxDigest }
func (d Declaration) APIDigest() string     { return d.apiDigest }
func (d Declaration) PublicAPIChange() bool { return d.publicAPIChange }

type Reference struct {
	identity, declarationIdentity, declarationKey, filePath string
	line, column                                            int
	affectedTest                                            bool
	grade                                                   Grade
}

func (r Reference) Identity() string            { return r.identity }
func (r Reference) DeclarationIdentity() string { return r.declarationIdentity }
func (r Reference) DeclarationKey() string      { return r.declarationKey }
func (r Reference) Path() string                { return r.filePath }
func (r Reference) Line() int                   { return r.line }
func (r Reference) Column() int                 { return r.column }
func (r Reference) AffectedTest() bool          { return r.affectedTest }
func (r Reference) Grade() Grade                { return r.grade }

type Gap struct {
	identity, filePath, detail string
	reason                     GapReason
}

func (g Gap) Identity() string  { return g.identity }
func (g Gap) Path() string      { return g.filePath }
func (g Gap) Reason() GapReason { return g.reason }
func (g Gap) Detail() string    { return g.detail }
func NewCoverageGap(filePath string, reason GapReason) (Gap, error) {
	detail := ""
	switch reason {
	case GapLimitExceeded:
		detail = "semantic source resource limit"
	case GapSourceUnavailable:
		detail = "semantic source is unavailable"
	default:
		return Gap{}, ErrInvalidInput
	}
	if !validPath(filePath) {
		return Gap{}, ErrInvalidInput
	}
	return newGap(filePath, reason, detail), nil
}

type Profile struct {
	identity, adapterIdentity, graphSchema, inputIdentity, baseSnapshotIdentity, headSnapshotIdentity, changeModelIdentity string
	declarations                                                                                                           []Declaration
	references                                                                                                             []Reference
	gaps                                                                                                                   []Gap
}

func (p Profile) Identity() string             { return p.identity }
func (p Profile) AdapterIdentity() string      { return p.adapterIdentity }
func (p Profile) GraphSchema() string          { return p.graphSchema }
func (p Profile) InputIdentity() string        { return p.inputIdentity }
func (p Profile) BaseSnapshotIdentity() string { return p.baseSnapshotIdentity }
func (p Profile) HeadSnapshotIdentity() string { return p.headSnapshotIdentity }
func (p Profile) ChangeModelIdentity() string  { return p.changeModelIdentity }
func (p Profile) Declarations() []Declaration  { return append([]Declaration(nil), p.declarations...) }
func (p Profile) References() []Reference      { return append([]Reference(nil), p.references...) }
func (p Profile) Gaps() []Gap                  { return append([]Gap(nil), p.gaps...) }
func (p Profile) PublicAPIChanges() []Declaration {
	out := []Declaration{}
	for _, d := range p.declarations {
		if d.publicAPIChange {
			out = append(out, d)
		}
	}
	return out
}

func (f File) String() string   { return "semantic source file" }
func (f File) GoString() string { return "semanticimpact.File{<redacted>}" }
func (f File) Format(s fmt.State, v rune) {
	writeRedacted(s, v, "semantic source file", "semanticimpact.File{<redacted>}")
}
func (i Input) String() string   { return "semantic impact input" }
func (i Input) GoString() string { return "semanticimpact.Input{<redacted>}" }
func (i Input) Format(s fmt.State, v rune) {
	writeRedacted(s, v, "semantic impact input", "semanticimpact.Input{<redacted>}")
}
func (p Profile) String() string   { return "semantic impact profile" }
func (p Profile) GoString() string { return "semanticimpact.Profile{<redacted>}" }
func (p Profile) Format(s fmt.State, v rune) {
	writeRedacted(s, v, "semantic impact profile", "semanticimpact.Profile{<redacted>}")
}
func writeRedacted(s fmt.State, v rune, plain, goSyntax string) {
	value := plain
	if v == 'v' && s.Flag('#') {
		value = goSyntax
	}
	_, _ = s.Write([]byte(value))
}
