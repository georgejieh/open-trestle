package semanticimpact

import (
	"bytes"
	"encoding/json"
	"io"
)

const maximumProfileBytes = 16 << 20

type declarationWire struct {
	Identity        string `json:"identity"`
	Key             string `json:"key"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Path            string `json:"path"`
	Change          Change `json:"change"`
	Exported        bool   `json:"exported"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	SyntaxDigest    string `json:"syntax_digest"`
	APIDigest       string `json:"api_digest"`
	PublicAPIChange bool   `json:"public_api_change"`
	Grade           Grade  `json:"grade"`
}
type referenceWire struct {
	Identity            string `json:"identity"`
	DeclarationIdentity string `json:"declaration_identity"`
	DeclarationKey      string `json:"declaration_key"`
	Path                string `json:"path"`
	Line                int    `json:"line"`
	Column              int    `json:"column"`
	AffectedTest        bool   `json:"affected_test"`
	Grade               Grade  `json:"grade"`
}
type gapWire struct {
	Identity string    `json:"identity"`
	Path     string    `json:"path"`
	Reason   GapReason `json:"reason"`
	Detail   string    `json:"detail"`
}
type profileWire struct {
	Contract             string            `json:"contract"`
	SchemaVersion        int               `json:"schema_version"`
	Identity             string            `json:"identity"`
	AdapterIdentity      string            `json:"adapter_identity"`
	GraphSchema          string            `json:"graph_schema"`
	InputIdentity        string            `json:"input_identity"`
	BaseSnapshotIdentity string            `json:"base_snapshot_identity"`
	HeadSnapshotIdentity string            `json:"head_snapshot_identity"`
	ChangeModelIdentity  string            `json:"change_model_identity"`
	Declarations         []declarationWire `json:"declarations"`
	References           []referenceWire   `json:"references"`
	Gaps                 []gapWire         `json:"gaps"`
}

func EncodeProfile(p Profile) ([]byte, error) {
	if validateProfile(p) != nil {
		return nil, ErrInvalidInput
	}
	w := toProfileWire(p)
	encoded, err := json.Marshal(w)
	if err != nil || len(encoded) > maximumProfileBytes {
		return nil, ErrImpactLimit
	}
	return encoded, nil
}
func DecodeProfile(encoded []byte) (Profile, error) {
	if len(encoded) == 0 || len(encoded) > maximumProfileBytes {
		return Profile{}, ErrInvalidInput
	}
	var w profileWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&w) != nil {
		return Profile{}, ErrInvalidInput
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Profile{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(w)
	if err != nil || !bytes.Equal(canonical, encoded) || w.Declarations == nil || w.References == nil || w.Gaps == nil {
		return Profile{}, ErrInvalidInput
	}
	p := Profile{identity: w.Identity, adapterIdentity: w.AdapterIdentity, graphSchema: w.GraphSchema, inputIdentity: w.InputIdentity, baseSnapshotIdentity: w.BaseSnapshotIdentity, headSnapshotIdentity: w.HeadSnapshotIdentity, changeModelIdentity: w.ChangeModelIdentity}
	for _, d := range w.Declarations {
		if d.Grade != GradeStructural {
			return Profile{}, ErrInvalidInput
		}
		p.declarations = append(p.declarations, Declaration{identity: d.Identity, key: d.Key, name: d.Name, kind: d.Kind, filePath: d.Path, change: d.Change, exported: d.Exported, startLine: d.StartLine, endLine: d.EndLine, syntaxDigest: d.SyntaxDigest, apiDigest: d.APIDigest, publicAPIChange: d.PublicAPIChange})
	}
	for _, r := range w.References {
		p.references = append(p.references, Reference{identity: r.Identity, declarationIdentity: r.DeclarationIdentity, declarationKey: r.DeclarationKey, filePath: r.Path, line: r.Line, column: r.Column, affectedTest: r.AffectedTest, grade: r.Grade})
	}
	for _, g := range w.Gaps {
		p.gaps = append(p.gaps, Gap{identity: g.Identity, filePath: g.Path, reason: g.Reason, detail: g.Detail})
	}
	if w.Contract != "open-trestle/semantic-impact-profile" || w.SchemaVersion != 1 || validateProfile(p) != nil {
		return Profile{}, ErrInvalidInput
	}
	return p, nil
}
func toProfileWire(p Profile) profileWire {
	w := profileWire{Contract: "open-trestle/semantic-impact-profile", SchemaVersion: 1, Identity: p.identity, AdapterIdentity: p.adapterIdentity, GraphSchema: p.graphSchema, InputIdentity: p.inputIdentity, BaseSnapshotIdentity: p.baseSnapshotIdentity, HeadSnapshotIdentity: p.headSnapshotIdentity, ChangeModelIdentity: p.changeModelIdentity, Declarations: make([]declarationWire, 0, len(p.declarations)), References: make([]referenceWire, 0, len(p.references)), Gaps: make([]gapWire, 0, len(p.gaps))}
	for _, d := range p.declarations {
		w.Declarations = append(w.Declarations, declarationWire{d.identity, d.key, d.name, d.kind, d.filePath, d.change, d.exported, d.startLine, d.endLine, d.syntaxDigest, d.apiDigest, d.publicAPIChange, GradeStructural})
	}
	for _, r := range p.references {
		w.References = append(w.References, referenceWire{r.identity, r.declarationIdentity, r.declarationKey, r.filePath, r.line, r.column, r.affectedTest, r.grade})
	}
	for _, g := range p.gaps {
		w.Gaps = append(w.Gaps, gapWire{g.identity, g.filePath, g.reason, g.detail})
	}
	return w
}
func validateProfile(p Profile) error {
	if !validDigest(p.identity) || !validDigest(p.adapterIdentity) || !validDigest(p.inputIdentity) || !validDigest(p.baseSnapshotIdentity) || !validDigest(p.headSnapshotIdentity) || !validDigest(p.changeModelIdentity) || p.adapterIdentity != goAdapterIdentity || p.graphSchema != goGraphSchema || len(p.declarations) > maximumDeclarations || len(p.references) > maximumReferences || len(p.gaps) > maximumGaps {
		return ErrInvalidInput
	}
	declIDs := map[string]string{}
	last := ""
	for _, d := range p.declarations {
		if !validPath(d.filePath) || !validDigest(d.syntaxDigest) || !validDigest(d.apiDigest) || d.key == "" || len(d.key) > 4096 || d.name == "" || len(d.name) > 1024 || !validDeclarationKind(d.kind) || d.startLine < 1 || d.startLine > maximumSourcePosition || d.endLine < d.startLine || d.endLine > maximumSourcePosition || (d.change != ChangeAdded && d.change != ChangeModified && d.change != ChangeRemoved) || (d.publicAPIChange && !d.exported) || (d.exported && d.change != ChangeModified && !d.publicAPIChange) || d.identity != declarationIdentity(d) {
			return ErrInvalidInput
		}
		order := d.filePath + "\x00" + d.key
		if order <= last || declIDs[d.identity] != "" {
			return ErrInvalidInput
		}
		last = order
		declIDs[d.identity] = d.key
	}
	last = ""
	seenReferences := map[string]bool{}
	var previousReference *Reference
	for index := range p.references {
		r := p.references[index]
		key, declared := declIDs[r.declarationIdentity]
		if !declared || key != r.declarationKey || !validPath(r.filePath) || r.line < 1 || r.line > maximumSourcePosition || r.column < 1 || r.column > maximumSourcePosition || r.grade != GradeSyntacticCandidate || r.identity != referenceIdentity(r) {
			return ErrInvalidInput
		}
		if previousReference != nil && !referenceLess(*previousReference, r) || seenReferences[r.identity] {
			return ErrInvalidInput
		}
		seenReferences[r.identity] = true
		previousReference = &p.references[index]
	}
	last = ""
	seenGaps := map[string]bool{}
	for _, g := range p.gaps {
		if !validPath(g.filePath) || g.detail == "" || len(g.detail) > 128 || (g.reason != GapUnsupportedLanguage && g.reason != GapParseFailure && g.reason != GapSourceUnavailable && g.reason != GapLimitExceeded) || g.identity != newGap(g.filePath, g.reason, g.detail).identity {
			return ErrInvalidInput
		}
		order := g.filePath + "\x00" + string(g.reason)
		if order <= last || seenGaps[g.identity] {
			return ErrInvalidInput
		}
		seenGaps[g.identity] = true
		last = order
	}
	if p.identity != deriveProfileIdentity(p) {
		return ErrInvalidInput
	}
	return nil
}

type profileIdentityWire struct {
	Adapter, Graph, Input, Base, Head, Change string
	Declarations, References, Gaps            []string
}

func deriveProfileIdentity(p Profile) string {
	wire := profileIdentityWire{Adapter: p.adapterIdentity, Graph: p.graphSchema, Input: p.inputIdentity, Base: p.baseSnapshotIdentity, Head: p.headSnapshotIdentity, Change: p.changeModelIdentity}
	for _, d := range p.declarations {
		wire.Declarations = append(wire.Declarations, d.identity)
	}
	for _, r := range p.references {
		wire.References = append(wire.References, r.identity)
	}
	for _, g := range p.gaps {
		wire.Gaps = append(wire.Gaps, g.identity)
	}
	return hashJSON(wire)
}
func validDeclarationKind(value string) bool {
	switch value {
	case "function", "method", "type", "var", "const":
		return true
	default:
		return false
	}
}
func declarationIdentity(d Declaration) string {
	return hashJSON(struct {
		Path, Key, Name, Kind, Change, Digest, APIDigest string
		Exported, PublicAPIChange                        bool
		Start, End                                       int
	}{d.filePath, d.key, d.name, d.kind, string(d.change), d.syntaxDigest, d.apiDigest, d.exported, d.publicAPIChange, d.startLine, d.endLine})
}
func referenceIdentity(r Reference) string {
	return hashJSON(struct {
		Declaration, Path string
		Line, Column      int
		Test              bool
		Grade             Grade
	}{r.declarationIdentity, r.filePath, r.line, r.column, r.affectedTest, r.grade})
}
func referenceLess(a, b Reference) bool {
	if a.declarationIdentity != b.declarationIdentity {
		return a.declarationIdentity < b.declarationIdentity
	}
	if a.filePath != b.filePath {
		return a.filePath < b.filePath
	}
	if a.line != b.line {
		return a.line < b.line
	}
	return a.column < b.column
}
