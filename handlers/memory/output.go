package memory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	maximumQueries      = 64
	maximumRecords      = 50
	maximumPayloadBytes = 16 << 20
)

var (
	ErrInvalidHandler = errors.New("invalid memory retrieval handler")
	ErrInvalidResult  = errors.New("invalid memory retrieval result")
)

type Item struct {
	identity, queryIdentity, recordIdentity, kind, taint, path, text, producerIdentity, freshnessIdentity string
	rank, pathScore, symbolScore, textScore                                                               uint8
	symbols, evidenceIDs, derivedFromIDs, counterEvidenceIDs                                              []string
	observedAt, validFrom, validUntil, staleAfter                                                         int64
	confidence                                                                                            uint16
}

func (i Item) Identity() string             { return i.identity }
func (i Item) RecordIdentity() string       { return i.recordIdentity }
func (i Item) Text() string                 { return i.text }
func (i Item) Taint() string                { return i.taint }
func (i Item) CounterEvidenceIDs() []string { return append([]string(nil), i.counterEvidenceIDs...) }
func (i Item) Record(scope memorycore.Scope) (memorycore.Record, error) {
	kind, err := memorycore.ParseRecordKind(i.kind)
	if err != nil {
		return memorycore.Record{}, err
	}
	taint, err := memorycore.ParseTaintClass(i.taint)
	if err != nil {
		return memorycore.Record{}, err
	}
	input := memorycore.RecordInput{Kind: kind, Taint: taint, Path: i.path, Symbols: i.symbols, Text: i.text, EvidenceIDs: i.evidenceIDs, DerivedFromIDs: i.derivedFromIDs, CounterEvidenceIDs: i.counterEvidenceIDs, ProducerIdentity: i.producerIdentity, ObservedAt: time.UnixMilli(i.observedAt), ValidFrom: time.UnixMilli(i.validFrom), FreshnessIdentity: i.freshnessIdentity, ConfidenceBasisPoints: i.confidence}
	if i.validUntil != 0 {
		input.ValidUntil = time.UnixMilli(i.validUntil)
	}
	if i.staleAfter != 0 {
		input.StaleAfter = time.UnixMilli(i.staleAfter)
	}
	return memorycore.NewRecord(scope, input)
}

type Query struct {
	path, identity, retrievalIdentity string
	indexRevision                     uint64
	limit                             uint8
	items                             []Item
}

func (q Query) Path() string  { return q.path }
func (q Query) Items() []Item { return append([]Item(nil), q.items...) }
func (q Query) Retrieval(scope memorycore.Scope, asOf time.Time) (memorycore.LexicalRetrieval, error) {
	query, err := memorycore.NewLexicalQuery(scope, q.path, nil, nil, asOf, q.limit)
	if err != nil || query.Identity() != q.identity {
		return memorycore.LexicalRetrieval{}, ErrInvalidResult
	}
	inputs := make([]memorycore.RetrievalItemInput, len(q.items))
	for index, item := range q.items {
		record, recordErr := item.Record(scope)
		if recordErr != nil {
			return memorycore.LexicalRetrieval{}, ErrInvalidResult
		}
		inputs[index] = memorycore.RetrievalItemInput{Record: record, Rank: item.rank, PathScore: item.pathScore, SymbolScore: item.symbolScore, TextScore: item.textScore}
	}
	retrieval, err := memorycore.NewLexicalRetrieval(scope, query, q.indexRevision, inputs)
	if err != nil || retrieval.Identity() != q.retrievalIdentity {
		return memorycore.LexicalRetrieval{}, ErrInvalidResult
	}
	return retrieval, nil
}

type Omission struct{ path, reason string }

func (o Omission) Path() string   { return o.path }
func (o Omission) Reason() string { return o.reason }

type Result struct {
	identity, artifactIdentity, scopeIdentity, changeArtifactIdentity, changeIdentity, policyIdentity, retrieverIdentity, memoryScopeIdentity, tenantID, repositoryID, actorID, visibility, refSetIdentity string
	pathPrefixes                                                                                                                                                                                           []string
	asOf                                                                                                                                                                                                   int64
	queries                                                                                                                                                                                                []Query
	omissions                                                                                                                                                                                              []Omission
}

func (r Result) Identity() string               { return r.identity }
func (r Result) ArtifactIdentity() string       { return r.artifactIdentity }
func (r Result) ChangeArtifactIdentity() string { return r.changeArtifactIdentity }
func (r Result) MemoryScopeIdentity() string    { return r.memoryScopeIdentity }
func (r Result) PolicyIdentity() string         { return r.policyIdentity }
func (r Result) RetrieverIdentity() string      { return r.retrieverIdentity }
func (r Result) AsOf() time.Time                { return time.UnixMilli(r.asOf) }
func (r Result) MemoryScope() (memorycore.Scope, error) {
	visibility, err := memorycore.ParseRefVisibility(r.visibility)
	if err != nil {
		return memorycore.Scope{}, err
	}
	return memorycore.NewScope(r.tenantID, r.repositoryID, r.actorID, visibility, r.refSetIdentity, r.pathPrefixes)
}
func (r Result) Queries() []Query      { return append([]Query(nil), r.queries...) }
func (r Result) Omissions() []Omission { return append([]Omission(nil), r.omissions...) }
func (r Result) String() string        { return "memory retrieval result" }
func (r Result) GoString() string      { return "memory.Result{<redacted>}" }
func (r Result) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "memory retrieval result", "memory.Result{<redacted>}")
}

type itemWire struct {
	Identity           string   `json:"identity"`
	QueryIdentity      string   `json:"query_identity"`
	RecordIdentity     string   `json:"record_identity"`
	Rank               uint8    `json:"rank"`
	PathScore          uint8    `json:"path_score"`
	SymbolScore        uint8    `json:"symbol_score"`
	TextScore          uint8    `json:"text_score"`
	Kind               string   `json:"kind"`
	Taint              string   `json:"taint"`
	Path               string   `json:"path"`
	Symbols            []string `json:"symbols"`
	Text               string   `json:"text"`
	EvidenceIDs        []string `json:"evidence_ids"`
	DerivedFromIDs     []string `json:"derived_from_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
	ProducerIdentity   string   `json:"producer_identity"`
	ObservedAt         int64    `json:"observed_at"`
	ValidFrom          int64    `json:"valid_from"`
	ValidUntil         int64    `json:"valid_until"`
	StaleAfter         int64    `json:"stale_after"`
	FreshnessIdentity  string   `json:"freshness_identity"`
	Confidence         uint16   `json:"confidence_basis_points"`
}
type queryWire struct {
	Path              string     `json:"path"`
	Identity          string     `json:"identity"`
	RetrievalIdentity string     `json:"retrieval_identity"`
	IndexRevision     uint64     `json:"index_revision"`
	Limit             uint8      `json:"limit"`
	Items             []itemWire `json:"items"`
}
type omissionWire struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type resultWire struct {
	Contract               string         `json:"contract"`
	SchemaVersion          int            `json:"schema_version"`
	Identity               string         `json:"identity"`
	ChangeArtifactIdentity string         `json:"change_artifact_identity"`
	ChangeIdentity         string         `json:"change_identity"`
	PolicyIdentity         string         `json:"policy_identity"`
	RetrieverIdentity      string         `json:"retriever_identity"`
	MemoryScopeIdentity    string         `json:"memory_scope_identity"`
	TenantID               string         `json:"tenant_id"`
	RepositoryID           string         `json:"repository_id"`
	ActorID                string         `json:"actor_id"`
	Visibility             string         `json:"visibility"`
	RefSetIdentity         string         `json:"ref_set_identity"`
	PathPrefixes           []string       `json:"path_prefixes"`
	AsOf                   int64          `json:"as_of"`
	Queries                []queryWire    `json:"queries"`
	Omissions              []omissionWire `json:"omissions"`
}

func newResult(changeArtifact artifact.Artifact, change changehandler.Result, policy, retriever string, scope memorycore.Scope, at time.Time, queries []Query, omissions []Omission) (Result, error) {
	if scope.TenantID() != changeArtifact.Scope().TenantID() || scope.RepositoryID() != changeArtifact.Scope().RepositoryID() {
		return Result{}, ErrInvalidResult
	}
	result := Result{changeArtifactIdentity: changeArtifact.Identity(), changeIdentity: change.Identity(), policyIdentity: policy, retrieverIdentity: retriever, memoryScopeIdentity: scope.Identity(), tenantID: scope.TenantID(), repositoryID: scope.RepositoryID(), actorID: scope.ActorID(), visibility: scope.RefVisibility().String(), refSetIdentity: scope.RefSetIdentity(), pathPrefixes: scope.PathPrefixes(), asOf: at.UnixMilli(), queries: append([]Query(nil), queries...), omissions: append([]Omission(nil), omissions...)}
	sort.Slice(result.queries, func(i, j int) bool { return result.queries[i].path < result.queries[j].path })
	sort.Slice(result.omissions, func(i, j int) bool { return result.omissions[i].path < result.omissions[j].path })
	result.identity = deriveIdentity(result)
	if result.validate(false, change) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func (r Result) validate(requireArtifact bool, change changehandler.Result) error {
	visibility, err := memorycore.ParseRefVisibility(r.visibility)
	if err != nil {
		return ErrInvalidResult
	}
	scope, err := memorycore.NewScope(r.tenantID, r.repositoryID, r.actorID, visibility, r.refSetIdentity, r.pathPrefixes)
	if err != nil || scope.Identity() != r.memoryScopeIdentity || r.refSetIdentity != change.HeadRevision().Identity() || r.changeIdentity != change.Identity() || r.changeArtifactIdentity != change.ArtifactIdentity() || !validDigest(r.policyIdentity) || !validDigest(r.retrieverIdentity) || r.asOf <= 0 || len(r.queries) > maximumQueries || requireArtifact && (!validDigest(r.artifactIdentity) || !validDigest(r.scopeIdentity)) {
		return ErrInvalidResult
	}
	paths := make(map[string]struct{}, len(change.Entries()))
	for _, entry := range change.Entries() {
		paths[entry.Path()] = struct{}{}
	}
	covered := make(map[string]struct{}, len(paths))
	records := 0
	previous := ""
	asOf := time.UnixMilli(r.asOf)
	for _, query := range r.queries {
		if query.path <= previous || !scope.AllowsPath(query.path) {
			return ErrInvalidResult
		}
		if _, ok := paths[query.path]; !ok {
			return ErrInvalidResult
		}
		if _, ok := covered[query.path]; ok {
			return ErrInvalidResult
		}
		covered[query.path] = struct{}{}
		expected, err := memorycore.NewLexicalQuery(scope, query.path, nil, nil, asOf, query.limit)
		if err != nil || expected.Identity() != query.identity || !validDigest(query.retrievalIdentity) || len(query.items) > int(query.limit) || len(query.items) > 0 && query.indexRevision == 0 {
			return ErrInvalidResult
		}
		for index, item := range query.items {
			if !validItem(scope, query, item, index, asOf) {
				return ErrInvalidResult
			}
		}
		if deriveRetrievalIdentity(scope.Identity(), query) != query.retrievalIdentity {
			return ErrInvalidResult
		}
		records += len(query.items)
		previous = query.path
	}
	if records > maximumRecords {
		return ErrInvalidResult
	}
	previous = ""
	for _, omission := range r.omissions {
		if omission.path <= previous {
			return ErrInvalidResult
		}
		if _, ok := paths[omission.path]; !ok {
			return ErrInvalidResult
		}
		if _, ok := covered[omission.path]; ok {
			return ErrInvalidResult
		}
		if omission.reason != "path_not_authorized" && omission.reason != "query_limit" && omission.reason != "result_limit" {
			return ErrInvalidResult
		}
		covered[omission.path] = struct{}{}
		previous = omission.path
	}
	if len(covered) != len(paths) || r.identity != deriveIdentity(r) {
		return ErrInvalidResult
	}
	return nil
}
func validItem(scope memorycore.Scope, query Query, item Item, index int, asOf time.Time) bool {
	kind, err := memorycore.ParseRecordKind(item.kind)
	if err != nil {
		return false
	}
	taint, err := memorycore.ParseTaintClass(item.taint)
	if err != nil {
		return false
	}
	input := memorycore.RecordInput{Kind: kind, Taint: taint, Path: item.path, Symbols: item.symbols, Text: item.text, EvidenceIDs: item.evidenceIDs, DerivedFromIDs: item.derivedFromIDs, CounterEvidenceIDs: item.counterEvidenceIDs, ProducerIdentity: item.producerIdentity, ObservedAt: time.UnixMilli(item.observedAt), ValidFrom: time.UnixMilli(item.validFrom), FreshnessIdentity: item.freshnessIdentity, ConfidenceBasisPoints: item.confidence}
	if item.validUntil != 0 {
		input.ValidUntil = time.UnixMilli(item.validUntil)
	}
	if item.staleAfter != 0 {
		input.StaleAfter = time.UnixMilli(item.staleAfter)
	}
	record, err := memorycore.NewRecord(scope, input)
	return err == nil && record.Identity() == item.recordIdentity && record.FreshAt(asOf) && item.queryIdentity == query.identity && item.rank == uint8(index+1) && item.rank > 0 && (item.pathScore > 0 || item.symbolScore > 0 || item.textScore > 0) && item.identity == deriveRetrievalItemIdentity(item)
}
func encodeResult(result Result) ([]byte, error) {
	encoded, err := json.Marshal(toWire(result))
	if err != nil || len(encoded) > maximumPayloadBytes {
		return nil, ErrInvalidResult
	}
	return encoded, nil
}
func ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindRetrievalResult || value.MediaType() != "application/json" || value.Origin() != artifact.OriginMemory || value.Scope().Identity() != changeArtifact.Scope().Identity() || value.Classification() != changeArtifact.Classification() || value.Protection() != changeArtifact.Protection() || !contains(value.Provenance(), changeArtifact.Identity()) {
		return Result{}, ErrInvalidResult
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumPayloadBytes {
		return Result{}, ErrInvalidResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire resultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Result{}, ErrInvalidResult
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/memory-retrieval-result" || wire.SchemaVersion != 1 {
		return Result{}, ErrInvalidResult
	}
	result := fromWire(wire)
	result.artifactIdentity = value.Identity()
	result.scopeIdentity = value.Scope().Identity()
	if result.asOf != value.CreatedAt().UnixMilli() || result.tenantID != value.Scope().TenantID() || result.repositoryID != value.Scope().RepositoryID() || result.validate(true, change) != nil || !contains(value.Provenance(), result.memoryScopeIdentity) || !contains(value.Provenance(), result.policyIdentity) || !contains(value.Provenance(), result.retrieverIdentity) {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func toWire(r Result) resultWire {
	queries := make([]queryWire, len(r.queries))
	for i, q := range r.queries {
		items := make([]itemWire, len(q.items))
		for j, v := range q.items {
			items[j] = itemWire{v.identity, v.queryIdentity, v.recordIdentity, v.rank, v.pathScore, v.symbolScore, v.textScore, v.kind, v.taint, v.path, v.symbols, v.text, v.evidenceIDs, v.derivedFromIDs, v.counterEvidenceIDs, v.producerIdentity, v.observedAt, v.validFrom, v.validUntil, v.staleAfter, v.freshnessIdentity, v.confidence}
		}
		queries[i] = queryWire{q.path, q.identity, q.retrievalIdentity, q.indexRevision, q.limit, items}
	}
	omissions := make([]omissionWire, len(r.omissions))
	for i, v := range r.omissions {
		omissions[i] = omissionWire{v.path, v.reason}
	}
	return resultWire{"open-trestle/memory-retrieval-result", 1, r.identity, r.changeArtifactIdentity, r.changeIdentity, r.policyIdentity, r.retrieverIdentity, r.memoryScopeIdentity, r.tenantID, r.repositoryID, r.actorID, r.visibility, r.refSetIdentity, r.pathPrefixes, r.asOf, queries, omissions}
}
func fromWire(w resultWire) Result {
	queries := make([]Query, len(w.Queries))
	for i, q := range w.Queries {
		items := make([]Item, len(q.Items))
		for j, v := range q.Items {
			items[j] = Item{v.Identity, v.QueryIdentity, v.RecordIdentity, v.Kind, v.Taint, v.Path, v.Text, v.ProducerIdentity, v.FreshnessIdentity, v.Rank, v.PathScore, v.SymbolScore, v.TextScore, v.Symbols, v.EvidenceIDs, v.DerivedFromIDs, v.CounterEvidenceIDs, v.ObservedAt, v.ValidFrom, v.ValidUntil, v.StaleAfter, v.Confidence}
		}
		queries[i] = Query{q.Path, q.Identity, q.RetrievalIdentity, q.IndexRevision, q.Limit, items}
	}
	omissions := make([]Omission, len(w.Omissions))
	for i, v := range w.Omissions {
		omissions[i] = Omission{v.Path, v.Reason}
	}
	return Result{identity: w.Identity, changeArtifactIdentity: w.ChangeArtifactIdentity, changeIdentity: w.ChangeIdentity, policyIdentity: w.PolicyIdentity, retrieverIdentity: w.RetrieverIdentity, memoryScopeIdentity: w.MemoryScopeIdentity, tenantID: w.TenantID, repositoryID: w.RepositoryID, actorID: w.ActorID, visibility: w.Visibility, refSetIdentity: w.RefSetIdentity, pathPrefixes: w.PathPrefixes, asOf: w.AsOf, queries: queries, omissions: omissions}
}
func deriveIdentity(r Result) string {
	wire := toWire(r)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func validDigest(v string) bool {
	if len(v) != 64 || v != strings.ToLower(v) || strings.Trim(v, "0") == "" {
		return false
	}
	d, e := hex.DecodeString(v)
	return e == nil && hex.EncodeToString(d) == v
}
func contains(v []string, t string) bool {
	for _, x := range v {
		if x == t {
			return true
		}
	}
	return false
}
func deriveRetrievalItemIdentity(item Item) string {
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Query    string `json:"query"`
		Record   string `json:"record"`
		Rank     uint8  `json:"rank"`
		Path     uint8  `json:"path"`
		Symbol   uint8  `json:"symbol"`
		Text     uint8  `json:"text"`
	}{"open-trestle/memory-retrieval-item", 1, item.queryIdentity, item.recordIdentity, item.rank, item.pathScore, item.symbolScore, item.textScore})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func deriveRetrievalIdentity(scopeIdentity string, query Query) string {
	identities := make([]string, len(query.items))
	for index, item := range query.items {
		identities[index] = item.identity
	}
	encoded, _ := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Query    string   `json:"query"`
		Revision uint64   `json:"revision"`
		Items    []string `json:"items"`
	}{"open-trestle/memory-lexical-retrieval", 1, scopeIdentity, query.identity, query.indexRevision, identities})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func writeRedacted(s fmt.State, v rune, p, d string) {
	x := p
	if v == 'q' {
		x = fmt.Sprintf("%q", p)
	} else if v == 'v' && s.Flag('#') {
		x = d
	}
	_, _ = s.Write([]byte(x))
}
