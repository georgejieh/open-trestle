package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxLexicalRecordsPerScope = 10_000
	maxLexicalRecordsTotal    = 100_000
)

var (
	// ErrInvalidMemoryIndex identifies a missing index implementation.
	ErrInvalidMemoryIndex = errors.New("invalid memory index")
	// ErrInvalidMemoryContext identifies a nil operation context.
	ErrInvalidMemoryContext = errors.New("invalid memory context")
	// ErrMemoryContextDone identifies cancellation before an index operation completed.
	ErrMemoryContextDone = errors.New("memory context done")
	// ErrMemoryRecordScopeMismatch identifies a record from another hard partition.
	ErrMemoryRecordScopeMismatch = errors.New("memory record scope mismatch")
	// ErrMemoryQueryScopeMismatch identifies a query from another hard partition.
	ErrMemoryQueryScopeMismatch = errors.New("memory query scope mismatch")
	// ErrMemoryIndexCapacity identifies a bounded index that cannot accept another record.
	ErrMemoryIndexCapacity = errors.New("memory index capacity exceeded")
	// ErrMemoryIndexRevisionOverflow identifies an exhausted revision counter.
	ErrMemoryIndexRevisionOverflow = errors.New("memory index revision overflow")
	// ErrInvalidRetrievalItem identifies inconsistent score, rank, record, or query fields.
	ErrInvalidRetrievalItem = errors.New("invalid memory retrieval item")
	// ErrInvalidRetrievalItemIdentity identifies item content inconsistent with its identity.
	ErrInvalidRetrievalItemIdentity = errors.New("invalid memory retrieval item identity")
	// ErrInvalidLexicalRetrieval identifies a malformed result collection.
	ErrInvalidLexicalRetrieval = errors.New("invalid lexical memory retrieval")
	// ErrInvalidLexicalRetrievalIdentity identifies retrieval content inconsistent with its identity.
	ErrInvalidLexicalRetrievalIdentity = errors.New("invalid lexical memory retrieval identity")
	// ErrInvalidMemoryDeletionReceipt identifies inconsistent deletion accounting.
	ErrInvalidMemoryDeletionReceipt = errors.New("invalid memory deletion receipt")
	// ErrInvalidMemoryDeletionReceiptIdentity identifies deletion content inconsistent with its identity.
	ErrInvalidMemoryDeletionReceiptIdentity = errors.New("invalid memory deletion receipt identity")
)

// LexicalIndex is a rebuildable in-memory path, symbol, and text index with hard scope partitions.
type LexicalIndex struct {
	mu        sync.RWMutex
	records   map[string]map[string]Record
	revisions map[string]uint64
	total     int
}

// NewLexicalIndex creates an empty concurrency-safe derived index.
func NewLexicalIndex() *LexicalIndex {
	return &LexicalIndex{records: make(map[string]map[string]Record), revisions: make(map[string]uint64)}
}

// Add idempotently indexes one immutable record inside its exact authorization scope.
func (i *LexicalIndex) Add(ctx context.Context, scope Scope, record Record) (uint64, bool, error) {
	if i == nil {
		return 0, false, ErrInvalidMemoryIndex
	}
	if err := validateMemoryContext(ctx); err != nil {
		return 0, false, err
	}
	if err := scope.Validate(); err != nil {
		return 0, false, err
	}
	if err := record.Validate(); err != nil {
		return 0, false, err
	}
	if record.ScopeIdentity() != scope.Identity() {
		return 0, false, ErrMemoryRecordScopeMismatch
	}
	if record.Path() == "." {
		if !scopeAllowsRoot(scope) {
			return 0, false, ErrMemoryPathNotAuthorized
		}
	} else if !scope.AllowsPath(record.Path()) {
		return 0, false, ErrMemoryPathNotAuthorized
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := memoryContextDone(ctx); err != nil {
		return 0, false, err
	}
	if i.records == nil {
		i.records = make(map[string]map[string]Record)
		i.revisions = make(map[string]uint64)
	}
	partition := i.records[scope.Identity()]
	if existing, exists := partition[record.Identity()]; exists {
		if existing.Identity() != record.Identity() {
			return 0, false, ErrInvalidMemoryRecordIdentity
		}
		return i.revisions[scope.Identity()], false, nil
	}
	if len(partition) >= maxLexicalRecordsPerScope || i.total >= maxLexicalRecordsTotal {
		return 0, false, ErrMemoryIndexCapacity
	}
	if i.revisions[scope.Identity()] == math.MaxUint64 {
		return 0, false, ErrMemoryIndexRevisionOverflow
	}
	if partition == nil {
		partition = make(map[string]Record)
		i.records[scope.Identity()] = partition
	}
	partition[record.Identity()] = cloneRecord(record)
	i.total++
	i.revisions[scope.Identity()]++
	return i.revisions[scope.Identity()], true, nil
}

// Search filters by the exact scope partition before scoring any record.
func (i *LexicalIndex) Search(ctx context.Context, scope Scope, query LexicalQuery) (LexicalRetrieval, error) {
	if i == nil {
		return LexicalRetrieval{}, ErrInvalidMemoryIndex
	}
	if err := validateMemoryContext(ctx); err != nil {
		return LexicalRetrieval{}, err
	}
	if err := scope.Validate(); err != nil {
		return LexicalRetrieval{}, err
	}
	if err := query.Validate(); err != nil {
		return LexicalRetrieval{}, err
	}
	if query.ScopeIdentity() != scope.Identity() {
		return LexicalRetrieval{}, ErrMemoryQueryScopeMismatch
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if err := memoryContextDone(ctx); err != nil {
		return LexicalRetrieval{}, err
	}
	partition := i.records[scope.Identity()]
	items := make([]RetrievalItem, 0, len(partition))
	asOf := time.UnixMilli(query.AsOfUnixMilliseconds())
	for _, record := range partition {
		if !record.FreshAt(asOf) {
			continue
		}
		pathScore, symbolScore, textScore := scoreMemoryRecord(query, record)
		if pathScore == 0 && symbolScore == 0 && textScore == 0 {
			continue
		}
		items = append(items, RetrievalItem{queryIdentity: query.Identity(), record: cloneRecord(record), pathScore: pathScore, symbolScore: symbolScore, textScore: textScore})
	}
	sort.Slice(items, func(left, right int) bool { return retrievalItemLess(items[left], items[right]) })
	if len(items) > int(query.Limit()) {
		items = items[:query.Limit()]
	}
	for index := range items {
		items[index].rank = uint8(index + 1)
		items[index].identity = deriveRetrievalItemIdentity(items[index])
	}
	if len(items) == 0 {
		items = nil
	}
	retrieval := LexicalRetrieval{scopeIdentity: scope.Identity(), query: query, indexRevision: i.revisions[scope.Identity()], items: items}
	retrieval.identity = deriveLexicalRetrievalIdentity(retrieval)
	if err := retrieval.Validate(); err != nil {
		return LexicalRetrieval{}, err
	}
	return retrieval, nil
}

// RecordCount returns the number of records in one valid scope partition.
func (i *LexicalIndex) RecordCount(scope Scope) int {
	if i == nil || scope.Validate() != nil {
		return 0
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.records[scope.Identity()])
}

// DeleteScope physically removes one derived partition and emits a verifiable receipt.
func (i *LexicalIndex) DeleteScope(ctx context.Context, scope Scope, completedAt time.Time) (DeletionReceipt, error) {
	if i == nil {
		return DeletionReceipt{}, ErrInvalidMemoryIndex
	}
	if err := validateMemoryContext(ctx); err != nil {
		return DeletionReceipt{}, err
	}
	if err := scope.Validate(); err != nil {
		return DeletionReceipt{}, err
	}
	completed := completedAt.UnixMilli()
	if !validMemoryTimestamp(completed) {
		return DeletionReceipt{}, ErrInvalidMemoryTime
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := memoryContextDone(ctx); err != nil {
		return DeletionReceipt{}, err
	}
	previous := i.revisions[scope.Identity()]
	if previous == math.MaxUint64 {
		return DeletionReceipt{}, ErrMemoryIndexRevisionOverflow
	}
	deleted := len(i.records[scope.Identity()])
	delete(i.records, scope.Identity())
	i.total -= deleted
	i.revisions[scope.Identity()] = previous + 1
	receipt := DeletionReceipt{
		scopeIdentity: scope.Identity(), previousRevision: previous, newRevision: previous + 1,
		deletedRecordCount: uint32(deleted), completedAtUnixMilliseconds: completed,
	}
	receipt.identity = deriveDeletionReceiptIdentity(receipt)
	return receipt, nil
}

// RetrievalItem contains explicit lexical score components for one authorized record.
type RetrievalItem struct {
	identity      string
	queryIdentity string
	record        Record
	rank          uint8
	pathScore     uint8
	symbolScore   uint8
	textScore     uint8
}

func (i RetrievalItem) Identity() string      { return i.identity }
func (i RetrievalItem) QueryIdentity() string { return i.queryIdentity }
func (i RetrievalItem) Record() Record        { return cloneRecord(i.record) }
func (i RetrievalItem) Rank() uint8           { return i.rank }
func (i RetrievalItem) PathScore() uint8      { return i.pathScore }
func (i RetrievalItem) SymbolScore() uint8    { return i.symbolScore }
func (i RetrievalItem) TextScore() uint8      { return i.textScore }
func (i RetrievalItem) String() string        { return "memory retrieval item" }
func (i RetrievalItem) GoString() string      { return "memory.RetrievalItem{<redacted>}" }
func (i RetrievalItem) Format(state fmt.State, verb rune) {
	writeRedactedMemoryFormat(state, verb, "memory retrieval item", "memory.RetrievalItem{<redacted>}")
}

// Validate verifies one item's record, score, rank, and content identity.
func (i RetrievalItem) Validate() error {
	if !validDigest(i.queryIdentity) || i.record.Validate() != nil || i.rank == 0 || i.rank > maxLexicalResults || i.pathScore == 0 && i.symbolScore == 0 && i.textScore == 0 {
		return ErrInvalidRetrievalItem
	}
	if i.identity != deriveRetrievalItemIdentity(i) {
		return ErrInvalidRetrievalItemIdentity
	}
	return nil
}

// RetrievalItemInput supplies one ranked record and its exact lexical scores for reconstruction.
type RetrievalItemInput struct {
	Record      Record
	Rank        uint8
	PathScore   uint8
	SymbolScore uint8
	TextScore   uint8
}

// NewLexicalRetrieval reconstructs a canonical retrieval from persisted bounded fields.
func NewLexicalRetrieval(scope Scope, query LexicalQuery, indexRevision uint64, inputs []RetrievalItemInput) (LexicalRetrieval, error) {
	if scope.Validate() != nil || query.Validate() != nil || query.ScopeIdentity() != scope.Identity() || len(inputs) > int(query.Limit()) {
		return LexicalRetrieval{}, ErrInvalidLexicalRetrieval
	}
	items := make([]RetrievalItem, len(inputs))
	for index, input := range inputs {
		items[index] = RetrievalItem{queryIdentity: query.Identity(), record: cloneRecord(input.Record), rank: input.Rank, pathScore: input.PathScore, symbolScore: input.SymbolScore, textScore: input.TextScore}
		items[index].identity = deriveRetrievalItemIdentity(items[index])
	}
	if len(items) == 0 {
		items = nil
	}
	retrieval := LexicalRetrieval{scopeIdentity: scope.Identity(), query: query, indexRevision: indexRevision, items: items}
	retrieval.identity = deriveLexicalRetrievalIdentity(retrieval)
	if err := retrieval.Validate(); err != nil {
		return LexicalRetrieval{}, err
	}
	return retrieval, nil
}

// LexicalRetrieval is a content-addressed result from one scope partition revision.
type LexicalRetrieval struct {
	identity      string
	scopeIdentity string
	query         LexicalQuery
	indexRevision uint64
	items         []RetrievalItem
}

func (r LexicalRetrieval) Identity() string       { return r.identity }
func (r LexicalRetrieval) ScopeIdentity() string  { return r.scopeIdentity }
func (r LexicalRetrieval) Query() LexicalQuery    { return r.query }
func (r LexicalRetrieval) IndexRevision() uint64  { return r.indexRevision }
func (r LexicalRetrieval) Items() []RetrievalItem { return append([]RetrievalItem(nil), r.items...) }
func (r LexicalRetrieval) String() string         { return "memory lexical retrieval" }
func (r LexicalRetrieval) GoString() string       { return "memory.LexicalRetrieval{<redacted>}" }
func (r LexicalRetrieval) Format(state fmt.State, verb rune) {
	writeRedactedMemoryFormat(state, verb, "memory lexical retrieval", "memory.LexicalRetrieval{<redacted>}")
}

// Validate verifies scope filtering, scores, ordering, freshness, and content identity.
func (r LexicalRetrieval) Validate() error {
	if !validDigest(r.scopeIdentity) || r.query.Validate() != nil || r.query.ScopeIdentity() != r.scopeIdentity || len(r.items) > int(r.query.Limit()) || len(r.items) > 0 && r.indexRevision == 0 {
		return ErrInvalidLexicalRetrieval
	}
	asOf := time.UnixMilli(r.query.AsOfUnixMilliseconds())
	seenRecords := make(map[string]struct{}, len(r.items))
	for index, item := range r.items {
		if err := item.Validate(); err != nil {
			return err
		}
		pathScore, symbolScore, textScore := scoreMemoryRecord(r.query, item.record)
		validBinding := item.queryIdentity == r.query.Identity() && item.record.ScopeIdentity() == r.scopeIdentity
		validScore := item.pathScore == pathScore && item.symbolScore == symbolScore && item.textScore == textScore
		if !validBinding || !validScore || !item.record.FreshAt(asOf) || item.rank != uint8(index+1) {
			return ErrInvalidLexicalRetrieval
		}
		if _, exists := seenRecords[item.record.Identity()]; exists {
			return ErrInvalidLexicalRetrieval
		}
		seenRecords[item.record.Identity()] = struct{}{}
		if index > 0 && retrievalItemLess(item, r.items[index-1]) {
			return ErrInvalidLexicalRetrieval
		}
	}
	if r.identity != deriveLexicalRetrievalIdentity(r) {
		return ErrInvalidLexicalRetrievalIdentity
	}
	return nil
}

// DeletionReceipt records a completed physical removal from the rebuildable index.
type DeletionReceipt struct {
	identity                    string
	scopeIdentity               string
	previousRevision            uint64
	newRevision                 uint64
	deletedRecordCount          uint32
	completedAtUnixMilliseconds int64
}

func (r DeletionReceipt) Identity() string                   { return r.identity }
func (r DeletionReceipt) ScopeIdentity() string              { return r.scopeIdentity }
func (r DeletionReceipt) PreviousRevision() uint64           { return r.previousRevision }
func (r DeletionReceipt) NewRevision() uint64                { return r.newRevision }
func (r DeletionReceipt) DeletedRecordCount() uint32         { return r.deletedRecordCount }
func (r DeletionReceipt) CompletedAtUnixMilliseconds() int64 { return r.completedAtUnixMilliseconds }
func (r DeletionReceipt) String() string                     { return "memory deletion receipt" }
func (r DeletionReceipt) GoString() string                   { return "memory.DeletionReceipt{<redacted>}" }
func (r DeletionReceipt) Format(state fmt.State, verb rune) {
	writeRedactedMemoryFormat(state, verb, "memory deletion receipt", "memory.DeletionReceipt{<redacted>}")
}

// Validate verifies revision arithmetic, time, scope, and content identity.
func (r DeletionReceipt) Validate() error {
	if !validDigest(r.scopeIdentity) || r.previousRevision == math.MaxUint64 || r.newRevision != r.previousRevision+1 || !validMemoryTimestamp(r.completedAtUnixMilliseconds) {
		return ErrInvalidMemoryDeletionReceipt
	}
	if r.identity != deriveDeletionReceiptIdentity(r) {
		return ErrInvalidMemoryDeletionReceiptIdentity
	}
	return nil
}

func cloneRecord(record Record) Record {
	record.symbols = append([]string(nil), record.symbols...)
	record.evidenceIDs = append([]string(nil), record.evidenceIDs...)
	record.derivedFromIDs = append([]string(nil), record.derivedFromIDs...)
	record.counterEvidenceIDs = append([]string(nil), record.counterEvidenceIDs...)
	return record
}

func scoreMemoryRecord(query LexicalQuery, record Record) (uint8, uint8, uint8) {
	var pathScore uint8
	if query.Path() != "" && query.Path() == record.Path() {
		pathScore = 1
	}
	symbols := make(map[string]struct{}, len(record.symbols))
	for _, symbol := range record.symbols {
		symbols[symbol] = struct{}{}
	}
	var symbolScore uint8
	for _, symbol := range query.symbols {
		if _, exists := symbols[symbol]; exists {
			symbolScore++
		}
	}
	text := strings.ToLower(record.text)
	var textScore uint8
	for _, term := range query.terms {
		if strings.Contains(text, term) {
			textScore++
		}
	}
	return pathScore, symbolScore, textScore
}

func retrievalItemLess(left, right RetrievalItem) bool {
	if left.pathScore != right.pathScore {
		return left.pathScore > right.pathScore
	}
	if left.symbolScore != right.symbolScore {
		return left.symbolScore > right.symbolScore
	}
	if left.textScore != right.textScore {
		return left.textScore > right.textScore
	}
	if left.record.observedAtUnixMilliseconds != right.record.observedAtUnixMilliseconds {
		return left.record.observedAtUnixMilliseconds > right.record.observedAtUnixMilliseconds
	}
	return left.record.Identity() < right.record.Identity()
}

func deriveRetrievalItemIdentity(item RetrievalItem) string {
	preimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Query    string `json:"query"`
		Record   string `json:"record"`
		Rank     uint8  `json:"rank"`
		Path     uint8  `json:"path"`
		Symbol   uint8  `json:"symbol"`
		Text     uint8  `json:"text"`
	}{
		Contract: "open-trestle/memory-retrieval-item", Version: 1,
		Query: item.queryIdentity, Record: item.record.Identity(), Rank: item.rank,
		Path: item.pathScore, Symbol: item.symbolScore, Text: item.textScore,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveLexicalRetrievalIdentity(retrieval LexicalRetrieval) string {
	identities := make([]string, len(retrieval.items))
	for index, item := range retrieval.items {
		identities[index] = item.Identity()
	}
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Query    string   `json:"query"`
		Revision uint64   `json:"revision"`
		Items    []string `json:"items"`
	}{
		Contract: "open-trestle/memory-lexical-retrieval", Version: 1,
		Scope: retrieval.scopeIdentity, Query: retrieval.query.Identity(),
		Revision: retrieval.indexRevision, Items: identities,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveDeletionReceiptIdentity(receipt DeletionReceipt) string {
	preimage := struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Scope     string `json:"scope"`
		Previous  uint64 `json:"previous"`
		New       uint64 `json:"new"`
		Deleted   uint32 `json:"deleted"`
		Completed int64  `json:"completed"`
	}{
		Contract: "open-trestle/memory-deletion-receipt", Version: 1,
		Scope: receipt.scopeIdentity, Previous: receipt.previousRevision, New: receipt.newRevision,
		Deleted: receipt.deletedRecordCount, Completed: receipt.completedAtUnixMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateMemoryContext(ctx context.Context) error {
	if isNilMemoryInterface(ctx) {
		return ErrInvalidMemoryContext
	}
	return memoryContextDone(ctx)
}

func memoryContextDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrMemoryContextDone, err)
	}
	return nil
}

func isNilMemoryInterface(candidate any) bool {
	if candidate == nil {
		return true
	}
	value := reflect.ValueOf(candidate)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
