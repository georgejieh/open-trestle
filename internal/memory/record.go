package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxMemoryTextBytes        = 4 << 10
	maxMemorySymbols          = 32
	maxMemorySymbolBytes      = 256
	maxMemoryReferences       = 32
	maxMemoryReferenceBytes   = 128
	maxMemoryUnixMilliseconds = int64(253_402_300_799_999)
)

var (
	// ErrInvalidRecordKind identifies an unknown canonical or derived memory class.
	ErrInvalidRecordKind = errors.New("invalid memory record kind")
	// ErrInvalidTaintClass identifies an unknown content trust label.
	ErrInvalidTaintClass = errors.New("invalid memory taint class")
	// ErrInvalidMemoryPath identifies an unsafe or malformed record path.
	ErrInvalidMemoryPath = errors.New("invalid memory path")
	// ErrMemoryPathNotAuthorized identifies a path outside the record scope.
	ErrMemoryPathNotAuthorized = errors.New("memory path not authorized")
	// ErrInvalidMemoryText identifies empty, excessive, invalid, or hidden-control text.
	ErrInvalidMemoryText = errors.New("invalid memory text")
	// ErrInvalidMemorySymbol identifies a malformed retrieval symbol.
	ErrInvalidMemorySymbol = errors.New("invalid memory symbol")
	// ErrDuplicateMemorySymbol identifies a repeated symbol.
	ErrDuplicateMemorySymbol = errors.New("duplicate memory symbol")
	// ErrInvalidMemoryEvidence identifies a missing, excessive, or malformed evidence set.
	ErrInvalidMemoryEvidence = errors.New("invalid memory evidence")
	// ErrDuplicateMemoryReference identifies a repeated support, counterevidence, or evidence ID.
	ErrDuplicateMemoryReference = errors.New("duplicate memory reference")
	// ErrInvalidMemoryProducer identifies a malformed extractor, tool, model, or configuration identity.
	ErrInvalidMemoryProducer = errors.New("invalid memory producer")
	// ErrInvalidMemoryTime identifies an invalid observation, validity, or freshness interval.
	ErrInvalidMemoryTime = errors.New("invalid memory time")
	// ErrInvalidMemoryDerivation identifies missing support or illegal derivation fields.
	ErrInvalidMemoryDerivation = errors.New("invalid memory derivation")
	// ErrInvalidMemoryRecordIdentity identifies record content inconsistent with its identity.
	ErrInvalidMemoryRecordIdentity = errors.New("invalid memory record identity")
)

// RecordKind identifies the authority and lifecycle class of one memory record.
type RecordKind uint8

const (
	RecordCanonicalFact RecordKind = iota + 1
	RecordReviewEpisode
	RecordDerivedObservation
	RecordHumanFeedback
)

func (k RecordKind) String() string {
	switch k {
	case RecordCanonicalFact:
		return "canonical_fact"
	case RecordReviewEpisode:
		return "review_episode"
	case RecordDerivedObservation:
		return "derived_observation"
	case RecordHumanFeedback:
		return "human_feedback"
	default:
		return ""
	}
}

func ParseRecordKind(value string) (RecordKind, error) {
	for kind := RecordCanonicalFact; kind <= RecordHumanFeedback; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, ErrInvalidRecordKind
}

func (k RecordKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidRecordKind
	}
	return nil
}

// TaintClass identifies who controlled text before it entered memory.
type TaintClass uint8

const (
	TaintTrusted TaintClass = iota + 1
	TaintRepositoryControlled
	TaintUserControlled
	TaintExternalUnverified
)

func (t TaintClass) String() string {
	switch t {
	case TaintTrusted:
		return "trusted"
	case TaintRepositoryControlled:
		return "repository_controlled"
	case TaintUserControlled:
		return "user_controlled"
	case TaintExternalUnverified:
		return "external_unverified"
	default:
		return ""
	}
}

func ParseTaintClass(value string) (TaintClass, error) {
	for taint := TaintTrusted; taint <= TaintExternalUnverified; taint++ {
		if taint.String() == value {
			return taint, nil
		}
	}
	return 0, ErrInvalidTaintClass
}

func (t TaintClass) Validate() error {
	if t.String() == "" {
		return ErrInvalidTaintClass
	}
	return nil
}

// RecordInput supplies bounded source data for an immutable memory record.
type RecordInput struct {
	Kind                  RecordKind
	Taint                 TaintClass
	Path                  string
	Symbols               []string
	Text                  string
	EvidenceIDs           []string
	DerivedFromIDs        []string
	CounterEvidenceIDs    []string
	ProducerIdentity      string
	ObservedAt            time.Time
	ValidFrom             time.Time
	ValidUntil            time.Time
	StaleAfter            time.Time
	FreshnessIdentity     string
	ConfidenceBasisPoints uint16
}

// Record is an immutable, content-addressed, scope-bound memory item.
type Record struct {
	identity                   string
	scopeIdentity              string
	kind                       RecordKind
	taint                      TaintClass
	path                       string
	symbols                    []string
	text                       string
	evidenceIDs                []string
	derivedFromIDs             []string
	counterEvidenceIDs         []string
	producerIdentity           string
	observedAtUnixMilliseconds int64
	validFromUnixMilliseconds  int64
	validUntilUnixMilliseconds int64
	staleAfterUnixMilliseconds int64
	freshnessIdentity          string
	confidenceBasisPoints      uint16
}

// NewRecord validates, canonicalizes, and copies one memory record.
func NewRecord(scope Scope, input RecordInput) (Record, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, err
	}
	if !validRepositoryPath(input.Path, true) {
		return Record{}, ErrInvalidMemoryPath
	}
	if input.Path == "." {
		if !scopeAllowsRoot(scope) {
			return Record{}, ErrMemoryPathNotAuthorized
		}
	} else if !scope.AllowsPath(input.Path) {
		return Record{}, ErrMemoryPathNotAuthorized
	}
	symbols, err := canonicalSymbols(input.Symbols)
	if err != nil {
		return Record{}, err
	}
	evidenceIDs, err := canonicalReferences(input.EvidenceIDs)
	if err != nil {
		return Record{}, err
	}
	derivedFromIDs, err := canonicalReferences(input.DerivedFromIDs)
	if err != nil {
		return Record{}, err
	}
	counterEvidenceIDs, err := canonicalReferences(input.CounterEvidenceIDs)
	if err != nil {
		return Record{}, err
	}
	record := Record{
		scopeIdentity: scope.Identity(), kind: input.Kind, taint: input.Taint,
		path: strings.Clone(input.Path), symbols: symbols, text: strings.Clone(input.Text),
		evidenceIDs: evidenceIDs, derivedFromIDs: derivedFromIDs, counterEvidenceIDs: counterEvidenceIDs,
		producerIdentity:           strings.Clone(input.ProducerIdentity),
		freshnessIdentity:          strings.Clone(input.FreshnessIdentity),
		confidenceBasisPoints:      input.ConfidenceBasisPoints,
		observedAtUnixMilliseconds: input.ObservedAt.UnixMilli(),
		validFromUnixMilliseconds:  input.ValidFrom.UnixMilli(),
	}
	if !input.ValidUntil.IsZero() {
		record.validUntilUnixMilliseconds = input.ValidUntil.UnixMilli()
	}
	if !input.StaleAfter.IsZero() {
		record.staleAfterUnixMilliseconds = input.StaleAfter.UnixMilli()
	}
	if err := record.validateFields(); err != nil {
		return Record{}, err
	}
	record.identity = deriveRecordIdentity(record)
	return record, nil
}

func (r Record) Identity() string                  { return r.identity }
func (r Record) ScopeIdentity() string             { return r.scopeIdentity }
func (r Record) Kind() RecordKind                  { return r.kind }
func (r Record) Taint() TaintClass                 { return r.taint }
func (r Record) Path() string                      { return r.path }
func (r Record) Symbols() []string                 { return append([]string(nil), r.symbols...) }
func (r Record) Text() string                      { return r.text }
func (r Record) EvidenceIDs() []string             { return append([]string(nil), r.evidenceIDs...) }
func (r Record) DerivedFromIDs() []string          { return append([]string(nil), r.derivedFromIDs...) }
func (r Record) CounterEvidenceIDs() []string      { return append([]string(nil), r.counterEvidenceIDs...) }
func (r Record) ProducerIdentity() string          { return r.producerIdentity }
func (r Record) ObservedAtUnixMilliseconds() int64 { return r.observedAtUnixMilliseconds }
func (r Record) ValidFromUnixMilliseconds() int64  { return r.validFromUnixMilliseconds }
func (r Record) ValidUntilUnixMilliseconds() int64 { return r.validUntilUnixMilliseconds }
func (r Record) StaleAfterUnixMilliseconds() int64 { return r.staleAfterUnixMilliseconds }
func (r Record) FreshnessIdentity() string         { return r.freshnessIdentity }
func (r Record) ConfidenceBasisPoints() uint16     { return r.confidenceBasisPoints }
func (r Record) IsDerived() bool                   { return r.kind == RecordDerivedObservation }
func (r Record) String() string                    { return "memory record" }
func (r Record) GoString() string                  { return "memory.Record{<redacted>}" }
func (r Record) Format(state fmt.State, verb rune) {
	formatted := "memory record"
	if verb == 'q' {
		formatted = `"memory record"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "memory.Record{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// FreshAt reports whether the record was observed and remains valid and fresh at a time.
func (r Record) FreshAt(at time.Time) bool {
	if r.Validate() != nil {
		return false
	}
	value := at.UnixMilli()
	if value < r.observedAtUnixMilliseconds || value < r.validFromUnixMilliseconds {
		return false
	}
	if r.validUntilUnixMilliseconds != 0 && value >= r.validUntilUnixMilliseconds {
		return false
	}
	return r.staleAfterUnixMilliseconds == 0 || value < r.staleAfterUnixMilliseconds
}

// Validate verifies canonical sets, time semantics, derivation rules, and identity.
func (r Record) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if r.identity != deriveRecordIdentity(r) {
		return ErrInvalidMemoryRecordIdentity
	}
	return nil
}

func (r Record) validateFields() error {
	if !validDigest(r.scopeIdentity) {
		return ErrInvalidScopeIdentity
	}
	if err := r.kind.Validate(); err != nil {
		return err
	}
	if err := r.taint.Validate(); err != nil {
		return err
	}
	if !validRepositoryPath(r.path, true) {
		return ErrInvalidMemoryPath
	}
	if !validMemoryText(r.text) {
		return ErrInvalidMemoryText
	}
	if !validCanonicalSymbols(r.symbols) {
		return ErrInvalidMemorySymbol
	}
	if !validDigest(r.producerIdentity) {
		return ErrInvalidMemoryProducer
	}
	validObserved := validMemoryTimestamp(r.observedAtUnixMilliseconds)
	validFrom := validMemoryTimestamp(r.validFromUnixMilliseconds) && r.validFromUnixMilliseconds <= r.observedAtUnixMilliseconds
	validUntil := r.validUntilUnixMilliseconds == 0 || validMemoryTimestamp(r.validUntilUnixMilliseconds) && r.validUntilUnixMilliseconds > r.validFromUnixMilliseconds
	if !validObserved || !validFrom || !validUntil {
		return ErrInvalidMemoryTime
	}
	if !validCanonicalReferences(r.evidenceIDs) || !validCanonicalReferences(r.derivedFromIDs) || !validCanonicalReferences(r.counterEvidenceIDs) {
		return ErrInvalidMemoryEvidence
	}
	if r.kind == RecordDerivedObservation {
		validSupport := len(r.derivedFromIDs) >= 2 && len(r.derivedFromIDs) <= maxMemoryReferences
		validFreshness := validMemoryTimestamp(r.staleAfterUnixMilliseconds) && r.staleAfterUnixMilliseconds > r.observedAtUnixMilliseconds
		validWatermark := validDigest(r.freshnessIdentity)
		validConfidence := r.confidenceBasisPoints > 0 && r.confidenceBasisPoints <= 10_000
		if !validSupport || len(r.evidenceIDs) != 0 || !validFreshness || !validWatermark || !validConfidence || referenceSetsOverlap(r.derivedFromIDs, r.counterEvidenceIDs) {
			return ErrInvalidMemoryDerivation
		}
	} else {
		validEvidence := len(r.evidenceIDs) > 0 && len(r.evidenceIDs) <= maxMemoryReferences
		hasDerivation := len(r.derivedFromIDs) != 0 || len(r.counterEvidenceIDs) != 0 || r.staleAfterUnixMilliseconds != 0 || r.freshnessIdentity != "" || r.confidenceBasisPoints != 0
		if !validEvidence {
			return ErrInvalidMemoryEvidence
		}
		if hasDerivation {
			return ErrInvalidMemoryDerivation
		}
	}
	return nil
}

func scopeAllowsRoot(scope Scope) bool {
	for _, prefix := range scope.pathPrefixes {
		if prefix == "." {
			return true
		}
	}
	return false
}

func canonicalSymbols(values []string) ([]string, error) {
	if len(values) > maxMemorySymbols {
		return nil, ErrInvalidMemorySymbol
	}
	canonical := append([]string(nil), values...)
	for _, value := range canonical {
		if !validMemorySymbol(value) {
			return nil, ErrInvalidMemorySymbol
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, ErrDuplicateMemorySymbol
		}
	}
	for index := range canonical {
		canonical[index] = strings.Clone(canonical[index])
	}
	return canonical, nil
}

func validCanonicalSymbols(values []string) bool {
	if len(values) > maxMemorySymbols {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validMemorySymbol(value) || previous != "" && value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validMemorySymbol(value string) bool {
	if len(value) == 0 || len(value) > maxMemorySymbolBytes || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsSpace) < 0 && strings.IndexFunc(value, disallowedMemoryRune) < 0
}

func validMemoryText(value string) bool {
	return len(value) > 0 && len(value) <= maxMemoryTextBytes && utf8.ValidString(value) && strings.TrimSpace(value) != "" && strings.IndexFunc(value, disallowedMemoryRune) < 0
}

func disallowedMemoryRune(value rune) bool {
	if value == '\n' || value == '\t' {
		return false
	}
	return unicode.IsControl(value) || unicode.In(value, unicode.Cf)
}

func canonicalReferences(values []string) ([]string, error) {
	if len(values) > maxMemoryReferences {
		return nil, ErrInvalidMemoryEvidence
	}
	canonical := append([]string(nil), values...)
	for _, value := range canonical {
		if !validMemoryReference(value) {
			return nil, ErrInvalidMemoryEvidence
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, ErrDuplicateMemoryReference
		}
	}
	for index := range canonical {
		canonical[index] = strings.Clone(canonical[index])
	}
	return canonical, nil
}

func validCanonicalReferences(values []string) bool {
	if len(values) > maxMemoryReferences {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validMemoryReference(value) || previous != "" && value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validMemoryReference(value string) bool {
	if len(value) == 0 || len(value) > maxMemoryReferenceBytes || !isMemoryReferenceAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if isMemoryReferenceAlphaNumeric(character) || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func isMemoryReferenceAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validMemoryTimestamp(value int64) bool {
	return value > 0 && value <= maxMemoryUnixMilliseconds
}

func referenceSetsOverlap(left, right []string) bool {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		switch strings.Compare(left[leftIndex], right[rightIndex]) {
		case -1:
			leftIndex++
		case 1:
			rightIndex++
		default:
			return true
		}
	}
	return false
}

func deriveRecordIdentity(record Record) string {
	textDigest := sha256.Sum256([]byte(record.text))
	preimage := struct {
		Contract        string   `json:"contract"`
		Version         int      `json:"version"`
		Scope           string   `json:"scope"`
		Kind            string   `json:"kind"`
		Taint           string   `json:"taint"`
		Path            string   `json:"path"`
		Symbols         []string `json:"symbols"`
		TextDigest      string   `json:"text_digest"`
		TextBytes       int      `json:"text_bytes"`
		Evidence        []string `json:"evidence"`
		DerivedFrom     []string `json:"derived_from"`
		CounterEvidence []string `json:"counter_evidence"`
		Producer        string   `json:"producer"`
		ObservedAt      int64    `json:"observed_at"`
		ValidFrom       int64    `json:"valid_from"`
		ValidUntil      int64    `json:"valid_until"`
		StaleAfter      int64    `json:"stale_after"`
		Freshness       string   `json:"freshness"`
		Confidence      uint16   `json:"confidence"`
	}{
		Contract: "open-trestle/memory-record", Version: 1,
		Scope: record.scopeIdentity, Kind: record.kind.String(), Taint: record.taint.String(),
		Path: record.path, Symbols: record.symbols,
		TextDigest: hex.EncodeToString(textDigest[:]), TextBytes: len(record.text),
		Evidence: record.evidenceIDs, DerivedFrom: record.derivedFromIDs,
		CounterEvidence: record.counterEvidenceIDs, Producer: record.producerIdentity,
		ObservedAt: record.observedAtUnixMilliseconds, ValidFrom: record.validFromUnixMilliseconds,
		ValidUntil: record.validUntilUnixMilliseconds, StaleAfter: record.staleAfterUnixMilliseconds,
		Freshness: record.freshnessIdentity, Confidence: record.confidenceBasisPoints,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func writeRedactedMemoryFormat(state fmt.State, verb rune, plain, goSyntax string) {
	formatted := plain
	if verb == 'q' {
		formatted = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		formatted = goSyntax
	}
	_, _ = state.Write([]byte(formatted))
}
