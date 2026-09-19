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
	maxLexicalQueryTerms      = 16
	maxLexicalQuerySymbols    = 16
	maxLexicalQueryValueBytes = 256
	maxLexicalResults         = 50
)

var (
	// ErrEmptyLexicalQuery identifies a query without a path, term, or symbol.
	ErrEmptyLexicalQuery = errors.New("empty lexical memory query")
	// ErrInvalidLexicalQueryTerm identifies excessive or unsafe query text.
	ErrInvalidLexicalQueryTerm = errors.New("invalid lexical memory query term")
	// ErrInvalidLexicalQueryLimit identifies an unbounded or excessive result limit.
	ErrInvalidLexicalQueryLimit = errors.New("invalid lexical memory query limit")
	// ErrInvalidLexicalQueryIdentity identifies query content inconsistent with its identity.
	ErrInvalidLexicalQueryIdentity = errors.New("invalid lexical memory query identity")
)

// LexicalQuery is an immutable scope-bound path, symbol, and text lookup.
type LexicalQuery struct {
	identity             string
	scopeIdentity        string
	path                 string
	terms                []string
	symbols              []string
	asOfUnixMilliseconds int64
	limit                uint8
}

// NewLexicalQuery canonicalizes one bounded query after checking its path authorization.
func NewLexicalQuery(scope Scope, queryPath string, terms, symbols []string, asOf time.Time, limit uint8) (LexicalQuery, error) {
	if err := scope.Validate(); err != nil {
		return LexicalQuery{}, err
	}
	if queryPath != "" {
		if !validRepositoryPath(queryPath, false) {
			return LexicalQuery{}, ErrInvalidMemoryPath
		}
		if !scope.AllowsPath(queryPath) {
			return LexicalQuery{}, ErrMemoryPathNotAuthorized
		}
	}
	canonicalTerms, err := canonicalQueryTerms(terms, false)
	if err != nil {
		return LexicalQuery{}, err
	}
	canonicalSymbols, err := canonicalQueryTerms(symbols, true)
	if err != nil {
		return LexicalQuery{}, err
	}
	query := LexicalQuery{
		scopeIdentity: scope.Identity(), path: strings.Clone(queryPath), terms: canonicalTerms,
		symbols: canonicalSymbols, asOfUnixMilliseconds: asOf.UnixMilli(), limit: limit,
	}
	if err := query.validateFields(); err != nil {
		return LexicalQuery{}, err
	}
	query.identity = deriveLexicalQueryIdentity(query)
	return query, nil
}

func (q LexicalQuery) Identity() string            { return q.identity }
func (q LexicalQuery) ScopeIdentity() string       { return q.scopeIdentity }
func (q LexicalQuery) Path() string                { return q.path }
func (q LexicalQuery) Terms() []string             { return append([]string(nil), q.terms...) }
func (q LexicalQuery) Symbols() []string           { return append([]string(nil), q.symbols...) }
func (q LexicalQuery) AsOfUnixMilliseconds() int64 { return q.asOfUnixMilliseconds }
func (q LexicalQuery) Limit() uint8                { return q.limit }
func (q LexicalQuery) String() string              { return "memory lexical query" }
func (q LexicalQuery) GoString() string            { return "memory.LexicalQuery{<redacted>}" }
func (q LexicalQuery) Format(state fmt.State, verb rune) {
	writeRedactedMemoryFormat(state, verb, "memory lexical query", "memory.LexicalQuery{<redacted>}")
}

// Validate verifies canonical terms, bounds, scope, and content identity.
func (q LexicalQuery) Validate() error {
	if err := q.validateFields(); err != nil {
		return err
	}
	if q.identity != deriveLexicalQueryIdentity(q) {
		return ErrInvalidLexicalQueryIdentity
	}
	return nil
}

func (q LexicalQuery) validateFields() error {
	if !validDigest(q.scopeIdentity) {
		return ErrInvalidScopeIdentity
	}
	if q.path != "" && !validRepositoryPath(q.path, false) {
		return ErrInvalidMemoryPath
	}
	if len(q.path) == 0 && len(q.terms) == 0 && len(q.symbols) == 0 {
		return ErrEmptyLexicalQuery
	}
	if !validCanonicalQueryTerms(q.terms, false) || !validCanonicalQueryTerms(q.symbols, true) {
		return ErrInvalidLexicalQueryTerm
	}
	if !validMemoryTimestamp(q.asOfUnixMilliseconds) {
		return ErrInvalidMemoryTime
	}
	if q.limit == 0 || q.limit > maxLexicalResults {
		return ErrInvalidLexicalQueryLimit
	}
	return nil
}

func canonicalQueryTerms(values []string, preserveCase bool) ([]string, error) {
	limit := maxLexicalQueryTerms
	if preserveCase {
		limit = maxLexicalQuerySymbols
	}
	if len(values) > limit {
		return nil, ErrInvalidLexicalQueryTerm
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !preserveCase {
			value = strings.ToLower(value)
		}
		if !validQueryValue(value) {
			return nil, ErrInvalidLexicalQueryTerm
		}
		set[value] = struct{}{}
	}
	canonical := make([]string, 0, len(set))
	for value := range set {
		canonical = append(canonical, strings.Clone(value))
	}
	sort.Strings(canonical)
	return canonical, nil
}

func validCanonicalQueryTerms(values []string, preserveCase bool) bool {
	limit := maxLexicalQueryTerms
	if preserveCase {
		limit = maxLexicalQuerySymbols
	}
	if len(values) > limit {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validQueryValue(value) || !preserveCase && value != strings.ToLower(value) || previous != "" && value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validQueryValue(value string) bool {
	if len(value) == 0 || len(value) > maxLexicalQueryValueBytes || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsSpace) < 0 && strings.IndexFunc(value, disallowedMemoryRune) < 0
}

func deriveLexicalQueryIdentity(query LexicalQuery) string {
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Path     string   `json:"path"`
		Terms    []string `json:"terms"`
		Symbols  []string `json:"symbols"`
		AsOf     int64    `json:"as_of"`
		Limit    uint8    `json:"limit"`
	}{
		Contract: "open-trestle/memory-lexical-query", Version: 1,
		Scope: query.scopeIdentity, Path: query.path, Terms: query.terms,
		Symbols: query.symbols, AsOf: query.asOfUnixMilliseconds, Limit: query.limit,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
