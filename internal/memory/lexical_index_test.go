package memory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func memoryRecord(t *testing.T, scope Scope, kind RecordKind, path string, symbols []string, text string, marker byte, observed time.Time, staleAfter time.Time) Record {
	t.Helper()
	input := canonicalRecordInput()
	input.Kind = kind
	input.Path = path
	input.Symbols = symbols
	input.Text = text
	input.ProducerIdentity = strings.Repeat(string(marker), 64)
	input.ObservedAt = observed
	input.ValidFrom = observed
	if kind == RecordDerivedObservation {
		input.EvidenceIDs = nil
		input.DerivedFromIDs = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
		input.StaleAfter = staleAfter
		input.FreshnessIdentity = strings.Repeat("e", 64)
		input.ConfidenceBasisPoints = 7_500
	}
	record, err := NewRecord(scope, input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestLexicalIndexRanksExplicitScoreComponents(t *testing.T) {
	scope := testScope(t)
	index := NewLexicalIndex()
	observed := time.UnixMilli(1_700_000_000_000)
	exact := memoryRecord(t, scope, RecordCanonicalFact, "internal/review/candidate.go", []string{"ParseCandidateBatch"}, "Exact evidence binding prevents a missing citation.", 'c', observed, time.Time{})
	textOnly := memoryRecord(t, scope, RecordHumanFeedback, "internal/review/other.go", nil, "A missing evidence citation was rejected.", 'd', observed.Add(time.Millisecond), time.Time{})
	for _, record := range []Record{textOnly, exact} {
		if _, added, err := index.Add(context.Background(), scope, record); err != nil || !added {
			t.Fatalf("Add() = (%t, %v)", added, err)
		}
	}
	query, err := NewLexicalQuery(scope, "internal/review/candidate.go", []string{"missing", "evidence"}, []string{"ParseCandidateBatch"}, observed.Add(time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := index.Search(context.Background(), scope, query)
	if err != nil {
		t.Fatal(err)
	}
	items := retrieval.Items()
	if retrieval.Identity() == "" || retrieval.ScopeIdentity() != scope.Identity() || retrieval.Query().Identity() != query.Identity() || retrieval.IndexRevision() != 2 || len(items) != 2 || retrieval.Validate() != nil {
		t.Fatalf("retrieval did not round trip: %#v", retrieval)
	}
	if items[0].Record().Identity() != exact.Identity() || items[0].PathScore() == 0 || items[0].SymbolScore() == 0 || items[0].TextScore() != 2 || items[0].Rank() != 1 || items[0].Validate() != nil {
		t.Fatalf("exact item score = %#v", items[0])
	}
	if items[1].Record().Identity() != textOnly.Identity() || items[1].PathScore() != 0 || items[1].SymbolScore() != 0 || items[1].TextScore() != 2 {
		t.Fatalf("text item score = %#v", items[1])
	}
	items[0] = RetrievalItem{}
	if len(retrieval.Items()) != 2 {
		t.Fatal("retrieval exposed mutable items")
	}
	if fmt.Sprint(retrieval) != "memory lexical retrieval" || strings.Contains(fmt.Sprintf("%v", retrieval), "missing") {
		t.Fatalf("retrieval formatting leaked: %v", retrieval)
	}
}

func TestLexicalIndexFiltersScopeBeforeScoring(t *testing.T) {
	firstScope := testScope(t)
	secondScope, _ := NewScope("tenant-2", "repo-1", "actor-1", RefVisibilityExact, strings.Repeat("a", 64), []string{"internal/review", "cmd"})
	index := NewLexicalIndex()
	observed := time.UnixMilli(1_700_000_000_000)
	first := memoryRecord(t, firstScope, RecordCanonicalFact, "internal/review/a.go", nil, "ordinary record", 'c', observed, time.Time{})
	canary := memoryRecord(t, secondScope, RecordCanonicalFact, "internal/review/a.go", nil, "DISTINCTIVE_CROSS_TENANT_CANARY", 'd', observed, time.Time{})
	_, _, _ = index.Add(context.Background(), firstScope, first)
	_, _, _ = index.Add(context.Background(), secondScope, canary)
	query, _ := NewLexicalQuery(firstScope, "", []string{"distinctive_cross_tenant_canary"}, nil, observed.Add(time.Hour), 10)
	retrieval, err := index.Search(context.Background(), firstScope, query)
	if err != nil || len(retrieval.Items()) != 0 {
		t.Fatalf("cross-tenant search = (%#v, %v)", retrieval, err)
	}
	if cross, err := index.Search(context.Background(), secondScope, query); !errors.Is(err, ErrMemoryQueryScopeMismatch) || cross.Identity() != "" {
		t.Fatalf("cross-wired query = (%#v, %v)", cross, err)
	}
}

func TestLexicalIndexExcludesStaleAndOutOfValidityRecords(t *testing.T) {
	scope := testScope(t)
	index := NewLexicalIndex()
	observed := time.UnixMilli(1_700_000_000_000)
	stale := memoryRecord(t, scope, RecordDerivedObservation, "internal/review/a.go", nil, "recurring null issue", 'c', observed, observed.Add(time.Hour))
	_, _, _ = index.Add(context.Background(), scope, stale)
	freshQuery, _ := NewLexicalQuery(scope, "", []string{"recurring"}, nil, observed.Add(time.Minute), 10)
	fresh, _ := index.Search(context.Background(), scope, freshQuery)
	if len(fresh.Items()) != 1 || !fresh.Items()[0].Record().IsDerived() {
		t.Fatalf("fresh result = %#v", fresh)
	}
	staleQuery, _ := NewLexicalQuery(scope, "", []string{"recurring"}, nil, observed.Add(2*time.Hour), 10)
	expired, _ := index.Search(context.Background(), scope, staleQuery)
	if len(expired.Items()) != 0 {
		t.Fatalf("stale result = %#v", expired)
	}
}

func TestLexicalQueryIsCanonicalAndScopeBound(t *testing.T) {
	scope := testScope(t)
	when := time.UnixMilli(1_700_000_000_000)
	query, err := NewLexicalQuery(scope, "internal/review/candidate.go", []string{"Evidence", "missing", "evidence"}, []string{"B", "A"}, when, 5)
	if err != nil {
		t.Fatal(err)
	}
	if query.Identity() == "" || !reflect.DeepEqual(query.Terms(), []string{"evidence", "missing"}) || !reflect.DeepEqual(query.Symbols(), []string{"A", "B"}) || query.Limit() != 5 || query.Validate() != nil {
		t.Fatalf("query did not canonicalize: %#v", query)
	}
	terms := query.Terms()
	terms[0] = "changed"
	if query.Terms()[0] != "evidence" {
		t.Fatal("query exposed mutable terms")
	}
	if _, err := NewLexicalQuery(scope, "docs/outside.md", []string{"x"}, nil, when, 1); !errors.Is(err, ErrMemoryPathNotAuthorized) {
		t.Fatalf("unauthorized query path = %v", err)
	}
	if _, err := NewLexicalQuery(scope, "", nil, nil, when, 1); !errors.Is(err, ErrEmptyLexicalQuery) {
		t.Fatalf("empty query = %v", err)
	}
	forged := query
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidLexicalQueryIdentity) {
		t.Fatal("forged query accepted")
	}
}

func TestLexicalIndexAddIsIdempotentAndConcurrentSafe(t *testing.T) {
	scope := testScope(t)
	index := NewLexicalIndex()
	record := memoryRecord(t, scope, RecordCanonicalFact, "internal/review/a.go", nil, "record", 'c', time.UnixMilli(1), time.Time{})
	var wait sync.WaitGroup
	added := make(chan bool, 2)
	errorsSeen := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasAdded, err := index.Add(context.Background(), scope, record)
			added <- wasAdded
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(added)
	close(errorsSeen)
	count := 0
	for value := range added {
		if value {
			count++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 || index.RecordCount(scope) != 1 {
		t.Fatalf("added=%d records=%d", count, index.RecordCount(scope))
	}
	if revision, wasAdded, err := index.Add(context.Background(), scope, record); err != nil || wasAdded || revision != 1 {
		t.Fatalf("idempotent Add() = (%d,%t,%v)", revision, wasAdded, err)
	}
}

func TestLexicalIndexDeletionPhysicallyRemovesPartition(t *testing.T) {
	scope := testScope(t)
	index := NewLexicalIndex()
	record := memoryRecord(t, scope, RecordCanonicalFact, "internal/review/a.go", nil, "deletion canary", 'c', time.UnixMilli(1), time.Time{})
	_, _, _ = index.Add(context.Background(), scope, record)
	receipt, err := index.DeleteScope(context.Background(), scope, time.UnixMilli(2))
	if err != nil || receipt.Identity() == "" || receipt.ScopeIdentity() != scope.Identity() || receipt.DeletedRecordCount() != 1 || receipt.PreviousRevision() != 1 || receipt.NewRevision() != 2 || receipt.Validate() != nil || index.RecordCount(scope) != 0 {
		t.Fatalf("DeleteScope() = (%#v, %v)", receipt, err)
	}
	query, _ := NewLexicalQuery(scope, "", []string{"deletion"}, nil, time.UnixMilli(3), 10)
	retrieval, err := index.Search(context.Background(), scope, query)
	if err != nil || len(retrieval.Items()) != 0 || retrieval.IndexRevision() != 2 {
		t.Fatalf("negative retrieval = (%#v, %v)", retrieval, err)
	}
	forged := receipt
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidMemoryDeletionReceiptIdentity) {
		t.Fatal("forged deletion receipt accepted")
	}
}

func TestNewLexicalRetrievalRejectsRecordsAtRevisionZero(t *testing.T) {
	scope := testScope(t)
	record := memoryRecord(t, scope, RecordCanonicalFact, "internal/review/a.go", nil, "record", 'c', time.UnixMilli(100), time.Time{})
	query, _ := NewLexicalQuery(scope, record.Path(), nil, nil, time.UnixMilli(200), 1)
	if result, err := NewLexicalRetrieval(scope, query, 0, []RetrievalItemInput{{Record: record, Rank: 1, PathScore: 1}}); !errors.Is(err, ErrInvalidLexicalRetrieval) || result.Identity() != "" {
		t.Fatalf("result=(%#v,%v)", result, err)
	}
}
