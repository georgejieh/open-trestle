package runtimeconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	retainedRawLimit                   = 65536
	retainedRecordLimit                = 16
	retainedPathLimit                  = 16
	retainedCanonicalRecordLimit       = 4096
	retainedTextLimit                  = 1024
	retainedTotalTextLimit             = 8192
	retainedStringLimit                = 32768
	retainedMaximumMilliseconds  int64 = 253402300799999
	retainedLifetimeMilliseconds int64 = 604800000
	retainedProducer                   = "084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f"
)

// ErrInvalidRetainedMemoryInput is the sole, unwrapped input refusal.
var ErrInvalidRetainedMemoryInput = errors.New("invalid retained memory input")

// RetainedMemoryInput is a protected, content-bound snapshot of operator advice.
// It does not attest source custody, truth, retrieval, or future caller egress.
// Only LoadProtectedRetainedMemoryInput publishes usable snapshots.
type RetainedMemoryInput struct {
	declared retainedEnvelope
	scope    memory.Scope
	records  []memory.Record
	identity string
}

type retainedScope struct {
	Identity   string   `json:"identity"`
	Tenant     string   `json:"tenant_id"`
	Repository string   `json:"repository_id"`
	Actor      string   `json:"actor_id"`
	Visibility string   `json:"ref_visibility"`
	RefSet     string   `json:"ref_set_identity"`
	Prefixes   []string `json:"path_prefixes"`
}

type retainedHead struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Identity  string `json:"identity"`
}

type retainedRecord struct {
	Identity string   `json:"record_identity"`
	Kind     string   `json:"kind"`
	Taint    string   `json:"taint"`
	Path     string   `json:"path"`
	Symbols  []string `json:"symbols"`
	Text     string   `json:"text"`
	Evidence []string `json:"evidence_ids"`
	Producer string   `json:"producer_identity"`
	Observed int64    `json:"observed_at"`
	From     int64    `json:"valid_from"`
	Until    int64    `json:"valid_until"`
}

type retainedEnvelope struct {
	Contract    string           `json:"contract"`
	Version     int              `json:"schema_version"`
	Attestation string           `json:"attestation"`
	Scope       retainedScope    `json:"scope"`
	Repository  string           `json:"repository_identity"`
	Head        retainedHead     `json:"head_revision"`
	Policy      string           `json:"runtime_policy_identity"`
	Paths       []string         `json:"allowed_paths"`
	Records     []retainedRecord `json:"records"`
}

func (v RetainedMemoryInput) Identity() string    { return v.identity }
func (v RetainedMemoryInput) Scope() memory.Scope { return v.scope }
func (v RetainedMemoryInput) Records() []memory.Record {
	return append([]memory.Record(nil), v.records...)
}
func (v RetainedMemoryInput) String() string { return "retained memory input" }
func (v RetainedMemoryInput) GoString() string {
	return "runtimeconfig.RetainedMemoryInput{<redacted>}"
}
func (v RetainedMemoryInput) Format(state fmt.State, verb rune) {
	formatted := v.String()
	if verb == 'q' {
		formatted = `"retained memory input"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = v.GoString()
	}
	_, _ = state.Write([]byte(formatted))
}

// ValidateFor reconstructs the stored declaration without reading a file or clock.
func (v RetainedMemoryInput) ValidateFor(scope memory.Scope, repository evidence.RepositoryIdentity, policy RuntimePolicy, at time.Time) error {
	if v.identity == "" || len(v.records) != len(v.declared.Records) || !validRetainedShape(v.declared, true) {
		return ErrInvalidRetainedMemoryInput
	}
	instant, ok := retainedArguments(scope, repository, policy, at)
	if !ok {
		return ErrInvalidRetainedMemoryInput
	}
	declaredScope, records, ok := reconstructRetained(context.Background(), v.declared)
	if !ok || v.scope.Validate() != nil || !sameRetainedScope(v.scope, declaredScope) {
		return ErrInvalidRetainedMemoryInput
	}
	for i, record := range records {
		if v.records[i].Validate() != nil || !sameRetainedRecord(v.records[i], record) {
			return ErrInvalidRetainedMemoryInput
		}
	}
	if !fixedRetainedSlice(v.declared, declaredScope, records) ||
		!retainedBindings(v.declared, declaredScope, scope, repository, policy) || !freshRetained(records, instant) {
		return ErrInvalidRetainedMemoryInput
	}
	identity, ok := retainedInputIdentity(v.declared)
	if !ok || identity != v.identity {
		return ErrInvalidRetainedMemoryInput
	}
	return nil
}

func retainedArguments(scope memory.Scope, repository evidence.RepositoryIdentity, policy RuntimePolicy, at time.Time) (time.Time, bool) {
	if scope.Validate() != nil {
		return time.Time{}, false
	}
	rebuilt, err := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	if err != nil || rebuilt.Identity() != repository.Identity() || policy.Validate() != nil {
		return time.Time{}, false
	}
	for _, connection := range policy.Connections() {
		locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
		if err != nil || locality != provider.ServiceEndpointLoopback {
			return time.Time{}, false
		}
	}
	instant := at.Round(0).UTC()
	if instant.Before(time.UnixMilli(1).UTC()) || !instant.Before(time.UnixMilli(retainedMaximumMilliseconds+1).UTC()) {
		return time.Time{}, false
	}
	return instant, true
}

// Keys and strings are counted per occurrence, including repeated paths and IDs.
// Load already accounted its decoded tokens; pure revalidation accounts stored fields.
func validRetainedShape(w retainedEnvelope, countStrings bool) bool {
	if w.Contract != "open-trestle/retained-memory-input" || w.Version != 1 || w.Attestation != "operator_attested_advisory_feedback" ||
		len(w.Scope.Prefixes) != 1 || len(w.Paths) < 1 || len(w.Paths) > retainedPathLimit || len(w.Records) < 1 || len(w.Records) > retainedRecordLimit {
		return false
	}
	total := 0
	stringsOK := func(values ...string) bool {
		for _, value := range values {
			if value == "" || !utf8.ValidString(value) || len(value) > retainedStringLimit {
				return false
			}
			if countStrings {
				if len(value) > retainedStringLimit-total {
					return false
				}
				total += len(value)
			}
		}
		return true
	}
	if !stringsOK(retainedKeys(retainedEnvelopeObject)...) || !stringsOK(w.Contract, w.Attestation) ||
		!stringsOK(retainedKeys(retainedScopeObject)...) ||
		!stringsOK(w.Scope.Identity, w.Scope.Tenant, w.Scope.Repository, w.Scope.Actor, w.Scope.Visibility, w.Scope.RefSet) ||
		!stringsOK(w.Scope.Prefixes...) || !stringsOK(w.Repository) || !stringsOK(retainedKeys(retainedHeadObject)...) ||
		!stringsOK(w.Head.Kind, w.Head.Algorithm, w.Head.Digest, w.Head.Identity, w.Policy) || !stringsOK(w.Paths...) {
		return false
	}
	textTotal := 0
	for _, r := range w.Records {
		if r.Symbols == nil || len(r.Symbols) != 0 || len(r.Evidence) != 1 ||
			!stringsOK(retainedKeys(retainedRecordObject)...) ||
			!stringsOK(r.Identity, r.Kind, r.Taint, r.Path, r.Text) || !stringsOK(r.Evidence...) || !stringsOK(r.Producer) ||
			!retainedMilliseconds(r.Observed) || !retainedMilliseconds(r.From) || !retainedMilliseconds(r.Until) ||
			len(r.Text) > retainedTextLimit || len(r.Text) > retainedTotalTextLimit-textTotal {
			return false
		}
		textTotal += len(r.Text)
		encoded, err := json.Marshal(r)
		if err != nil || len(encoded) > retainedCanonicalRecordLimit {
			return false
		}
	}
	return true
}

func retainedMilliseconds(value int64) bool {
	return value >= 1 && value <= retainedMaximumMilliseconds
}

func reconstructRetained(ctx context.Context, w retainedEnvelope) (memory.Scope, []memory.Record, bool) {
	visibility, err := memory.ParseRefVisibility(w.Scope.Visibility)
	if err != nil {
		return memory.Scope{}, nil, false
	}
	scope, err := memory.NewScope(w.Scope.Tenant, w.Scope.Repository, w.Scope.Actor, visibility, w.Scope.RefSet, w.Scope.Prefixes)
	if err != nil || scope.Validate() != nil || scope.Identity() != w.Scope.Identity ||
		scope.TenantID() != w.Scope.Tenant || scope.RepositoryID() != w.Scope.Repository || scope.ActorID() != w.Scope.Actor ||
		scope.RefVisibility().String() != w.Scope.Visibility || scope.RefSetIdentity() != w.Scope.RefSet || !slices.Equal(scope.PathPrefixes(), w.Scope.Prefixes) {
		return memory.Scope{}, nil, false
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKind(w.Head.Kind), evidence.RevisionAlgorithm(w.Head.Algorithm), w.Head.Digest)
	if err != nil || head.Identity() != w.Head.Identity || head.Identity() != scope.RefSetIdentity() ||
		string(head.Kind()) != w.Head.Kind || string(head.Algorithm()) != w.Head.Algorithm || head.Digest() != w.Head.Digest {
		return memory.Scope{}, nil, false
	}
	records := make([]memory.Record, len(w.Records))
	for i, r := range w.Records {
		if ctx.Err() != nil {
			return memory.Scope{}, nil, false
		}
		kind, err := memory.ParseRecordKind(r.Kind)
		if err != nil {
			return memory.Scope{}, nil, false
		}
		taint, err := memory.ParseTaintClass(r.Taint)
		if err != nil || !retainedMilliseconds(r.Observed) || !retainedMilliseconds(r.From) || !retainedMilliseconds(r.Until) {
			return memory.Scope{}, nil, false
		}
		// Native empty authority slices stay nil; the separate wire symbols is [].
		record, err := memory.NewRecord(scope, memory.RecordInput{
			Kind: kind, Taint: taint, Path: r.Path, Text: r.Text, EvidenceIDs: r.Evidence,
			ProducerIdentity: r.Producer, ObservedAt: time.UnixMilli(r.Observed).UTC(),
			ValidFrom: time.UnixMilli(r.From).UTC(), ValidUntil: time.UnixMilli(r.Until).UTC(),
		})
		if err != nil || record.Validate() != nil || record.Identity() != r.Identity {
			return memory.Scope{}, nil, false
		}
		records[i] = record
	}
	return scope, records, true
}

func fixedRetainedSlice(w retainedEnvelope, scope memory.Scope, records []memory.Record) bool {
	if scope.ActorID() != "local-reviewer" || scope.RefVisibility() != memory.RefVisibilityExact || len(w.Scope.Prefixes) != 1 || w.Scope.Prefixes[0] != "." {
		return false
	}
	for i, path := range w.Paths {
		if !scope.AllowsPath(path) || i > 0 && w.Paths[i-1] >= path {
			return false
		}
	}
	for i, r := range w.Records {
		if records[i].Kind() != memory.RecordHumanFeedback || records[i].Taint() != memory.TaintUserControlled ||
			r.Producer != retainedProducer || i > 0 && w.Records[i-1].Identity >= r.Identity || !slices.Contains(w.Paths, r.Path) ||
			!scope.AllowsPath(r.Path) || r.From > r.Observed || r.Observed >= r.Until || r.Until-r.Observed > retainedLifetimeMilliseconds {
			return false
		}
		for j := 0; j < i; j++ {
			if w.Records[j].Path == r.Path {
				return false
			}
		}
		note, err := json.Marshal([]any{"open-trestle/operator-feedback-note", 1, scope.Identity(), r.Path, r.Text, r.Observed, r.From, r.Until})
		if err != nil || len(r.Evidence) != 1 || r.Evidence[0] != "operator-note:"+retainedDigest(note) {
			return false
		}
	}
	return true
}

func sameRetainedScope(a, b memory.Scope) bool {
	return a.Identity() == b.Identity() && a.TenantID() == b.TenantID() && a.RepositoryID() == b.RepositoryID() && a.ActorID() == b.ActorID() &&
		a.RefVisibility() == b.RefVisibility() && a.RefSetIdentity() == b.RefSetIdentity() && slices.Equal(a.PathPrefixes(), b.PathPrefixes())
}

func sameRetainedRecord(a, b memory.Record) bool {
	return a.Identity() == b.Identity() && a.ScopeIdentity() == b.ScopeIdentity() && a.Kind() == b.Kind() && a.Taint() == b.Taint() &&
		a.Path() == b.Path() && slices.Equal(a.Symbols(), b.Symbols()) && a.Text() == b.Text() && slices.Equal(a.EvidenceIDs(), b.EvidenceIDs()) &&
		slices.Equal(a.DerivedFromIDs(), b.DerivedFromIDs()) && slices.Equal(a.CounterEvidenceIDs(), b.CounterEvidenceIDs()) &&
		a.ProducerIdentity() == b.ProducerIdentity() && a.ObservedAtUnixMilliseconds() == b.ObservedAtUnixMilliseconds() &&
		a.ValidFromUnixMilliseconds() == b.ValidFromUnixMilliseconds() && a.ValidUntilUnixMilliseconds() == b.ValidUntilUnixMilliseconds() &&
		a.StaleAfterUnixMilliseconds() == b.StaleAfterUnixMilliseconds() && a.FreshnessIdentity() == b.FreshnessIdentity() && a.ConfidenceBasisPoints() == b.ConfidenceBasisPoints()
}

func retainedBindings(w retainedEnvelope, declared, expected memory.Scope, repository evidence.RepositoryIdentity, policy RuntimePolicy) bool {
	return sameRetainedScope(declared, expected) && w.Repository == repository.Identity() && w.Policy == policy.Identity()
}

func freshRetained(records []memory.Record, at time.Time) bool {
	for _, record := range records {
		if !record.FreshAt(at) {
			return false
		}
	}
	return true
}

func retainedInputIdentity(w retainedEnvelope) (string, bool) {
	encoded, err := json.Marshal([]any{
		"open-trestle/protected-retained-input", 1, "local-only", retainedRawLimit, retainedRecordLimit, retainedPathLimit,
		retainedCanonicalRecordLimit, retainedTextLimit, retainedTotalTextLimit, retainedStringLimit, retainedLifetimeMilliseconds, w,
	})
	if err != nil {
		return "", false
	}
	return retainedDigest(encoded), true
}

func retainedDigest(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
