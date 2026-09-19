package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func rmaInputs(t *testing.T) (memory.Scope, evidence.RepositoryIdentity, evidence.RevisionIdentity, RuntimePolicy, []RetainedMemoryFeedback, time.Time, time.Time, rmEnvelopeWire) {
	t.Helper()
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	repository := rmRepository(t, "source-repository")
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope("tenant-a", "logical-repo", "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.UnixMilli(rmObserved).UTC()
	until := time.UnixMilli(rmUntil).UTC()
	feedback := []RetainedMemoryFeedback{
		{Path: "src/zeta.go", Text: "second operator note"},
		{Path: "src/alpha.go", Text: "first operator note"},
	}
	want := rmEnvelopeWire{
		Contract:    "open-trestle/retained-memory-input",
		Version:     1,
		Attestation: "operator_attested_advisory_feedback",
		Scope: rmScopeWire{
			Tenant:     scope.TenantID(),
			Repository: scope.RepositoryID(),
			Actor:      scope.ActorID(),
			Visibility: scope.RefVisibility().String(),
			RefSet:     scope.RefSetIdentity(),
			Prefixes:   scope.PathPrefixes(),
		},
		Repository: repository.Identity(),
		Head: rmHeadWire{
			Kind:      string(head.Kind()),
			Algorithm: string(head.Algorithm()),
			Digest:    head.Digest(),
		},
		Policy: policy.Identity(),
		Paths:  []string{"src/alpha.go", "src/zeta.go"},
		Records: []rmRecordWire{
			{Kind: "human_feedback", Taint: "user_controlled", Path: "src/alpha.go", Symbols: []string{}, Text: "first operator note", Producer: rmProducer, Observed: rmObserved, From: rmObserved, Until: rmUntil},
			{Kind: "human_feedback", Taint: "user_controlled", Path: "src/zeta.go", Symbols: []string{}, Text: "second operator note", Producer: rmProducer, Observed: rmObserved, From: rmObserved, Until: rmUntil},
		},
	}
	rmReseal(t, &want, true)
	return scope, repository, head, policy, feedback, observed, until, want
}

func rmaLoadBytes(t *testing.T, encoded []byte, expected rmEnvelopeWire, repository evidence.RepositoryIdentity, policy RuntimePolicy, at time.Time) RetainedMemoryInput {
	t.Helper()
	if !rmaTrustedFileAuthoritySupported() {
		t.Skip("protected loader requires trusted local file ownership")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "retained-memory-input.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadProtectedRetainedMemoryInput(context.Background(), path, rmScope(t, expected.Scope), repository, policy, at)
	if err != nil {
		t.Fatal("valid protected input refused")
	}
	if value.ValidateFor(rmScope(t, expected.Scope), repository, policy, at) != nil {
		t.Fatal("loaded snapshot failed pure validation")
	}
	return value
}

func rmaTrustedFileAuthoritySupported() bool {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}

func TestEncodeRetainedMemoryInputCanonicalBytesAdmitThroughProtectedLoader(t *testing.T) {
	scope, repository, head, policy, feedback, observed, until, want := rmaInputs(t)
	encoded, err := EncodeRetainedMemoryInput(context.Background(), scope, repository, head, policy, feedback, observed, until)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, rmJSON(t, want)) {
		t.Fatalf("encoder bytes are not the canonical retained-memory wire form\n got: %s\nwant: %s", encoded, rmJSON(t, want))
	}
	if len(encoded) == 0 || encoded[0] != '{' || bytes.Contains(encoded, []byte("\n")) || len(encoded) > 65536 {
		t.Fatal("encoder did not return compact bounded JSON bytes")
	}
	var got rmEnvelopeWire
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("canonical retained-memory fields drifted")
	}
	if got.Scope.Identity != rmHash(rmScopeBytes(t, got.Scope)) || got.Head.Identity != rmHash(rmHeadBytes(t, got.Head)) || got.Policy != policy.Identity() || got.Repository != repository.Identity() || got.Scope.RefSet != head.Identity() {
		t.Fatal("scope, head, repository, or policy identity is not independently reproducible")
	}
	if !slices.IsSorted(got.Paths) {
		t.Fatal("allowed paths are not sorted")
	}
	for i, record := range got.Records {
		if record.Identity != rmHash(rmRecordBytes(t, got.Scope.Identity, record)) || len(record.Evidence) != 1 || record.Evidence[0] != "operator-note:"+rmHash(rmNoteBytes(t, got.Scope.Identity, record)) {
			t.Fatal("record or operator-note identity is not independently reproducible")
		}
		if i > 0 && got.Records[i-1].Identity > record.Identity {
			t.Fatal("records are not sorted by record identity")
		}
	}
	loaded := rmaLoadBytes(t, encoded, want, repository, policy, observed.Add(time.Millisecond))
	if loaded.Identity() != rmHash(rmInputBytes(t, want)) {
		t.Fatal("loader identity differs from canonical protected-input preimage")
	}
	if !loaded.MatchesEncoding(encoded) {
		t.Fatal("loader-created snapshot does not match its exact encoder bytes")
	}
	if loaded.MatchesEncoding(append(append([]byte(nil), encoded...), '\n')) || loaded.MatchesEncoding(bytes.Replace(encoded, []byte("src/alpha.go"), []byte("src/zeta.go"), 1)) || loaded.MatchesEncoding(nil) {
		t.Fatal("MatchesEncoding accepted non-exact or empty bytes")
	}
	var zero RetainedMemoryInput
	if zero.MatchesEncoding(encoded) || zero.MatchesEncoding(nil) {
		t.Fatal("zero snapshot matched encoded bytes")
	}
}

func TestEncodeRetainedMemoryInputRejectsInvalidTypedInputs(t *testing.T) {
	scope, repository, head, policy, feedback, observed, until, _ := rmaInputs(t)
	cases := map[string]struct {
		scope    memory.Scope
		repo     evidence.RepositoryIdentity
		head     evidence.RevisionIdentity
		policy   RuntimePolicy
		feedback []RetainedMemoryFeedback
		observed time.Time
		until    time.Time
	}{
		"nil context":           {scope, repository, head, policy, feedback, observed, until},
		"zero scope":            {memory.Scope{}, repository, head, policy, feedback, observed, until},
		"zero repository":       {scope, evidence.RepositoryIdentity{}, head, policy, feedback, observed, until},
		"zero head":             {scope, repository, evidence.RevisionIdentity{}, policy, feedback, observed, until},
		"zero policy":           {scope, repository, head, RuntimePolicy{}, feedback, observed, until},
		"wrong actor scope":     {rmaScope(t, head.Identity(), "other-reviewer"), repository, head, policy, feedback, observed, until},
		"wrong ref scope":       {rmaScope(t, strings.Repeat("c", 64), "local-reviewer"), repository, head, policy, feedback, observed, until},
		"empty feedback":        {scope, repository, head, policy, nil, observed, until},
		"duplicate path":        {scope, repository, head, policy, []RetainedMemoryFeedback{{Path: "a.go", Text: "one"}, {Path: "a.go", Text: "two"}}, observed, until},
		"unsafe path":           {scope, repository, head, policy, []RetainedMemoryFeedback{{Path: "../a.go", Text: "one"}}, observed, until},
		"empty text":            {scope, repository, head, policy, []RetainedMemoryFeedback{{Path: "a.go", Text: "  \n\t  "}}, observed, until},
		"too much text":         {scope, repository, head, policy, []RetainedMemoryFeedback{{Path: "a.go", Text: strings.Repeat("a", 1025)}}, observed, until},
		"submillisecond time":   {scope, repository, head, policy, feedback, observed.Add(time.Nanosecond), until},
		"valid until before":    {scope, repository, head, policy, feedback, observed, observed.Add(-time.Millisecond)},
		"lifetime too long":     {scope, repository, head, policy, feedback, observed, observed.Add(168*time.Hour + time.Millisecond)},
		"maximum time overflow": {scope, repository, head, policy, feedback, time.UnixMilli(rmMaximum), time.UnixMilli(rmMaximum).Add(time.Millisecond)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "nil context" {
				ctx = nil
			}
			encoded, err := EncodeRetainedMemoryInput(ctx, tc.scope, tc.repo, tc.head, tc.policy, tc.feedback, tc.observed, tc.until)
			if err == nil || len(encoded) != 0 || strings.Contains(err.Error(), "operator note") || strings.Contains(err.Error(), "a.go") {
				t.Fatal("invalid encoder input was accepted or leaked feedback")
			}
		})
	}
}

func TestRetainedMemoryInputMatchesEncodingRejectsDifferentValidDeclarations(t *testing.T) {
	scope, repository, head, policy, feedback, observed, until, want := rmaInputs(t)
	encoded, err := EncodeRetainedMemoryInput(context.Background(), scope, repository, head, policy, feedback, observed, until)
	if err != nil {
		t.Fatal(err)
	}
	loaded := rmaLoadBytes(t, encoded, want, repository, policy, observed.Add(time.Millisecond))
	otherFeedback := []RetainedMemoryFeedback{{Path: "src/alpha.go", Text: "different accepted note"}}
	other, err := EncodeRetainedMemoryInput(context.Background(), scope, repository, head, policy, otherFeedback, observed, until)
	if err != nil {
		t.Fatal(err)
	}
	otherWant := want
	otherWant.Paths = []string{"src/alpha.go"}
	otherWant.Records = []rmRecordWire{{Kind: "human_feedback", Taint: "user_controlled", Path: "src/alpha.go", Symbols: []string{}, Text: "different accepted note", Producer: rmProducer, Observed: rmObserved, From: rmObserved, Until: rmUntil}}
	rmReseal(t, &otherWant, true)
	rmaLoadBytes(t, other, otherWant, repository, policy, observed.Add(time.Millisecond))
	if loaded.MatchesEncoding(other) {
		t.Fatal("snapshot matched a different but valid retained-memory input")
	}
}

func rmaScope(t *testing.T, refSet, actor string) memory.Scope {
	t.Helper()
	scope, err := memory.NewScope("tenant-a", "logical-repo", actor, memory.RefVisibilityExact, refSet, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
