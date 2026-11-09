package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

// A review refused because its reservation exceeds the route's declared
// context says how many tokens it needs, what the route declares and what to
// raise, in JSON and in text.
func TestLocalModelReviewExplainsARouteContextShortfall(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{capacity: true})
	var stdout, stderr bytes.Buffer
	if code := run(f.args, &stdout, &stderr); code != 4 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var wire struct {
		Status           string `json:"status"`
		Failure          string `json:"failure"`
		FailureDetail    string `json:"failure_detail"`
		ContextShortfall *struct {
			RequiredTokens        uint64 `json:"required_tokens"`
			EstimatedInputTokens  uint64 `json:"estimated_input_tokens"`
			MaxOutputTokens       uint64 `json:"max_output_tokens"`
			DeclaredContextTokens uint64 `json:"declared_context_tokens"`
		} `json:"context_shortfall"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil || wire.Status != "refused" || wire.Failure != "policy" || wire.FailureDetail != localreview.FailureDetailRouteContextInsufficient || wire.ContextShortfall == nil {
		t.Fatalf("result=%+v err=%v", wire, err)
	}
	shortfall := *wire.ContextShortfall
	if shortfall.DeclaredContextTokens != 5000 || shortfall.RequiredTokens != shortfall.EstimatedInputTokens+shortfall.MaxOutputTokens || shortfall.RequiredTokens <= 5000 {
		t.Fatalf("shortfall=%+v", shortfall)
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{capacity: true}), 4)
	want := fmt.Sprintf(": route_context_insufficient\nhint: the review needs up to %d tokens (a byte-based upper bound: %d input plus %d output) but the route declares max_context_tokens 5000; raise max_context_tokens on the route and the model server's context length to at least %d", shortfall.RequiredTokens, shortfall.EstimatedInputTokens, shortfall.MaxOutputTokens, shortfall.RequiredTokens)
	if !strings.Contains(text, want) {
		t.Fatalf("text lacks %q:\n%s", want, text)
	}
	// Other refusals keep the detail absent.
	stdout.Reset()
	other := newLocalModelFixture(t, localModelFixtureOptions{expensive: true})
	if code := run(other.args, &stdout, &stderr); code != 4 || bytes.Contains(stdout.Bytes(), []byte("context_shortfall")) || bytes.Contains(stdout.Bytes(), []byte("failure_detail")) {
		t.Fatalf("cost refusal carried a context shortfall: %s", stdout.String())
	}
}

// A review set member refused for a context shortfall carries the same counts.
func TestLocalModelReviewSetMemberCarriesARouteContextShortfall(t *testing.T) {
	type member struct {
		Member           string `json:"member"`
		FailureDetail    string `json:"failure_detail"`
		ContextShortfall *struct {
			RequiredTokens        uint64 `json:"required_tokens"`
			EstimatedInputTokens  uint64 `json:"estimated_input_tokens"`
			MaxOutputTokens       uint64 `json:"max_output_tokens"`
			DeclaredContextTokens uint64 `json:"declared_context_tokens"`
		} `json:"context_shortfall"`
	}
	members := func(options localModelFixtureOptions, code int) ([]member, string) {
		t.Helper()
		f := newLocalModelFixture(t, options)
		args := append(append([]string(nil), f.args...), "--specialists", "bug_hunter")
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != code {
			t.Fatalf("exit=%d want %d stderr=%q", got, code, stderr.String())
		}
		var wire struct {
			Members []member `json:"members"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil || len(wire.Members) == 0 {
			t.Fatalf("set=%s err=%v", stdout.String(), err)
		}
		return wire.Members, stdout.String()
	}
	refused, _ := members(localModelFixtureOptions{capacity: true}, 4)
	general := refused[0]
	if general.Member != "general" || general.FailureDetail != localreview.FailureDetailRouteContextInsufficient || general.ContextShortfall == nil {
		t.Fatalf("general member=%+v", general)
	}
	if s := *general.ContextShortfall; s.DeclaredContextTokens != 5000 || s.RequiredTokens != s.EstimatedInputTokens+s.MaxOutputTokens || s.RequiredTokens <= 5000 {
		t.Fatalf("member shortfall=%+v", s)
	}
	if _, encoded := members(localModelFixtureOptions{generationMode: "malformed"}, 1); strings.Contains(encoded, "context_shortfall") {
		t.Fatalf("an unrelated member failure carried a context shortfall: %s", encoded)
	}
}
