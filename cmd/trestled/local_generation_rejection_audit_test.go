//go:build unix

package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func testGenerationRejectionAuditProof(t *testing.T, events []audit.Event, value, input, packet, requestArtifact, receiptArtifact artifact.Artifact, descriptor controlplane.ContextInputDescriptor, route runtimecatalog.LocalGenerationRoutePlan, handler string, now time.Time) {
	t.Helper()
	check := func(events []audit.Event, value artifact.Artifact, handler string, now time.Time) error {
		return validateGenerationRejectionAudit(events, value, input, packet, requestArtifact, receiptArtifact, descriptor, route, handler, now)
	}
	if err := check(events, value, handler, now); err != nil {
		t.Fatalf("actual rejection audit refused: %v", err)
	}
	rebuild := func(change func(int, audit.Event) (audit.EventKind, string, []string, time.Time), source []audit.Event) []audit.Event {
		result := make([]audit.Event, len(source))
		previous := ""
		for i, event := range source {
			kind, subject, parents, at := change(i, event)
			current, err := audit.NewEvent(event.Scope(), uint64(i+1), previous, kind, subject, parents, at)
			if err != nil {
				t.Fatal(err)
			}
			result[i], previous = current, current.Identity()
		}
		return result
	}
	unchanged := func(_ int, event audit.Event) (audit.EventKind, string, []string, time.Time) {
		return event.Kind(), event.SubjectIdentity(), event.CausalParentIdentities(), time.UnixMilli(event.OccurredAtUnixMilliseconds())
	}
	for index := range events {
		t.Run("event bindings", func(t *testing.T) {
			fields := []string{"subject", "kind"}
			for range events[index].CausalParentIdentities() {
				fields = append(fields, "parent")
			}
			parentIndex := 0
			for _, field := range fields {
				changed := rebuild(func(i int, event audit.Event) (audit.EventKind, string, []string, time.Time) {
					kind, subject, parents, at := unchanged(i, event)
					if i == index {
						switch field {
						case "subject":
							subject = strings.Repeat("f", 64)
						case "parent":
							parents[parentIndex] = strings.Repeat("f", 64)
						case "kind":
							kind = audit.EventPublicationClaimed
						}
					}
					return kind, subject, parents, at
				}, events)
				if field == "parent" {
					parentIndex++
				}
				if err := check(changed, value, handler, now); !errors.Is(err, errGenerationRejectionAudit) {
					t.Fatalf("changed %s event %d admitted: %v", field, index, err)
				}
			}
			removed := append(slices.Clone(events[:index]), events[index+1:]...)
			if err := check(rebuild(unchanged, removed), value, handler, now); err == nil {
				t.Fatal("missing event admitted")
			}
		})
	}
	for _, kind := range []audit.EventKind{audit.EventGenerationRejected, audit.EventRouteContinuationPlanned, audit.EventPublicationCompleted, audit.EventRouteAttemptClaimed} {
		extra, err := audit.NewEvent(value.Scope(), uint64(len(events)+1), events[len(events)-1].Identity(), kind, events[0].SubjectIdentity(), events[0].CausalParentIdentities(), now)
		if err != nil {
			t.Fatal(err)
		}
		if err := check(append(slices.Clone(events), extra), value, handler, now); err == nil {
			t.Fatal("extra effect admitted")
		}
	}
	same := rebuild(func(i int, event audit.Event) (audit.EventKind, string, []string, time.Time) {
		kind, subject, parents, _ := unchanged(i, event)
		return kind, subject, parents, value.CreatedAt()
	}, events)
	if err := check(same, value, handler, now); err != nil {
		t.Fatalf("same-millisecond order refused: %v", err)
	}
	backwards := rebuild(func(i int, event audit.Event) (audit.EventKind, string, []string, time.Time) {
		kind, subject, parents, at := unchanged(i, event)
		if i == 2 {
			at = time.UnixMilli(events[0].OccurredAtUnixMilliseconds() - 1)
		}
		return kind, subject, parents, at
	}, events)
	if err := check(backwards, value, handler, now); err == nil {
		t.Fatal("backward event time admitted")
	}
	if err := check(events, value, strings.Repeat("f", 64), now); err == nil {
		t.Fatal("wrong current handler admitted")
	}
	if err := check(events, value, handler, value.ExpiresAt()); err == nil {
		t.Fatal("expired receipt admitted")
	}
	if err := check(events, artifact.Artifact{}, handler, now); err == nil {
		t.Fatal("missing receipt admitted")
	}
	for index := 1; index < len(events); index++ {
		for _, field := range []string{"sequence", "previous"} {
			broken := slices.Clone(events)
			event := broken[index]
			sequence, previous := event.Sequence(), event.PreviousIdentity()
			if field == "sequence" {
				sequence++
			} else {
				previous = strings.Repeat("f", 64)
			}
			changed, err := audit.NewEvent(event.Scope(), sequence, previous, event.Kind(), event.SubjectIdentity(), event.CausalParentIdentities(), time.UnixMilli(event.OccurredAtUnixMilliseconds()))
			if err != nil {
				t.Fatal(err)
			}
			broken[index] = changed
			if err := check(broken, value, handler, now); err == nil {
				t.Fatalf("broken chain %s admitted", field)
			}
		}
	}
	future := rebuild(func(i int, event audit.Event) (audit.EventKind, string, []string, time.Time) {
		kind, subject, parents, _ := unchanged(i, event)
		return kind, subject, parents, now.Add(time.Millisecond)
	}, events)
	if err := check(future, value, handler, now); err == nil {
		t.Fatal("future events admitted")
	}
	if err := check(events, value, handler, value.CreatedAt().Add(-time.Millisecond)); err == nil {
		t.Fatal("future receipt admitted")
	}
	other, _ := audit.NewReviewScope("other", "repo-a", "cross")
	cross := slices.Clone(events)
	first, err := audit.NewEvent(other, 1, "", cross[0].Kind(), cross[0].SubjectIdentity(), cross[0].CausalParentIdentities(), time.UnixMilli(cross[0].OccurredAtUnixMilliseconds()))
	if err != nil {
		t.Fatal(err)
	}
	cross[0] = first
	if err := check(cross, value, handler, now); err == nil {
		t.Fatal("cross scope admitted")
	}
	for _, role := range []string{"input", "request", "receipt"} {
		for _, field := range []string{"digest", "created", "expires", "provenance", "classification", "protection"} {
			altered := descriptor
			target := &altered.Input
			if role == "request" {
				target = &altered.Request
			}
			if role == "receipt" {
				target = &altered.Receipt
			}
			switch field {
			case "digest":
				target.PayloadDigest = strings.Repeat("f", 64)
			case "created":
				target.CreatedAtMilliseconds++
			case "expires":
				target.ExpiresAtMilliseconds--
			case "provenance":
				target.Provenance = []string{strings.Repeat("f", 64)}
			case "classification":
				target.Classification = "restricted"
			case "protection":
				target.Protection = "envelope_encrypted"
			}
			if err := validateGenerationRejectionAudit(events, value, input, packet, requestArtifact, receiptArtifact, altered, route, handler, now); err == nil {
				t.Fatalf("altered %s %s admitted", role, field)
			}
		}
	}
	altered := descriptor
	altered.AuthorizationIdentity = strings.Repeat("f", 64)
	if err := validateGenerationRejectionAudit(events, value, input, packet, requestArtifact, receiptArtifact, altered, route, handler, now); err == nil {
		t.Fatal("cross-wired descriptor admitted")
	}
	if err := validateGenerationRejectionAudit(events, value, input, packet, requestArtifact, receiptArtifact, descriptor, runtimecatalog.LocalGenerationRoutePlan{}, handler, now); err == nil {
		t.Fatal("missing current route plan admitted")
	}
}
