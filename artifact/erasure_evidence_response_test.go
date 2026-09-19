package artifact_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestEvMetaResponseEnumMatrix(t *testing.T) {
	constants := []artifact.AttemptResponseCode{artifact.AttemptResponsePresent, artifact.AttemptResponseAbsent, artifact.AttemptResponseCreated, artifact.AttemptResponseConditionLost, artifact.AttemptResponseDeleted, artifact.AttemptResponseNotFound, artifact.AttemptResponseConflict, artifact.AttemptResponseDenied, artifact.AttemptResponseMalformed, artifact.AttemptResponseUnavailable, artifact.AttemptResponseAbandoned}
	wires := []string{"present", "absent", "created", "condition_lost", "deleted", "not_found", "conflict", "denied", "malformed", "unavailable", "abandoned"}
	for i, c := range constants {
		if c != artifact.AttemptResponseCode(i+1) || c.String() != wires[i] {
			t.Fatal("enum", i)
		}
	}
	for _, c := range []artifact.AttemptResponseCode{0, 12, 255} {
		if c.String() != "" {
			t.Fatal("unknown enum string")
		}
		evMetaBadResponse(t, artifact.AttemptResponseOptions{Attempt: evMetaAttempt(t, "initial"), Code: c, ObservedAt: evMetaTime(1002)}, artifact.ErrInvalidErasureContract)
	}
	cases := []struct {
		name, kind string
		code       artifact.AttemptResponseCode
		allowed    bool
	}{
		{"matrix_current_read_present", "current_read", artifact.AttemptResponseCode(1), true},
		{"matrix_current_read_absent", "current_read", artifact.AttemptResponseCode(2), true},
		{"matrix_current_read_created", "current_read", artifact.AttemptResponseCode(3), false},
		{"matrix_current_read_condition_lost", "current_read", artifact.AttemptResponseCode(4), false},
		{"matrix_current_read_deleted", "current_read", artifact.AttemptResponseCode(5), false},
		{"matrix_current_read_not_found", "current_read", artifact.AttemptResponseCode(6), false},
		{"matrix_current_read_conflict", "current_read", artifact.AttemptResponseCode(7), true},
		{"matrix_current_read_denied", "current_read", artifact.AttemptResponseCode(8), true},
		{"matrix_current_read_malformed", "current_read", artifact.AttemptResponseCode(9), true},
		{"matrix_current_read_unavailable", "current_read", artifact.AttemptResponseCode(10), true},
		{"matrix_current_read_abandoned", "current_read", artifact.AttemptResponseCode(11), true},
		{"matrix_intent_read_present", "intent_read", artifact.AttemptResponseCode(1), true},
		{"matrix_intent_read_absent", "intent_read", artifact.AttemptResponseCode(2), true},
		{"matrix_intent_read_created", "intent_read", artifact.AttemptResponseCode(3), false},
		{"matrix_intent_read_condition_lost", "intent_read", artifact.AttemptResponseCode(4), false},
		{"matrix_intent_read_deleted", "intent_read", artifact.AttemptResponseCode(5), false},
		{"matrix_intent_read_not_found", "intent_read", artifact.AttemptResponseCode(6), false},
		{"matrix_intent_read_conflict", "intent_read", artifact.AttemptResponseCode(7), true},
		{"matrix_intent_read_denied", "intent_read", artifact.AttemptResponseCode(8), true},
		{"matrix_intent_read_malformed", "intent_read", artifact.AttemptResponseCode(9), true},
		{"matrix_intent_read_unavailable", "intent_read", artifact.AttemptResponseCode(10), true},
		{"matrix_intent_read_abandoned", "intent_read", artifact.AttemptResponseCode(11), true},
		{"matrix_attestation_read_present", "attestation_read", artifact.AttemptResponseCode(1), true},
		{"matrix_attestation_read_absent", "attestation_read", artifact.AttemptResponseCode(2), true},
		{"matrix_attestation_read_created", "attestation_read", artifact.AttemptResponseCode(3), false},
		{"matrix_attestation_read_condition_lost", "attestation_read", artifact.AttemptResponseCode(4), false},
		{"matrix_attestation_read_deleted", "attestation_read", artifact.AttemptResponseCode(5), false},
		{"matrix_attestation_read_not_found", "attestation_read", artifact.AttemptResponseCode(6), false},
		{"matrix_attestation_read_conflict", "attestation_read", artifact.AttemptResponseCode(7), true},
		{"matrix_attestation_read_denied", "attestation_read", artifact.AttemptResponseCode(8), true},
		{"matrix_attestation_read_malformed", "attestation_read", artifact.AttemptResponseCode(9), true},
		{"matrix_attestation_read_unavailable", "attestation_read", artifact.AttemptResponseCode(10), true},
		{"matrix_attestation_read_abandoned", "attestation_read", artifact.AttemptResponseCode(11), true},
		{"matrix_version_list_present", "version_list", artifact.AttemptResponseCode(1), true},
		{"matrix_version_list_absent", "version_list", artifact.AttemptResponseCode(2), false},
		{"matrix_version_list_created", "version_list", artifact.AttemptResponseCode(3), false},
		{"matrix_version_list_condition_lost", "version_list", artifact.AttemptResponseCode(4), false},
		{"matrix_version_list_deleted", "version_list", artifact.AttemptResponseCode(5), false},
		{"matrix_version_list_not_found", "version_list", artifact.AttemptResponseCode(6), false},
		{"matrix_version_list_conflict", "version_list", artifact.AttemptResponseCode(7), true},
		{"matrix_version_list_denied", "version_list", artifact.AttemptResponseCode(8), true},
		{"matrix_version_list_malformed", "version_list", artifact.AttemptResponseCode(9), true},
		{"matrix_version_list_unavailable", "version_list", artifact.AttemptResponseCode(10), true},
		{"matrix_version_list_abandoned", "version_list", artifact.AttemptResponseCode(11), true},
		{"matrix_intent_create_present", "intent_create", artifact.AttemptResponseCode(1), false},
		{"matrix_intent_create_absent", "intent_create", artifact.AttemptResponseCode(2), false},
		{"matrix_intent_create_created", "intent_create", artifact.AttemptResponseCode(3), true},
		{"matrix_intent_create_condition_lost", "intent_create", artifact.AttemptResponseCode(4), true},
		{"matrix_intent_create_deleted", "intent_create", artifact.AttemptResponseCode(5), false},
		{"matrix_intent_create_not_found", "intent_create", artifact.AttemptResponseCode(6), false},
		{"matrix_intent_create_conflict", "intent_create", artifact.AttemptResponseCode(7), true},
		{"matrix_intent_create_denied", "intent_create", artifact.AttemptResponseCode(8), true},
		{"matrix_intent_create_malformed", "intent_create", artifact.AttemptResponseCode(9), true},
		{"matrix_intent_create_unavailable", "intent_create", artifact.AttemptResponseCode(10), true},
		{"matrix_intent_create_abandoned", "intent_create", artifact.AttemptResponseCode(11), true},
		{"matrix_fence_create_present", "fence_create", artifact.AttemptResponseCode(1), false},
		{"matrix_fence_create_absent", "fence_create", artifact.AttemptResponseCode(2), false},
		{"matrix_fence_create_created", "fence_create", artifact.AttemptResponseCode(3), true},
		{"matrix_fence_create_condition_lost", "fence_create", artifact.AttemptResponseCode(4), true},
		{"matrix_fence_create_deleted", "fence_create", artifact.AttemptResponseCode(5), false},
		{"matrix_fence_create_not_found", "fence_create", artifact.AttemptResponseCode(6), false},
		{"matrix_fence_create_conflict", "fence_create", artifact.AttemptResponseCode(7), true},
		{"matrix_fence_create_denied", "fence_create", artifact.AttemptResponseCode(8), true},
		{"matrix_fence_create_malformed", "fence_create", artifact.AttemptResponseCode(9), true},
		{"matrix_fence_create_unavailable", "fence_create", artifact.AttemptResponseCode(10), true},
		{"matrix_fence_create_abandoned", "fence_create", artifact.AttemptResponseCode(11), true},
		{"matrix_version_delete_present", "version_delete", artifact.AttemptResponseCode(1), false},
		{"matrix_version_delete_absent", "version_delete", artifact.AttemptResponseCode(2), false},
		{"matrix_version_delete_created", "version_delete", artifact.AttemptResponseCode(3), false},
		{"matrix_version_delete_condition_lost", "version_delete", artifact.AttemptResponseCode(4), false},
		{"matrix_version_delete_deleted", "version_delete", artifact.AttemptResponseCode(5), true},
		{"matrix_version_delete_not_found", "version_delete", artifact.AttemptResponseCode(6), true},
		{"matrix_version_delete_conflict", "version_delete", artifact.AttemptResponseCode(7), true},
		{"matrix_version_delete_denied", "version_delete", artifact.AttemptResponseCode(8), true},
		{"matrix_version_delete_malformed", "version_delete", artifact.AttemptResponseCode(9), true},
		{"matrix_version_delete_unavailable", "version_delete", artifact.AttemptResponseCode(10), true},
		{"matrix_version_delete_abandoned", "version_delete", artifact.AttemptResponseCode(11), true},
		{"matrix_attestation_create_present", "attestation_create", artifact.AttemptResponseCode(1), false},
		{"matrix_attestation_create_absent", "attestation_create", artifact.AttemptResponseCode(2), false},
		{"matrix_attestation_create_created", "attestation_create", artifact.AttemptResponseCode(3), true},
		{"matrix_attestation_create_condition_lost", "attestation_create", artifact.AttemptResponseCode(4), true},
		{"matrix_attestation_create_deleted", "attestation_create", artifact.AttemptResponseCode(5), false},
		{"matrix_attestation_create_not_found", "attestation_create", artifact.AttemptResponseCode(6), false},
		{"matrix_attestation_create_conflict", "attestation_create", artifact.AttemptResponseCode(7), true},
		{"matrix_attestation_create_denied", "attestation_create", artifact.AttemptResponseCode(8), true},
		{"matrix_attestation_create_malformed", "attestation_create", artifact.AttemptResponseCode(9), true},
		{"matrix_attestation_create_unavailable", "attestation_create", artifact.AttemptResponseCode(10), true},
		{"matrix_attestation_create_abandoned", "attestation_create", artifact.AttemptResponseCode(11), true},
	}
	allowed, forbidden := 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := evMetaAttempt(t, "matrix_"+tc.kind)
			if tc.allowed {
				allowed++
				evMetaNewResponse(t, evMetaOptions(t, a, evMetaWire(tc.name+"_record")), evMetaWire(tc.name))
			} else {
				forbidden++
				evMetaBadResponse(t, artifact.AttemptResponseOptions{Attempt: a, Code: tc.code, ObservedAt: evMetaTime(1002)}, artifact.ErrInvalidErasureContract)
			}
		})
	}
	if allowed != 55 || forbidden != 33 {
		t.Fatal("matrix coverage", allowed, forbidden)
	}
	for _, name := range []string{"branch_fence", "branch_delete_marker"} {
		t.Run(name, func(t *testing.T) {
			evMetaNewResponse(t, evMetaOptions(t, evMetaAttempt(t, "matrix_current_read"), evMetaWire(name+"_record")), evMetaWire(name))
		})
	}
	for _, prefix := range []string{"initial", "terminal", "final", "proof"} {
		t.Run(prefix, func(t *testing.T) {
			evMetaNewResponse(t, evMetaOptions(t, evMetaAttempt(t, prefix), evMetaWire(prefix+"_response_record")), evMetaWire(prefix+"_response"))
		})
	}
}

func TestEvMetaResponseEmptyFieldsExclusive(t *testing.T) {
	names := []string{
		"matrix_current_read_absent",
		"matrix_current_read_conflict",
		"matrix_current_read_denied",
		"matrix_current_read_malformed",
		"matrix_current_read_unavailable",
		"matrix_current_read_abandoned",
		"matrix_intent_read_absent",
		"matrix_intent_read_conflict",
		"matrix_intent_read_denied",
		"matrix_intent_read_malformed",
		"matrix_intent_read_unavailable",
		"matrix_intent_read_abandoned",
		"matrix_attestation_read_absent",
		"matrix_attestation_read_conflict",
		"matrix_attestation_read_denied",
		"matrix_attestation_read_malformed",
		"matrix_attestation_read_unavailable",
		"matrix_attestation_read_abandoned",
		"matrix_version_list_conflict",
		"matrix_version_list_denied",
		"matrix_version_list_malformed",
		"matrix_version_list_unavailable",
		"matrix_version_list_abandoned",
		"matrix_intent_create_created",
		"matrix_intent_create_condition_lost",
		"matrix_intent_create_conflict",
		"matrix_intent_create_denied",
		"matrix_intent_create_malformed",
		"matrix_intent_create_unavailable",
		"matrix_intent_create_abandoned",
		"matrix_fence_create_created",
		"matrix_fence_create_condition_lost",
		"matrix_fence_create_conflict",
		"matrix_fence_create_denied",
		"matrix_fence_create_malformed",
		"matrix_fence_create_unavailable",
		"matrix_fence_create_abandoned",
		"matrix_version_delete_deleted",
		"matrix_version_delete_not_found",
		"matrix_version_delete_conflict",
		"matrix_version_delete_denied",
		"matrix_version_delete_malformed",
		"matrix_version_delete_unavailable",
		"matrix_version_delete_abandoned",
		"matrix_attestation_create_created",
		"matrix_attestation_create_condition_lost",
		"matrix_attestation_create_conflict",
		"matrix_attestation_create_denied",
		"matrix_attestation_create_malformed",
		"matrix_attestation_create_unavailable",
		"matrix_attestation_create_abandoned",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			m := evMetaFields(t, evMetaWire(name+"_record"))
			attemptID := evMetaString(t, m, "attempt_identity")
			var a artifact.ErasureAttempt
			for _, kind := range []string{"current_read", "intent_read", "attestation_read", "version_list", "intent_create", "fence_create", "version_delete", "attestation_create"} {
				x := evMetaAttempt(t, "matrix_"+kind)
				if x.Identity() == attemptID {
					a = x
					break
				}
			}
			base := evMetaOptions(t, a, evMetaWire(name+"_record"))
			evMetaNewResponse(t, base, evMetaWire(name))
			mutations := []struct {
				name   string
				change func(*artifact.AttemptResponseOptions)
			}{
				{"version", func(o *artifact.AttemptResponseOptions) {
					o.Version = evMetaVersion(t, a.Request().Key(), artifact.ObjectVersionData, "extra-v1")
				}},
				{"content-kind", func(o *artifact.AttemptResponseOptions) { o.ContentKind = "ciphertext" }},
				{"digest", func(o *artifact.AttemptResponseOptions) { o.ContentDigest = evMetaOther }},
				{"record", func(o *artifact.AttemptResponseOptions) { o.CanonicalRecord = []byte(evMetaFence) }},
				{"entries", func(o *artifact.AttemptResponseOptions) {
					o.Page.Entries = []artifact.VersionEntry{{Version: evMetaVersion(t, a.Request().Key(), artifact.ObjectVersionData, "extra-v1"), IsLatest: true}}
				}},
				{"key-marker", func(o *artifact.AttemptResponseOptions) { o.Page.Next.KeyMarker = a.Request().Key() }},
				{"version-marker", func(o *artifact.AttemptResponseOptions) { o.Page.Next.VersionIDMarker = "extra-v1" }},
				{"truncated", func(o *artifact.AttemptResponseOptions) { o.Page.Truncated = true }},
				{"page-count", func(o *artifact.AttemptResponseOptions) { o.Page.ResponseBytes = 1 }},
				{"response-count", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes = 1 }},
			}
			for _, m := range mutations {
				t.Run(m.name, func(t *testing.T) {
					o := base
					m.change(&o)
					evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
				})
			}
			base.CanonicalRecord = []byte{}
			base.Page.Entries = []artifact.VersionEntry{}
			evMetaNewResponse(t, base, evMetaWire(name))
		})
	}
	for _, kind := range []string{"intent_read", "attestation_read"} {
		o := evMetaOptions(t, evMetaAttempt(t, "matrix_"+kind), evMetaWire("matrix_"+kind+"_absent_record"))
		o.ContentKind = "delete_marker"
		o.Version = evMetaVersion(t, o.Attempt.Request().Key(), artifact.ObjectVersionDeleteMarker, "marker-v1")
		evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
	}
}

func TestEvMetaResponseReadBindingsAndBody(t *testing.T) {
	for _, prefix := range []string{"initial", "proof"} {
		t.Run(prefix, func(t *testing.T) {
			a := evMetaAttempt(t, prefix)
			base := evMetaOptions(t, a, evMetaWire(prefix+"_response_record"))
			evMetaNewResponse(t, base, evMetaWire(prefix+"_response"))
			for _, tc := range []struct {
				name   string
				mutate func(*artifact.AttemptResponseOptions)
				want   error
			}{
				{"zero-version", func(o *artifact.AttemptResponseOptions) { o.Version = artifact.ObjectVersion{} }, artifact.ErrInvalidErasureContract},
				{"marker", func(o *artifact.AttemptResponseOptions) {
					o.Version = evMetaVersion(t, a.Request().Key(), artifact.ObjectVersionDeleteMarker, "fence-v1")
				}, artifact.ErrInvalidErasureContract},
				{"other-key", func(o *artifact.AttemptResponseOptions) {
					o.Version = evMetaVersion(t, "other/key", artifact.ObjectVersionData, "fence-v1")
				}, artifact.ErrErasureBindingMismatch},
				{"other-namespace", func(o *artifact.AttemptResponseOptions) {
					v, e := artifact.NewObjectVersion(evMetaOther, a.Request().Key(), artifact.ObjectVersionData, "fence-v1")
					evMetaError(t, e, nil)
					o.Version = v
				}, artifact.ErrErasureBindingMismatch},
				{"unknown-content", func(o *artifact.AttemptResponseOptions) { o.ContentKind = "historical" }, artifact.ErrInvalidErasureContract},
				{"bad-digest", func(o *artifact.AttemptResponseOptions) { o.ContentDigest = "z" }, artifact.ErrInvalidErasureContract},
				{"zero-digest", func(o *artifact.AttemptResponseOptions) { o.ContentDigest = strings.Repeat("0", 64) }, artifact.ErrInvalidErasureContract},
				{"digest-binding", func(o *artifact.AttemptResponseOptions) { o.ContentDigest = evMetaOther }, artifact.ErrErasureBindingMismatch},
				{"size-binding", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes++ }, artifact.ErrErasureBindingMismatch},
				{"request-ceiling", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes = a.Request().MaximumResponseBytes() + 1 }, artifact.ErrInvalidErasureContract},
				{"zero-count", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes = 0 }, artifact.ErrInvalidErasureContract},
				{"empty-body", func(o *artifact.AttemptResponseOptions) { o.CanonicalRecord = nil }, artifact.ErrInvalidErasureContract},
				{"page-count", func(o *artifact.AttemptResponseOptions) { o.Page.ResponseBytes = 1 }, artifact.ErrInvalidErasureContract},
				{"page-next", func(o *artifact.AttemptResponseOptions) {
					o.Page.Next = artifact.VersionCursor{KeyMarker: a.Request().Key(), VersionIDMarker: "v1"}
				}, artifact.ErrInvalidErasureContract},
				{"page-truncated", func(o *artifact.AttemptResponseOptions) { o.Page.Truncated = true }, artifact.ErrInvalidErasureContract},
				{"page-entry", func(o *artifact.AttemptResponseOptions) {
					o.Page.Entries = []artifact.VersionEntry{{Version: base.Version}}
				}, artifact.ErrInvalidErasureContract},
			} {
				t.Run(tc.name, func(t *testing.T) { o := base; tc.mutate(&o); evMetaBadResponse(t, o, tc.want) })
			}
			for _, body := range []string{"OTAF0001" + evMetaFence, strings.TrimPrefix(evMetaFence, "OTAF0001"), "OTAF0002" + strings.TrimPrefix(evMetaFence, "OTAF0001"), evMetaOperation, evMetaWire("required_version"), evMetaPolicy, evMetaAllowance, evMetaAdmission, "ciphertext", evMetaWire("initial_response")} {
				o := base
				o.CanonicalRecord = []byte(body)
				o.ContentDigest = evMetaHash(body)
				o.ResponseBytes = uint32(len(body))
				evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
			}
		})
	}
	o := evMetaOptions(t, evMetaAttempt(t, "matrix_current_read"), evMetaWire("matrix_current_read_present_record"))
	o.CanonicalRecord = []byte("ciphertext")
	evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
	// Ciphertext hashes and XML counts are metadata claims, not body authentication.
	o = evMetaOptions(t, evMetaAttempt(t, "matrix_current_read"), evMetaWire("matrix_current_read_present_record"))
	o.ContentDigest = evMetaOther
	e, err := artifact.NewAttemptResponseEvidence(o)
	evMetaError(t, err, nil)
	if len(e.RecordBytes()) == 0 {
		t.Fatal("missing response metadata")
	}
}

func TestEvMetaResponseTimesAndCopies(t *testing.T) {
	base := evMetaOptions(t, evMetaAttempt(t, "initial"), evMetaWire("initial_response_record"))
	for _, at := range []time.Time{time.Time{}, evMetaTime(0), evMetaTime(-1), evMetaTime(1002).Add(time.Nanosecond), evMetaTime(1002).In(time.FixedZone("offset", 3600)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1000000000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		o := base
		o.ObservedAt = at
		evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
	}
	o := base
	o.ObservedAt = evMetaTime(1000)
	evMetaBadResponse(t, o, artifact.ErrErasureBindingMismatch)
	o = base
	o.ObservedAt = evMetaTime(1002).In(time.FixedZone("alias", 0))
	evMetaNewResponse(t, o, evMetaWire("initial_response"))
	for _, ms := range []int64{1001, 253402300799999} {
		o := base
		o.ObservedAt = evMetaTime(ms)
		inner := evMetaChange(t, evMetaWire("initial_response_record"), map[string]string{"observed_at_milliseconds": fmt.Sprint(ms)}, true)
		wire := evMetaChange(t, evMetaNested(t, evMetaWire("initial_response"), inner), map[string]string{"observed_at_milliseconds": fmt.Sprint(ms)}, true)
		evMetaNewResponse(t, o, wire)
	}
	e := evMetaNewResponse(t, base, evMetaWire("initial_response"))
	base.CanonicalRecord[0] = 'X'
	evMetaWantEvidence(t, e, evMetaWire("initial_response"))
	evMetaBadResponse(t, artifact.AttemptResponseOptions{}, artifact.ErrInvalidErasureContract)
}

func TestEvMetaResponseListRelationships(t *testing.T) {
	base := evMetaOptions(t, evMetaAttempt(t, "terminal"), evMetaWire("terminal_response_record"))
	evMetaNewResponse(t, base, evMetaWire("terminal_response"))
	for _, tc := range []struct {
		name   string
		mutate func(*artifact.AttemptResponseOptions)
		want   error
	}{
		{"count-claim", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes++ }, artifact.ErrErasureBindingMismatch},
		{"zero-count", func(o *artifact.AttemptResponseOptions) { o.ResponseBytes = 0; o.Page.ResponseBytes = 0 }, artifact.ErrInvalidErasureContract},
		{"count-ceiling", func(o *artifact.AttemptResponseOptions) {
			o.ResponseBytes = o.Attempt.Request().MaximumResponseBytes() + 1
			o.Page.ResponseBytes = o.ResponseBytes
		}, artifact.ErrInvalidErasureContract},
		{"duplicate-token", func(o *artifact.AttemptResponseOptions) {
			o.Page.Entries = append(o.Page.Entries, artifact.VersionEntry{Version: evMetaVersion(t, o.Attempt.Request().Key(), artifact.ObjectVersionDeleteMarker, "fence-v1")})
		}, artifact.ErrInvalidErasureContract},
		{"two-latest", func(o *artifact.AttemptResponseOptions) {
			o.Page.Entries = append(o.Page.Entries, artifact.VersionEntry{Version: evMetaVersion(t, o.Attempt.Request().Key(), artifact.ObjectVersionData, "sibling"), IsLatest: true})
		}, artifact.ErrInvalidErasureContract},
		{"no-latest", func(o *artifact.AttemptResponseOptions) { o.Page.Entries[0].IsLatest = false }, artifact.ErrInvalidErasureContract},
		{"wrong-key", func(o *artifact.AttemptResponseOptions) {
			o.Page.Entries[0].Version = evMetaVersion(t, "other/key", artifact.ObjectVersionData, "fence-v1")
		}, artifact.ErrErasureBindingMismatch},
		{"zero-version", func(o *artifact.AttemptResponseOptions) { o.Page.Entries[0].Version = artifact.ObjectVersion{} }, artifact.ErrInvalidErasureContract},
		{"truncated-no-next", func(o *artifact.AttemptResponseOptions) { o.Page.Truncated = true }, artifact.ErrInvalidErasureContract},
		{"untruncated-next", func(o *artifact.AttemptResponseOptions) {
			o.Page.Next = artifact.VersionCursor{KeyMarker: o.Attempt.Request().Key(), VersionIDMarker: "v2"}
		}, artifact.ErrInvalidErasureContract},
		{"version", func(o *artifact.AttemptResponseOptions) { o.Version = o.Page.Entries[0].Version }, artifact.ErrInvalidErasureContract},
		{"kind", func(o *artifact.AttemptResponseOptions) { o.ContentKind = "fence" }, artifact.ErrInvalidErasureContract},
		{"digest", func(o *artifact.AttemptResponseOptions) { o.ContentDigest = evMetaOther }, artifact.ErrInvalidErasureContract},
		{"body", func(o *artifact.AttemptResponseOptions) { o.CanonicalRecord = []byte(evMetaFence) }, artifact.ErrInvalidErasureContract},
		{"requested-limit", func(o *artifact.AttemptResponseOptions) {
			for i := 0; i < 2; i++ {
				o.Page.Entries = append(o.Page.Entries, artifact.VersionEntry{Version: evMetaVersion(t, o.Attempt.Request().Key(), artifact.ObjectVersionData, fmt.Sprint(i))})
			}
		}, artifact.ErrInvalidErasureContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			o.Page.Entries = append([]artifact.VersionEntry{}, base.Page.Entries...)
			tc.mutate(&o)
			evMetaBadResponse(t, o, tc.want)
		})
	}
	e := evMetaNewResponse(t, base, evMetaWire("terminal_response"))
	base.Page.Entries[0] = artifact.VersionEntry{}
	evMetaWantEvidence(t, e, evMetaWire("terminal_response"))
}

func TestEvMetaResponseConjunctivePageCaps(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		escaped  bool
		wantSize int
		ok       bool
	}{
		{"escaped-80", 80, true, 252885, true}, {"escaped-82", 82, true, 259193, true}, {"escaped-83", 83, true, 262347, false}, {"escaped-256", 256, true, 807989, false}, {"ascii-256", 256, false, 166709, true}, {"count-257", 257, false, 167358, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqWire := evMetaChange(t, evMetaWire("terminal_request"), map[string]string{"page_limit": "256", "maximum_response_bytes": "1048576"}, true)
			r := evMetaRequest(t, reqWire)
			a, err := artifact.NewErasureAttempt(r, 2, evMetaTime(1004))
			evMetaError(t, err, nil)
			o := artifact.AttemptResponseOptions{Attempt: a, Code: artifact.AttemptResponsePresent, ObservedAt: evMetaTime(253402300799999), ResponseBytes: 1048576, Page: artifact.VersionPage{ResponseBytes: 1048576, Entries: []artifact.VersionEntry{}}}
			entries := []string{}
			for i := 0; i < tc.count; i++ {
				ch := "a"
				if tc.escaped {
					ch = "<"
				}
				token := strings.Repeat(ch, 501) + fmt.Sprintf("%03d", i)
				v := evMetaVersion(t, r.Key(), artifact.ObjectVersionDeleteMarker, token)
				o.Page.Entries = append(o.Page.Entries, artifact.VersionEntry{Version: v, IsLatest: i == 0})
				// The expected identity includes the exact key preimage.
				unsigned := `{"contract":"open-trestle/artifact-object-version","schema_version":1,"namespace_identity":` + evMetaJSON(r.NamespaceIdentity()) + `,"key":` + evMetaJSON(r.Key()) + `,"kind":"delete_marker","version_id":` + evMetaJSON(token) + `}`
				id := evMetaHash("open-trestle/artifact-object-version/v1\x00" + unsigned)
				if id != v.Identity() {
					t.Fatal("typed version identity")
				}
				entries = append(entries, `{"version_identity":`+evMetaJSON(id)+`,"kind":"delete_marker","version_id":`+evMetaJSON(token)+`,"is_latest":`+fmt.Sprint(i == 0)+`}`)
			}
			inner := evMetaChange(t, evMetaWire("terminal_response_record"), map[string]string{"attempt_identity": evMetaJSON(a.Identity()), "observed_at_milliseconds": "253402300799999", "response_bytes": "1048576", "entries": "[" + strings.Join(entries, ",") + "]"}, true)
			if len(inner) != tc.wantSize {
				t.Fatalf("independent canonical size %d want %d", len(inner), tc.wantSize)
			}
			if !tc.ok {
				evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
				return
			}
			wire := evMetaChange(t, evMetaWire("terminal_response"), map[string]string{"attempt_identity": evMetaJSON(a.Identity()), "slot": evMetaJSON("response:" + a.Identity()), "observed_at_milliseconds": "253402300799999", "record_hex": evMetaJSON(hex.EncodeToString([]byte(inner)))}, true)
			evMetaNewResponse(t, o, wire)
		})
	}
}

func TestEvMetaResponseListLiteralOrderCursorsAndEscapes(t *testing.T) {
	for _, name := range []string{"list_provider_order", "list_continuation", "list_truncated", "list_escaped", "list_one_byte", "list_max_raw_bytes"} {
		t.Run(name, func(t *testing.T) {
			a := evMetaAttempt(t, name)
			o := evMetaOptions(t, a, evMetaWire(name+"_record"))
			evMetaNewResponse(t, o, evMetaWire(name))
		})
	}
	base := evMetaOptions(t, evMetaAttempt(t, "list_truncated"), evMetaWire("list_truncated_record"))
	for _, tc := range []struct {
		name  string
		next  artifact.VersionCursor
		empty bool
		want  error
	}{
		{"key-only", artifact.VersionCursor{KeyMarker: base.Attempt.Request().Key()}, false, artifact.ErrInvalidErasureContract},
		{"token-only", artifact.VersionCursor{VersionIDMarker: "next"}, false, artifact.ErrInvalidErasureContract},
		{"wrong-key", artifact.VersionCursor{KeyMarker: "other/key", VersionIDMarker: "next"}, false, artifact.ErrErasureBindingMismatch},
		{"invalid-key", artifact.VersionCursor{KeyMarker: "../bad", VersionIDMarker: "next"}, false, artifact.ErrInvalidErasureContract},
		{"null-token", artifact.VersionCursor{KeyMarker: base.Attempt.Request().Key(), VersionIDMarker: "null"}, false, artifact.ErrInvalidErasureContract},
		{"empty-truncated", base.Page.Next, true, artifact.ErrInvalidErasureContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			o.Page.Next = tc.next
			if tc.empty {
				o.Page.Entries = nil
			}
			evMetaBadResponse(t, o, tc.want)
		})
	}
	req := evMetaRequest(t, evMetaChange(t, evMetaWire("list_truncated_request"), map[string]string{"key_marker": evMetaJSON(base.Page.Next.KeyMarker), "version_id_marker": evMetaJSON(base.Page.Next.VersionIDMarker)}, true))
	a, err := artifact.NewErasureAttempt(req, 2, evMetaTime(1004))
	evMetaError(t, err, nil)
	base.Attempt = a
	evMetaBadResponse(t, base, artifact.ErrInvalidErasureContract)
	for _, token := range []string{"", "null", "has space", "tab\t", "line\n", "\x00", strings.Repeat("x", 505), "wide\u00a0space"} {
		inner := evMetaChange(t, evMetaWire("initial_response_record"), map[string]string{"version_id": evMetaJSON(token)}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), inner), artifact.ErrInvalidErasureContract)
	}
	for _, kind := range []string{"DATA", "marker", "version", "null"} {
		inner := evMetaChange(t, evMetaWire("initial_response_record"), map[string]string{"version_kind": evMetaJSON(kind)}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("initial_response"), inner), artifact.ErrInvalidErasureContract)
	}
}

func TestEvMetaResponseAvailableBodyLineage(t *testing.T) {
	for _, tc := range []struct {
		prefix, kind, body string
		fields             []string
	}{
		{"initial", "fence", evMetaFence, []string{"namespace_identity", "scope_identity", "operation_identity", "artifact_identity"}},
		{"matrix_intent_read", "operation", evMetaOperation, []string{"namespace_identity", "scope_identity", "operation_identity", "artifact_identity", "admission_identity", "original_authorization_identity", "authorization_document_digest"}},
		{"proof", "attestation", evMetaWire("attestation"), []string{"namespace_identity", "scope_identity", "operation_identity", "artifact_identity", "admission_identity", "original_authorization_identity", "authorization_document_digest"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			recordName := tc.prefix + "_response_record"
			wireName := tc.prefix + "_response"
			if tc.prefix == "matrix_intent_read" {
				recordName = tc.prefix + "_present_record"
				wireName = tc.prefix + "_present"
			}
			base := evMetaOptions(t, evMetaAttempt(t, tc.prefix), evMetaWire(recordName))
			evMetaNewResponse(t, base, evMetaWire(wireName))
			for _, field := range tc.fields {
				t.Run(field, func(t *testing.T) {
					body := strings.TrimPrefix(tc.body, "OTAF0001")
					if tc.kind == "operation" && field == "operation_identity" {
						field = "prepared_at_milliseconds"
						body = evMetaChange(t, body, map[string]string{field: "1001"}, true)
					} else {
						body = evMetaChange(t, body, map[string]string{field: evMetaJSON(evMetaOther)}, true)
					}
					if tc.kind == "fence" {
						body = "OTAF0001" + body
					}
					o := base
					o.CanonicalRecord = []byte(body)
					o.ContentDigest = evMetaHash(body)
					o.ResponseBytes = uint32(len(body))
					evMetaBadResponse(t, o, artifact.ErrErasureBindingMismatch)
				})
			}
		})
	}
	// The framed body is compared in full at the operation-aware boundary.
	body := "OTAF0001" + evMetaChange(t, strings.TrimPrefix(evMetaFence, "OTAF0001"), map[string]string{"prepared_at_milliseconds": "999"}, true)
	parent := evMetaResponseChange(t, "initial_response", map[string]string{"record_hex": evMetaJSON(evMetaHex(body)), "content_digest": evMetaJSON(evMetaHash(body)), "response_bytes": evMetaJSON(len(body))})
	e, err := artifact.NewFenceObservationEvidence(evMetaOp(t), evMetaKey(t), parent, evMetaTime(1003))
	evMetaError(t, err, artifact.ErrErasureBindingMismatch)
	evMetaZeroEvidence(t, e)
	v, err := artifact.NewErasureVerification(evMetaOp(t), evMetaEvidence(t, "fence_evidence"), []artifact.ErasureEvidence{evMetaEvidence(t, "terminal_response")}, evMetaResponseChange(t, "final_response", map[string]string{"record_hex": evMetaJSON(evMetaHex(body)), "content_digest": evMetaJSON(evMetaHash(body)), "response_bytes": evMetaJSON(len(body))}), evMetaTime(1008))
	evMetaError(t, err, artifact.ErrErasureBindingMismatch)
	evMetaZeroVerification(t, v)
}

func TestEvMetaResponseNumericClaimsStayBounded(t *testing.T) {
	req := evMetaRequest(t, evMetaChange(t, evMetaWire("matrix_current_read_request"), map[string]string{"maximum_response_bytes": "33554432"}, true))
	a, err := artifact.NewErasureAttempt(req, 1, evMetaTime(1001))
	evMetaError(t, err, nil)
	for _, count := range []uint32{1, 33554432} {
		inner := evMetaChange(t, evMetaWire("matrix_current_read_present_record"), map[string]string{"attempt_identity": evMetaJSON(a.Identity()), "response_bytes": evMetaJSON(count)}, true)
		wire := evMetaChange(t, evMetaNested(t, evMetaWire("matrix_current_read_present"), inner), map[string]string{"attempt_identity": evMetaJSON(a.Identity()), "slot": evMetaJSON("response:" + a.Identity())}, true)
		o := evMetaOptions(t, a, inner)
		e := evMetaNewResponse(t, o, wire)
		if len(e.RecordBytes()) > 2048 {
			t.Fatal("numeric claim expanded into a body")
		}
	}
	o := evMetaOptions(t, a, evMetaWire("matrix_current_read_present_record"))
	for _, count := range []uint32{0, 33554433, 4294967295} {
		o.ResponseBytes = count
		evMetaBadResponse(t, o, artifact.ErrInvalidErasureContract)
	}
	for _, count := range []string{"4294967296", "33554433", "0"} {
		inner := evMetaChange(t, evMetaWire("matrix_current_read_present_record"), map[string]string{"response_bytes": count}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("matrix_current_read_present"), inner), artifact.ErrInvalidErasureContract)
	}
}

func TestEvMetaResponseClosedVocabulary(t *testing.T) {
	for _, code := range []string{"", "unknown", "PRESENT", "success", "not-found"} {
		inner := evMetaChange(t, evMetaWire("matrix_current_read_unavailable_record"), map[string]string{"code": evMetaJSON(code)}, true)
		evMetaDeniedEvidence(t, evMetaNested(t, evMetaWire("matrix_current_read_unavailable"), inner), artifact.ErrInvalidErasureContract)
	}
	for _, tc := range []struct{ prefix, kind, body string }{
		{"initial", "operation", evMetaOperation}, {"initial", "attestation", evMetaWire("attestation")}, {"proof", "fence", evMetaFence},
	} {
		base := evMetaOptions(t, evMetaAttempt(t, tc.prefix), evMetaWire(tc.prefix+"_response_record"))
		base.ContentKind = tc.kind
		base.CanonicalRecord = []byte(tc.body)
		base.ContentDigest = evMetaHash(tc.body)
		base.ResponseBytes = uint32(len(tc.body))
		evMetaBadResponse(t, base, artifact.ErrInvalidErasureContract)
	}
}
