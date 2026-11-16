//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/internal/review"
)

type mismatchedGenerationScanner struct {
	review.GenerationRequestSanitizer
}

func (s mismatchedGenerationScanner) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	d := s.GenerationRequestSanitizer.ExpectedBinaryDigests()
	d.WorkerSHA256 = strings.Repeat("f", 64)
	return d
}

type mismatchedVerificationScanner struct {
	review.VerificationRequestSanitizer
}

func (s mismatchedVerificationScanner) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	d := s.VerificationRequestSanitizer.ExpectedBinaryDigests()
	d.WorkerSHA256 = strings.Repeat("e", 64)
	return d
}

type generationRejectionExpiryClock struct{ at time.Time }

func (c generationRejectionExpiryClock) Now() time.Time { return c.at }

func testGenerationRejectionStartupRefusals(t *testing.T, args []string, getenv func(string) string, scope audit.ReviewScope) {
	t.Helper()
	state := daemonTestFlagValue(t, args, "--state-dir")
	auditPath := filepath.Join(state, "audit", scope.Identity()+".audit.jsonl")
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical last event names the host-authored rejection artifact.
	rows := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	events, err := audit.ParseEvent(rows[len(rows)-1])
	if err != nil {
		t.Fatal(err)
	}
	rejectionPath := filepath.Join(state, "artifacts", scope.Identity()+"-"+events.SubjectIdentity()+".artifact.json")
	rejected, err := os.ReadFile(rejectionPath)
	if err != nil {
		t.Fatal(err)
	}
	refusal := func(name string, deps daemonDependencies) {
		t.Helper()
		d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
		if d != nil {
			d.Close()
			t.Fatalf("%s admitted", name)
		}
		if err == nil {
			t.Fatalf("%s had no refusal", name)
		}
	}
	deps := func() daemonDependencies {
		return daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()}
	}
	for _, path := range []string{auditPath, rejectionPath} {
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		refusal("missing evidence", deps())
		if err := os.WriteFile(path, saved, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("malformed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		refusal("malformed evidence", deps())
		if err := os.WriteFile(path, saved, 0600); err != nil {
			t.Fatal(err)
		}
	}
	extra := filepath.Join(state, "artifacts", scope.Identity()+"-"+strings.Repeat("f", 64)+".artifact.json")
	if err := os.WriteFile(extra, rejected, 0600); err != nil {
		t.Fatal(err)
	}
	refusal("orphan artifact", deps())
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(append([]byte{}, raw...), append(rows[len(rows)-1], '\n')...), 0600); err != nil {
		t.Fatal(err)
	}
	refusal("extra audit", deps())
	if err := os.WriteFile(auditPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []audit.EventKind{audit.EventRouteContinuationPlanned, audit.EventPublicationClaimed} {
		extraEvent, err := audit.NewEvent(scope, events.Sequence()+1, events.Identity(), kind, strings.Repeat("a", 64), []string{events.SubjectIdentity()}, time.UnixMilli(events.OccurredAtUnixMilliseconds()))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := audit.EncodeEvent(extraEvent)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(auditPath, append(append([]byte{}, raw...), append(encoded, '\n')...), 0600); err != nil {
			t.Fatal(err)
		}
		refusal("additional effect evidence", deps())
		if err := os.WriteFile(auditPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	changed := deps()
	changed.generationSanitizer = mismatchedGenerationScanner{changed.generationSanitizer}
	refusal("changed scanner", changed)
	changedVerifier := deps()
	changedVerifier.verificationSanitizer = mismatchedVerificationScanner{changedVerifier.verificationSanitizer}
	refusal("changed verification catalog enrollment", changedVerifier)
	// Past retention the settled rejection is proved from its journal and
	// audit alone, so startup admits it without reading the expired bytes;
	// the audit chain must still hold.
	expired := deps()
	expired.clock = generationRejectionExpiryClock{time.Now().UTC().Add(48 * time.Hour)}
	lapsed, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, expired)
	if err != nil {
		t.Fatalf("settled rejection refused after retention: %v", err)
	}
	if err := lapsed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(append([]byte{}, raw...), append(rows[len(rows)-1], '\n')...), 0600); err != nil {
		t.Fatal(err)
	}
	refusal("extra audit after retention", expired)
	if err := os.WriteFile(auditPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
