package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func boundaryDiagnosticSet(t *testing.T, scope audit.ReviewScope) diagnostics.Set {
	t.Helper()
	findings := []diagnostics.Finding{}
	build := func(extra int) (diagnostics.Set, int, bool) {
		candidate := append([]diagnostics.Finding(nil), findings...)
		if extra > 0 {
			i := len(candidate) + 1
			finding, err := diagnostics.NewFinding(fmt.Sprintf("%064x", i), fmt.Sprintf("%064x", i+100), "verified issue", strings.Repeat("<", extra), diagnostics.SeverityWarning, "a.go", 1, 1, []string{strings.Repeat("c", 64)})
			if err != nil {
				t.Fatal(err)
			}
			candidate = append(candidate, finding)
		}
		set, err := diagnostics.NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), candidate)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := diagnostics.EncodeSet(set)
		return set, len(encoded), err == nil
	}
	for len(findings) < 99 {
		set, _, fits := build(4096)
		if !fits {
			break
		}
		findings = set.Findings()
	}
	low, high := 1, 4096
	var best diagnostics.Set
	var size int
	for low <= high {
		middle := (low + high) / 2
		set, n, fits := build(middle)
		if fits {
			best, size = set, n
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best.Identity() == "" || size > (1<<20) || size < (1<<20)-6 {
		t.Fatalf("fixture not at domain bound: %d", size)
	}
	return best
}

func TestClientAcceptsMaximumDiagnosticsInsideAPIEnvelope(t *testing.T) {
	plan, _, _ := receiptBindingFixture(t, "tenant-a", "repo-a", "run-a", strings.Repeat("b", 64))
	set := boundaryDiagnosticSet(t, plan.Scope())
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "diagnostics": json.RawMessage(encoded)})
	if err != nil || len(envelope) <= 1<<20 {
		t.Fatal("fixture does not cross old whole-body bound")
	}
	store := diagnostics.NewMemoryStore()
	if _, err := store.PutDiagnosticSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	principal, err := httpapi.NewPrincipal("observer", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: clientTestToken, Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.NewServerWithDiagnostics(coordinator, auth, clientClock{at: time.UnixMilli(200)}, store)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := New(server.URL, clientTestToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := client.GetDiagnosticSet(context.Background(), plan.Scope())
	if err != nil || actual.Identity() != set.Identity() {
		t.Fatalf("valid maximum diagnostic set rejected: %v", err)
	}
}

func TestClientRejectsBytesBeyondWholeResponseBudget(t *testing.T) {
	_, tooLarge, err := readClientBody(bytes.NewReader(make([]byte, maxClientResponseBytes+1)))
	if err != nil || !tooLarge {
		t.Fatalf("response budget not enforced: tooLarge=%t err=%v", tooLarge, err)
	}
}
