package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/tui"
	"github.com/georgejieh/open-trestle/webhook"
)

// trestle tui reads refusals through the same API client.
var _ tui.RefusalService = (*client.Client)(nil)

type cliRefusals struct{ record webhook.RefusalRecord }

func (r cliRefusals) DeliveryRefusal(_ context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, bool, error) {
	return r.record, scope.ReviewRunID() == "webhook-"+r.record.DeduplicationKey(), nil
}

// A refused delivery has no run: runs status names the recorded reason, and
// runs refusal prints the content-free refusal record.
func TestRunsReportADeliveryRefusal(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"secret":"payload"}`), time.UnixMilli(1000))
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), "invalid_pull_request_payload", time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	principal, _ := httpapi.NewPrincipal("reader", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	token := "01234567890123456789012345678901"
	authenticator, _ := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: token, Principal: principal}})
	api, _ := httpapi.NewServer(coordinator, authenticator, httpapi.SystemClock{})
	api, err = api.WithDeliveryRefusals(cliRefusals{record: record})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api)
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", token)
	scopeArgs := []string{"--tenant", "tenant-a", "--repository", "repo-a", "--run", "webhook-" + delivery.DeduplicationKey(), "--server", server.URL}
	var stdout, stderr bytes.Buffer
	if exit := run(append([]string{"runs", "status"}, scopeArgs...), &stdout, &stderr); exit != 1 || !strings.Contains(stderr.String(), "intake refused the delivery: invalid_pull_request_payload") {
		t.Fatalf("status exit=%d stderr=%s", exit, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run(append([]string{"runs", "refusal"}, scopeArgs...), &stdout, &stderr); exit != 0 {
		t.Fatalf("refusal exit=%d stderr=%s", exit, stderr.String())
	}
	parsed, err := webhook.ParseRefusalRecord(bytes.TrimSuffix(stdout.Bytes(), []byte("\n")))
	if err != nil || parsed.Identity() != record.Identity() || strings.Contains(stdout.String(), "secret") {
		t.Fatalf("refusal output=%s err=%v", stdout.String(), err)
	}
}
