package client

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/webhook"
)

type clientRefusals struct{ record webhook.RefusalRecord }

func (r clientRefusals) DeliveryRefusal(_ context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, bool, error) {
	return r.record, scope.ReviewRunID() == "webhook-"+r.record.DeduplicationKey(), nil
}

func TestGetDeliveryRefusalReadsTheRecordedReason(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{}`), time.UnixMilli(1000))
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), "invalid_pull_request_payload", time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	principal, _ := httpapi.NewPrincipal("reader", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	authenticator, _ := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: strings.Repeat("a", 32), Principal: principal}})
	api, _ := httpapi.NewServer(coordinator, authenticator, httpapi.SystemClock{})
	api, err = api.WithDeliveryRefusals(clientRefusals{record: record})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api)
	defer server.Close()
	c, err := New(server.URL, strings.Repeat("a", 32), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "webhook-"+delivery.DeduplicationKey())
	got, err := c.GetDeliveryRefusal(context.Background(), scope)
	if err != nil || got.Identity() != record.Identity() || got.Reason() != "invalid_pull_request_payload" {
		t.Fatalf("refusal=%v", err)
	}
	other, _ := audit.NewReviewScope("tenant-a", "repo-a", "webhook-"+strings.Repeat("b", 64))
	var apiErr *APIError
	if _, err := c.GetDeliveryRefusal(context.Background(), other); !errors.As(err, &apiErr) || apiErr.Code() != "not_found" {
		t.Fatalf("missing refusal err=%v", err)
	}
}
