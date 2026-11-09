package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// The daemon answers the refusal route from its inbox for exactly the
// planner it admits deliveries with, and only for webhook run scopes.
func TestDaemonDeliveryRefusalsReadTheInboxForThisPlanner(t *testing.T) {
	ctx := context.Background()
	store := webhook.NewMemoryStore()
	repository, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repository, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{}`), time.UnixMilli(1000))
	stored, _, err := store.Put(ctx, delivery, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	planner := strings.Repeat("d", 64)
	record, _ := webhook.NewRefusalRecord(stored, planner, webhook.RefusalReasonRetriesExhausted, time.UnixMilli(2000))
	if _, _, err := store.RecordRefusal(ctx, record); err != nil {
		t.Fatal(err)
	}
	reader := daemonDeliveryRefusals{store: store, source: webhook.SourceGitHub, plannerIdentity: planner}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", webhook.ReviewRunIDForDelivery(delivery))
	if got, found, err := reader.DeliveryRefusal(ctx, scope); err != nil || !found || got.Identity() != record.Identity() {
		t.Fatalf("refusal=(%t,%v)", found, err)
	}
	other := daemonDeliveryRefusals{store: store, source: webhook.SourceGitHub, plannerIdentity: strings.Repeat("e", 64)}
	if _, found, err := other.DeliveryRefusal(ctx, scope); err != nil || found {
		t.Fatal("another planner's refusal was reported")
	}
	for _, run := range []string{"run-a", "webhook-short", "webhook-" + strings.Repeat("Z", 64)} {
		nonWebhook, _ := audit.NewReviewScope("tenant-a", "repo-a", run)
		if _, found, err := reader.DeliveryRefusal(ctx, nonWebhook); err != nil || found {
			t.Fatalf("run %s reported a refusal: %v", run, err)
		}
	}
}
