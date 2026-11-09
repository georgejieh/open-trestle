package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/webhook"
)

type refusalService struct {
	fakeService
	record webhook.RefusalRecord
	found  bool
}

func (s *refusalService) GetDeliveryRefusal(context.Context, audit.ReviewScope) (webhook.RefusalRecord, error) {
	if !s.found {
		return webhook.RefusalRecord{}, errors.New("not found")
	}
	return s.record, nil
}

// A delivery that intake refused has no run to watch: the terminal shows the
// recorded refusal and its reason instead of failing to load a run, but only
// when the run is not found; any other read failure stays an error.
func TestRunShowsADeliveryRefusalWhenNoRunExists(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"secret":"payload"}`), time.UnixMilli(1000))
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), webhook.RefusalReasonRetriesExhausted, time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", webhook.ReviewRunIDForDelivery(delivery))
	service := &refusalService{fakeService: fakeService{runErr: fmt.Errorf("read run: %w", controlplane.ErrRunNotOpened)}, record: record, found: true}
	var output bytes.Buffer
	view, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Run(context.Background()); err != nil {
		t.Fatalf("refused delivery failed the view: %v", err)
	}
	rendered := output.String()
	for _, want := range []string{"Run         not opened", "Refusal     retries_exhausted (the delivery kept failing on its own until its retries were spent)", "Refused     1970-01-01 00:00:02 UTC", "Delivery    " + delivery.Identity()} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "secret") {
		t.Fatal("refusal view rendered delivery content")
	}
	service.runErr = errors.New("daemon unavailable")
	output.Reset()
	view, _ = New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err := view.Run(context.Background()); err == nil || strings.Contains(output.String(), "Refusal") {
		t.Fatalf("a transient read failure was shown as a refusal: %v\n%s", err, output.String())
	}
	service.runErr = controlplane.ErrRunNotOpened
	service.found = false
	output.Reset()
	view, _ = New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err := view.Run(context.Background()); err == nil {
		t.Fatal("a missing run without a refusal was not reported as an error")
	}
}
