package webhook

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"
)

type supervisorPlanner struct{ identity string }

func (p supervisorPlanner) Identity() string { return p.identity }
func (p supervisorPlanner) Plan(_ context.Context, stored StoredDelivery) (controlplane.ReviewRunPlan, error) {
	delivery := stored.Delivery()
	scope, _ := audit.NewReviewScope(delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), ReviewRunIDForDelivery(delivery))
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, delivery.Identity(), strings.Repeat("b", 64), nil, 2, 100, 1000, true)
	return controlplane.NewReviewRunPlan(scope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
}
func TestSupervisorReconcilesDurableInboxAndOpensRun(t *testing.T) {
	repositoryScope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := NewVerifiedDelivery(repositoryScope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"value":true}`), time.UnixMilli(1000))
	store := NewMemoryStore()
	_, _, _ = store.Put(context.Background(), delivery, time.UnixMilli(1000))
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	processor, _ := NewProcessor(coordinator, supervisorPlanner{identity: strings.Repeat("d", 64)})
	supervisor, err := NewSupervisor(store, processor, repositoryScope, SourceGitHub, SupervisorOptions{QueueCapacity: 4, MaximumRetries: 3, RetryDelay: 10 * time.Millisecond, Clock: supervisorClock{at: time.UnixMilli(1001)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-supervisor.Ready():
	case <-time.After(time.Second):
		t.Fatal("supervisor not ready")
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", ReviewRunIDForDelivery(delivery))
	plan, state, err := coordinator.Resume(context.Background(), scope)
	if err != nil || plan.Identity() == "" || state.Revision() == 0 {
		t.Fatalf("resume=(%#v,%#v,%v)", plan, state, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestSupervisorNotificationIsBoundedAndScopeChecked(t *testing.T) {
	repositoryScope, _ := NewRepositoryScope("tenant-a", "repo-a")
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	processor, _ := NewProcessor(coordinator, supervisorPlanner{identity: strings.Repeat("d", 64)})
	supervisor, _ := NewSupervisor(NewMemoryStore(), processor, repositoryScope, SourceGitHub, SupervisorOptions{QueueCapacity: 1, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond, Clock: supervisorClock{at: time.UnixMilli(1)}})
	other, _ := NewRepositoryScope("tenant-b", "repo-a")
	if supervisor.Notify(DeliveryNotice{Scope: other, Source: SourceGitHub, DeduplicationKey: strings.Repeat("a", 64)}) {
		t.Fatal("accepted foreign notice")
	}
	if !supervisor.Notify(DeliveryNotice{Scope: repositoryScope, Source: SourceGitHub, DeduplicationKey: strings.Repeat("a", 64)}) {
		t.Fatal("first notice rejected")
	}
	if supervisor.Notify(DeliveryNotice{Scope: repositoryScope, Source: SourceGitHub, DeduplicationKey: strings.Repeat("b", 64)}) {
		t.Fatal("full queue reported direct acceptance")
	}
}

type supervisorClock struct{ at time.Time }

func (c supervisorClock) Now() time.Time { return c.at }
