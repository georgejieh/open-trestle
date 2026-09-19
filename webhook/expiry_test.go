package webhook

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

type retiredNoticeStore struct {
	Store
	err error
}

func (s retiredNoticeStore) Get(context.Context, RepositoryScope, Source, string) (StoredDelivery, bool, error) {
	return StoredDelivery{}, false, s.err
}

func TestSupervisorSkipsOnlyExplicitlyExpiredNotices(t *testing.T) {
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	processor, _ := NewProcessor(coordinator, supervisorPlanner{identity: strings.Repeat("d", 64)})
	unavailable := errors.New("storage unavailable")
	for _, failure := range []error{ErrDeliveryExpired, unavailable} {
		store := retiredNoticeStore{Store: NewMemoryStore(), err: failure}
		supervisor, err := NewSupervisor(store, processor, scope, SourceGitHub, SupervisorOptions{QueueCapacity: 1, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond, Clock: supervisorClock{at: time.UnixMilli(1000)}})
		if err != nil {
			t.Fatal(err)
		}
		err = supervisor.processNotice(context.Background(), DeliveryNotice{Scope: scope, Source: SourceGitHub, DeduplicationKey: strings.Repeat("a", 64)})
		if failure == ErrDeliveryExpired && err != nil {
			t.Fatalf("retired hint blocked reconciliation: %v", err)
		}
		if failure == unavailable && !errors.Is(err, unavailable) {
			t.Fatalf("real storage error hidden: %v", err)
		}
	}
}
