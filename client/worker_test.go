package client

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type clientClock struct{ at time.Time }

func (c clientClock) Now() time.Time { return c.at }
func TestClientWorkerLeaseRoundTrip(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-worker")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	principal, _ := httpapi.NewPrincipal("worker-1", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunWrite, httpapi.CapabilityTaskClaim, httpapi.CapabilityTaskComplete})
	authenticator, _ := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: clientTestToken, Principal: principal}})
	journal := controlplane.NewMemoryRunJournal()
	queue := controlplane.NewMemoryTaskNotificationQueue()
	handler, _ := httpapi.NewServerWithRuntimeServices(journal, authenticator, clientClock{at: time.UnixMilli(1000)}, diagnostics.NewMemoryStore(), queue)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := New(server.URL, clientTestToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitRun(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	notification, found, err := client.ClaimTaskNotification(context.Background(), scope, 0, time.Second)
	if err != nil || !found || notification.Notification().TaskKey() != "source" {
		t.Fatalf("notification=(%#v,%v,%v)", notification, found, err)
	}
	if err := client.AcknowledgeTaskNotification(context.Background(), scope, notification); err != nil {
		t.Fatal(err)
	}
	if _, found, err := client.ClaimTaskNotification(context.Background(), scope, 0, time.Second); err != nil || found {
		t.Fatalf("empty notification=(%v,%v)", found, err)
	}
	lease, err := client.ClaimTask(context.Background(), scope, "source", strings.Repeat("d", 64))
	if err != nil || lease.WorkerIdentity() != "worker-1" {
		t.Fatalf("lease=(%#v,%v)", lease, err)
	}
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	receipt, err := client.CompleteTask(context.Background(), scope, lease, completion)
	if err != nil {
		t.Fatal(err)
	}
	state, found := receipt.Task("source")
	if !found || state.Status() != controlplane.TaskRuntimeSucceeded || receipt.Status() != controlplane.ReviewRunSucceeded || receipt.OutputIdentity() != completion.OutputIdentity() {
		t.Fatalf("state=%#v receipt=%#v", state, receipt)
	}
	finalized, err := client.FinalizeRun(context.Background(), scope, completion)
	if err != nil || finalized.Status() != controlplane.ReviewRunSucceeded || finalized.OutputIdentity() != completion.OutputIdentity() {
		t.Fatalf("finalized=(%#v,%v)", finalized, err)
	}
}
