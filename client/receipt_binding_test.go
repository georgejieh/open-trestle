package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type receiptTransport func(*http.Request) (*http.Response, error)

func (f receiptTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func receiptBindingFixture(t *testing.T, tenant, repository, run, requestID string) (controlplane.ReviewRunPlan, controlplane.ReviewRunReceipt, controlplane.TaskLease) {
	t.Helper()
	scope, err := audit.NewReviewScope(tenant, repository, run)
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, requestID, strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := coordinator.ClaimTask(context.Background(), plan, "source", task.HandlerIdentity(), "worker-a", time.UnixMilli(101))
	if err != nil || !found {
		t.Fatalf("claim: found=%t err=%v", found, err)
	}
	return plan, receipt, lease
}

func TestReceiptOperationsRejectCrossWiredScope(t *testing.T) {
	plan, _, lease := receiptBindingFixture(t, "tenant-a", "repo-a", "run-a", strings.Repeat("b", 64))
	completion, err := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		name   string
		status int
		invoke func(*Client) (controlplane.ReviewRunReceipt, error)
	}{
		{"get", http.StatusOK, func(c *Client) (controlplane.ReviewRunReceipt, error) {
			return c.GetRun(context.Background(), plan.Scope())
		}},
		{"submit", http.StatusAccepted, func(c *Client) (controlplane.ReviewRunReceipt, error) { return c.SubmitRun(context.Background(), plan) }},
		{"cancel", http.StatusOK, func(c *Client) (controlplane.ReviewRunReceipt, error) {
			return c.CancelRun(context.Background(), plan.Scope())
		}},
		{"finalize", http.StatusOK, func(c *Client) (controlplane.ReviewRunReceipt, error) {
			return c.FinalizeRun(context.Background(), plan.Scope(), completion)
		}},
		{"complete", http.StatusOK, func(c *Client) (controlplane.ReviewRunReceipt, error) {
			return c.CompleteTask(context.Background(), plan.Scope(), lease, completion)
		}},
	}
	for _, scope := range [][3]string{{"tenant-b", "repo-a", "run-a"}, {"tenant-a", "repo-b", "run-a"}, {"tenant-a", "repo-a", "run-b"}} {
		_, wrong, _ := receiptBindingFixture(t, scope[0], scope[1], scope[2], strings.Repeat("b", 64))
		for _, op := range operations {
			t.Run(op.name+"/"+strings.Join(scope[:], "/"), func(t *testing.T) {
				transport := receiptTransport(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: op.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(responseBody(t, wrong))))}, nil
				})
				c, err := New("https://example.invalid", clientTestToken, &http.Client{Transport: transport})
				if err != nil {
					t.Fatal(err)
				}
				got, err := op.invoke(c)
				if !errors.Is(err, ErrInvalidResponse) || got.Identity() != "" {
					t.Fatalf("cross-wired receipt accepted: identity=%s err=%v", got.Identity(), err)
				}
			})
		}
	}
}

func TestSubmitRejectsReceiptForDifferentPlan(t *testing.T) {
	plan, _, _ := receiptBindingFixture(t, "tenant-a", "repo-a", "run-a", strings.Repeat("b", 64))
	other, receipt, _ := receiptBindingFixture(t, "tenant-a", "repo-a", "run-a", strings.Repeat("f", 64))
	if other.Identity() == plan.Identity() || receipt.Scope().Identity() != plan.Scope().Identity() {
		t.Fatal("invalid cross-plan fixture")
	}
	transport := receiptTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(responseBody(t, receipt))))}, nil
	})
	c, err := New("https://example.invalid", clientTestToken, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.SubmitRun(context.Background(), plan)
	if !errors.Is(err, ErrInvalidResponse) || got.Identity() != "" {
		t.Fatalf("wrong plan accepted: identity=%s err=%v", got.Identity(), err)
	}
}
