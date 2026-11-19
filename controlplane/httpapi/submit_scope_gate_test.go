package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestServerSubmitWaitsForInFlightScopeEffect(t *testing.T) {
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	principal, err := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead, CapabilityRunWrite})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(coordinator, authenticator, fixedClock{at: time.UnixMilli(1000)})
	if err != nil {
		t.Fatal(err)
	}
	plan := apiPlan(t)
	encodedPlan, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// A worker holds a scope intent while the caller-authored plan is saved,
	// opened and advanced. Submission must wait for it instead of reading its
	// transient marker as an unresolved effect.
	entered, release := make(chan struct{}), make(chan struct{})
	effectDone := make(chan error, 1)
	go func() {
		effectDone <- journal.WithScopeIntent(context.Background(), plan.Scope(), "test-effect", strings.Repeat("6", 64), func(context.Context) error {
			close(entered)
			<-release
			return nil
		}, func(context.Context) error { return nil })
	}()
	<-entered
	waiting, stop, err := journal.WatchEffectGateContention()
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer stop()
	submitted := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encodedPlan))
		submitted <- response
	}()
	select {
	case <-waiting:
	case response := <-submitted:
		close(release)
		t.Fatalf("submission did not wait for the in-flight effect: status=%d body=%s", response.Code, response.Body.String())
	}
	close(release)
	if err := <-effectDone; err != nil {
		t.Fatal(err)
	}
	response := <-submitted
	if response.Code != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", response.Code, response.Body.String())
	}
	if receipt := decodeAPIReceipt(t, response.Body.Bytes()); receipt.PlanIdentity() != plan.Identity() || receipt.Status() != controlplane.ReviewRunActive {
		t.Fatalf("receipt=%#v", receipt)
	}
}
