package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
)

func TestLocalGitInvestigationUnknownEffectCannotRestartOrRelabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f, endpoint, limits, _ := newInvestigationFixture(t, "unknown usage", cancel)
	policy, err := review.ParseInvestigationPolicy(localModelJSON(t, limits))
	if err != nil {
		t.Fatal(err)
	}
	newSession := func() *localreview.Session {
		options, objects := localModelSessionOptions(t, f)
		session, err := localreview.NewInvestigationSession(options, policy)
		if err != nil {
			_ = objects.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := session.Close(closeCtx); err != nil {
				t.Error(err)
			}
		})
		return session
	}
	owner := newSession()
	prepared := localModelPrepare(t, owner, f, "unknown-investigation")
	result, err := owner.Run(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	receipt := localModelSessionReceipt(t, result)
	if receipt.RunStatus == "succeeded" || len(endpoint.snapshot()) != 2 {
		t.Fatal("unknown usage did not freeze the real session")
	}
	if _, err := owner.Run(ctx, prepared); !errors.Is(err, localreview.ErrReviewRunAlreadyExists) {
		t.Fatal("existing scope became dispatchable")
	}
	// A fresh Session has no authority to resume another owner's prepared request.
	other := newSession()
	if _, err := other.Run(ctx, prepared); !errors.Is(err, localreview.ErrPreparedReviewMismatch) {
		t.Fatal("old prepared authority survived a new session nonce")
	}
	if len(endpoint.snapshot()) != 2 {
		t.Fatal("duplicate or restarted owner repeated model dispatch")
	}
}
