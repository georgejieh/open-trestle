package publication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func TestBuildFinalDiagnosticPartsDoesNotInventEvidence(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant", "repo", "run-final-parts")
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	deterministic, verified, err := BuildFinalDiagnosticParts(ctx, store, scope, "", "", "", time.UnixMilli(100))
	if err != nil || deterministic.Identity() != "" || verified.Identity() != "" {
		t.Fatalf("unavailable parts=(%#v,%#v,%v)", deterministic, verified, err)
	}
	if _, _, err = BuildFinalDiagnosticParts(ctx, store, scope, strings.Repeat("a", 64), "", "", time.UnixMilli(100)); !errors.Is(err, ErrInvalidReadinessResult) {
		t.Fatalf("missing change allowed: %v", err)
	}
	if _, _, err = BuildFinalDiagnosticParts(ctx, store, scope, "", "", strings.Repeat("a", 64), time.UnixMilli(100)); !errors.Is(err, ErrInvalidReadinessResult) {
		t.Fatalf("verification without analysis allowed: %v", err)
	}
	if _, _, err = BuildFinalDiagnosticParts(ctx, store, scope, strings.Repeat("a", 64), strings.Repeat("b", 64), "", time.UnixMilli(100)); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("supplied artifact missing allowed: %v", err)
	}
}
