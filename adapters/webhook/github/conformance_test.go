package github

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/webhook"
)

func conformanceFixture(t *testing.T) (webhook.RepositoryScope, *webhook.FileStore) {
	t.Helper()
	scope, err := webhook.NewRepositoryScope("tenant-a", "repository-a")
	if err != nil {
		t.Fatal(err)
	}
	store, err := webhook.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return scope, store
}

func TestRuntimeWebhookSecretPolicyRejectsMalformedAndTrivialValues(t *testing.T) {
	valid := []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if err := ValidateRuntimeSecret(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		[]byte("short"),
		[]byte(strings.Repeat("a", 64)),
		[]byte(strings.Repeat("0", 64)),
		[]byte(strings.Repeat("0123456789abcdef", 4)),
		[]byte("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
		[]byte(strings.Repeat("a", 63) + "b"),
	} {
		if err := ValidateRuntimeSecret(value); !errors.Is(err, ErrInvalidVerifier) {
			t.Fatalf("accepted %q: %v", value, err)
		}
	}
}

func TestWebhookConformanceAuthorityBindsExactContract(t *testing.T) {
	scope, _ := conformanceFixture(t)
	identity, err := ConformanceAuthorityIdentity(scope, "primary-2026", strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	if identity != "cd7f2cbb0f2156eef773ad89edf8e61eeee79f273f025e4a464a1ac9545286ba" {
		t.Fatalf("identity=%s", identity)
	}
	changedKey, _ := ConformanceAuthorityIdentity(scope, "secondary-2026", strings.Repeat("c", 64))
	changedCredential, _ := ConformanceAuthorityIdentity(scope, "primary-2026", strings.Repeat("d", 64))
	otherScope, _ := webhook.NewRepositoryScope("tenant-a", "repository-b")
	changedScope, _ := ConformanceAuthorityIdentity(otherScope, "primary-2026", strings.Repeat("c", 64))
	if changedKey == identity || changedCredential == identity || changedScope == identity {
		t.Fatal("authority did not bind all inputs")
	}
	if _, err := ConformanceAuthorityIdentity(scope, " bad ", strings.Repeat("c", 64)); !errors.Is(err, ErrInvalidWebhookConformance) {
		t.Fatalf("key error=%v", err)
	}
}

func TestVerifyWebhookConformanceUsesDurableFileStore(t *testing.T) {
	scope, store := conformanceFixture(t)
	secret := []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	observation, err := VerifyConformance(context.Background(), secret, scope, "primary-2026", strings.Repeat("c", 64), store)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Validate() != nil || observation.Identity() == "" || observation.AuthorityIdentity() == "" || observation.AcceptanceIdentity() == "" {
		t.Fatalf("observation=%#v", observation)
	}
	entries, err := store.List(context.Background(), scope, webhook.SourceGitHub, "", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	if entries[0].Receipt().Identity() != observation.AcceptanceIdentity() || string(entries[0].Delivery().Payload()) != string(conformanceAcceptedPayload) {
		t.Fatal("stored delivery did not match the conformance observation")
	}
}

func TestVerifyWebhookConformanceRejectsInvalidOrNonDisposableInputs(t *testing.T) {
	scope, store := conformanceFixture(t)
	credential := strings.Repeat("c", 64)
	if _, err := VerifyConformance(context.Background(), []byte("short"), scope, "primary-2026", credential, store); !errors.Is(err, ErrInvalidWebhookConformance) {
		t.Fatalf("weak secret error=%v", err)
	}
	if _, err := VerifyConformance(nil, []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), scope, "primary-2026", credential, store); !errors.Is(err, ErrInvalidWebhookConformance) {
		t.Fatalf("context error=%v", err)
	}
	first, err := VerifyConformance(context.Background(), []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), scope, "primary-2026", credential, store)
	if err != nil || first.Validate() != nil {
		t.Fatal(err)
	}
	if _, err := VerifyConformance(context.Background(), []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), scope, "primary-2026", credential, store); !errors.Is(err, ErrWebhookConformanceFailed) {
		t.Fatalf("reused store error=%v", err)
	}
}
