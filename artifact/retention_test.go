package artifact

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func deletionAuthorizationFixture(t *testing.T, scope audit.ReviewScope, artifactIdentity string, reason DeletionReason, issued time.Time) DeletionAuthorization {
	t.Helper()
	authorization, err := NewDeletionAuthorization(scope, artifactIdentity, strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), reason, issued, issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}
func TestMemoryStoreDeletesOnlyWithLiveHoldClearedAuthorization(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	store, _ := NewMemoryStore(ProtectionProcessPrivate, 10)
	value := artifactFixture(t, scope, `{}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	if receipt, err := store.Delete(context.Background(), authorization, time.UnixMilli(999)); !errors.Is(err, ErrDeletionNotAllowed) || receipt.Identity() != "" {
		t.Fatalf("early=(%#v,%v)", receipt, err)
	}
	receipt, err := store.Delete(context.Background(), authorization, time.UnixMilli(1000))
	if err != nil || receipt.Validate() != nil || receipt.ArtifactIdentity() != value.Identity() || receipt.PayloadDigest() != value.PayloadDigest() {
		t.Fatalf("delete=(%#v,%v)", receipt, err)
	}
	if got, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(1000)); !errors.Is(err, ErrArtifactNotFound) || got.Identity() != "" {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
	again, err := store.Delete(context.Background(), authorization, time.UnixMilli(1001))
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("again=(%#v,%v)", again, err)
	}
}
func TestFileStorePersistsPhysicalDeletionReceipt(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	root := filepath.Join(t.TempDir(), "artifacts")
	store, _ := NewFileStore(root)
	value := artifactFixture(t, scope, `{}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	artifactPath := store.artifactPath(scope, value.Identity())
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt, err := store.Delete(context.Background(), authorization, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifactPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact remains: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.Delete(context.Background(), authorization, time.UnixMilli(1001))
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("again=(%#v,%v)", again, err)
	}
	if created, err := reopened.Put(context.Background(), value, time.UnixMilli(200)); !errors.Is(err, ErrArtifactDeleted) || created {
		t.Fatalf("put=(%t,%v)", created, err)
	}
}

func TestFileStoreRecoversPreparedDeletionAfterRestart(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-recovery")
	root := filepath.Join(t.TempDir(), "artifacts")
	store, _ := NewFileStore(root)
	value := artifactFixture(t, scope, `{"recover":true}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1000))
	prepared, _ := encodeDeletionRecord(receipt, false)
	if err := store.persist(store.deletionPath(scope, value.Identity()), prepared); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Stat(reopened.artifactPath(scope, value.Identity())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("payload remains after recovery: %v", err)
	}
	again, err := reopened.Delete(context.Background(), authorization, time.UnixMilli(1001))
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("receipt=(%#v,%v)", again, err)
	}
}

func TestDeletionContractsRoundTripCanonicalJSON(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-wire")
	authorization := deletionAuthorizationFixture(t, scope, strings.Repeat("a", 64), DeletionTenantErasure, time.UnixMilli(100))
	encodedAuthorization, err := EncodeDeletionAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	parsedAuthorization, err := ParseDeletionAuthorization(encodedAuthorization)
	if err != nil || parsedAuthorization.Identity() != authorization.Identity() {
		t.Fatalf("authorization=(%#v,%v)", parsedAuthorization, err)
	}
	value := artifactFixture(t, scope, `{}`)
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(101))
	encodedReceipt, err := EncodeDeletionReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsedReceipt, err := ParseDeletionReceipt(encodedReceipt)
	if err != nil || parsedReceipt.Identity() != receipt.Identity() {
		t.Fatalf("receipt=(%#v,%v)", parsedReceipt, err)
	}
}

func TestRecordDeletionAuditIsContentFreeAndIdempotent(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-audit")
	store, _ := NewMemoryStore(ProtectionProcessPrivate, 10)
	value := artifactFixture(t, scope, `{"secret-looking":"not-in-audit"}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt, _ := store.Delete(context.Background(), authorization, time.UnixMilli(1000))
	ledger := audit.NewMemoryLedger()
	event, err := RecordDeletionAudit(context.Background(), ledger, receipt, time.UnixMilli(1001))
	if err != nil || event.Kind() != audit.EventArtifactDeleted || event.SubjectIdentity() != receipt.Identity() {
		t.Fatalf("event=(%#v,%v)", event, err)
	}
	again, err := RecordDeletionAudit(context.Background(), ledger, receipt, time.UnixMilli(2000))
	if err != nil || again.Identity() != event.Identity() {
		t.Fatalf("again=(%#v,%v)", again, err)
	}
	encoded, _ := audit.EncodeEvent(event)
	if strings.Contains(string(encoded), "secret-looking") {
		t.Fatal("audit leaked payload")
	}
}
