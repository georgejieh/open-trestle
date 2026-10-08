package artifact

import (
	"bytes"
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestPendingFileStoreOpenDefersPreparedDeletion(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-pending")
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"pending":true}`)
	if _, err := store.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1000))
	prepared, _ := encodeDeletionRecord(receipt, false)
	payloadPath, receiptPath := store.artifactPath(scope, value.Identity()), store.deletionPath(scope, value.Identity())
	if err := store.persist(receiptPath, prepared); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(pending).(Store); ok {
		t.Fatal("pending implements Store")
	}
	if _, ok := any(pending).(RetentionStore); ok {
		t.Fatal("pending implements RetentionStore")
	}
	assertUnchanged := func() {
		t.Helper()
		gotPayload, err := os.ReadFile(payloadPath)
		if err != nil || string(gotPayload) != string(payload) {
			t.Fatalf("payload changed: %v", err)
		}
		gotReceipt, err := os.ReadFile(receiptPath)
		if err != nil || string(gotReceipt) != string(prepared) {
			t.Fatalf("receipt changed: %v", err)
		}
	}
	assertUnchanged()
	competing, err := NewFileStore(root)
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("competing=(%v,%v)", competing, err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	assertUnchanged()
	if activated, err := pending.Activate(); activated != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed activation=(%v,%v)", activated, err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Stat(payloadPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy recovery did not remove payload: %v", err)
	}
	completed, _ := encodeDeletionRecord(receipt, true)
	gotReceipt, err := os.ReadFile(receiptPath)
	if err != nil || string(gotReceipt) != string(completed) {
		t.Fatalf("legacy recovery receipt: %v", err)
	}
}

func TestPendingFileStoreActivationTransfersLockAndRecovers(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-transfer")
	root := filepath.Join(t.TempDir(), "artifacts")
	original, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"recover":true}`)
	if _, err := original.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1000))
	prepared, _ := encodeDeletionRecord(receipt, false)
	payloadPath, receiptPath := original.artifactPath(scope, value.Identity()), original.deletionPath(scope, value.Identity())
	if err := original.persist(receiptPath, prepared); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	active, err := pending.Activate()
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := os.Stat(payloadPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("payload remains: %v", err)
	}
	completed, _ := encodeDeletionRecord(receipt, true)
	got, err := os.ReadFile(receiptPath)
	if err != nil || string(got) != string(completed) {
		t.Fatalf("receipt not completed: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	competing, err := NewFileStore(root)
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("lock transferred=(%v,%v)", competing, err)
	}
	fresh := artifactFixture(t, scope, `{"fresh":true}`)
	if created, err := active.Put(context.Background(), fresh, time.UnixMilli(200)); !created || err != nil {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	gotValue, err := active.Get(context.Background(), scope, fresh.Identity(), time.UnixMilli(200))
	if err != nil || gotValue.Identity() != fresh.Identity() {
		t.Fatalf("get=(%v,%v)", gotValue, err)
	}
	freshAuthorization := deletionAuthorizationFixture(t, scope, fresh.Identity(), DeletionExpired, time.UnixMilli(1000))
	if deleted, err := active.Delete(context.Background(), freshAuthorization, time.UnixMilli(1000)); err != nil || deleted.ArtifactIdentity() != fresh.Identity() {
		t.Fatalf("delete=(%v,%v)", deleted, err)
	}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestPendingFileStoreCorruptReceiptFailsActivationAndReleasesLock(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-corrupt")
	root := filepath.Join(t.TempDir(), "artifacts")
	original, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"corrupt":true}`)
	if _, err := original.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	payloadPath, receiptPath := original.artifactPath(scope, value.Identity()), original.deletionPath(scope, value.Identity())
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("not a deletion receipt")
	if err := original.persist(receiptPath, corrupt); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes := func() {
		t.Helper()
		got, err := os.ReadFile(payloadPath)
		if err != nil || string(got) != string(payload) {
			t.Fatalf("payload changed: %v", err)
		}
		got, err = os.ReadFile(receiptPath)
		if err != nil || string(got) != string(corrupt) {
			t.Fatalf("receipt changed: %v", err)
		}
	}
	checkBytes()
	active, err := pending.Activate()
	if active != nil || !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("activation=(%v,%v)", active, err)
	}
	checkBytes() // One corrupt record only; mixed-record recovery is not atomic.
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := NewFileStore(root)
	if legacy != nil || !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("legacy=(%v,%v)", legacy, err)
	}
}

func TestPendingFileStoreValueCopiesShareLockTransfer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	clone := *pending
	active, err := clone.Activate()
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	if again, err := clone.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("clone activation=(%v,%v)", again, err)
	}
	competing, err := OpenPendingFileStore(root)
	if competing != nil {
		_ = competing.Close()
	}
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("active owner lost lock=(%v,%v)", competing, err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-copy")
	value := artifactFixture(t, scope, `{"copy":true}`)
	if created, err := active.Put(context.Background(), value, time.UnixMilli(200)); !created || err != nil {
		t.Fatalf("active put=(%v,%v)", created, err)
	}
	got, err := active.Get(context.Background(), scope, value.Identity(), time.UnixMilli(200))
	if err != nil || got.Identity() != value.Identity() {
		t.Fatalf("active get=(%v,%v)", got, err)
	}
}

func TestPendingFileStoreActivateCloseRaceHasAtMostOneOwner(t *testing.T) {
	for i := 0; i < 20; i++ {
		root := filepath.Join(t.TempDir(), "artifacts")
		pending, err := OpenPendingFileStore(root)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		var active *FileStore
		var activationErr, closeErr error
		go func() { defer wait.Done(); <-start; active, activationErr = pending.Activate() }()
		go func() { defer wait.Done(); <-start; closeErr = pending.Close() }()
		close(start)
		wait.Wait()
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if active == nil {
			if !errors.Is(activationErr, ErrStoreClosed) {
				t.Fatalf("failed activation: %v", activationErr)
			}
		} else {
			if activationErr != nil {
				t.Fatal(activationErr)
			}
			competing, err := OpenPendingFileStore(root)
			if competing != nil || !errors.Is(err, ErrStoreLocked) {
				t.Fatalf("active owner lost lock: %v, %v", competing, err)
			}
			if err := active.Close(); err != nil {
				t.Fatal(err)
			}
		}
		reopened, err := OpenPendingFileStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPendingFileStoreActivationRejectsReplacedRootBeforeRecovery(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-replaced")
	root := filepath.Join(t.TempDir(), "artifacts")
	original, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{}`)
	if _, err := original.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1000))
	prepared, _ := encodeDeletionRecord(receipt, false)
	path := original.deletionPath(scope, value.Identity())
	if err := original.persist(path, prepared); err != nil {
		t.Fatal(err)
	}
	payloadPath := original.artifactPath(scope, value.Identity())
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// Seed valid prepared deletion bytes directly: no constructor may recover this replacement.
	replacementScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-replacement")
	replacementValue := artifactFixture(t, replacementScope, `{"replacement":true}`)
	replacementPayload, err := Encode(replacementValue)
	if err != nil {
		t.Fatal(err)
	}
	replacementAuthorization := deletionAuthorizationFixture(t, replacementScope, replacementValue.Identity(), DeletionExpired, time.UnixMilli(1000))
	replacementReceipt := newDeletionReceipt(replacementValue, replacementAuthorization, time.UnixMilli(1000))
	replacementPrepared, err := encodeDeletionRecord(replacementReceipt, false)
	if err != nil {
		t.Fatal(err)
	}
	replacementPayloadPath := original.artifactPath(replacementScope, replacementValue.Identity())
	replacementReceiptPath := original.deletionPath(replacementScope, replacementValue.Identity())
	if err := os.WriteFile(replacementPayloadPath, replacementPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacementReceiptPath, replacementPrepared, 0o600); err != nil {
		t.Fatal(err)
	}
	active, err := pending.Activate()
	if active != nil || !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("replaced activation=(%v,%v)", active, err)
	}
	for _, file := range []struct {
		path string
		want []byte
	}{
		{filepath.Join(moved, filepath.Base(payloadPath)), payload},
		{filepath.Join(moved, filepath.Base(path)), prepared},
		{replacementPayloadPath, replacementPayload},
		{replacementReceiptPath, replacementPrepared},
	} {
		got, err := os.ReadFile(file.path)
		if err != nil || !bytes.Equal(got, file.want) {
			t.Fatalf("activation changed %s: %v", file.path, err)
		}
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+"-replacement"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, root); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatalf("moved original writer lock not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
