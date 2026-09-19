package webhook

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStorePersistsDeduplicatesAndLists(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	delivery := inboxFixture(t, `{"action":"opened"}`)
	stored, created, err := store.Put(context.Background(), delivery, time.UnixMilli(200))
	if err != nil || !created {
		t.Fatalf("put=(%#v,%t,%v)", stored, created, err)
	}
	information, err := os.Stat(root)
	if err != nil || information.Mode().Perm() != 0o700 {
		t.Fatalf("root=(%v,%v)", information, err)
	}
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		info, infoErr := file.Info()
		if infoErr != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("file=%s info=%v err=%v", file.Name(), info, infoErr)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	duplicate, created, err := reopened.Put(context.Background(), delivery, time.UnixMilli(300))
	if err != nil || created || duplicate.Receipt().Identity() != stored.Receipt().Identity() {
		t.Fatalf("duplicate=(%#v,%t,%v)", duplicate, created, err)
	}
	got, found, err := reopened.Get(context.Background(), delivery.Scope(), delivery.Source(), delivery.DeduplicationKey())
	if err != nil || !found || got.Delivery().Identity() != delivery.Identity() {
		t.Fatalf("get=(%#v,%t,%v)", got, found, err)
	}
	listed, err := reopened.List(context.Background(), delivery.Scope(), delivery.Source(), "", 10)
	if err != nil || len(listed) != 1 || listed[0].Delivery().Identity() != delivery.Identity() {
		t.Fatalf("list=(%#v,%v)", listed, err)
	}
}
func TestFileStoreUsesExclusiveWriterAndDetectsCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if competing, err := NewFileStore(root); !errors.Is(err, ErrInboxStoreLocked) || competing != nil {
		t.Fatalf("competing=(%#v,%v)", competing, err)
	}
	delivery := inboxFixture(t, `{}`)
	_, _, _ = store.Put(context.Background(), delivery, time.UnixMilli(200))
	path := store.deliveryPath(delivery.Scope(), delivery.Source(), delivery.DeduplicationKey())
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), delivery.Scope(), delivery.Source(), delivery.DeduplicationKey()); !errors.Is(err, ErrInvalidStoredDeliveryEncoding) {
		t.Fatalf("corruption=%v", err)
	}
	_ = store.Close()
}
func TestFileStoreRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if store, err := NewFileStore(link); !errors.Is(err, ErrInvalidInboxStoreRoot) || store != nil {
		t.Fatalf("store=(%#v,%v)", store, err)
	}
}
func TestFileStoreRejectsDeliveryConflictAfterRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	store, _ := NewFileStore(root)
	first := inboxFixture(t, `{}`)
	_, _, _ = store.Put(context.Background(), first, time.UnixMilli(200))
	second := inboxFixture(t, `{"value":"`+strings.Repeat("x", 20)+`"}`)
	if got, created, err := store.Put(context.Background(), second, time.UnixMilli(200)); !errors.Is(err, ErrDeliveryConflict) || created || got.Validate() == nil {
		t.Fatalf("conflict=(%#v,%t,%v)", got, created, err)
	}
	_ = store.Close()
}
