//go:build unix

package setup

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

type ownershipInfo struct {
	uid  uint32
	mode fs.FileMode
}

func (ownershipInfo) Name() string       { return "entry" }
func (ownershipInfo) Size() int64        { return 0 }
func (ownershipInfo) Mode() fs.FileMode  { return 0o700 }
func (ownershipInfo) ModTime() time.Time { return time.Time{} }
func (ownershipInfo) IsDir() bool        { return true }
func (i ownershipInfo) Sys() any         { return &syscall.Stat_t{Uid: i.uid} }
func TestWritableAncestorOwnershipTrust(t *testing.T) {
	current := uint32(os.Geteuid())
	if !fileOwnedByTrustedProcessOrRoot(ownershipInfo{uid: 0}) || !fileOwnedByTrustedProcessOrRoot(ownershipInfo{uid: current}) {
		t.Fatal("trusted owner rejected")
	}
	untrusted := current + 1
	if untrusted == 0 {
		untrusted = 1
	}
	if fileOwnedByTrustedProcessOrRoot(ownershipInfo{uid: untrusted}) {
		t.Fatal("untrusted owner accepted")
	}
}

func TestAncestorAuthorityRejectsUntrustedOwnerRegardlessOfMode(t *testing.T) {
	current := uint32(os.Geteuid())
	untrusted := current + 1
	if untrusted == 0 {
		untrusted = 1
	}
	child := ownershipInfo{uid: current, mode: 0o700}
	for _, mode := range []fs.FileMode{0o755, 0o555, 0o1777} {
		if stableAncestorAuthority(ownershipInfo{uid: untrusted, mode: mode}, child) {
			t.Fatalf("accepted untrusted mode %o", mode)
		}
	}
	if !stableAncestorAuthority(ownershipInfo{uid: 0, mode: 0o755}, child) || !stableAncestorAuthority(ownershipInfo{uid: 0, mode: 0o1777 | os.ModeSticky}, child) {
		t.Fatal("trusted ancestor rejected")
	}
}
