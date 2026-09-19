package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateStorageCheckerValidatesPrivateDirectory(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	checker, err := NewStateStorageChecker(root)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed {
		t.Fatalf("pass=%s", result.State())
	}
	if err = os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || result.RecoveryAction() != RecoveryConfigureDependency {
		t.Fatalf("unsafe=%s", result.State())
	}
	if err = os.Chmod(root, 0o000); err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("owner inaccessible=%s", result.State())
	}
	unsafeParent := filepath.Join(t.TempDir(), "writable")
	if err = os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(unsafeParent, 0o777)
	privateChild := filepath.Join(unsafeParent, "private")
	if err = os.Mkdir(privateChild, 0o700); err != nil {
		t.Fatal(err)
	}
	parentChecker, _ := NewStateStorageChecker(privateChild)
	if result := parentChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("replaceable parent=%s", result.State())
	}
	replaceableGrandparent := filepath.Join(t.TempDir(), "world")
	if err = os.Mkdir(replaceableGrandparent, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(replaceableGrandparent, 0o777)
	protectedParent := filepath.Join(replaceableGrandparent, "parent")
	_ = os.Mkdir(protectedParent, 0o700)
	protectedChild := filepath.Join(protectedParent, "storage")
	_ = os.Mkdir(protectedChild, 0o700)
	grandparentChecker, _ := NewStateStorageChecker(protectedChild)
	if result := grandparentChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("replaceable grandparent=%s", result.State())
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	linkChecker, _ := NewStateStorageChecker(link)
	if result := linkChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("symlink=%s", result.State())
	}
}
func TestObserverCheckerDoesNotPersistCredentialMaterial(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	operator := "operator-" + strings.Repeat("a", 32)
	observer := "observer-" + strings.Repeat("b", 32)
	checker, _ := NewObserverCredentialPostureChecker(func(key string) string {
		if key == "OPEN_TRESTLE_API_TOKEN" {
			return operator
		}
		return observer
	})
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckPassed {
		t.Fatalf("result=%s", result.State())
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), operator) || strings.Contains(string(encoded), observer) {
		t.Fatal("credential escaped")
	}
	same, _ := NewObserverCredentialPostureChecker(func(string) string { return operator })
	if result = same.Check(context.Background(), plan); result.State() != CheckBlocked || result.RecoveryAction() != RecoveryConfigureObserver {
		t.Fatalf("same=%s", result.State())
	}
}

func TestNilBuiltInCheckersFailClosed(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	var storage *StateStorageChecker
	if result := storage.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("storage=%s", result.State())
	}
	var observer *ObserverCredentialPostureChecker
	if result := observer.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("observer=%s", result.State())
	}
}

func TestBuiltInCheckersRedactConfiguration(t *testing.T) {
	storage, _ := NewStateStorageChecker("/private/setup/path")
	observer, _ := NewObserverCredentialPostureChecker(func(string) string { return "hidden-value" })
	if strings.Contains(fmt.Sprintf("%#v", storage), "/private") || strings.Contains(fmt.Sprintf("%#v", observer), "hidden") {
		t.Fatal("checker leaked configuration")
	}
}
