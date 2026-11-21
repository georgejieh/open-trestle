package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeadmin"
)

func TestRunDispatchesAdmin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"admin"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "trestle admin runtime status") {
		t.Fatalf("result=(%d,%q)", code, stderr.String())
	}
}

func TestRunRuntimeAdminPrintsContentFreeSnapshot(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", strings.Repeat("t", 32))
	configuration, _ := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, MetadataBackend: runtimeadmin.MetadataLocal, ArtifactBackend: runtimeadmin.ArtifactLocal, ArtifactProtection: runtimeadmin.ProtectionProcessPrivate, NotificationBackend: runtimeadmin.NotificationProcessLocal, RateLimitBackend: runtimeadmin.RateLimitProcessLocal, ReviewMode: runtimeadmin.ReviewDisabled})
	service, _ := runtimeadmin.NewService(configuration, nil)
	snapshot, _ := service.Snapshot("tenant-a", "repo-a", time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	var stdout, stderr bytes.Buffer
	called := false
	code := runRuntimeAdminWithExecutor([]string{"status", "--server", "http://127.0.0.1:8741", "--tenant", "tenant-a", "--repository", "repo-a"}, &stdout, &stderr, func(_ context.Context, server, token, tenant, repository string) (runtimeadmin.Snapshot, error) {
		called = true
		if server != "http://127.0.0.1:8741" || token != strings.Repeat("t", 32) || tenant != "tenant-a" || repository != "repo-a" {
			t.Fatal("cross-wired request")
		}
		return snapshot, nil
	})
	if code != 0 || !called || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/runtime-status"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
