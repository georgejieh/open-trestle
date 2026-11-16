package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

// The direct-review scope prepares only the foreground checkout review, so an
// ordinary packed checkout with a 0755 objects folder is accepted, the daemon
// tokens are never consulted, and no daemon command is emitted or qualified.
func TestSetupBootstrapDirectReviewScopeAcceptsPackedCheckout(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "")
	args, dir, f, probes := bootstrapFixture(t)
	checkout := args[slices.Index(args, "--checkout")+1]
	objects := filepath.Join(checkout, ".git", "objects")
	checkoutGit(t, checkout, "gc", "--quiet", "--prune=now")
	if err := os.Chmod(objects, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(objects, f.head[:2], f.head[2:])); !os.IsNotExist(err) {
		t.Fatal("the fixture head commit is still loose")
	}
	direct := append(append([]string(nil), args...), "--scope", "direct-review")
	initial := bootstrapInvoke(t, direct, 3)
	if initial.Scope != "direct-review" || initial.Ready || len(initial.LaunchCommand) != 0 || len(initial.StatusCommand) != 0 || len(initial.ReviewCommand) != 0 || len(initial.EphemeralReviewCommand) < 4 {
		t.Fatalf("direct-review init: %+v", initial)
	}
	for _, key := range []string{"observer_credential_posture_validated", "backup_validated", "local_inference_validated"} {
		if slices.Contains(initial.Pending, key) {
			t.Fatalf("direct-review scope listed %s as required", key)
		}
	}
	if !slices.Contains(initial.Limitations, "direct_review_scope_excludes_daemon_checks") {
		t.Fatal("direct-review result does not state its narrower scope")
	}
	if manifest := stringMustRead(t, filepath.Join(dir, "bootstrap.json")); !strings.Contains(manifest, `"scope":"direct-review"`) {
		t.Fatalf("manifest lacks the scope: %s", manifest)
	}
	bootstrapInvoke(t, direct, 3) // repeating init accepts the identical output

	ready := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 0)
	if !ready.Ready || ready.Status != "ready" || len(ready.Pending) != 0 || probes.Load() != 0 || ready.Scope != "direct-review" {
		t.Fatalf("direct-review check without daemon tokens: %+v probes=%d", ready, probes.Load())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), filepath.Join(dir, "runs", "setup", "plan.json"))
	if err != nil || plan.Ready() {
		t.Fatal("the daemon setup plan became ready without its daemon checks", err)
	}
	probed := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe"}, 0)
	if !probed.Ready || probes.Load() != 2 {
		t.Fatalf("probe in direct-review scope: %+v probes=%d", probed, probes.Load())
	}
	for _, refused := range [][]string{{"check", "--directory", dir, "--approved-by", "owner", "--scope", "daemon"}, {"prepare-review", "--directory", dir}} {
		if result := bootstrapInvoke(t, refused, 4); result.Ready || len(result.LaunchCommand) != 0 {
			t.Fatalf("%v did not refuse a direct-review setup", refused)
		}
	}
	var out, errOut bytes.Buffer
	if code := runSetupBootstrap([]string{"check", "--directory", dir, "--approved-by", "owner", "--backup-directory", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("daemon backup in direct-review scope: code=%d", code)
	}
	if info, err := os.Stat(objects); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatal("bootstrap changed source permissions", err)
	}

	reviewArgs := replaceLocalGitChangeValue(append([]string(nil), ready.EphemeralReviewCommand[3:]...), "--format", "json")
	out.Reset()
	errOut.Reset()
	code := runLocalGitModelReview(context.Background(), reviewArgs, &out, &errOut)
	var receipt localModelReceipt
	if json.Unmarshal(out.Bytes(), &receipt) != nil || code != 4 || receipt.Status != "findings" || len(receipt.Diagnostics.Findings) != 1 || receipt.Diagnostics.Head != f.head {
		t.Fatalf("direct review of the packed checkout: code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
}

// A daemon setup checked in the direct-review scope reports the direct review's
// readiness without its daemon checks, and the daemon scope is unchanged.
func TestSetupBootstrapDaemonSetupCheckedInDirectReviewScope(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "")
	args, dir, _, probes := bootstrapFixture(t)
	initial := bootstrapInvoke(t, args, 3)
	if initial.Scope != "" || len(initial.LaunchCommand) == 0 {
		t.Fatalf("daemon init changed: %+v", initial)
	}
	// Without daemon tokens the daemon scope refuses at the observer check, as before.
	daemon := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 4)
	if daemon.Ready || daemon.Scope != "" || !slices.Contains(daemon.Pending, "observer_credential_posture_validated") || !slices.Contains(daemon.Pending, "policy_validated") || len(daemon.LaunchCommand) == 0 {
		t.Fatalf("daemon check without tokens changed: %+v", daemon)
	}
	direct := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--scope", "direct-review"}, 0)
	if !direct.Ready || direct.Scope != "direct-review" || len(direct.LaunchCommand) != 0 || probes.Load() != 0 {
		t.Fatalf("direct-review check of a daemon setup: %+v", direct)
	}
	again := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 4)
	if again.Ready || !slices.Contains(again.Pending, "observer_credential_posture_validated") || slices.Contains(again.Pending, "policy_validated") {
		t.Fatalf("daemon scope after a direct-review check: %+v", again)
	}
	if manifest := stringMustRead(t, filepath.Join(dir, "bootstrap.json")); strings.Contains(manifest, "scope") {
		t.Fatal("a daemon manifest gained a scope field")
	}
}
