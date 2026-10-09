package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/setup"
)

func historicalPacketJournal(t *testing.T, root string, legacyV3 bool) {
	t.Helper()
	ctx := context.Background()
	journal, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("previous-tenant", "previous-repository", "previous-run")
	if err != nil {
		t.Fatal(err)
	}
	tasks := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}}, {"readiness", controlplane.TaskEvaluatePublication, []string{"verification"}},
		{"publication", controlplane.TaskPublishResult, []string{"readiness"}},
	}
	definitions := make([]controlplane.TaskDefinition, 0, len(tasks))
	for _, task := range tasks {
		attempts := uint8(3)
		if task.key == "publication" {
			attempts = 1
		}
		definition, err := controlplane.NewTaskDefinition(task.key, task.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), task.dependencies, attempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, definition)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunRequired, definitions)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err = coordinator.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatalf("context claim: %v", err)
	}
	if legacyV3 {
		item, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", artifact.ClassificationInternal, artifact.OriginDeterministicTool, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{"evidence":"legacy"}`), time.UnixMilli(280), time.UnixMilli(3600280))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := artifact.Encode(item)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.PrepareContextAbstention(ctx, plan, lease, encoded, controlplane.RunFailurePolicy, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		events, err := journal.Read(ctx, scope, 1, 100)
		if err != nil {
			t.Fatal(err)
		}
		last, err := controlplane.EncodeRunEvent(events[len(events)-1])
		if err != nil || !strings.Contains(string(last), `"schema_version":3`) {
			t.Fatalf("v3 fixture: %s %v", last, err)
		}
		if _, err := coordinator.CancelRun(ctx, plan, time.UnixMilli(at+2)); err != nil {
			t.Fatal(err)
		}
	} else {
		packet, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationInternal, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, []byte(`{"packet":"historical"}`), time.UnixMilli(280), time.UnixMilli(3600280))
		if err != nil {
			t.Fatal(err)
		}
		descriptor := controlplane.ContextPacketDescriptor{ArtifactIdentity: packet.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), PayloadDigest: packet.PayloadDigest(), Classification: packet.Classification().String(), Protection: packet.Protection().String(), Provenance: packet.Provenance(), SourceRootIdentity: strings.Repeat("a", 64), SnapshotIdentity: strings.Repeat("b", 64), DependencyIdentities: []string{strings.Repeat("e", 64)}, CreatedAtMilliseconds: packet.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: packet.ExpiresAt().UnixMilli()}
		prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, time.UnixMilli(at+1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = coordinator.TerminatePreparedContextPacket(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err = coordinator.CancelRun(ctx, plan, lease.ExpiresAt().Add(2*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	resumed, _ := controlplane.NewCoordinator(reopened)
	_, state, err := resumed.Resume(ctx, scope)
	if err != nil || state.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("terminal replay: %v", err)
	}
	runtime, _ := state.Task("context")
	if _, ok := runtime.PreparedContextPacket(); ok {
		t.Fatal("packet remains currently prepared")
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDaemonRejectsHistoricalTerminalPacketFromOtherScope(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	historicalPacketJournal(t, root, false)
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "new-tenant", "--repository", "new-repository"}
	d, err := buildDaemon(context.Background(), args, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), os.Stderr)
	if d != nil {
		d.Close()
	}
	if d != nil || !errors.Is(err, controlplane.ErrPreparedContextPacketAtStartup) {
		t.Fatalf("historical packet: daemon=%v error=%v", d, err)
	}
	for _, name := range []string{"audit", "diagnostics"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s created: %v", name, err)
		}
	}
	journal, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("journal lease: %v", err)
	}
	journal.Close()
	pending, err := artifact.OpenPendingFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatalf("pending artifact lease: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDaemonRejectsHistoricalPacketInDeterministicAndFullLocalModes(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "deterministic"
		if full {
			name = "full"
		}
		t.Run(name, func(t *testing.T) {
			args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
			if !full {
				args = args[:len(args)-5]
			} // Drop full-review and both runtime configuration flag/value pairs.
			root := daemonTestFlagValue(t, args, "--state-dir")

			// Bootstrap a real owner against the fixture's Git objects and setup
			// state. A recordless runtime with a journal must fail before inventory.
			first, err := buildDaemon(context.Background(), args, getenv, os.Stderr)
			if err != nil || first == nil {
				t.Fatalf("valid owner bootstrap: daemon=%v error=%v", first, err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			historicalPacketJournal(t, root, false)

			type entry struct {
				path string
				info os.FileInfo
				data []byte
			}
			snapshot := func() ([]entry, error) {
				var entries []entry
				for _, name := range []string{localSourceOwnerLeaf, "audit", "diagnostics"} {
					path := filepath.Join(root, name)
					err := filepath.WalkDir(path, func(path string, item os.DirEntry, walkErr error) error {
						if walkErr != nil {
							return walkErr
						}
						info, err := os.Lstat(path)
						if err != nil {
							return err
						}
						observed := entry{path: path, info: info}
						if info.Mode().IsRegular() {
							observed.data, err = os.ReadFile(path)
							if err != nil {
								return err
							}
						}
						entries = append(entries, observed)
						return nil
					})
					if err != nil {
						return nil, err
					}
				}
				return entries, nil
			}
			before, err := snapshot()
			if err != nil {
				t.Fatalf("pre-restart owner and output snapshot: %v", err)
			}
			d, err := buildDaemon(context.Background(), args, getenv, os.Stderr)
			if d != nil {
				d.Close()
			}
			if d != nil || !errors.Is(err, controlplane.ErrPreparedContextPacketAtStartup) {
				t.Fatalf("historical packet: daemon=%v error=%v", d, err)
			}
			after, err := snapshot()
			if err != nil {
				t.Fatalf("post-refusal owner and output snapshot: %v", err)
			}
			if len(before) != len(after) {
				t.Fatalf("refused restart changed owner/audit/diagnostics entry count: before=%d after=%d", len(before), len(after))
			}
			for i := range before {
				if before[i].path != after[i].path || before[i].info.Mode() != after[i].info.Mode() || !os.SameFile(before[i].info, after[i].info) || !bytes.Equal(before[i].data, after[i].data) {
					t.Fatalf("refused restart changed owner/audit/diagnostics entry: before=%s after=%s", before[i].path, after[i].path)
				}
			}
			journal, err := controlplane.NewFileRunJournal(root)
			if err != nil {
				t.Fatalf("journal lease: %v", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			pending, err := artifact.OpenPendingFileStore(filepath.Join(root, "artifacts"))
			if err != nil {
				t.Fatalf("pending artifact lease: %v", err)
			}
			if err := pending.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func daemonTestFlagValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	t.Fatalf("missing %s", flag)
	return ""
}
func TestLocalStartupLayoutAndValidJournal(t *testing.T) {
	getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	for _, name := range []string{"clean", "v3", "unconfigured-plan", "unconfigured-setup-json", "unconfigured-symlink"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if name == "v3" {
				historicalPacketJournal(t, root, true)
			}
			if name == "unconfigured-plan" || name == "unconfigured-setup-json" {
				file := "plan.json"
				if name == "unconfigured-setup-json" {
					file = "setup.json"
				}
				if err := os.WriteFile(filepath.Join(root, file), []byte("orphan"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if name == "unconfigured-symlink" {
				// setup is an admitted directory name; a link at that name must fail
				// for its type, not merely because the filename is unknown.
				if err := os.Symlink("artifacts", filepath.Join(root, "setup")); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--state-dir", root, "--tenant", "new-tenant", "--repository", "new-repository"}
			d, err := buildDaemon(context.Background(), args, getenv, os.Stderr)
			bad := strings.HasPrefix(name, "unconfigured-")
			if bad {
				if d != nil {
					d.Close()
				}
				if d != nil || !errors.Is(err, controlplane.ErrInvalidStartupInventoryEntry) || !strings.Contains(err.Error(), "unknown direct entry") {
					t.Fatalf("unknown root: daemon=%v err=%v", d, err)
				}
				for _, directory := range []string{"audit", "diagnostics"} {
					if _, err := os.Lstat(filepath.Join(root, directory)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s created: %v", directory, err)
					}
				}
				journal, lockErr := controlplane.NewFileRunJournal(root)
				if lockErr != nil {
					t.Fatal(lockErr)
				}
				journal.Close()
				store, lockErr := artifact.NewFileStore(filepath.Join(root, "artifacts"))
				if lockErr != nil {
					t.Fatal(lockErr)
				}
				store.Close()
			} else {
				if err != nil {
					t.Fatal(err)
				}
				d.Close()
			}
		})
	}
}
func TestLocalStartupSetupStateLayout(t *testing.T) {
	for _, location := range []string{"direct-plan", "direct-setup-json", "direct-masquerade", "nested", "outside"} {
		t.Run(location, func(t *testing.T) {
			args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
			args = args[:len(args)-5]
			root := daemonTestFlagValue(t, args, "--state-dir")
			original := daemonTestFlagValue(t, args, "--setup-state")
			plan, err := setup.InspectStateFile(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "setup", "plan.json")
			switch location {
			case "direct-plan":
				path = filepath.Join(root, "plan.json")
			case "direct-setup-json":
				path = filepath.Join(root, "setup.json")
			case "direct-masquerade":
				path = filepath.Join(root, strings.Repeat("a", 64)+".run-plan.json")
			case "outside":
				path = original
			}
			if path != original {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				state, err := setup.OpenStateFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = state.Initialize(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				if err = state.Close(); err != nil {
					t.Fatal(err)
				}
				for i := range args {
					if args[i] == "--setup-state" {
						args[i+1] = path
						break
					}
				}
			}
			d, err := buildDaemon(context.Background(), args, getenv, os.Stderr)
			if strings.HasPrefix(location, "direct-") {
				if d != nil {
					d.Close()
				}
				if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) || !strings.Contains(err.Error(), "--setup-state directly inside --state-dir") || strings.Contains(err.Error(), "packet") {
					t.Fatalf("direct layout: daemon=%v err=%v", d, err)
				}
				for _, suffix := range []string{"", ".lock", ".receipts"} {
					if _, err := os.Lstat(path + suffix); err != nil {
						t.Fatalf("setup %s moved/deleted: %v", suffix, err)
					}
				}
				if _, err := os.Lstat(filepath.Join(root, "artifacts")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("artifact constructor reached: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				d.Close()
			}
		})
	}
}

func TestLocalFullStartupAcceptsNestedSetupState(t *testing.T) {
	args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
	root := daemonTestFlagValue(t, args, "--state-dir")
	original := daemonTestFlagValue(t, args, "--setup-state")
	plan, err := setup.InspectStateFile(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "setup", "plan.json")
	if err := os.MkdirAll(filepath.Dir(nested), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := setup.OpenStateFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range args {
		if args[i] == "--setup-state" {
			args[i+1] = nested
			break
		}
	}
	d, err := buildDaemon(context.Background(), args, getenv, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	for _, suffix := range []string{"", ".lock", ".receipts"} {
		if _, err := os.Lstat(nested + suffix); err != nil {
			t.Fatalf("missing setup %s: %v", suffix, err)
		}
	}
}
func TestLocalStartupRejectsIncompleteAndBoundedInventory(t *testing.T) {
	for _, variant := range []string{"plan-only", "root-entry-limit"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			journal, err := controlplane.NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "plan-only" {
				scope, err := audit.NewReviewScope("old-tenant", "old-repo", "old-run")
				if err != nil {
					t.Fatal(err)
				}
				task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 3, 1000, 30000, true)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunRequired, []controlplane.TaskDefinition{task})
				if err != nil {
					t.Fatal(err)
				}
				if err = journal.SavePlan(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
			} else {
				for i := 0; i < 1024; i++ {
					path := filepath.Join(root, fmt.Sprintf("extra-%04d", i))
					if err := os.WriteFile(path, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			journal.Close()
			d, err := buildDaemon(context.Background(), []string{"--state-dir", root, "--tenant", "new-tenant", "--repository", "new-repository"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), os.Stderr)
			if d != nil {
				d.Close()
			}
			expected := controlplane.ErrIncompleteStartupInventoryPrefix
			if variant == "root-entry-limit" {
				expected = controlplane.ErrStartupInventoryLimit
			}
			if d != nil || !errors.Is(err, expected) || errors.Is(err, controlplane.ErrPreparedContextPacketAtStartup) {
				t.Fatalf("inventory: daemon=%v err=%v", d, err)
			}
			for _, directory := range []string{"audit", "diagnostics"} {
				if _, err := os.Lstat(filepath.Join(root, directory)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s created: %v", directory, err)
				}
			}
			journal, err = controlplane.NewFileRunJournal(root)
			if err != nil {
				t.Fatalf("journal lease not released: %v", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
			if err != nil {
				t.Fatalf("artifact lease not released: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
