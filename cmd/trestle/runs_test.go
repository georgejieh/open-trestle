package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func remotePlanAndReceipt(t *testing.T) (controlplane.ReviewRunPlan, controlplane.ReviewRunReceipt) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	return plan, receipt
}
func TestRunRemoteCommandsUseDaemonContracts(t *testing.T) {
	plan, receipt := remotePlanAndReceipt(t)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	response, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encodedReceipt)})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Errorf("authorization missing")
		}
		if requests == 1 {
			writer.WriteHeader(http.StatusAccepted)
		}
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_URL", server.URL)
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, encodedPlan, 0o600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{{"runs", "submit", "--plan", planPath}, {"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}, {"runs", "cancel", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}}
	for _, command := range commands {
		var stdout, stderr bytes.Buffer
		if exit := run(command, &stdout, &stderr); exit != 0 {
			t.Fatalf("%v exit=%d stderr=%q", command, exit, stderr.String())
		}
		parsed, err := controlplane.ParseReviewRunReceipt(bytes.TrimSpace(stdout.Bytes()))
		if err != nil || parsed.Identity() != receipt.Identity() {
			t.Fatalf("%v output=(%s,%v)", command, stdout.String(), err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%v stderr=%q", command, stderr.String())
		}
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestReadRegularBoundedFileRejectsDirectFIFOBeforeOpening(t *testing.T) {
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo is unavailable")
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if output, err := exec.Command(mkfifo, path).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo error=%v output=%q", err, output)
	}
	opened := false
	_, err = readRegularBoundedFileWithOpener(path, 1<<20, func(string) (*os.File, error) {
		opened = true
		return nil, os.ErrInvalid
	})
	if opened {
		t.Fatal("direct FIFO reached opener")
	}
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("read error=%v, want regular-file rejection", err)
	}
}

func TestReadRegularBoundedFileRejectsReplacementAtOpen(t *testing.T) {
	for _, replacement := range []string{"fifo", "symlink", "regular", "regular-before"} {
		t.Run(replacement, func(t *testing.T) {
			if runtime.GOOS == "windows" && replacement == "regular" {
				t.Skip("Windows prevents replacing an open input file")
			}
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "input.json")
			if err := os.WriteFile(sourcePath, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(directory, "target.json")
			if err := os.WriteFile(targetPath, []byte("target"), 0o600); err != nil {
				t.Fatal(err)
			}

			mkfifo := ""
			switch replacement {
			case "fifo":
				var err error
				mkfifo, err = exec.LookPath("mkfifo")
				if err != nil {
					t.Skip("mkfifo is unavailable")
				}
			case "symlink":
				probePath := filepath.Join(directory, "probe-link.json")
				if err := os.Symlink(targetPath, probePath); err != nil {
					t.Skipf("symlink is unavailable: %v", err)
				}
				if err := os.Remove(probePath); err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadRegularBoundedFileReplacementHelper$")
			command.Env = append(os.Environ(),
				"OPEN_TRESTLE_TEST_REPLACE_REGULAR_INPUT=1",
				"OPEN_TRESTLE_TEST_REPLACE_KIND="+replacement,
				"OPEN_TRESTLE_TEST_REPLACE_PATH="+sourcePath,
				"OPEN_TRESTLE_TEST_REPLACE_TARGET="+targetPath,
				"OPEN_TRESTLE_TEST_REPLACE_MKFIFO="+mkfifo,
			)
			output, err := command.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("read blocked after %s replacement at open; output=%q", replacement, output)
			}
			if err != nil {
				t.Fatalf("read after %s replacement at open: %v; output=%q", replacement, err, output)
			}
		})
	}
}

func TestReadRegularBoundedFileReplacementHelper(t *testing.T) {
	if os.Getenv("OPEN_TRESTLE_TEST_REPLACE_REGULAR_INPUT") != "1" {
		return
	}

	sourcePath := os.Getenv("OPEN_TRESTLE_TEST_REPLACE_PATH")
	targetPath := os.Getenv("OPEN_TRESTLE_TEST_REPLACE_TARGET")
	replacement := os.Getenv("OPEN_TRESTLE_TEST_REPLACE_KIND")
	replaced := false
	openFile := func(path string) (*os.File, error) {
		if path == sourcePath && !replaced {
			replaced = true
			if replacement == "regular" {
				file, err := openRegularInputFileNative(path)
				if err != nil {
					return nil, err
				}
				if err := os.Remove(sourcePath); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := os.Rename(targetPath, sourcePath); err != nil {
					file.Close()
					t.Fatal(err)
				}
				return file, nil
			}
			if err := os.Remove(sourcePath); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "fifo":
				if output, err := exec.Command(os.Getenv("OPEN_TRESTLE_TEST_REPLACE_MKFIFO"), sourcePath).CombinedOutput(); err != nil {
					t.Fatalf("mkfifo error=%v output=%q", err, output)
				}
			case "symlink":
				if err := os.Symlink(targetPath, sourcePath); err != nil {
					t.Fatal(err)
				}
			case "regular-before":
				if err := os.Rename(targetPath, sourcePath); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown replacement %q", replacement)
			}
		}
		return openRegularInputFileNative(path)
	}

	_, err := readRegularBoundedFileWithOpener(sourcePath, 1<<20, openFile)
	if !replaced {
		t.Fatal("input was not replaced at open")
	}
	want := "regular file"
	if replacement == "regular" || replacement == "regular-before" {
		want = "unchanged regular file"
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("read error=%v, want %q rejection", err, want)
	}
}

func TestRunRemoteRejectsMissingCredentialAndUnsafePlanInput(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}, &stdout, &stderr); exit != 2 || !strings.Contains(stderr.String(), "OPEN_TRESTLE_API_TOKEN") {
		t.Fatalf("missing token=(%d,%q)", exit, stderr.String())
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "plan.json")
	_ = os.WriteFile(target, []byte("{}"), 0o600)
	link := filepath.Join(directory, "plan-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"runs", "submit", "--plan", link}, &stdout, &stderr); exit != 1 || !strings.Contains(stderr.String(), "regular file") {
		t.Fatalf("symlink=(%d,%q)", exit, stderr.String())
	}
}

func TestRunStatusExportsSameStoredDeterministicSetAsJSONAndSARIF(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	analysisIdentity := strings.Repeat("8", 64)
	changeIdentity := strings.Repeat("7", 64)
	sourceCheck := diagnostics.DeterministicCheck{}
	// Use the canonical source-check identity for one failed exact match.
	check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b", analysisIdentity, changeIdentity, diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = sourceCheck
	observation, _ := diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), analysisIdentity, check.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", diagnostics.SeverityWarning, "main.go", 3, 3, []string{strings.Repeat("4", 64), strings.Repeat("9", 64)})
	set, err := diagnostics.NewSetWithDeterministicObservations(receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	encodedSet, _ := diagnostics.EncodeSet(set)
	runResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-run", "run": json.RawMessage(encodedReceipt)})
	diagnosticResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-diagnostics", "diagnostics": json.RawMessage(encodedSet)})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(request.URL.Path, "/diagnostics") {
			_, _ = writer.Write(diagnosticResponse)
		} else {
			_, _ = writer.Write(runResponse)
		}
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	base := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL}
	var jsonOut, jsonErr bytes.Buffer
	if exit := run(append(base, "--format", "json"), &jsonOut, &jsonErr); exit != 0 || !bytes.Equal(bytes.TrimSpace(jsonOut.Bytes()), encodedSet) {
		t.Fatalf("json=(%d,%s,%s)", exit, jsonOut.Bytes(), jsonErr.Bytes())
	}
	var sarifOut, sarifErr bytes.Buffer
	if exit := run(append(base, "--format", "sarif"), &sarifOut, &sarifErr); exit != 0 || !bytes.Contains(sarifOut.Bytes(), []byte(`"uri":"main.go"`)) || !bytes.Contains(sarifOut.Bytes(), []byte(observation.Identity())) || !bytes.Contains(sarifOut.Bytes(), []byte(strings.Repeat("4", 64))) || !bytes.Contains(sarifOut.Bytes(), []byte(strings.Repeat("9", 64))) || !bytes.Contains(sarifOut.Bytes(), []byte("human review is required")) || bytes.Contains(sarifOut.Bytes(), []byte(`"trestleStatus":"verified"`)) {
		t.Fatalf("sarif=(%d,%s,%s)", exit, sarifOut.Bytes(), sarifErr.Bytes())
	}
	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string            `json:"ruleId"`
				Fingerprints map[string]string `json:"fingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifOut.Bytes(), &sarif); err != nil {
		t.Fatalf("decode v6 SARIF: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Tool.Driver.Rules) != 1 || sarif.Runs[0].Tool.Driver.Rules[0].ID != "static-debug-output" || len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].RuleID != "static-debug-output" || sarif.Runs[0].Results[0].Fingerprints["openTrestleObservationId/v1"] != observation.Identity() {
		t.Fatalf("v6 observation rule/fingerprint not preserved: %+v", sarif.Runs)
	}
}

// The receipt stays in a memory journal; only the diagnostic store is reopened.
func TestRunStatusReadsStoredDeterministicSetAcrossFileStoreReopen(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Open(ctx, plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Scope().Identity() != scope.Identity() {
		t.Fatal("memory-journal receipt scope differs")
	}

	analysisIdentity := strings.Repeat("8", 64)
	check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b", analysisIdentity, strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), analysisIdentity, check.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", diagnostics.SeverityWarning, "main.go", 3, 3, []string{strings.Repeat("4", 64), strings.Repeat("9", 64)})
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	assertSet := func(label string, got diagnostics.Set) {
		t.Helper()
		checks, observations := got.DeterministicChecks(), got.DeterministicObservations()
		if got.SchemaVersion() != 6 || got.Scope().Identity() != scope.Identity() || got.Identity() != set.Identity() || got.AnalysisResultIdentity() != analysisIdentity || len(got.Findings()) != 0 || len(checks) != 1 || len(observations) != 1 {
			t.Fatalf("%s: v6 set shape or identity differs", label)
		}
		if checks[0].Identity() != check.Identity() || checks[0].AnalysisResultIdentity() != analysisIdentity || observations[0].Identity() != observation.Identity() || observations[0].CheckIdentity() != check.Identity() || observations[0].AnalysisResultIdentity() != analysisIdentity {
			t.Fatalf("%s: check/observation/analysis identities differ", label)
		}
	}
	assertSet("constructed", set)
	encodedSet, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	assertStored := func(label string, store *diagnostics.FileStore) {
		t.Helper()
		stored, readErr := store.GetDiagnosticSet(ctx, scope)
		if readErr != nil {
			t.Fatalf("%s: read diagnostic set: %v", label, readErr)
		}
		assertSet(label, stored)
		encoded, encodeErr := diagnostics.EncodeSet(stored)
		if encodeErr != nil {
			t.Fatalf("%s: encode diagnostic set: %v", label, encodeErr)
		}
		if !bytes.Equal(encoded, encodedSet) {
			t.Fatalf("%s: stored canonical set bytes differ", label)
		}
	}
	root := filepath.Join(t.TempDir(), "diagnostics")
	store, err := diagnostics.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("cleanup first diagnostic writer: %v", err)
		}
	})
	inserted, err := store.PutDiagnosticSet(ctx, set)
	if err != nil || !inserted {
		t.Fatalf("put diagnostic set: inserted=%t err=%v", inserted, err)
	}
	assertStored("initial store", store)

	const token = "01234567890123456789012345678901"
	principal, err := httpapi.NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: token, Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", token)

	type phaseOutput struct{ json, sarif []byte }
	phase := func(label string, store *diagnostics.FileStore) phaseOutput {
		t.Helper()
		serverHandler, serverErr := httpapi.NewServerWithDiagnostics(coordinator, authenticator, httpapi.SystemClock{}, store)
		if serverErr != nil {
			t.Fatalf("%s: construct server: %v", label, serverErr)
		}
		server := httptest.NewServer(serverHandler)
		t.Cleanup(server.Close)
		defer server.Close()
		apiClient, clientErr := client.NewLocal(server.URL, token, nil)
		if clientErr != nil {
			t.Fatalf("%s: create local client: %v", label, clientErr)
		}
		gotReceipt, clientErr := apiClient.GetRun(ctx, scope)
		if clientErr != nil || gotReceipt.Identity() != receipt.Identity() || gotReceipt.Scope().Identity() != scope.Identity() {
			t.Fatalf("%s: client receipt identity/scope: got=%q err=%v", label, gotReceipt.Identity(), clientErr)
		}
		gotSet, clientErr := apiClient.GetDiagnosticSet(ctx, scope)
		if clientErr != nil {
			t.Fatalf("%s: client diagnostic set: %v", label, clientErr)
		}
		assertSet(label+" client", gotSet)
		clientEncoded, encodeErr := diagnostics.EncodeSet(gotSet)
		if encodeErr != nil || !bytes.Equal(clientEncoded, encodedSet) {
			t.Fatalf("%s: client canonical bytes: err=%v", label, encodeErr)
		}

		base := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL}
		invoke := func(format string) []byte {
			t.Helper()
			var stdout, stderr bytes.Buffer
			args := append(append([]string(nil), base...), "--format", format)
			if exit := run(args, &stdout, &stderr); exit != 0 || stderr.Len() != 0 {
				t.Fatalf("%s CLI %s: exit=%d stderr=%q stdout=%q", label, format, exit, stderr.String(), stdout.String())
			}
			return bytes.Clone(stdout.Bytes())
		}
		jsonOutput := invoke("json")
		if !bytes.Equal(jsonOutput, append(bytes.Clone(encodedSet), '\n')) {
			t.Fatalf("%s: CLI JSON differs from canonical set plus newline", label)
		}
		cliSet, parseErr := diagnostics.ParseSet(bytes.TrimSuffix(jsonOutput, []byte{'\n'}))
		if parseErr != nil {
			t.Fatalf("%s: parse CLI JSON: %v", label, parseErr)
		}
		assertSet(label+" CLI JSON", cliSet)
		sarifOutput := invoke("sarif")
		var sarif struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID string `json:"id"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Properties struct {
					SetID      string `json:"trestleDiagnosticSetId"`
					CheckID    string `json:"trestleCheckId"`
					Status     string `json:"trestleStatus"`
					CheckState string `json:"trestleCheckState"`
				} `json:"properties"`
				Results []struct {
					RuleID       string            `json:"ruleId"`
					Fingerprints map[string]string `json:"fingerprints"`
					Properties   struct {
						ObservationID string `json:"trestleObservationId"`
						CheckID       string `json:"trestleCheckId"`
					} `json:"properties"`
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI string `json:"uri"`
							} `json:"artifactLocation"`
							Region struct {
								StartLine int `json:"startLine"`
								EndLine   int `json:"endLine"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		}
		if parseErr := json.Unmarshal(sarifOutput, &sarif); parseErr != nil {
			t.Fatalf("%s: parse SARIF: %v", label, parseErr)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("%s: SARIF runs=%d", label, len(sarif.Runs))
		}
		runResult := sarif.Runs[0]
		if runResult.Properties.SetID != set.Identity() || runResult.Properties.CheckID != check.Identity() || runResult.Properties.Status != "inconclusive" || runResult.Properties.CheckState != "failed" || len(runResult.Tool.Driver.Rules) != 1 || runResult.Tool.Driver.Rules[0].ID != "static-debug-output" || len(runResult.Results) != 1 {
			t.Fatalf("%s: SARIF run properties/rules/results differ: %+v", label, runResult)
		}
		result := runResult.Results[0]
		if result.RuleID != "static-debug-output" || result.Fingerprints["openTrestleObservationId/v1"] != observation.Identity() || result.Properties.ObservationID != observation.Identity() || result.Properties.CheckID != check.Identity() || len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "main.go" || result.Locations[0].PhysicalLocation.Region.StartLine != 3 || result.Locations[0].PhysicalLocation.Region.EndLine != 3 {
			t.Fatalf("%s: SARIF observation identity/location differs: %+v", label, result)
		}
		if bytes.Contains(sarifOutput, []byte("open-trestle-verified-finding")) || bytes.Contains(sarifOutput, []byte(`"trestleStatus":"verified"`)) {
			t.Fatalf("%s: SARIF claims a verified finding", label)
		}

		path := "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a"
		request := func(endpoint, bearer string, wantStatus int, wantCode string) json.RawMessage {
			t.Helper()
			req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+endpoint, nil)
			if requestErr != nil {
				t.Fatalf("%s: create request: %v", label, requestErr)
			}
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			response, requestErr := server.Client().Do(req)
			if requestErr != nil {
				t.Fatalf("%s: direct HTTP GET %s: %v", label, endpoint, requestErr)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != wantStatus {
				t.Fatalf("%s: direct HTTP GET %s: status=%d read=%v close=%v body=%s", label, endpoint, response.StatusCode, readErr, closeErr, body)
			}
			var envelope struct {
				Diagnostics json.RawMessage `json:"diagnostics"`
				Error       *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if decodeErr := json.Unmarshal(body, &envelope); decodeErr != nil {
				t.Fatalf("%s: decode HTTP envelope: %v", label, decodeErr)
			}
			if wantCode != "" {
				if envelope.Error == nil || envelope.Error.Code != wantCode || len(envelope.Diagnostics) != 0 {
					t.Fatalf("%s: HTTP denial %s: %+v", label, endpoint, envelope.Error)
				}
			} else if envelope.Error != nil {
				t.Fatalf("%s: HTTP success had error: %+v", label, envelope.Error)
			}
			return envelope.Diagnostics
		}
		apiJSON := request(path+"/diagnostics", token, http.StatusOK, "")
		if !bytes.Equal(apiJSON, encodedSet) {
			t.Fatalf("%s: HTTP diagnostics raw value differs from canonical set", label)
		}
		parsedAPISet, parseErr := diagnostics.ParseSet(apiJSON)
		if parseErr != nil {
			t.Fatalf("%s: parse HTTP diagnostics: %v", label, parseErr)
		}
		assertSet(label+" direct API", parsedAPISet)
		for _, endpoint := range []string{path, path + "/diagnostics"} {
			request(endpoint, "", http.StatusUnauthorized, "unauthenticated")
			request(strings.Replace(endpoint, "/repo-a/", "/repo-b/", 1), token, http.StatusForbidden, "forbidden")
		}
		return phaseOutput{json: jsonOutput, sarif: sarifOutput}
	}
	first := phase("before reopen", store)
	if err := store.Close(); err != nil {
		t.Fatalf("close first diagnostic writer: %v", err)
	}
	reopened, err := diagnostics.NewFileStore(root)
	if err != nil {
		t.Fatalf("reopen diagnostic store: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("cleanup reopened diagnostic writer: %v", err)
		}
	})
	assertStored("reopened store", reopened)
	second := phase("after reopen", reopened)
	if !bytes.Equal(first.json, second.json) || !bytes.Equal(first.sarif, second.sarif) {
		t.Fatal("CLI JSON or SARIF bytes changed across diagnostic store/server reopen")
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened diagnostic writer: %v", err)
	}
}

func TestRunSubmitAcceptsPlanFileWithOneTrailingNewline(t *testing.T) {
	plan, receipt := remotePlanAndReceipt(t)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	response, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encodedReceipt)})
	var submitted []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		submitted, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_URL", server.URL)
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	canonical, _ := controlplane.EncodeReviewRunPlan(plan)
	directory := t.TempDir()
	for _, tc := range []struct {
		name    string
		content []byte
		exit    int
	}{
		{"exact", canonical, 0},
		{"one newline", append(bytes.Clone(canonical), '\n'), 0},
		{"two newlines", append(bytes.Clone(canonical), '\n', '\n'), 1},
		{"carriage return", append(bytes.Clone(canonical), '\r', '\n'), 1},
	} {
		path := filepath.Join(directory, strings.ReplaceAll(tc.name, " ", "-")+".json")
		if err := os.WriteFile(path, tc.content, 0o600); err != nil {
			t.Fatal(err)
		}
		submitted = nil
		var stdout, stderr bytes.Buffer
		if exit := run([]string{"runs", "submit", "--plan", path}, &stdout, &stderr); exit != tc.exit {
			t.Fatalf("%s: exit=%d stderr=%q", tc.name, exit, stderr.String())
		}
		if (tc.exit == 0) != bytes.Equal(submitted, canonical) {
			t.Fatalf("%s: submitted body=%q", tc.name, submitted)
		}
	}
}
