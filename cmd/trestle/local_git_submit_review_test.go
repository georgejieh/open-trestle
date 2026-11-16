package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func TestLocalGitSubmitReviewSendsFullIntentWithoutSourceOrRouteAuthority(t *testing.T) {
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file.go": []byte("package p\n")}, map[string][]byte{"file.go": []byte("package p\nimport \"fmt\"\nfunc f(){fmt.Println(\"debug\")}\n")})
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(1000))
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	posted := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/runs" || request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Errorf("request=%s %s", request.Method, request.URL.Path)
		}
		var encoded bytes.Buffer
		_, _ = encoded.ReadFrom(request.Body)
		posted = append(posted, encoded.String())
		intent, err := runtimecatalog.ParseLocalFullReviewIntent(encoded.Bytes())
		if err != nil || intent.Scope().Identity() != scope.Identity() || intent.BaseRevision().Digest() != baseDigest || intent.HeadRevision().Digest() != headDigest || intent.ReviewPolicyIdentity() != strings.Repeat("e", 64) || intent.InventoryIdentity() != strings.Repeat("f", 64) || intent.RuntimePolicyIdentity() != strings.Repeat("a", 64) || bytes.Contains(encoded.Bytes(), []byte(objects)) || bytes.Contains(encoded.Bytes(), []byte("objects_root")) {
			t.Errorf("intent=(%#v,%v) body=%s", intent, err, encoded.Bytes())
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"contract":"open-trestle/api-response","schema_version":1,"request_id":"request-1","run":` + string(encodedReceipt) + `}`))
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	args := append(localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest), "--server", server.URL, "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--review-policy-identity", strings.Repeat("e", 64), "--inventory-identity", strings.Repeat("f", 64), "--runtime-policy-identity", strings.Repeat("a", 64))
	var stdout, stderr bytes.Buffer
	if code := runLocalGitSubmitReview(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("submit=%d stdout=%s stderr=%s", code, stdout.Bytes(), stderr.Bytes())
	}
	parsed, err := controlplane.ParseReviewRunReceipt(bytes.TrimSpace(stdout.Bytes()))
	if err != nil || parsed.Scope().Identity() != scope.Identity() {
		t.Fatalf("receipt=(%#v,%v)", parsed, err)
	}
	args[len(args)-1] = "bad"
	stdout.Reset()
	stderr.Reset()
	if code := runLocalGitSubmitReview(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("invalid identity=%d stdout=%s stderr=%s", code, stdout.Bytes(), stderr.Bytes())
	}
	args[len(args)-1] = strings.Repeat("a", 64)
	args = append(args, "--created-at-unix-milliseconds", strconv.FormatInt(time.Now().UTC().UnixMilli(), 10))
	for i := 0; i < 2; i++ {
		stdout.Reset()
		stderr.Reset()
		if code := runLocalGitSubmitReview(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("retry %d=%d stdout=%s stderr=%s", i, code, stdout.Bytes(), stderr.Bytes())
		}
	}
	if len(posted) != 3 || posted[1] != posted[2] {
		t.Fatalf("explicit timestamp did not preserve exact replay: %d posts", len(posted))
	}
}
