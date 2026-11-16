package runtimecatalog

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalFullReviewIntentBindsExpectedPolicyWithoutClientAuthority(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	intent, err := NewLocalFullReviewIntent(scope, repository, base, head, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeLocalFullReviewIntent(intent)
	parsed, parseErr := ParseLocalFullReviewIntent(encoded)
	if err != nil || parseErr != nil || parsed.Identity() != intent.Identity() || parsed.ReviewPolicyIdentity() != strings.Repeat("a", 64) || parsed.InventoryIdentity() != strings.Repeat("b", 64) || parsed.RuntimePolicyIdentity() != strings.Repeat("c", 64) {
		t.Fatalf("round trip=(%#v,%v,%v)", parsed, err, parseErr)
	}
	for _, forbidden := range [][]byte{[]byte("objects_root"), []byte("endpoint"), []byte("credential"), []byte("publication")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("client supplied authority: %s", encoded)
		}
	}
	mutated := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"objects_root":"/tmp/repo"`), 1)
	if _, err := ParseLocalFullReviewIntent(mutated); err == nil {
		t.Fatalf("path-bearing intent accepted: %s", mutated)
	}
	changed := bytes.Replace(encoded, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("d", 64)), 1)
	if _, err := ParseLocalFullReviewIntent(changed); err == nil {
		t.Fatal("unbound policy identity accepted")
	}
}
