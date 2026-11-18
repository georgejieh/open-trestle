package analysiscodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

type goldenArtifact struct {
	ScopeTenant         string                  `json:"scope_tenant"`
	ScopeRepository     string                  `json:"scope_repository"`
	ScopeRun            string                  `json:"scope_run"`
	ScopeIdentity       string                  `json:"scope_identity"`
	Kind                artifact.Kind           `json:"kind"`
	KindName            string                  `json:"kind_name"`
	MediaType           string                  `json:"media_type"`
	Classification      artifact.Classification `json:"classification"`
	ClassificationName  string                  `json:"classification_name"`
	Origin              artifact.Origin         `json:"origin"`
	OriginName          string                  `json:"origin_name"`
	Protection          artifact.Protection     `json:"protection"`
	ProtectionName      string                  `json:"protection_name"`
	Provenance          []string                `json:"provenance"`
	CreatedMilliseconds int64                   `json:"created_milliseconds"`
	ExpiresMilliseconds int64                   `json:"expires_milliseconds"`
	Payload             []byte                  `json:"payload_base64"`
	PayloadSHA256       string                  `json:"payload_sha256"`
	Identity            string                  `json:"identity"`
}
type analysisGolden struct {
	Scenario                string         `json:"scenario"`
	Base                    goldenArtifact `json:"base"`
	Head                    goldenArtifact `json:"head"`
	Change                  goldenArtifact `json:"change"`
	Evidence                goldenArtifact `json:"evidence"`
	ResultIdentity          string         `json:"result_identity"`
	CheckIdentities         []string       `json:"check_identities"`
	ObservationIdentities   []string       `json:"observation_identities"`
	ObservationFingerprints []string       `json:"observation_fingerprints"`
	SemanticIdentity        string         `json:"semantic_identity"`
}

func freezeArtifact(a artifact.Artifact) goldenArtifact {
	scope := a.Scope()
	digest := sha256.Sum256(a.Payload())
	return goldenArtifact{
		ScopeTenant: scope.TenantID(), ScopeRepository: scope.RepositoryID(), ScopeRun: scope.ReviewRunID(), ScopeIdentity: scope.Identity(),
		Kind: a.Kind(), KindName: a.Kind().String(), MediaType: a.MediaType(), Classification: a.Classification(), ClassificationName: a.Classification().String(),
		Origin: a.Origin(), OriginName: a.Origin().String(), Protection: a.Protection(), ProtectionName: a.Protection().String(),
		Provenance: a.Provenance(), CreatedMilliseconds: a.CreatedAt().UnixMilli(), ExpiresMilliseconds: a.ExpiresAt().UnixMilli(),
		Payload: a.Payload(), PayloadSHA256: hex.EncodeToString(digest[:]), Identity: a.Identity(),
	}
}

func readOldCodeGolden(t *testing.T, name string) analysisGolden {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "handlers", "analysis", "testdata", "old-code-analysis-"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var frozen analysisGolden
	if err := json.Unmarshal(payload, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.Scenario != name {
		t.Fatalf("scenario=%s, want %s", frozen.Scenario, name)
	}
	return frozen
}
func rebuildOldCodeArtifact(t *testing.T, frozen goldenArtifact) artifact.Artifact {
	t.Helper()
	scope, err := audit.NewReviewScope(frozen.ScopeTenant, frozen.ScopeRepository, frozen.ScopeRun)
	if err != nil || scope.Identity() != frozen.ScopeIdentity {
		t.Fatalf("scope identity=%s err=%v, want %s", scope.Identity(), err, frozen.ScopeIdentity)
	}
	a, err := artifact.New(scope, frozen.Kind, frozen.MediaType, frozen.Classification, frozen.Origin, frozen.Protection,
		frozen.Provenance, frozen.Payload, time.UnixMilli(frozen.CreatedMilliseconds), time.UnixMilli(frozen.ExpiresMilliseconds))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(a.Payload())
	if got := hex.EncodeToString(digest[:]); got != frozen.PayloadSHA256 {
		t.Fatalf("payload SHA-256=%s want %s", got, frozen.PayloadSHA256)
	}
	if a.Identity() != frozen.Identity || !reflect.DeepEqual(freezeArtifact(a), frozen) {
		t.Fatalf("reconstructed %s artifact metadata or identity differs from frozen values", frozen.KindName)
	}
	return a
}
func verifyOldCodeGolden(t *testing.T, frozen analysisGolden) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) {
	t.Helper()
	base := rebuildOldCodeArtifact(t, frozen.Base)
	head := rebuildOldCodeArtifact(t, frozen.Head)
	change := rebuildOldCodeArtifact(t, frozen.Change)
	evidence := rebuildOldCodeArtifact(t, frozen.Evidence)
	parsed, err := ParseResultArtifact(evidence, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identity() != frozen.ResultIdentity || parsed.ArtifactIdentity() != frozen.Evidence.Identity || parsed.SemanticImpact().Identity() != frozen.SemanticIdentity {
		t.Fatalf("parsed result/artifact/semantic identities differ from %s", frozen.Scenario)
	}
	checks := make([]string, 0, len(parsed.Checks()))
	for _, c := range parsed.Checks() {
		checks = append(checks, c.Identity())
	}
	observations := make([]string, 0, len(parsed.Observations()))
	fingerprints := make([]string, 0, len(parsed.Observations()))
	for _, o := range parsed.Observations() {
		observations = append(observations, o.Identity())
		fingerprints = append(fingerprints, o.Fingerprint())
	}
	if !reflect.DeepEqual(checks, frozen.CheckIdentities) || !reflect.DeepEqual(observations, frozen.ObservationIdentities) || !reflect.DeepEqual(fingerprints, frozen.ObservationFingerprints) {
		t.Fatalf("check/observation/fingerprint identities differ from %s", frozen.Scenario)
	}
	switch frozen.Scenario {
	case "produced-v4-failed-one-observation":
		if parsed.SchemaVersion() != 4 || len(checks) != 1 || len(observations) != 1 || parsed.Checks()[0].State() != CheckFailed {
			t.Fatal("produced v4 shape changed")
		}
	case "produced-v4-removed-file-gap":
		if parsed.SchemaVersion() != 4 || len(checks) != 1 || len(observations) != 0 || len(parsed.Gaps()) != 1 || len(parsed.Items()) != 0 || parsed.Checks()[0].State() != CheckNotApplicable {
			t.Fatal("removed-file v4 shape changed")
		}
	case "produced-v4-go-affected-test":
		if parsed.SchemaVersion() != 4 || len(checks) != 1 || len(observations) != 0 || len(parsed.Items()) != 1 || len(parsed.Gaps()) != 0 || parsed.SemanticImpact().GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v1" || parsed.Checks()[0].State() != CheckPassed {
			t.Fatal("Go affected-test v4 shape changed")
		}
	case "produced-v4-go-modified-function":
		if parsed.SchemaVersion() != 4 || len(checks) != 1 || len(observations) != 0 || len(parsed.Items()) != 1 || len(parsed.Gaps()) != 0 || parsed.SemanticImpact().GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v2" || len(parsed.SemanticImpact().Declarations()) != 1 || parsed.Checks()[0].State() != CheckPassed {
			t.Fatal("Go modified-function v4 shape changed")
		}
	case "synthetic-v4-zero-match":
		if parsed.SchemaVersion() != 4 || len(checks) != 1 || len(observations) != 0 || !bytes.Contains(evidence.Payload(), []byte(`"observations":[]`)) {
			t.Fatal("zero-match v4 shape changed")
		}
	case "synthetic-v3-check-no-observations":
		if parsed.SchemaVersion() != 3 || len(checks) != 1 || len(observations) != 0 || bytes.Contains(evidence.Payload(), []byte(`"observations"`)) {
			t.Fatal("legacy v3 shape changed")
		}
	case "synthetic-v2-no-checks-observations":
		if parsed.SchemaVersion() != 2 || len(checks) != 0 || len(observations) != 0 || bytes.Contains(evidence.Payload(), []byte(`"checks"`)) || bytes.Contains(evidence.Payload(), []byte(`"observations"`)) || parsed.Identity() != "9b51d2bfc59feabac5deb4f8b49f40ae89a7cc6b969fe07542b4a8a6b19b88a1" {
			t.Fatal("legacy v2 shape or retained identity changed")
		}
	default:
		t.Fatalf("unknown golden scenario %s", frozen.Scenario)
	}
	return base, head, change, evidence
}
func TestOldCodeAnalysisGoldenFixtures(t *testing.T) {
	for _, name := range []string{"produced-v4-failed-one-observation", "produced-v4-removed-file-gap", "produced-v4-go-affected-test", "produced-v4-go-modified-function", "synthetic-v4-zero-match", "synthetic-v3-check-no-observations", "synthetic-v2-no-checks-observations"} {
		t.Run(name, func(t *testing.T) { verifyOldCodeGolden(t, readOldCodeGolden(t, name)) })
	}
}
