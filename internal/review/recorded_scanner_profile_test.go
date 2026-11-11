package review

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

const recordedGo12610BuildProfile = "public_detect_run_re2_purego_go1.26.10_linux_amd64_v1"

func readRecordedReceipt(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRecordedGo12610SanitizedEgressReceiptReadsBackByteForByte(t *testing.T) {
	recorded := readRecordedReceipt(t, "sanitized-egress-receipt-v1-go1.26.10.json")
	receipt, err := ParseSanitizedEgressReceipt(recorded)
	if err != nil || receipt.Scanner().BuildProfile != recordedGo12610BuildProfile {
		t.Fatalf("recorded go1.26.10 receipt did not read back: %v", err)
	}
	encoded, err := EncodeSanitizedEgressReceipt(receipt)
	if err != nil || !bytes.Equal(encoded, recorded) {
		t.Fatalf("recorded go1.26.10 receipt changed on re-encode: %v", err)
	}
	for _, profile := range []string{"public_detect_run_re2_purego_go1.26.8_linux_amd64_v1", "public_detect_run_re2_purego_go1.26.12_linux_amd64_v1"} {
		input := receiptInputFrom(t, receipt)
		input.Scanner.BuildProfile = profile
		if _, err := NewSanitizedEgressReceipt(input); err == nil {
			t.Fatalf("receipt accepted unrecorded build profile %q", profile)
		}
		mutated := bytes.Replace(recorded, []byte(recordedGo12610BuildProfile), []byte(profile), 1)
		if _, err := ParseSanitizedEgressReceipt(mutated); err == nil {
			t.Fatalf("recorded bytes accepted unrecorded build profile %q", profile)
		}
	}
}

func TestRecordedGo12610PublicationContentScanReceiptReadsBackByteForByte(t *testing.T) {
	recorded := readRecordedReceipt(t, "publication-content-scan-receipt-v1-go1.26.10.json")
	receipt, err := ParsePublicationContentScanReceipt(recorded)
	if err != nil || receipt.Scanner().BuildProfile != recordedGo12610BuildProfile {
		t.Fatalf("recorded go1.26.10 receipt did not read back: %v", err)
	}
	encoded, err := EncodePublicationContentScanReceipt(receipt)
	if err != nil || !bytes.Equal(encoded, recorded) {
		t.Fatalf("recorded go1.26.10 receipt changed on re-encode: %v", err)
	}
	if receipt.ScannerAuthorityIdentity() != PublicationContentScannerIdentity(receipt.Scanner()) {
		t.Fatal("recorded scanner authority is not derived from its own build profile")
	}
	live := newFixedPublicationContentScanner(&fixedGenerationClientFixture{launcher: receipt.Scanner().LauncherSHA256, worker: receipt.Scanner().WorkerSHA256})
	if live.Identity() == receipt.ScannerAuthorityIdentity() {
		t.Fatal("a current scanner with the recorded digests inherited the go1.26.10 scanner authority")
	}
	current := receipt.Scanner()
	current.BuildProfile = secretscan.BuildProfile
	if live.Identity() != PublicationContentScannerIdentity(current) {
		t.Fatal("current scanner authority does not match its own profile")
	}
}

func TestLiveScanProjectionRequiresTheCurrentBuildProfile(t *testing.T) {
	expected := ScannerBinaryDigests{LauncherSHA256: strings.Repeat("a", 64), WorkerSHA256: strings.Repeat("b", 64)}
	metadata := secretscan.ScanMetadata{
		Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit,
		RulesetIdentity: secretscan.RulesetIdentity, BuildProfile: secretscan.BuildProfile,
		LauncherSHA256: expected.LauncherSHA256, WorkerSHA256: expected.WorkerSHA256, SourceCount: 1,
	}
	if !validProjectionMetadata(metadata, expected, 1) {
		t.Fatal("live scan rejected the current build profile")
	}
	metadata.BuildProfile = recordedGo12610BuildProfile
	if validProjectionMetadata(metadata, expected, 1) {
		t.Fatal("live scan accepted the recorded go1.26.10 build profile")
	}
}

func TestReceiptSchemasAcceptExactlyCurrentAndRecordedBuildProfiles(t *testing.T) {
	for _, name := range []string{"sanitized-egress-receipt-v1.schema.json", "publication-content-scan-receipt-v1.schema.json"} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", name))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties struct {
				Scanner struct {
					Properties struct {
						BuildProfile map[string]any `json:"build_profile"`
					} `json:"properties"`
				} `json:"scanner"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"enum": []any{secretscan.BuildProfile, recordedGo12610BuildProfile}}
		if got := schema.Properties.Scanner.Properties.BuildProfile; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s build_profile = %v, want %v", name, got, want)
		}
	}
}
