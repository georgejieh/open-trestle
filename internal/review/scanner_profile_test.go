package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

const nativeWorkerBuildProfile = "public_detect_run_re2_purego_go1.26.11_linux_amd64_v1"

func TestLiveScanProjectionRequiresTheHelperProfileAndDigest(t *testing.T) {
	expected := ScannerBinaryDigests{HelperSHA256: strings.Repeat("a", 64)}
	metadata := secretscan.ScanMetadata{
		Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit,
		RulesetIdentity: secretscan.RulesetIdentity, BuildProfile: secretscan.BuildProfile,
		HelperSHA256: expected.HelperSHA256, SourceCount: 1,
	}
	if !validProjectionMetadata(metadata, expected, 1) {
		t.Fatal("live scan rejected the helper build profile")
	}
	native := metadata
	native.BuildProfile = nativeWorkerBuildProfile
	other := metadata
	other.HelperSHA256 = strings.Repeat("b", 64)
	for name, value := range map[string]secretscan.ScanMetadata{"native profile": native, "other helper": other} {
		if validProjectionMetadata(value, expected, 1) {
			t.Fatalf("live scan accepted %s", name)
		}
	}
}

func TestReceiptScannerProfileNamesTheHelper(t *testing.T) {
	scanner := ScannerProfile{
		WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit,
		RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile,
		HelperSHA256: strings.Repeat("a", 64),
	}
	if !validScannerProfile(scanner) {
		t.Fatal("receipt scanner profile of the helper is invalid")
	}
	native := scanner
	native.BuildProfile = nativeWorkerBuildProfile
	zero := scanner
	zero.HelperSHA256 = strings.Repeat("0", 64)
	for name, value := range map[string]ScannerProfile{"native profile": native, "zero digest": zero} {
		if validScannerProfile(value) {
			t.Fatalf("receipt scanner profile accepted %s", name)
		}
	}
	if PublicationContentScannerIdentity(scanner) != derivePublicationContentScannerIdentity(ScannerBinaryDigests{HelperSHA256: scanner.HelperSHA256}) {
		t.Fatal("publication scanner authority differs between a receipt and a live scanner")
	}
}

func TestReceiptSchemasPinTheHelperBuildProfile(t *testing.T) {
	for _, name := range []string{"sanitized-egress-receipt-v1.schema.json", "publication-content-scan-receipt-v1.schema.json"} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", name))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties struct {
				Scanner struct {
					Required   []string `json:"required"`
					Properties struct {
						BuildProfile map[string]any `json:"build_profile"`
					} `json:"properties"`
				} `json:"scanner"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		if got := schema.Properties.Scanner.Properties.BuildProfile; len(got) != 1 || got["const"] != secretscan.BuildProfile {
			t.Fatalf("%s build_profile = %v, want the helper profile", name, got)
		}
		if required := schema.Properties.Scanner.Required; required[len(required)-1] != "helper_sha256" {
			t.Fatalf("%s scanner does not require helper_sha256: %v", name, required)
		}
	}
}
