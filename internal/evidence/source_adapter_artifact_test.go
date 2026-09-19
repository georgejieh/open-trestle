package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestNewSourceAdapterImplementationArtifact(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	content := []byte{0x00, 0xff, 0xfe, 'a'}
	artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, content)
	if err != nil {
		t.Fatalf("NewSourceAdapterImplementationArtifact() error = %v", err)
	}
	digest := sha256.Sum256(content)
	if artifact.Identity() == "" || artifact.SourceAdapterIdentity() != adapter.Identity() || artifact.Kind() != SourceAdapterArtifactComponent || artifact.DigestAlgorithm() != "sha256" || artifact.Digest() != hex.EncodeToString(digest[:]) || artifact.SizeBytes() != len(content) {
		t.Fatalf("artifact = %#v", artifact)
	}
}

func TestSourceAdapterImplementationArtifactIdentityPreimage(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	content := []byte("component")
	artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, content)
	if err != nil {
		t.Fatalf("NewSourceAdapterImplementationArtifact() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/source-adapter-implementation-artifact","schema_version":1,"source_adapter_identity":"%s","kind":"source_adapter_component","digest_algorithm":"sha256","digest":"%s","size_bytes":%d}`, adapter.Identity(), artifact.Digest(), len(content))
	digest := sha256.Sum256([]byte(preimage))
	if artifact.Identity() != hex.EncodeToString(digest[:]) {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", artifact.Identity(), preimage)
	}
}

func TestSourceAdapterImplementationArtifactBindsContentAndAdapter(t *testing.T) {
	baseAdapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	changedName, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "other-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity(name) error = %v", err)
	}
	changedVersion, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.4", []SourceAdapterCapability{SourceCapabilityReadManifest})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity(version) error = %v", err)
	}
	changedCapabilities := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	base, err := NewSourceAdapterImplementationArtifact(baseAdapter, SourceAdapterArtifactComponent, []byte("a"))
	if err != nil {
		t.Fatalf("NewSourceAdapterImplementationArtifact() error = %v", err)
	}
	changedContent, err := NewSourceAdapterImplementationArtifact(baseAdapter, SourceAdapterArtifactComponent, []byte("b"))
	if err != nil {
		t.Fatalf("changed content error = %v", err)
	}
	for name, adapter := range map[string]SourceAdapterIdentity{"name": changedName, "version": changedVersion, "capabilities": changedCapabilities} {
		t.Run(name, func(t *testing.T) {
			artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, []byte("a"))
			if err != nil {
				t.Fatalf("NewSourceAdapterImplementationArtifact() error = %v", err)
			}
			if artifact.Identity() == base.Identity() || artifact.Digest() != base.Digest() {
				t.Fatalf("adapter change artifact = %#v, base = %#v", artifact, base)
			}
		})
	}
	if changedContent.Identity() == base.Identity() || changedContent.Digest() == base.Digest() {
		t.Fatalf("content change artifacts = (%#v, %#v)", base, changedContent)
	}
}

func TestNewSourceAdapterImplementationArtifactRejectsEmptyAndOverBoundContent(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	if artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, nil); err == nil || artifact.Identity() != "" {
		t.Fatalf("empty content = (%#v, %v)", artifact, err)
	}
	atLimit := make([]byte, maxSourceAdapterArtifactBytes)
	atLimit[0] = 1
	artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, atLimit)
	if err != nil || artifact.SizeBytes() != maxSourceAdapterArtifactBytes {
		t.Fatalf("limit content = (%#v, %v)", artifact, err)
	}
	overLimit := make([]byte, maxSourceAdapterArtifactBytes+1)
	if artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, overLimit); err == nil || artifact.Identity() != "" {
		t.Fatalf("over-limit content = (%#v, %v)", artifact, err)
	}
}

func TestNewSourceAdapterImplementationArtifactRejectsUnsupportedKinds(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	for _, kind := range []SourceAdapterArtifactKind{"", "component", "executable", "SOURCE_ADAPTER_COMPONENT"} {
		if artifact, err := NewSourceAdapterImplementationArtifact(adapter, kind, []byte("component")); err == nil || artifact.Identity() != "" {
			t.Fatalf("kind %q = (%#v, %v)", kind, artifact, err)
		}
	}
}

func TestNewSourceAdapterImplementationArtifactRejectsForgedAdapter(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	forgeries := []SourceAdapterIdentity{{}}
	forged := adapter
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.name = "other-git"
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.version = "1.2.4"
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.majorVersion = 2
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.capabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	forgeries = append(forgeries, forged)
	for _, forgedAdapter := range forgeries {
		if artifact, err := NewSourceAdapterImplementationArtifact(forgedAdapter, SourceAdapterArtifactComponent, []byte("component")); err == nil || artifact.Identity() != "" {
			t.Fatalf("forged adapter = (%#v, %v)", artifact, err)
		}
	}
}

func TestSourceAdapterImplementationArtifactDoesNotRetainContent(t *testing.T) {
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	content := []byte("component")
	artifact, err := NewSourceAdapterImplementationArtifact(adapter, SourceAdapterArtifactComponent, content)
	if err != nil {
		t.Fatalf("NewSourceAdapterImplementationArtifact() error = %v", err)
	}
	identity := artifact.Identity()
	for i := range content {
		content[i] = 0
	}
	adapter.capabilities[0] = SourceCapabilityReadDiff
	if artifact.Identity() != identity || artifact.SizeBytes() != len(content) {
		t.Fatal("input mutation changed SourceAdapterImplementationArtifact")
	}
}

func TestSourceAdapterImplementationArtifactZeroValueIsEmpty(t *testing.T) {
	var artifact SourceAdapterImplementationArtifact
	if artifact.Identity() != "" || artifact.SourceAdapterIdentity() != "" || artifact.Kind() != "" || artifact.DigestAlgorithm() != "" || artifact.Digest() != "" || artifact.SizeBytes() != 0 {
		t.Fatalf("zero SourceAdapterImplementationArtifact = %#v", artifact)
	}
}
