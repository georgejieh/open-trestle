package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestNewSourceAdapterIdentityAcceptsCanonicalDescriptor(t *testing.T) {
	adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "open-trestle.local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	if len(adapter.Identity()) != 64 || adapter.Kind() != SourceAdapterKindGit || adapter.Name() != "open-trestle.local-git" || adapter.Version() != "1.2.3" || adapter.MajorVersion() != 1 {
		t.Fatalf("adapter = (%q, %q, %q, %q, %d)", adapter.Identity(), adapter.Kind(), adapter.Name(), adapter.Version(), adapter.MajorVersion())
	}
	if got := adapter.Capabilities(); !reflect.DeepEqual(got, []SourceAdapterCapability{SourceCapabilityReadManifest}) || !adapter.HasCapability(SourceCapabilityReadManifest) || adapter.HasCapability(SourceCapabilityReadContent) || adapter.HasCapability("") {
		t.Fatalf("adapter capabilities = %v", got)
	}
	repeated, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "open-trestle.local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
	if err != nil || !sourceAdapterIdentitiesEqual(repeated, adapter) {
		t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, adapter)
	}
}

func TestSourceAdapterIdentityCanonicalizesCapabilities(t *testing.T) {
	permutations := [][]SourceAdapterCapability{
		{SourceCapabilityReadContent, SourceCapabilityReadDiff, SourceCapabilityReadManifest},
		{SourceCapabilityReadContent, SourceCapabilityReadManifest, SourceCapabilityReadDiff},
		{SourceCapabilityReadDiff, SourceCapabilityReadContent, SourceCapabilityReadManifest},
		{SourceCapabilityReadDiff, SourceCapabilityReadManifest, SourceCapabilityReadContent},
		{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff},
		{SourceCapabilityReadManifest, SourceCapabilityReadDiff, SourceCapabilityReadContent},
	}
	var identity string
	wantCapabilities := []SourceAdapterCapability{SourceCapabilityReadContent, SourceCapabilityReadDiff, SourceCapabilityReadManifest}
	for i, permutation := range permutations {
		adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.3", permutation)
		if err != nil {
			t.Fatalf("NewSourceAdapterIdentity(permutation %d) error = %v", i, err)
		}
		if got := adapter.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
			t.Fatalf("Capabilities(permutation %d) = %v, want %v", i, got, wantCapabilities)
		}
		if i == 0 {
			identity = adapter.Identity()
		} else if adapter.Identity() != identity {
			t.Fatalf("permutation %d identity = %q, want %q", i, adapter.Identity(), identity)
		}
	}
}

func TestSourceAdapterIdentityUsesCanonicalPreimage(t *testing.T) {
	adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "open-trestle.local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	preimage := `{"contract":"open-trestle/source-adapter-identity","schema_version":1,"kind":"git","name":"open-trestle.local-git","version":"1.2.3","capabilities":["read_content","read_diff","read_manifest"]}`
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); adapter.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", adapter.Identity(), preimage)
	}
}

func TestSourceAdapterIdentityChangesWithDescriptor(t *testing.T) {
	first := mustSourceAdapterIdentity(t, "local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
	changedName := mustSourceAdapterIdentity(t, "other-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
	changedVersion := mustSourceAdapterIdentity(t, "local-git", "1.2.4", []SourceAdapterCapability{SourceCapabilityReadManifest})
	changedCapabilities := mustSourceAdapterIdentity(t, "local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	identities := map[string]struct{}{
		first.Identity():               {},
		changedName.Identity():         {},
		changedVersion.Identity():      {},
		changedCapabilities.Identity(): {},
	}
	if len(identities) != 4 {
		t.Fatalf("descriptor changes produced %d identities, want 4", len(identities))
	}
}

func TestNewSourceAdapterIdentityValidatesName(t *testing.T) {
	validNames := []string{
		"a",
		"0",
		"local-git",
		"local_git",
		"local.git",
		"open-trestle.local-git",
		strings.Repeat("a", 128),
	}
	for _, name := range validNames {
		t.Run("valid "+name, func(t *testing.T) {
			if _, err := NewSourceAdapterIdentity(SourceAdapterKindGit, name, "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest}); err != nil {
				t.Fatalf("NewSourceAdapterIdentity(%q) error = %v", name, err)
			}
		})
	}
	invalidNames := []string{
		"",
		strings.Repeat("a", 129),
		"Local-git",
		"local git",
		"local/git",
		"local:git",
		"local@git",
		"https://git",
		"例",
		"-local",
		"local-",
		"_local",
		"local_",
		".local",
		"local.",
		"a..b",
		"a-_b",
		"a.-b",
		"a__b",
		"a--b",
		"a._b",
	}
	for _, name := range invalidNames {
		t.Run("invalid "+name, func(t *testing.T) {
			adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, name, "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
			if err == nil || adapter.Identity() != "" {
				t.Fatalf("NewSourceAdapterIdentity(%q) = (%#v, %v), want zero error result", name, adapter, err)
			}
		})
	}
}

func TestNewSourceAdapterIdentityFreezesNameByteAllowlist(t *testing.T) {
	for candidate := 0; candidate < 128; candidate++ {
		name := "a" + string(byte(candidate)) + "b"
		_, err := NewSourceAdapterIdentity(SourceAdapterKindGit, name, "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
		allowed := candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '.' || candidate == '_' || candidate == '-'
		if (err == nil) != allowed {
			t.Fatalf("name byte 0x%02x allowed = %t, want %t; error = %v", candidate, err == nil, allowed, err)
		}
	}
	separators := []byte{'.', '_', '-'}
	for _, first := range separators {
		for _, second := range separators {
			name := "a" + string(first) + string(second) + "b"
			if adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, name, "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest}); err == nil || adapter.Identity() != "" {
				t.Fatalf("NewSourceAdapterIdentity(%q) = (%#v, %v), want zero error result", name, adapter, err)
			}
		}
	}
}

func TestNewSourceAdapterIdentityValidatesVersion(t *testing.T) {
	validVersions := []struct {
		version string
		major   uint32
	}{
		{version: "0.0.0"},
		{version: "9.10.99", major: 9},
		{version: "10.0.0", major: 10},
		{version: "4294967295.4294967295.4294967295", major: 4294967295},
	}
	for _, testCase := range validVersions {
		t.Run("valid "+testCase.version, func(t *testing.T) {
			adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", testCase.version, []SourceAdapterCapability{SourceCapabilityReadManifest})
			if err != nil || adapter.MajorVersion() != testCase.major || adapter.Version() != testCase.version {
				t.Fatalf("NewSourceAdapterIdentity() = (%#v, %v)", adapter, err)
			}
		})
	}
	invalidVersions := []string{
		"",
		"1",
		"1.2",
		"1.2.3.4",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"4294967296.0.0",
		"0.4294967296.0",
		"0.0.4294967296",
		"v1.2.3",
		"1.2.3-alpha",
		"1.2.3+build",
		" 1.2.3",
		"1.2.3 ",
		"+1.2.3",
		"-1.2.3",
		strings.Repeat("1", 33),
	}
	for _, version := range invalidVersions {
		t.Run("invalid "+version, func(t *testing.T) {
			adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", version, []SourceAdapterCapability{SourceCapabilityReadManifest})
			if err == nil || adapter.Identity() != "" {
				t.Fatalf("NewSourceAdapterIdentity(%q) = (%#v, %v), want zero error result", version, adapter, err)
			}
		})
	}
}

func TestNewSourceAdapterIdentityValidatesCapabilities(t *testing.T) {
	all := []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff}
	if _, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.3", all); err != nil {
		t.Fatalf("NewSourceAdapterIdentity(all capabilities) error = %v", err)
	}
	testCases := []struct {
		name         string
		capabilities []SourceAdapterCapability
	}{
		{name: "empty"},
		{name: "four entries", capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff, SourceCapabilityReadManifest}},
		{name: "duplicate two", capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadManifest}},
		{name: "duplicate three", capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadManifest}},
		{name: "zero", capabilities: []SourceAdapterCapability{""}},
		{name: "unknown one", capabilities: []SourceAdapterCapability{"read_tree"}},
		{name: "unknown three", capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, "read_tree"}},
		{name: "case variant", capabilities: []SourceAdapterCapability{"Read_manifest"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.3", testCase.capabilities)
			if err == nil || adapter.Identity() != "" {
				t.Fatalf("NewSourceAdapterIdentity() = (%#v, %v), want zero error result", adapter, err)
			}
		})
	}
}

func TestNewSourceAdapterIdentityRejectsUnknownKind(t *testing.T) {
	for _, kind := range []SourceAdapterKind{"", "Git", "scm", "git+ssh", "github"} {
		t.Run(string(kind), func(t *testing.T) {
			adapter, err := NewSourceAdapterIdentity(kind, "local-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest})
			if err == nil || adapter.Identity() != "" {
				t.Fatalf("NewSourceAdapterIdentity() = (%#v, %v), want zero error result", adapter, err)
			}
		})
	}
}

func TestSourceAdapterIdentityDefensivelyCopiesCapabilities(t *testing.T) {
	capabilities := []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.3", capabilities)
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	identity := adapter.Identity()
	capabilities[0] = SourceCapabilityReadDiff
	returned := adapter.Capabilities()
	returned[0] = SourceCapabilityReadManifest
	if adapter.Identity() != identity || !reflect.DeepEqual(adapter.Capabilities(), []SourceAdapterCapability{SourceCapabilityReadContent, SourceCapabilityReadManifest}) {
		t.Fatal("capability mutation changed SourceAdapterIdentity")
	}
}

func TestSourceAdapterIdentityZeroValueIsEmpty(t *testing.T) {
	var adapter SourceAdapterIdentity
	if adapter.Identity() != "" || adapter.Kind() != "" || adapter.Name() != "" || adapter.Version() != "" || adapter.MajorVersion() != 0 || len(adapter.Capabilities()) != 0 || adapter.HasCapability(SourceCapabilityReadManifest) {
		t.Fatalf("zero SourceAdapterIdentity = %#v", adapter)
	}
}

func mustSourceAdapterIdentity(t *testing.T, name, version string, capabilities []SourceAdapterCapability) SourceAdapterIdentity {
	t.Helper()
	adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, name, version, capabilities)
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	return adapter
}

func sourceAdapterIdentitiesEqual(first, second SourceAdapterIdentity) bool {
	return first.identity == second.identity && first.kind == second.kind && first.name == second.name && first.version == second.version && first.majorVersion == second.majorVersion && reflect.DeepEqual(first.capabilities, second.capabilities)
}
