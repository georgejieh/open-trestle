package sourceoutput

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func legacyDigestValidation(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func TestDigestValidationPreservesCanonicalInputSet(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("é", 32), strings.Repeat("a", 64)} {
		if validDigest(value) != legacyDigestValidation(value) {
			t.Fatalf("digest validation changed for %q", value)
		}
	}
	for index := 0; index < 64; index++ {
		for octet := 0; octet < 256; octet++ {
			value := []byte(strings.Repeat("0", 64))
			value[index] = byte(octet)
			text := string(value)
			if validDigest(text) != legacyDigestValidation(text) {
				t.Fatalf("digest validation changed at index=%d byte=%d", index, octet)
			}
		}
	}
}

func TestDigestValidationDoesNotAllocate(t *testing.T) {
	value := strings.Repeat("a", 64)
	allocations := testing.AllocsPerRun(100, func() {
		if !validDigest(value) {
			t.Fatal("canonical digest refused")
		}
	})
	if allocations != 0 {
		t.Fatalf("digest validation allocates %g times", allocations)
	}
}

func BenchmarkDigestValidation(b *testing.B) {
	value := strings.Repeat("a", 64)
	b.ReportAllocs()
	for b.Loop() {
		if !validDigest(value) {
			b.Fatal("canonical digest refused")
		}
	}
}
