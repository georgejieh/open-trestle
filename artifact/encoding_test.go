package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func codecFixture(t testing.TB, size int) Artifact {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "codec")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(scope, KindSourceFile, "application/json", ClassificationConfidential, OriginRepository, ProtectionProcessPrivate, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, bytes.Repeat([]byte("x"), size), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestParseArtifactKeepsCanonicalEnvelopeRefusals(t *testing.T) {
	value := codecFixture(t, 100)
	for _, test := range []struct {
		name   string
		mutate func(*record)
		want   error
	}{
		{"identity", func(r *record) { r.Identity = strings.Repeat("c", 64) }, ErrInvalidArtifactIdentity},
		{"payload-digest", func(r *record) { r.PayloadDigest = strings.Repeat("c", 64) }, ErrInvalidArtifactIdentity},
		{"payload", func(r *record) { r.Payload[0] = 'z' }, ErrInvalidArtifactIdentity},
		{"null-provenance", func(r *record) { r.Provenance = nil }, ErrInvalidArtifact},
		{"duplicate-provenance", func(r *record) { r.Provenance[1] = r.Provenance[0] }, ErrInvalidArtifact},
		{"unordered-provenance", func(r *record) { r.Provenance[0], r.Provenance[1] = r.Provenance[1], r.Provenance[0] }, ErrInvalidEncoding},
		{"retention", func(r *record) { r.ExpiresAtMilliseconds = r.CreatedAtMilliseconds }, ErrInvalidArtifact},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := toRecord(value)
			test.mutate(&r)
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(encoded); !errors.Is(err, test.want) {
				t.Fatalf("Parse error=%v want=%v", err, test.want)
			}
		})
	}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(append(encoded, '\n')); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("noncanonical Parse error=%v", err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := Encode(parsed)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("roundtrip changed: %v", err)
	}
	encoded[0] = 'x'
	if parsed.Validate() != nil || parsed.Identity() != value.Identity() {
		t.Fatal("parsed value shares input bytes")
	}
}

func BenchmarkParseArtifactPayloadSize(b *testing.B) {
	for _, size := range []int{100, 256 << 10} {
		b.Run(fmt.Sprintf("bytes-%d", size), func(b *testing.B) {
			value := codecFixture(b, size)
			encoded, err := Encode(value)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if _, err := Parse(encoded); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
