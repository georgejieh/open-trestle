package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"strings"
	"testing"
	"time"
)

func validationArtifact(t testing.TB, size int) Artifact {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "validation")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(scope, KindSourceFile, "application/octet-stream", ClassificationConfidential, OriginRepository, ProtectionProcessPrivate, []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}, bytes.Repeat([]byte("x"), size), time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func BenchmarkArtifactValidationPayloadSize(b *testing.B) {
	for _, size := range []int{64, 1 << 20} {
		b.Run(fmt.Sprintf("bytes-%d", size), func(b *testing.B) {
			value := validationArtifact(b, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if err := value.Validate(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestArtifactValidationPreservesConstructorChecks(t *testing.T) {
	value := validationArtifact(t, 64)
	canonical := value
	canonical.provenance = append([]string(nil), value.provenance...)
	value.provenance = []string{value.provenance[1], value.provenance[0]}
	if err := value.Validate(); err != nil {
		t.Fatalf("canonicalizable provenance rejected: %v", err)
	}
	if value.provenance[0] != canonical.provenance[1] {
		t.Fatal("validation mutated provenance")
	}
	cases := []struct {
		name   string
		change func(*Artifact)
		want   error
	}{
		{"payload", func(a *Artifact) { a.payload = []byte("changed") }, ErrInvalidArtifactIdentity},
		{"digest", func(a *Artifact) { a.payloadDigest = strings.Repeat("c", 64) }, ErrInvalidArtifactIdentity},
		{"identity", func(a *Artifact) { a.identity = strings.Repeat("c", 64) }, ErrInvalidArtifactIdentity},
		{"empty", func(a *Artifact) { a.payload = nil }, ErrInvalidArtifact},
		{"provenance", func(a *Artifact) { a.provenance = []string{strings.Repeat("a", 64), strings.Repeat("a", 64)} }, ErrInvalidArtifact},
		{"time", func(a *Artifact) { a.expiresAtMillis = a.createdAtMillis }, ErrInvalidArtifact},
		{"kind", func(a *Artifact) { a.kind = 0 }, ErrInvalidArtifact},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := canonical
			tc.change(&mutated)
			if err := mutated.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("validation=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestArtifactValidationDoesNotCopyPayload(t *testing.T) {
	value := validationArtifact(t, 1<<20)
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := value.Validate(); err != nil {
				b.Fatal(err)
			}
		}
	})
	if result.AllocedBytesPerOp() >= int64(len(value.payload)) {
		t.Fatalf("validation allocated %d bytes for a %d-byte borrowed payload", result.AllocedBytesPerOp(), len(value.payload))
	}
}

func TestNewArtifactOwnsBorrowedInput(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant", "repository", "ownership")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("owned source")
	provenance := []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}
	value, err := New(scope, KindSourceFile, "application/octet-stream", ClassificationConfidential, OriginRepository, ProtectionProcessPrivate, provenance, payload, time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	identity := value.Identity()
	clear(payload)
	provenance[0] = strings.Repeat("c", 64)
	if err := value.Validate(); err != nil || value.Identity() != identity || string(value.Payload()) != "owned source" || value.Provenance()[1] != strings.Repeat("b", 64) {
		t.Fatalf("constructor retained borrowed input: %v", err)
	}
}
