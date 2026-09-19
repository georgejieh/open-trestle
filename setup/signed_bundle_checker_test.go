package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSignedBundleVerifierAcceptsExactOpaqueFile(t *testing.T) {
	bundle := []byte("opaque offline bundle\n")
	path := filepath.Join(t.TempDir(), "release.bundle")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bundle)
	digestText := hex.EncodeToString(digest[:])
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	statement, err := EncodeSignedBundleStatement(digestText, uint64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatement := `{"contract":"open-trestle/offline-bundle-signature-statement","schema_version":1,"bundle_sha256":"` + digestText + `","bundle_bytes":` + strconv.Itoa(len(bundle)) + `}`
	if string(statement) != wantStatement {
		t.Fatalf("statement=%s", statement)
	}
	signature := ed25519.Sign(privateKey, statement)
	publicKeyText := hex.EncodeToString(publicKey)
	signatureText := hex.EncodeToString(signature)
	authority, err := SignedBundleAuthorityIdentity(digestText, uint64(len(bundle)), publicKeyText, signatureText)
	if err != nil {
		t.Fatal(err)
	}
	if authority != "7e4b2ca48a45031f3230ae7e32a8b5cf2038e1d2acb1dde6714c16fff97c29ea" {
		t.Fatalf("authority=%s", authority)
	}
	observation, err := VerifySignedBundle(context.Background(), path, digestText, uint64(len(bundle)), publicKeyText, signatureText)
	if err != nil || observation.Validate() != nil || observation.AuthorityIdentity() != authority || observation.BundleDigest() != digestText || observation.BundleBytes() != uint64(len(bundle)) {
		t.Fatalf("observation=%#v authority=%s err=%v", observation, authority, err)
	}
}

func signedBundleFixture(t *testing.T) (string, string, uint64, string, string) {
	t.Helper()
	bundle := []byte("opaque offline bundle fixture\n")
	path := filepath.Join(t.TempDir(), "release.bundle")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bundle)
	digestText := hex.EncodeToString(digest[:])
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	statement, _ := EncodeSignedBundleStatement(digestText, uint64(len(bundle)))
	signature := ed25519.Sign(privateKey, statement)
	return path, digestText, uint64(len(bundle)), hex.EncodeToString(publicKey), hex.EncodeToString(signature)
}

func TestSignedBundleVerifierTreatsCancellationAsUnavailable(t *testing.T) {
	path, digest, size, publicKey, signature := signedBundleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifySignedBundle(ctx, path, digest, size, publicKey, signature); !errors.Is(err, ErrSignedBundleUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestSignedBundleVerifierRejectsSubstitutionAndNonRegularFiles(t *testing.T) {
	path, digest, size, publicKey, signature := signedBundleFixture(t)
	wrongSignature := strings.Repeat("1", ed25519.SignatureSize*2)
	if _, err := VerifySignedBundle(context.Background(), path, digest, size, publicKey, wrongSignature); !errors.Is(err, ErrSignedBundleVerificationFailed) {
		t.Fatalf("signature err=%v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, int(size)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedBundle(context.Background(), path, digest, size, publicKey, signature); !errors.Is(err, ErrSignedBundleVerificationFailed) {
		t.Fatalf("digest err=%v", err)
	}
	target, _, _, _, _ := signedBundleFixture(t)
	link := filepath.Join(t.TempDir(), "bundle-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedBundle(context.Background(), link, digest, size, publicKey, signature); !errors.Is(err, ErrSignedBundleVerificationFailed) {
		t.Fatalf("symlink err=%v", err)
	}
}

func TestSignedBundleAuthorityBindsEveryPublicInput(t *testing.T) {
	_, digest, size, publicKey, signature := signedBundleFixture(t)
	authority, err := SignedBundleAuthorityIdentity(digest, size, publicKey, signature)
	if err != nil || !nonzeroSetupDigest(authority) {
		t.Fatalf("authority=%s err=%v", authority, err)
	}
	otherDigest := sha256.Sum256([]byte("other bundle"))
	values := []struct {
		digest    string
		size      uint64
		publicKey string
		signature string
	}{
		{hex.EncodeToString(otherDigest[:]), size, publicKey, signature},
		{digest, size + 1, publicKey, signature},
		{digest, size, "1" + publicKey[1:], signature},
		{digest, size, publicKey, "1" + signature[1:]},
	}
	for index, value := range values {
		changed, changeErr := SignedBundleAuthorityIdentity(value.digest, value.size, value.publicKey, value.signature)
		if changeErr != nil || changed == authority {
			t.Fatalf("case %d authority=%s err=%v", index, changed, changeErr)
		}
	}
}

func TestSignedBundleVerifierRejectsInvalidBoundsAndUnavailablePath(t *testing.T) {
	path, digest, size, publicKey, signature := signedBundleFixture(t)
	for _, input := range []struct {
		digest    string
		size      uint64
		publicKey string
		signature string
	}{
		{digest, 0, publicKey, signature},
		{digest, signedBundleMaximumBytes + 1, publicKey, signature},
		{digest, size, strings.Repeat("0", ed25519.PublicKeySize*2), signature},
		{digest, size, publicKey, strings.Repeat("0", ed25519.SignatureSize*2)},
		{"not-a-digest", size, publicKey, signature},
		{strings.ToUpper(digest), size, publicKey, signature},
	} {
		if _, err := VerifySignedBundle(context.Background(), path, input.digest, input.size, input.publicKey, input.signature); !errors.Is(err, ErrInvalidSignedBundle) {
			t.Fatalf("input=%#v err=%v", input, err)
		}
	}
	for _, wrongSize := range []uint64{size - 1, size + 1} {
		if _, err := VerifySignedBundle(context.Background(), path, digest, wrongSize, publicKey, signature); !errors.Is(err, ErrSignedBundleVerificationFailed) {
			t.Fatalf("size=%d err=%v", wrongSize, err)
		}
	}
	if _, err := VerifySignedBundle(context.Background(), "relative.bundle", digest, size, publicKey, signature); !errors.Is(err, ErrInvalidSignedBundle) {
		t.Fatalf("relative err=%v", err)
	}
	if _, err := VerifySignedBundle(context.Background(), t.TempDir(), digest, size, publicKey, signature); !errors.Is(err, ErrSignedBundleVerificationFailed) {
		t.Fatalf("directory err=%v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.bundle")
	if _, err := VerifySignedBundle(context.Background(), missing, digest, size, publicKey, signature); !errors.Is(err, ErrSignedBundleUnavailable) {
		t.Fatalf("missing err=%v", err)
	}
}
