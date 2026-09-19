package setup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	signedBundleMaximumBytes = uint64(1 << 30)
	signedBundleBufferBytes  = 64 << 10
	signedBundleMaximumPath  = 4096
)

var (
	ErrInvalidSignedBundle            = errors.New("invalid signed offline bundle")
	ErrSignedBundleUnavailable        = errors.New("signed offline bundle unavailable")
	ErrSignedBundleVerificationFailed = errors.New("signed offline bundle verification failed")
)

// SignedBundleObservation is one content-free opaque bundle verification result.
type SignedBundleObservation struct {
	identity, authorityIdentity, bundleDigest string
	bundleBytes                               uint64
}

func (o SignedBundleObservation) Identity() string          { return o.identity }
func (o SignedBundleObservation) AuthorityIdentity() string { return o.authorityIdentity }
func (o SignedBundleObservation) BundleDigest() string      { return o.bundleDigest }
func (o SignedBundleObservation) BundleBytes() uint64       { return o.bundleBytes }
func (o SignedBundleObservation) Validate() error {
	if !nonzeroSetupDigest(o.authorityIdentity) || !validSignedBundleDigest(o.bundleDigest) || o.bundleBytes == 0 || o.bundleBytes > signedBundleMaximumBytes || o.identity != signedBundleObservationIdentity(o.authorityIdentity, o.bundleDigest, o.bundleBytes) {
		return ErrSignedBundleVerificationFailed
	}
	return nil
}
func (o SignedBundleObservation) String() string { return "signed offline bundle observation" }
func (o SignedBundleObservation) GoString() string {
	return "setup.SignedBundleObservation{<redacted>}"
}
func (o SignedBundleObservation) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, o.String(), o.GoString())
}

// EncodeSignedBundleStatement returns the canonical statement signed by an offline bundle producer.
func EncodeSignedBundleStatement(bundleDigest string, bundleBytes uint64) ([]byte, error) {
	if !validSignedBundleDigest(bundleDigest) || bundleBytes == 0 || bundleBytes > signedBundleMaximumBytes {
		return nil, ErrInvalidSignedBundle
	}
	encoded, err := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		BundleDigest  string `json:"bundle_sha256"`
		BundleBytes   uint64 `json:"bundle_bytes"`
	}{"open-trestle/offline-bundle-signature-statement", 1, bundleDigest, bundleBytes})
	if err != nil {
		return nil, ErrInvalidSignedBundle
	}
	return encoded, nil
}

// SignedBundleAuthorityIdentity binds one exact bundle, public key, signature, and verifier contract.
func SignedBundleAuthorityIdentity(bundleDigest string, bundleBytes uint64, publicKeyHex, signatureHex string) (string, error) {
	statement, err := EncodeSignedBundleStatement(bundleDigest, bundleBytes)
	if err != nil {
		return "", err
	}
	publicKey, ok := decodeSignedBundleHex(publicKeyHex, ed25519.PublicKeySize)
	if !ok {
		return "", ErrInvalidSignedBundle
	}
	signature, ok := decodeSignedBundleHex(signatureHex, ed25519.SignatureSize)
	if !ok {
		return "", ErrInvalidSignedBundle
	}
	statementDigest := sha256.Sum256(statement)
	publicKeyIdentity := hashSignedBundle("public-key", publicKey)
	signatureIdentity := hashSignedBundle("signature", signature)
	encoded, err := json.Marshal(struct {
		Contract               string `json:"contract"`
		SchemaVersion          int    `json:"schema_version"`
		StatementContract      string `json:"statement_contract"`
		StatementSchemaVersion int    `json:"statement_schema_version"`
		StatementIdentity      string `json:"statement_identity"`
		BundleDigestAlgorithm  string `json:"bundle_digest_algorithm"`
		BundleDigest           string `json:"bundle_digest"`
		BundleBytes            uint64 `json:"bundle_bytes"`
		SignatureAlgorithm     string `json:"signature_algorithm"`
		SignatureInput         string `json:"signature_input"`
		PublicKeyIdentity      string `json:"public_key_identity"`
		SignatureIdentity      string `json:"signature_identity"`
		MaximumBundleBytes     uint64 `json:"maximum_bundle_bytes"`
		MaximumPathBytes       int    `json:"maximum_path_bytes"`
		StreamingBufferBytes   int    `json:"streaming_buffer_bytes"`
		PathRequirement        string `json:"path_requirement"`
		FileIdentityValidation string `json:"file_identity_validation"`
		SizeValidation         string `json:"size_validation"`
		StreamingCancellation  string `json:"streaming_cancellation"`
		RegularFileRequired    bool   `json:"regular_file_required"`
		IOFailurePosture       string `json:"io_failure_posture"`
		MismatchFailurePosture string `json:"mismatch_failure_posture"`
		ExtractionRequests     int    `json:"extraction_requests"`
		ImportRequests         int    `json:"import_requests"`
		ExecutionRequests      int    `json:"execution_requests"`
		NetworkRequests        int    `json:"network_requests"`
	}{
		"open-trestle/signed-offline-bundle-authority", 1,
		"open-trestle/offline-bundle-signature-statement", 1, hex.EncodeToString(statementDigest[:]),
		"sha256", bundleDigest, bundleBytes, "ed25519", "canonical_statement_bytes", publicKeyIdentity, signatureIdentity,
		signedBundleMaximumBytes, signedBundleMaximumPath, signedBundleBufferBytes,
		"absolute_clean_utf8_no_nul_cr_lf", "lstat_before_and_after_open_same_file_final_stat", "exact_before_stream_and_after", "before_open_and_each_read", true,
		"unavailable", "verification_failed", 0, 0, 0, 0,
	})
	if err != nil {
		return "", ErrInvalidSignedBundle
	}
	return hashSignedBundle("authority", encoded), nil
}

// VerifySignedBundle streams and verifies one opaque regular file without extraction or execution.
func VerifySignedBundle(ctx context.Context, path, expectedDigest string, expectedBytes uint64, publicKeyHex, signatureHex string) (SignedBundleObservation, error) {
	if ctx == nil || !validSignedBundlePath(path) {
		return SignedBundleObservation{}, ErrInvalidSignedBundle
	}
	if ctx.Err() != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	authority, err := SignedBundleAuthorityIdentity(expectedDigest, expectedBytes, publicKeyHex, signatureHex)
	if err != nil {
		return SignedBundleObservation{}, err
	}
	publicKey, _ := decodeSignedBundleHex(publicKeyHex, ed25519.PublicKeySize)
	signature, _ := decodeSignedBundleHex(signatureHex, ed25519.SignatureSize)
	before, err := os.Lstat(path)
	if err != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) != expectedBytes {
		return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
	}
	file, err := os.Open(path)
	if err != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() < 0 || uint64(opened.Size()) != expectedBytes {
		return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
	}
	hasher := sha256.New()
	buffer := make([]byte, signedBundleBufferBytes)
	var total uint64
	for {
		if ctx.Err() != nil {
			return SignedBundleObservation{}, ErrSignedBundleUnavailable
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			total += uint64(read)
			if total > expectedBytes {
				return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
			}
			_, _ = hasher.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return SignedBundleObservation{}, ErrSignedBundleUnavailable
		}
	}
	after, err := file.Stat()
	if err != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return SignedBundleObservation{}, ErrSignedBundleUnavailable
	}
	actualDigest := hex.EncodeToString(hasher.Sum(nil))
	if total != expectedBytes || !os.SameFile(opened, after) || !pathAfter.Mode().IsRegular() || !os.SameFile(opened, pathAfter) || after.Size() < 0 || uint64(after.Size()) != expectedBytes || pathAfter.Size() != after.Size() || actualDigest != expectedDigest {
		return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
	}
	statement, _ := EncodeSignedBundleStatement(actualDigest, total)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), statement, signature) {
		return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
	}
	observation := SignedBundleObservation{authorityIdentity: authority, bundleDigest: actualDigest, bundleBytes: total}
	observation.identity = signedBundleObservationIdentity(observation.authorityIdentity, observation.bundleDigest, observation.bundleBytes)
	if observation.Validate() != nil {
		return SignedBundleObservation{}, ErrSignedBundleVerificationFailed
	}
	return observation, nil
}

func validSignedBundleDigest(value string) bool {
	_, valid := decodeSignedBundleHex(value, sha256.Size)
	return valid
}
func validSignedBundlePath(value string) bool {
	return len(value) > 0 && len(value) <= signedBundleMaximumPath && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n") && filepath.IsAbs(value) && filepath.Clean(value) == value
}
func decodeSignedBundleHex(value string, size int) ([]byte, bool) {
	if len(value) != size*2 || strings.Trim(value, "0") == "" {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}
func hashSignedBundle(domain string, value []byte) string {
	digest := sha256.Sum256(append([]byte("open-trestle/signed-offline-bundle/v1\x00"+domain+"\x00"), value...))
	return hex.EncodeToString(digest[:])
}
func signedBundleObservationIdentity(authority, digest string, bytes uint64) string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Authority     string `json:"authority_identity"`
		BundleDigest  string `json:"bundle_digest"`
		BundleBytes   uint64 `json:"bundle_bytes"`
	}{"open-trestle/signed-offline-bundle-observation", 1, authority, digest, bytes})
	return hashSignedBundle("observation", encoded)
}
