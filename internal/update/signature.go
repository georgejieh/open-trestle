package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// A release is signed with Ed25519 over a statement: canonical JSON naming
// the archive, its SHA-256 and size, the version, the target and the release
// tag, after a fixed domain prefix so the signature cannot be reused for any
// other message. The signature file, open-trestle-linux-amd64.pyz.sig, is
// itself canonical JSON with one trailing newline: keys sorted, no spaces, as
// Python's json.dumps(sort_keys=True, separators=(",", ":")) writes it. Every
// field is ASCII from a closed alphabet, so Go and Python encode it alike.

const (
	// Target is the only packaged target.
	Target = "linux-amd64"
	// ArchiveName is the packaged archive's file name; its SHA-256 sidecar
	// and signature carry the same name with .sha256 and .sig appended.
	ArchiveName = "open-trestle-linux-amd64.pyz"
	// SidecarName is the archive's SHA-256 sidecar.
	SidecarName = ArchiveName + ".sha256"
	// SignatureName is the archive's detached signature.
	SignatureName = ArchiveName + ".sig"
	// MaxArchiveBytes is the packaged lifecycle's archive bound.
	MaxArchiveBytes = 256 << 20
	// MaxSignatureBytes bounds a signature file.
	MaxSignatureBytes = 4096
	// StatementContract names the signed statement.
	StatementContract = "open-trestle/release-statement"
	// SignatureContract names the signature file.
	SignatureContract = "open-trestle/release-signature"

	signatureDomain = "open-trestle-release-statement-v1\x00"
	maxPinnedKeys   = 16
)

var (
	// ErrNoPinnedKey is a build with no release signing key.
	ErrNoPinnedKey = errors.New("this build cannot verify releases; install the packaged release")
	// ErrUntrustedKey is a signature by a key this build does not pin.
	ErrUntrustedKey = errors.New("the release is signed with a key this build does not trust")
	// ErrBadSignature is a signature that does not verify.
	ErrBadSignature = errors.New("the release signature does not verify")
	// ErrMalformedSignature is a signature file or statement outside the
	// contract.
	ErrMalformedSignature = errors.New("the release signature file is malformed")

	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Statement is what a release signature covers. Its fields are declared in
// key order, so encoding/json writes them sorted.
type Statement struct {
	Archive       string `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
	ArchiveSize   int64  `json:"archive_size"`
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	Tag           string `json:"tag"`
	Target        string `json:"target"`
	Version       string `json:"version"`
}

// Validate checks the statement against the contract: the packaged archive
// name and target, a lowercase SHA-256, a size within the lifecycle's bound,
// a SemVer version and the tag "v" followed by that version.
func (s Statement) Validate() error {
	if s.Contract != StatementContract || s.SchemaVersion != 1 {
		return fmt.Errorf("%w: unknown statement contract", ErrMalformedSignature)
	}
	if s.Archive != ArchiveName || s.Target != Target {
		return fmt.Errorf("%w: the statement is not for %s on %s", ErrMalformedSignature, ArchiveName, Target)
	}
	if !sha256Pattern.MatchString(s.ArchiveSHA256) || s.ArchiveSize <= 0 || s.ArchiveSize > MaxArchiveBytes {
		return fmt.Errorf("%w: the statement's archive digest or size is invalid", ErrMalformedSignature)
	}
	if _, err := ParseVersion(s.Version); err != nil || s.Tag != "v"+s.Version {
		return fmt.Errorf("%w: the statement's version and tag do not match", ErrMalformedSignature)
	}
	return nil
}

// message is the exact signed bytes.
func (s Statement) message() []byte {
	encoded, err := json.Marshal(s)
	if err != nil {
		panic(err) // a struct of strings and integers always encodes
	}
	return append([]byte(signatureDomain), encoded...)
}

type signatureFile struct {
	Contract      string    `json:"contract"`
	KeyID         string    `json:"key_id"`
	SchemaVersion int       `json:"schema_version"`
	Signature     string    `json:"signature"`
	Statement     Statement `json:"statement"`
}

func (f signatureFile) encode() []byte {
	encoded, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}

// PublicKey is one pinned release key. ID is the first 16 hexadecimal digits
// of the SHA-256 of the raw key, which the signature file names.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// KeyRing is the set of keys a build trusts.
type KeyRing []PublicKey

func keyID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// ParseKeyRing reads a key file: one "ed25519 <base64>" line per key, with
// blank lines and # comments ignored. A malformed line or a repeated key
// refuses the whole file.
func ParseKeyRing(text []byte) (KeyRing, error) {
	ring := KeyRing{}
	seen := map[string]bool{}
	for number, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "ed25519" {
			return nil, fmt.Errorf("key file line %d is not \"ed25519 <base64>\"", number+1)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(fields[1])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key file line %d is not a 32-byte Ed25519 public key", number+1)
		}
		key := PublicKey{ID: keyID(raw), Key: ed25519.PublicKey(raw)}
		if seen[key.ID] {
			return nil, fmt.Errorf("key file line %d repeats key %s", number+1, key.ID)
		}
		if len(ring) == maxPinnedKeys {
			return nil, fmt.Errorf("key file lists more than %d keys", maxPinnedKeys)
		}
		seen[key.ID] = true
		ring = append(ring, key)
	}
	return ring, nil
}

//go:embed release_keys.txt
var pinnedKeyFile []byte

// PinnedKeys is the release key ring embedded in this build from
// release_keys.txt. It is empty until a release key is committed there.
func PinnedKeys() (KeyRing, error) { return ParseKeyRing(pinnedKeyFile) }

// Sign returns the signature file for statement, signed with private. It is
// for the offline signing tool; the product never signs.
func Sign(private ed25519.PrivateKey, statement Statement) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("not an Ed25519 private key")
	}
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	signature := ed25519.Sign(private, statement.message())
	return signatureFile{
		Contract:      SignatureContract,
		KeyID:         keyID(public),
		SchemaVersion: 1,
		Signature:     base64.StdEncoding.EncodeToString(signature),
		Statement:     statement,
	}.encode(), nil
}

// Verify checks a signature file and returns the statement it signs and the
// key that signed it. The file must be canonical, name a key in the ring, and
// verify with that key; the statement must satisfy Validate. Any other file
// is refused, and nothing it says is returned.
func (r KeyRing) Verify(raw []byte) (Statement, PublicKey, error) {
	if len(r) == 0 {
		return Statement{}, PublicKey{}, ErrNoPinnedKey
	}
	if len(raw) == 0 || len(raw) > MaxSignatureBytes {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: empty or larger than %d bytes", ErrMalformedSignature, MaxSignatureBytes)
	}
	var file signatureFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: not the signature JSON", ErrMalformedSignature)
	}
	if !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: more than one JSON document", ErrMalformedSignature)
	}
	if !bytes.Equal(file.encode(), raw) {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: not canonical JSON", ErrMalformedSignature)
	}
	if file.Contract != SignatureContract || file.SchemaVersion != 1 || !keyIDPattern.MatchString(file.KeyID) {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: unknown signature contract", ErrMalformedSignature)
	}
	if err := file.Statement.Validate(); err != nil {
		return Statement{}, PublicKey{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(file.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: the signature is not 64 bytes of base64", ErrMalformedSignature)
	}
	for _, key := range r {
		if key.ID != file.KeyID {
			continue
		}
		if !ed25519.Verify(key.Key, file.Statement.message(), signature) {
			return Statement{}, PublicKey{}, ErrBadSignature
		}
		return file.Statement, key, nil
	}
	return Statement{}, PublicKey{}, fmt.Errorf("%w (key %s)", ErrUntrustedKey, file.KeyID)
}
