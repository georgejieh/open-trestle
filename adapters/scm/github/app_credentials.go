package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// AppSigner owns a lazy App credential callback; construction never invokes it.
type AppSigner struct{ *appSignerState }

type appSignerState struct {
	mu              *sync.Mutex
	authority       InstallationBrokerAuthority
	getenv          func(string) string
	closed, claimed bool
	signing         bool
	failure         error
	key             *rsa.PrivateKey
}

func NewAppSigner(authority InstallationBrokerAuthority, getenv func(string) string) (*AppSigner, error) {
	if authority.Validate() != nil || getenv == nil {
		return nil, ErrInvalidBrokerConfig
	}
	return &AppSigner{appSignerState: &appSignerState{mu: new(sync.Mutex), authority: authority, getenv: getenv}}, nil
}
func (s *AppSigner) AuthorityIdentity() string {
	if s == nil || s.appSignerState == nil {
		return ""
	}
	return s.authority.Identity()
}
func (s *AppSigner) Validate() error {
	if s == nil || s.appSignerState == nil {
		return ErrInvalidBrokerConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrBrokerClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if s.authority.Validate() != nil || s.getenv == nil && s.key == nil && !s.signing {
		return ErrInvalidBrokerConfig
	}
	return nil
}
func (s *AppSigner) Close() error {
	if s == nil || s.appSignerState == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.getenv = nil
	s.key = nil
	s.mu.Unlock()
	return nil
}

const maximumAppPrivateKeyBytes = 16 << 10

func (s *AppSigner) sign(ctx context.Context, at time.Time) (Token, error) {
	if s == nil || s.appSignerState == nil {
		return Token{}, ErrInvalidBrokerConfig
	}
	if nilInterface(ctx) || ctx.Err() != nil {
		return Token{}, ErrBrokerUnavailable
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Token{}, ErrBrokerClosed
	}
	if s.failure != nil {
		err := s.failure
		s.mu.Unlock()
		return Token{}, err
	}
	if !s.claimed {
		s.mu.Unlock()
		return Token{}, ErrBrokerDenied
	}
	if s.signing {
		s.mu.Unlock()
		return Token{}, ErrBrokerUnavailable
	}
	s.signing = true
	key, getenv := s.key, s.getenv
	s.getenv = nil
	s.mu.Unlock()

	var err error
	if key == nil {
		if getenv == nil {
			err = ErrBrokerDenied
		} else {
			raw := getenv("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY")
			getenv = nil
			if len(raw) == 0 || len(raw) > maximumAppPrivateKeyBytes {
				err = ErrBrokerDenied
			} else {
				owned := []byte(raw)
				raw = ""
				key, err = parseAppPrivateKey(owned, s.authority.config.AppPublicKeySHA256)
				clear(owned)
			}
		}
	}
	var token Token
	if err == nil {
		if ctx.Err() != nil {
			err = ErrBrokerUnavailable
		} else {
			token, err = encodeAppJWT(key, s.authority.config.AppID, at)
		}
	}
	s.mu.Lock()
	s.signing = false
	if s.closed {
		err = ErrBrokerClosed
	}
	if ctx.Err() != nil && err == nil {
		err = ErrBrokerUnavailable
	}
	if err != nil {
		s.failure = err
		s.key = nil
		token = Token{}
	} else {
		s.key = key
	}
	s.mu.Unlock()
	return token, err
}

func parseAppPrivateKey(raw []byte, expectedPublicKeySHA256 string) (*rsa.PrivateKey, error) {
	if len(raw) == 0 || len(raw) > maximumAppPrivateKeyBytes || !validDigest(expectedPublicKeySHA256) {
		return nil, ErrBrokerDenied
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN RSA PRIVATE KEY-----")) && !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, ErrBrokerDenied
	}
	if bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, ErrBrokerDenied
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, ErrBrokerDenied
	}
	defer clear(block.Bytes)
	if len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || !bytes.HasSuffix(trimmed, []byte("-----END "+block.Type+"-----")) {
		return nil, ErrBrokerDenied
	}
	var envelope asn1.RawValue
	trailing, envelopeErr := asn1.Unmarshal(block.Bytes, &envelope)
	if envelopeErr != nil || len(trailing) != 0 || envelope.Tag != asn1.TagSequence || !envelope.IsCompound {
		return nil, ErrBrokerDenied
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, ErrBrokerDenied
	}
	if err != nil || key == nil {
		return nil, ErrBrokerDenied
	}
	digest, err := appPublicKeyDigest(&key.PublicKey)
	if err != nil || digest != expectedPublicKeySHA256 || key.Validate() != nil {
		return nil, ErrBrokerDenied
	}
	return key, nil
}

func encodeAppJWT(key *rsa.PrivateKey, appID uint64, at time.Time) (Token, error) {
	if key == nil || appID == 0 || appID > maxPermissionIdentifier || at.IsZero() || at.Unix() < 60 || at.Unix() > 253402300499 {
		return Token{}, ErrBrokerDenied
	}
	header := []byte(`{"alg":"RS256","typ":"JWT"}`)
	claims, err := json.Marshal(struct {
		Issuer    string `json:"iss"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}{strconv.FormatUint(appID, 10), at.Unix() - 60, at.Unix() + 300})
	if err != nil {
		return Token{}, ErrBrokerDenied
	}
	content := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return Token{}, ErrBrokerDenied
	}
	encoded := []byte(content + "." + base64.RawURLEncoding.EncodeToString(signature))
	defer clear(encoded)
	token, err := NewToken(encoded)
	if err != nil {
		return Token{}, ErrBrokerDenied
	}
	return token, nil
}

func appPublicKeyDigest(key *rsa.PublicKey) (string, error) {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E < 3 || key.E%2 == 0 {
		return "", ErrBrokerDenied
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", ErrBrokerDenied
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
func (s AppSigner) String() string   { return "GitHub App signer" }
func (s AppSigner) GoString() string { return "github.AppSigner{<redacted>}" }
func (s AppSigner) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, s.String(), s.GoString())
}

func (s appSignerState) String() string   { return "GitHub appSignerState" }
func (s appSignerState) GoString() string { return "github.appSignerState{<redacted>}" }
func (s appSignerState) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, s.String(), s.GoString())
}
