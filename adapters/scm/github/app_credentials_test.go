package github

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func credentialBoundaryRedacted(t *testing.T, value any, secrets ...string) {
	t.Helper()
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		printed := fmt.Sprintf(format, value)
		if printed == "" {
			t.Fatal("empty formatting is not a redaction control")
		}
		for _, secret := range secrets {
			if secret == "" {
				t.Fatal("redaction control needs a nonempty secret")
			}
			if strings.Contains(printed, secret) {
				t.Fatal("credential-bearing value leaked through formatting")
			}
		}
	}
}

func TestAppCredentialAdmission(t *testing.T) {
	key, encoded, pin := newFixtureAppKey(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("synthetic undersized RSA generation failed")
	}
	smallPublic, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal("synthetic undersized public key encoding failed")
	}
	smallSum := sha256.Sum256(smallPublic)
	smallPin := hex.EncodeToString(smallSum[:])
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("synthetic PKCS8 encoding failed")
	}
	other, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal("synthetic non-RSA encoding failed")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("synthetic public key encoding failed")
	}
	wrongPin := "0" + pin[1:]
	if wrongPin == pin {
		wrongPin = "1" + pin[1:]
	}
	at := time.Unix(1800000000, 0).UTC()
	t.Run("valid-key-and-JWT", func(t *testing.T) {
		gotPin, err := appPublicKeyDigest(&key.PublicKey)
		if err != nil || gotPin != pin {
			t.Fatal("public pin differs from independent PKIX SHA256 fixture")
		}
		for _, tc := range []struct {
			name string
			pem  []byte
		}{
			{"PKCS1", encoded},
			{"PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})},
			{"outer-whitespace", append(append([]byte(" \n\t"), encoded...), '\n', '\t')},
			{"exact-16KiB", append(append([]byte(nil), encoded...), bytes.Repeat([]byte(" "), (16<<10)-len(encoded))...)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				parsed, err := parseAppPrivateKey(tc.pem, pin)
				if err != nil || parsed == nil || parsed.Validate() != nil || parsed.N.Cmp(key.N) != 0 {
					t.Fatal("valid pinned private key refused")
				}
				token, err := encodeAppJWT(parsed, 7, at)
				if err != nil || token.Validate() != nil {
					t.Fatal("valid native App JWT refused")
				}
				request, err := http.NewRequest(http.MethodGet, "https://api.github.com/app/installations/42", nil)
				if err != nil {
					t.Fatal("inert request construction failed")
				}
				request.Header.Set("Authorization", "Bearer "+token.value)
				if fixtureAppJWTError(request, &key.PublicKey, 7, at) != nil {
					t.Fatal("JWT signature or exact RS256/string issuer/time claims failed")
				}
				credentialBoundaryRedacted(t, token, token.value, base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)))
			})
		}
	})
	t.Run("refuse-key-input", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  []byte
			pin  string
		}{
			{"empty", nil, pin},
			{"malformed-secret", []byte("fixture-private-key-secret-do-not-log"), pin},
			{"malformed-PEM", []byte("-----BEGIN RSA PRIVATE KEY-----\n!invalid!\n-----END RSA PRIVATE KEY-----"), pin},
			{"leading-text", append([]byte("fixture-secret-prefix\n"), encoded...), pin},
			{"trailing-text", append(append([]byte(nil), encoded...), []byte("fixture-secret-suffix")...), pin},
			{"multiple-PEM", append(append([]byte(nil), encoded...), encoded...), pin},
			{"PEM-headers", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Comment": "fixture-secret-header"}, Bytes: x509.MarshalPKCS1PrivateKey(key)}), pin},
			{"DER-trailing-byte", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: append(x509.MarshalPKCS1PrivateKey(key), 0)}), pin},
			{"public-key", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), pin},
			{"wrong-label", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), pin},
			{"non-RSA-PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: other}), pin},
			{"oversize-16KiB-plus-one", append(append([]byte(nil), encoded...), bytes.Repeat([]byte(" "), (16<<10)+1-len(encoded))...), pin},
			{"wrong-pin", encoded, wrongPin},
			{"empty-pin", encoded, ""},
			{"zero-pin", encoded, strings.Repeat("0", 64)},
			{"uppercase-pin", encoded, strings.Repeat("A", 64)},
			{"short-pin", encoded, pin[:63]},
			{"RSA-1024", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)}), smallPin},
		} {
			t.Run(tc.name, func(t *testing.T) {
				parsed, err := parseAppPrivateKey(tc.raw, tc.pin)
				if parsed != nil || !errors.Is(err, ErrBrokerDenied) {
					t.Fatal("invalid key input did not return empty key and closed denial")
				}
				credentialBoundaryRedacted(t, err, "fixture-private-key-secret-do-not-log", "fixture-secret-prefix", "fixture-secret-suffix", "fixture-secret-header", string(encoded))
			})
		}
	})
	t.Run("public-key-policy", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *rsa.PublicKey
		}{
			{"nil", nil},
			{"nil-modulus", &rsa.PublicKey{E: 65537}},
			{"undersized", &small.PublicKey},
			{"exponent-one", &rsa.PublicKey{N: key.N, E: 1}},
			{"even-exponent", &rsa.PublicKey{N: key.N, E: 4}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if digest, err := appPublicKeyDigest(tc.key); digest != "" || !errors.Is(err, ErrBrokerDenied) {
					t.Fatal("invalid public key admitted")
				}
			})
		}
	})
	t.Run("JWT-argument-boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *rsa.PrivateKey
			app  uint64
			at   time.Time
		}{
			{"nil-key", nil, 7, at},
			{"zero-app", key, 0, at},
			{"app-over-safe-integer", key, 9007199254740992, at},
			{"zero-time", key, 7, time.Time{}},
			{"before-iat-floor", key, 7, time.Unix(59, 0)},
			{"beyond-exp-calendar", key, 7, time.Unix(253402300500, 0)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				token, err := encodeAppJWT(tc.key, tc.app, tc.at)
				if token != (Token{}) || !errors.Is(err, ErrBrokerDenied) {
					t.Fatal("invalid JWT arguments did not refuse with empty token")
				}
			})
		}
	})
	t.Run("signer-ownership", func(t *testing.T) {
		credentialBoundarySignerOwnership(t, key, encoded, pin, at)
	})
}

func credentialBoundarySignerOwnership(t *testing.T, key *rsa.PrivateKey, encoded []byte, pin string, at time.Time) {
	t.Helper()
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "unexpected credential admission request", http.StatusForbidden)
	}))
	defer server.Close()
	assertNoHTTP := func() {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if requests != 0 {
			t.Fatal("credential admission performed HTTP")
		}
	}
	authority := brokerAuthorityFixture(t, server.URL+"/api/v3", pin)
	lane, err := NewIssuanceAuthority(authority, IssuancePurposeSetup)
	if err != nil {
		t.Fatal("setup lane construction failed")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	t.Run("nil-and-invalid-construction", func(t *testing.T) {
		var signer *AppSigner
		if signer.Validate() == nil || signer.AuthorityIdentity() != "" || signer.Close() != nil {
			t.Fatal("nil signer behavior changed")
		}
		if token, err := signer.sign(context.Background(), at); token != (Token{}) || !errors.Is(err, ErrInvalidBrokerConfig) {
			t.Fatal("nil signer signed")
		}
		reads := 0
		getenv := func(string) string { reads++; return string(encoded) }
		for _, tc := range []struct {
			authority InstallationBrokerAuthority
			getenv    func(string) string
		}{{InstallationBrokerAuthority{}, getenv}, {authority, nil}} {
			if got, err := NewAppSigner(tc.authority, tc.getenv); got != nil || !errors.Is(err, ErrInvalidBrokerConfig) {
				if got != nil {
					_ = got.Close()
				}
				t.Fatal("invalid signer constructor admitted")
			}
		}
		if reads != 0 {
			t.Fatal("invalid constructor loaded key")
		}
	})
	for _, mode := range []string{"lazy-success", "failed-load-latched", "close-before-load", "failed-constructor-keeps-caller-owner"} {
		t.Run(mode, func(t *testing.T) {
			var keyMu sync.Mutex
			reads := 0
			badName := false
			raw := string(encoded)
			if mode == "failed-load-latched" {
				raw = "fixture-private-key-secret-do-not-log"
			}
			signer, err := NewAppSigner(authority, func(name string) string {
				keyMu.Lock()
				defer keyMu.Unlock()
				reads++
				badName = badName || name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"
				return raw
			})
			if err != nil {
				t.Fatal("lazy signer constructor failed")
			}
			defer signer.Close()
			assertReads := func(want int) {
				t.Helper()
				keyMu.Lock()
				defer keyMu.Unlock()
				if reads != want || badName {
					t.Fatal("key callback count or reference mismatch")
				}
			}
			if signer.Validate() != nil || signer.AuthorityIdentity() != authority.Identity() {
				t.Fatal("lazy signer authority failed")
			}
			if token, err := signer.sign(context.Background(), at); token != (Token{}) || !errors.Is(err, ErrBrokerDenied) {
				t.Fatal("unclaimed signer signed")
			}
			assertReads(0)
			guard := newMemoryIssuanceGuard(lane)
			config := InstallationBrokerConfig{Authority: authority, IssuanceAuthority: lane, Signer: signer, Guard: guard, Clock: fixtureBrokerClock{at: at}}
			if mode == "failed-constructor-keeps-caller-owner" {
				wrong, err := NewIssuanceAuthority(authority, IssuancePurposeRuntime)
				if err != nil {
					t.Fatal("runtime lane fixture failed")
				}
				bad := config
				bad.IssuanceAuthority = wrong
				if broker, err := NewInstallationTokenBroker(context.Background(), bad); broker != nil || !errors.Is(err, ErrInvalidBrokerConfig) {
					if broker != nil {
						_ = broker.Close()
					}
					t.Fatal("crossed guard lane admitted")
				}
				if signer.Validate() != nil || guard.closes != 0 {
					t.Fatal("failed constructor took caller ownership")
				}
				assertReads(0)
			}
			broker, err := NewInstallationTokenBroker(context.Background(), config)
			if err != nil {
				_ = guard.Close()
				t.Fatal("real broker ownership failed")
			}
			defer broker.Close()
			if broker.Validate() != nil {
				t.Fatal("owned broker validation failed")
			}
			assertReads(0)
			secondGuard := newMemoryIssuanceGuard(lane)
			second := config
			second.Guard = secondGuard
			if duplicate, err := NewInstallationTokenBroker(context.Background(), second); duplicate != nil || !errors.Is(err, ErrInvalidBrokerConfig) {
				if duplicate != nil {
					_ = duplicate.Close()
				}
				t.Fatal("claimed signer acquired a second owner")
			}
			if secondGuard.closes != 0 {
				t.Fatal("failed second owner consumed caller guard")
			}
			_ = secondGuard.Close()
			for _, ctx := range []context.Context{nil, canceled} {
				if token, err := signer.sign(ctx, at); token != (Token{}) || !errors.Is(err, ErrBrokerUnavailable) {
					t.Fatal("nil or canceled context signed")
				}
			}
			assertReads(0)
			if mode == "close-before-load" {
				if broker.Close() != nil || !errors.Is(signer.Validate(), ErrBrokerClosed) {
					t.Fatal("broker did not close owned signer")
				}
				if token, err := signer.sign(context.Background(), at); token != (Token{}) || !errors.Is(err, ErrBrokerClosed) {
					t.Fatal("closed signer signed")
				}
				assertReads(0)
				assertNoHTTP()
				return
			}
			if mode == "failed-load-latched" {
				op, err := broker.beginInspection(context.Background(), authority.Identity())
				if err != nil {
					t.Fatal("actual inspection admission failed")
				}
				lease, err := broker.borrow(op)
				if lease != nil {
					lease.release()
				}
				op.Close()
				if lease != nil || !errors.Is(err, ErrBrokerDenied) {
					t.Fatal("malformed key reached usable broker grant")
				}
				credentialBoundaryRedacted(t, err, raw)
				keyMu.Lock()
				raw = string(encoded)
				keyMu.Unlock()
				if token, err := signer.sign(context.Background(), at); token != (Token{}) || !errors.Is(err, ErrBrokerDenied) {
					t.Fatal("failed signer recovered from changing environment")
				}
				if signer.Validate() == nil || broker.Validate() == nil {
					t.Fatal("failed key owner remained valid")
				}
				assertReads(1)
			} else {
				for n := 0; n < 2; n++ {
					token, err := signer.sign(context.Background(), at)
					if err != nil || token.Validate() != nil {
						t.Fatal("broker-owned native signer failed")
					}
					request, err := http.NewRequest(http.MethodGet, server.URL, nil)
					if err != nil {
						t.Fatal("inert request construction failed")
					}
					request.Header.Set("Authorization", "Bearer "+token.value)
					if fixtureAppJWTError(request, &key.PublicKey, 7, at) != nil {
						t.Fatal("owned signer JWT invalid")
					}
					keyMu.Lock()
					raw = "fixture-changing-key-must-not-be-read"
					keyMu.Unlock()
					credentialBoundaryRedacted(t, signer, string(encoded), key.D.String(), token.value)
				}
				assertReads(1)
			}
			for _, ctx := range []context.Context{nil, canceled} {
				if token, err := signer.sign(ctx, at); token != (Token{}) || !errors.Is(err, ErrBrokerUnavailable) {
					t.Fatal("nil or canceled context signed after load")
				}
			}
			assertReads(1)
			if broker.Close() != nil || broker.Close() != nil || guard.closes != 1 {
				t.Fatal("owned cleanup was not exact and idempotent")
			}
			if token, err := signer.sign(context.Background(), at); token != (Token{}) || !errors.Is(err, ErrBrokerClosed) {
				t.Fatal("closed loaded signer signed")
			}
			assertReads(1)
			assertNoHTTP()
		})
	}
	assertNoHTTP()
}
