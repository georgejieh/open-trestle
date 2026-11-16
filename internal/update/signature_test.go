package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Every key below is generated for the test and thrown away.

func testKey(t *testing.T) (ed25519.PrivateKey, PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := ParseKeyRing([]byte("ed25519 " + base64.StdEncoding.EncodeToString(public) + "\n"))
	if err != nil || len(ring) != 1 {
		t.Fatalf("ring=%v err=%v", ring, err)
	}
	return private, ring[0]
}

func testStatement() Statement {
	return Statement{
		Archive:       ArchiveName,
		ArchiveSHA256: strings.Repeat("ab", 32),
		ArchiveSize:   1234567,
		Contract:      StatementContract,
		SchemaVersion: 1,
		Tag:           "v0.2.0",
		Target:        Target,
		Version:       "0.2.0",
	}
}

func TestSignatureVerifiesWithThePinnedKey(t *testing.T) {
	private, public := testKey(t)
	raw, err := Sign(private, testStatement())
	if err != nil {
		t.Fatal(err)
	}
	statement, key, err := KeyRing{public}.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if statement != testStatement() || key.ID != public.ID {
		t.Fatalf("statement=%+v key=%s", statement, key.ID)
	}
	// The file is canonical JSON with one trailing newline, keys sorted.
	if !bytes.HasSuffix(raw, []byte("}\n")) || !bytes.HasPrefix(raw, []byte(`{"contract":"open-trestle/release-signature","key_id":"`+public.ID+`","schema_version":1,"signature":"`)) {
		t.Fatalf("signature file is not canonical:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"statement":{"archive":"open-trestle-linux-amd64.pyz","archive_sha256":"`) {
		t.Fatalf("statement is not canonical:\n%s", raw)
	}
}

func TestSignatureRefusals(t *testing.T) {
	private, public := testKey(t)
	otherPrivate, other := testKey(t)
	good, err := Sign(private, testStatement())
	if err != nil {
		t.Fatal(err)
	}
	signedByOther, err := Sign(otherPrivate, testStatement())
	if err != nil {
		t.Fatal(err)
	}
	// reencode returns the good file, canonical again, after change edits its
	// decoded document; the original signature is kept unless change replaces it.
	reencode := func(change func(document, statement map[string]any)) []byte {
		var document map[string]any
		if err := json.Unmarshal(good, &document); err != nil {
			t.Fatal(err)
		}
		change(document, document["statement"].(map[string]any))
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return append(encoded, '\n')
	}
	tampered := func(fields map[string]any) []byte {
		return reencode(func(_, statement map[string]any) {
			for key, value := range fields {
				statement[key] = value
			}
		})
	}
	flipped := reencode(func(document, _ map[string]any) {
		signature, err := base64.StdEncoding.DecodeString(document["signature"].(string))
		if err != nil {
			t.Fatal(err)
		}
		signature[10] ^= 0x01
		document["signature"] = base64.StdEncoding.EncodeToString(signature)
	})
	claimed := []byte(strings.Replace(string(signedByOther), other.ID, public.ID, 1))
	for name, test := range map[string]struct {
		ring KeyRing
		raw  []byte
		want error
	}{
		"good, re-encoded":         {KeyRing{public}, reencode(func(_, _ map[string]any) {}), nil},
		"bad signature":            {KeyRing{public}, flipped, ErrBadSignature},
		"wrong key":                {KeyRing{public}, signedByOther, ErrUntrustedKey},
		"another key's id claimed": {KeyRing{public}, claimed, ErrBadSignature},
		"tampered SHA-256":         {KeyRing{public}, tampered(map[string]any{"archive_sha256": strings.Repeat("cd", 32)}), ErrBadSignature},
		"tampered size":            {KeyRing{public}, tampered(map[string]any{"archive_size": 1234568}), ErrBadSignature},
		"tampered version and tag": {KeyRing{public}, tampered(map[string]any{"version": "0.3.0", "tag": "v0.3.0"}), ErrBadSignature},
		"tampered version only":    {KeyRing{public}, tampered(map[string]any{"version": "0.3.0"}), ErrMalformedSignature},
		"tampered tag only":        {KeyRing{public}, tampered(map[string]any{"tag": "v0.2.1"}), ErrMalformedSignature},
		"tampered target":          {KeyRing{public}, tampered(map[string]any{"target": "linux-arm64"}), ErrMalformedSignature},
		"tampered archive name":    {KeyRing{public}, tampered(map[string]any{"archive": "other.pyz"}), ErrMalformedSignature},
		"short signature":          {KeyRing{public}, reencode(func(document, _ map[string]any) { document["signature"] = "AAAA" }), ErrMalformedSignature},
		"no pinned key":            {nil, good, ErrNoPinnedKey},
		"not canonical":            {KeyRing{public}, bytes.Replace(good, []byte(`{"contract"`), []byte(`{ "contract"`), 1), ErrMalformedSignature},
		"no trailing newline":      {KeyRing{public}, bytes.TrimSuffix(good, []byte("\n")), ErrMalformedSignature},
		"unknown field":            {KeyRing{public}, bytes.Replace(good, []byte(`{"contract"`), []byte(`{"comment":"x","contract"`), 1), ErrMalformedSignature},
		"duplicate field":          {KeyRing{public}, bytes.Replace(good, []byte(`{"contract"`), []byte(`{"contract":"x","contract"`), 1), ErrMalformedSignature},
		"field case":               {KeyRing{public}, bytes.Replace(good, []byte(`"key_id"`), []byte(`"KEY_ID"`), 1), ErrMalformedSignature},
		"trailing document":        {KeyRing{public}, append(bytes.Clone(good), []byte("{}\n")...), ErrMalformedSignature},
		"empty":                    {KeyRing{public}, nil, ErrMalformedSignature},
		"oversized":                {KeyRing{public}, bytes.Repeat([]byte(" "), MaxSignatureBytes+1), ErrMalformedSignature},
	} {
		t.Run(name, func(t *testing.T) {
			statement, _, err := test.ring.Verify(test.raw)
			if test.want == nil {
				if err != nil || statement != testStatement() {
					t.Fatalf("statement=%+v err=%v", statement, err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v, want %v", err, test.want)
			}
			if statement != (Statement{}) {
				t.Fatalf("a refused signature returned a statement: %+v", statement)
			}
		})
	}
	// A rotated ring with both keys accepts either signer.
	for _, raw := range [][]byte{good, signedByOther} {
		if _, _, err := (KeyRing{other, public}).Verify(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignRefusesAnInvalidStatement(t *testing.T) {
	private, _ := testKey(t)
	for name, change := range map[string]func(*Statement){
		"tag mismatch":    func(s *Statement) { s.Tag = "v0.2.1" },
		"other target":    func(s *Statement) { s.Target = "darwin-arm64" },
		"other archive":   func(s *Statement) { s.Archive = "other.pyz" },
		"short digest":    func(s *Statement) { s.ArchiveSHA256 = "abcd" },
		"upper digest":    func(s *Statement) { s.ArchiveSHA256 = strings.Repeat("AB", 32) },
		"empty archive":   func(s *Statement) { s.ArchiveSize = 0 },
		"huge archive":    func(s *Statement) { s.ArchiveSize = MaxArchiveBytes + 1 },
		"bad version":     func(s *Statement) { s.Version, s.Tag = "1.0", "v1.0" },
		"contract":        func(s *Statement) { s.Contract = "x" },
		"schema version":  func(s *Statement) { s.SchemaVersion = 2 },
		"no private key":  nil,
		"short private":   nil,
		"unchanged works": func(*Statement) {},
	} {
		t.Run(name, func(t *testing.T) {
			statement := testStatement()
			key := private
			switch name {
			case "no private key":
				key = nil
			case "short private":
				key = private[:31]
			default:
				change(&statement)
			}
			_, err := Sign(key, statement)
			if name == "unchanged works" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("signed an invalid statement")
			}
		})
	}
}

func TestParseKeyRing(t *testing.T) {
	_, a := testKey(t)
	_, b := testKey(t)
	line := func(key PublicKey) string { return "ed25519 " + base64.StdEncoding.EncodeToString(key.Key) }
	ring, err := ParseKeyRing([]byte("# release keys\n\n  " + line(a) + "  \n" + line(b) + "\n"))
	if err != nil || len(ring) != 2 || ring[0].ID != a.ID || ring[1].ID != b.ID || len(a.ID) != 16 {
		t.Fatalf("ring=%v err=%v", ring, err)
	}
	if empty, err := ParseKeyRing([]byte("# no keys yet\n")); err != nil || len(empty) != 0 {
		t.Fatalf("empty ring: %v %v", empty, err)
	}
	for name, text := range map[string]string{
		"unknown algorithm": "rsa " + base64.StdEncoding.EncodeToString(a.Key),
		"short key":         "ed25519 " + base64.StdEncoding.EncodeToString(a.Key[:31]),
		"not base64":        "ed25519 not-base64!",
		"extra field":       line(a) + " comment",
		"duplicate":         line(a) + "\n" + line(a),
		"no key":            "ed25519",
	} {
		if _, err := ParseKeyRing([]byte(text)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The committed key file must always parse; an empty ring means this build
// cannot verify releases.
func TestPinnedKeysParse(t *testing.T) {
	if _, err := PinnedKeys(); err != nil {
		t.Fatal(err)
	}
}
