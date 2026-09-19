package controlplane

import (
	"bytes"
	"errors"
	"testing"
)

func TestRunEventCanonicalEncodingRoundTrips(t *testing.T) {
	plan := runPlanFixture(t)
	event := runOpenedEventFixture(t, plan)
	encoded, err := EncodeRunEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRunEvent(encoded)
	if err != nil || parsed.Identity() != event.Identity() || !bytes.Equal(encoded, mustEncodeRunEvent(t, parsed)) {
		t.Fatalf("roundtrip=(%#v,%v)", parsed, err)
	}
	withSpace := append([]byte(" "), encoded...)
	if parsed, err := ParseRunEvent(withSpace); !errors.Is(err, ErrInvalidRunEventEncoding) || parsed.Identity() != "" {
		t.Fatalf("noncanonical=(%#v,%v)", parsed, err)
	}
}
func TestParseRunEventRejectsUnknownDuplicateAndTamperedIdentity(t *testing.T) {
	plan := runPlanFixture(t)
	encoded := mustEncodeRunEvent(t, runOpenedEventFixture(t, plan))
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	duplicate := bytes.Replace(encoded, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1)
	tampered := bytes.Replace(encoded, []byte(`"identity":"`), []byte(`"identity":"f`), 1)
	for _, content := range [][]byte{unknown, duplicate, tampered} {
		if parsed, err := ParseRunEvent(content); err == nil || parsed.Identity() != "" {
			t.Fatalf("ParseRunEvent(%s)=(%#v,%v)", content, parsed, err)
		}
	}
}
func mustEncodeRunEvent(t *testing.T, event RunEvent) []byte {
	t.Helper()
	encoded, err := EncodeRunEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
