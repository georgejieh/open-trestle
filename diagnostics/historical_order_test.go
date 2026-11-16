package diagnostics

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestParseSetRetainsHistoricalTiedFindingOrder(t *testing.T) {
	encoded, err := os.ReadFile("testdata/historical-tied-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var payloads []json.RawMessage
	if err = json.Unmarshal(encoded, &payloads); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("historical fixture count=%d", len(payloads))
	}
	identities := make(map[string]bool)
	for index, payload := range payloads {
		set, err := ParseSet(payload)
		if err != nil {
			t.Fatalf("historical tied order %d was rejected: %v", index, err)
		}
		if err = set.Validate(); err != nil {
			t.Fatal(err)
		}
		roundTrip, err := EncodeSet(set)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(roundTrip, payload) {
			t.Fatalf("historical tied order %d changed on readback", index)
		}
		identities[set.Identity()] = true
	}
	if len(identities) != 2 {
		t.Fatal("historical distinct identities were collapsed")
	}
}
