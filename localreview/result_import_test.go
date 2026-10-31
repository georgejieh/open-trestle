package localreview

import "testing"

func TestCompletedResultImportRefusesUnstartedAndInvalidValues(t *testing.T) {
	for _, status := range []string{"refused", "incomplete", "canceled", "failed"} {
		result, err := NewUnstartedResult(status)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeResult(result)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseCompletedResult(encoded); err == nil {
			t.Fatal("unstarted result accepted as completed")
		}
		if _, err := result.CompletedMetadata(); err == nil {
			t.Fatal("unstarted result exposed completed metadata")
		}
	}
	if _, err := (Result{}).CompletedMetadata(); err == nil {
		t.Fatal("invalid result exposed metadata")
	}
	for _, encoded := range [][]byte{nil, []byte("null\n"), []byte("{}\n"), make([]byte, MaxResultJSONBytes+1)} {
		if _, err := ParseCompletedResult(encoded); err == nil {
			t.Fatal("invalid result accepted")
		}
	}
}
