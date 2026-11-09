package runtimeconfig

import "testing"

// TestFeedbackReviewStyleAdviceRefusesAdviceNoReviewEmits requires the
// feedback review to accept only style advice a review could have recorded.
func TestFeedbackReviewStyleAdviceRefusesAdviceNoReviewEmits(t *testing.T) {
	for _, test := range []struct {
		name     string
		document string
		styled   bool
		valid    bool
	}{
		{"no advice", `{"schema_version":1}`, false, true},
		{"recommendation", `{"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}`, true, true},
		{"withheld with unread count", `{"style_withheld":[{"language":"go","changed_files":1}],"style_configuration_unread":1}`, true, true},
		{"unavailable", `{"style_advice_unavailable":true}`, true, true},
		{"unknown language", `{"style_recommendations":[{"language":"cobol","changed_files":1,"recommendation":"gofmt and Effective Go"}]}`, true, false},
		{"recommendation text not from the table", `{"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt"}]}`, true, false},
		{"withheld without unread count", `{"style_withheld":[{"language":"go","changed_files":1}]}`, true, false},
		{"empty advice fields", `{"style_withheld":[],"style_advice_unavailable":false}`, true, false},
		{"malformed advice", `{"style_withheld":"go"}`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validFeedbackStyleAdvice([]byte(test.document), test.styled); got != test.valid {
				t.Fatalf("validFeedbackStyleAdvice() = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestFeedbackReviewVersionAcceptsEachResultVersionWithItsOwnFields(t *testing.T) {
	for _, test := range []struct {
		version        int
		guided, styled bool
		want           bool
	}{
		{1, false, false, true},
		{1, true, false, false},
		{1, false, true, false},
		{4, true, false, true},
		{4, false, false, false},
		{4, true, true, false},
		{5, false, true, true},
		{5, true, true, true},
		{5, false, false, false},
		{5, true, false, false},
		{2, false, false, false},
		{3, false, false, false},
		{6, false, true, false},
	} {
		if got := feedbackReviewVersion(test.version, test.guided, test.styled); got != test.want {
			t.Errorf("feedbackReviewVersion(%d, guided=%t, styled=%t) = %t, want %t", test.version, test.guided, test.styled, got, test.want)
		}
	}
}
