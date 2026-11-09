package runtimeconfig

import "testing"

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
