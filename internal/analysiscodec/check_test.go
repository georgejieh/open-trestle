package analysiscodec

import (
	"errors"
	"strings"
	"testing"
)

func TestNewStaticDebugCheckDerivesFailClosedState(t *testing.T) {
	change := strings.Repeat("a", 64)
	for _, test := range []struct {
		applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32
		want                                                                    DeterministicCheckState
	}{
		{2, 3, 2, 3, 0, CheckPassed},
		{2, 3, 1, 2, 1, CheckFailed},
		{2, 3, 1, 2, 0, CheckIncomplete},
		{0, 0, 0, 0, 0, CheckNotApplicable},
	} {
		check, err := NewStaticDebugCheck(change, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
		if err != nil || check.State() != test.want {
			t.Fatalf("check=%#v want=%s err=%v", check, test.want, err)
		}
	}
}
func TestInvalidStandaloneCheckSentinel(t *testing.T) {
	for _, test := range []func() error{
		func() error { _, err := NewStaticDebugCheck("bad", 1, 1, 1, 1, 0); return err },
		func() error { _, err := NewStaticDebugCheck(strings.Repeat("a", 64), 2, 1, 1, 1, 0); return err },
		func() error {
			_, err := NewDeterministicCheck(strings.Repeat("a", 64), CheckFailed, 1, 1, 1, 1, 0)
			return err
		},
	} {
		if !errors.Is(test(), ErrInvalidDeterministicCheck) {
			t.Fatal("wrong check error")
		}
	}
}
