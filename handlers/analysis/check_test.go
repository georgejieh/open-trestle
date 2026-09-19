package analysis

import (
	"strings"
	"testing"
)

func TestDeterministicCheckStatesBindExactCoverage(t *testing.T) {
	change := strings.Repeat("a", 64)
	tests := []struct {
		state                             DeterministicCheckState
		applicableFiles, applicableRanges uint32
		checkedFiles, checkedRanges       uint32
		matches                           uint32
		complete, cleared                 bool
	}{
		{CheckPassed, 2, 3, 2, 3, 0, true, true},
		{CheckFailed, 2, 3, 1, 2, 1, false, false},
		{CheckIncomplete, 2, 3, 1, 2, 0, false, false},
		{CheckNotApplicable, 0, 0, 0, 0, 0, true, false},
	}
	for _, test := range tests {
		check, err := NewDeterministicCheck(change, test.state, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
		if err != nil || check.Validate() != nil || check.Key() != "static_debug_output" || check.RuleVersion() != 1 || check.State() != test.state || check.Complete() != test.complete || check.Cleared() != test.cleared || check.Identity() == "" {
			t.Fatalf("state=%s check=%#v err=%v", test.state, check, err)
		}
	}
	golden, _ := NewDeterministicCheck(change, CheckPassed, 2, 3, 2, 3, 0)
	if golden.Identity() != "7d14e06842bbf9ba2db3c600f146d2e497bcaacd1664a1bdcb02b52e7b3d1a96" {
		t.Fatalf("identity=%s", golden.Identity())
	}
}

func TestDeterministicCheckRejectsImpossibleState(t *testing.T) {
	change := strings.Repeat("a", 64)
	for _, test := range []struct {
		state                             DeterministicCheckState
		applicableFiles, applicableRanges uint32
		checkedFiles, checkedRanges       uint32
		matches                           uint32
	}{
		{CheckPassed, 1, 1, 1, 1, 1},
		{CheckFailed, 1, 1, 1, 1, 0},
		{CheckIncomplete, 1, 1, 1, 1, 0},
		{CheckNotApplicable, 1, 1, 0, 0, 0},
		{CheckPassed, 1, 1, 2, 1, 0},
		{CheckPassed, 2, 1, 1, 1, 0},
		{CheckPassed, 0, 1, 0, 1, 0},
		{CheckFailed, 1, 1, 0, 1, 1},
	} {
		check, err := NewDeterministicCheck(change, test.state, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
		if err == nil || check.Identity() != "" {
			t.Fatalf("state=%s check=%#v err=%v", test.state, check, err)
		}
	}
}

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
		check, err := newStaticDebugCheck(change, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
		if err != nil || check.State() != test.want {
			t.Fatalf("check=%#v want=%s err=%v", check, test.want, err)
		}
	}
}
