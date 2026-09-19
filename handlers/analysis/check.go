package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	staticDebugCheckKey         = "static_debug_output"
	staticDebugCheckRuleVersion = uint16(1)
	maximumDeterministicFiles   = uint32(4096)
	maximumDeterministicRanges  = uint32(1000000)
	maximumDeterministicMatches = uint32(1 << 24)
)

var ErrInvalidDeterministicCheck = errors.New("invalid deterministic check")

// DeterministicCheckState is the closed outcome of one reproducible check.
type DeterministicCheckState uint8

const (
	CheckPassed DeterministicCheckState = iota + 1
	CheckFailed
	CheckIncomplete
	CheckNotApplicable
)

func (s DeterministicCheckState) String() string {
	switch s {
	case CheckPassed:
		return "passed"
	case CheckFailed:
		return "failed"
	case CheckIncomplete:
		return "incomplete"
	case CheckNotApplicable:
		return "not_applicable"
	default:
		return ""
	}
}

func parseDeterministicCheckState(value string) (DeterministicCheckState, error) {
	for state := CheckPassed; state <= CheckNotApplicable; state++ {
		if state.String() == value {
			return state, nil
		}
	}
	return 0, ErrInvalidDeterministicCheck
}

// DeterministicCheck records content-free coverage and matches for one exact rule.
type DeterministicCheck struct {
	identity, changeIdentity                                       string
	state                                                          DeterministicCheckState
	applicableFiles, applicableRanges, checkedFiles, checkedRanges uint32
	matches                                                        uint32
}

func newStaticDebugCheck(changeIdentity string, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32) (DeterministicCheck, error) {
	state := CheckPassed
	switch {
	case applicableRanges == 0:
		state = CheckNotApplicable
	case matches > 0:
		state = CheckFailed
	case checkedFiles != applicableFiles || checkedRanges != applicableRanges:
		state = CheckIncomplete
	}
	return NewDeterministicCheck(changeIdentity, state, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches)
}

func NewDeterministicCheck(changeIdentity string, state DeterministicCheckState, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32) (DeterministicCheck, error) {
	validBounds := applicableFiles <= maximumDeterministicFiles && applicableFiles <= applicableRanges && applicableRanges <= maximumDeterministicRanges && checkedFiles <= applicableFiles && checkedFiles <= checkedRanges && checkedRanges <= applicableRanges && matches <= maximumDeterministicMatches && (applicableFiles == 0) == (applicableRanges == 0) && (checkedFiles == 0) == (checkedRanges == 0)
	complete := checkedFiles == applicableFiles && checkedRanges == applicableRanges
	validState := state == CheckPassed && applicableRanges > 0 && complete && matches == 0 ||
		state == CheckFailed && applicableRanges > 0 && checkedRanges > 0 && matches > 0 ||
		state == CheckIncomplete && applicableRanges > 0 && !complete && matches == 0 ||
		state == CheckNotApplicable && applicableFiles == 0 && applicableRanges == 0 && checkedFiles == 0 && checkedRanges == 0 && matches == 0
	if !validDigest(changeIdentity) || state.String() == "" || !validBounds || !validState {
		return DeterministicCheck{}, ErrInvalidDeterministicCheck
	}
	check := DeterministicCheck{changeIdentity: changeIdentity, state: state, applicableFiles: applicableFiles, applicableRanges: applicableRanges, checkedFiles: checkedFiles, checkedRanges: checkedRanges, matches: matches}
	check.identity = deriveDeterministicCheckIdentity(check)
	return check, nil
}

func (c DeterministicCheck) Identity() string               { return c.identity }
func (c DeterministicCheck) Key() string                    { return staticDebugCheckKey }
func (c DeterministicCheck) RuleVersion() uint16            { return staticDebugCheckRuleVersion }
func (c DeterministicCheck) ChangeIdentity() string         { return c.changeIdentity }
func (c DeterministicCheck) State() DeterministicCheckState { return c.state }
func (c DeterministicCheck) ApplicableFiles() uint32        { return c.applicableFiles }
func (c DeterministicCheck) ApplicableRanges() uint32       { return c.applicableRanges }
func (c DeterministicCheck) CheckedFiles() uint32           { return c.checkedFiles }
func (c DeterministicCheck) CheckedRanges() uint32          { return c.checkedRanges }
func (c DeterministicCheck) MatchCount() uint32             { return c.matches }
func (c DeterministicCheck) Complete() bool {
	return c.checkedFiles == c.applicableFiles && c.checkedRanges == c.applicableRanges
}
func (c DeterministicCheck) Cleared() bool { return c.state == CheckPassed }
func (c DeterministicCheck) Validate() error {
	rebuilt, err := NewDeterministicCheck(c.changeIdentity, c.state, c.applicableFiles, c.applicableRanges, c.checkedFiles, c.checkedRanges, c.matches)
	if err != nil || rebuilt.identity != c.identity {
		return ErrInvalidDeterministicCheck
	}
	return nil
}

func deriveDeterministicCheckIdentity(c DeterministicCheck) string {
	encoded, _ := json.Marshal(struct {
		Contract         string `json:"contract"`
		Version          int    `json:"version"`
		Key              string `json:"key"`
		RuleVersion      uint16 `json:"rule_version"`
		ChangeIdentity   string `json:"change_identity"`
		State            string `json:"state"`
		ApplicableFiles  uint32 `json:"applicable_files"`
		ApplicableRanges uint32 `json:"applicable_ranges"`
		CheckedFiles     uint32 `json:"checked_files"`
		CheckedRanges    uint32 `json:"checked_ranges"`
		Matches          uint32 `json:"matches"`
	}{"open-trestle/deterministic-check", 1, staticDebugCheckKey, staticDebugCheckRuleVersion, c.changeIdentity, c.state.String(), c.applicableFiles, c.applicableRanges, c.checkedFiles, c.checkedRanges, c.matches})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
