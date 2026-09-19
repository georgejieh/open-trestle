package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	deterministicCheckKey         = "static_debug_output"
	deterministicCheckRuleVersion = uint16(1)
	maxDeterministicFiles         = uint32(4096)
	maxDeterministicRanges        = uint32(1000000)
	maxDeterministicMatches       = uint32(1 << 24)
)

// DeterministicCheckState is the closed public state of one reproducible check.
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
	return 0, ErrInvalidSet
}

// DeterministicCheck binds one analysis check without source paths or content.
type DeterministicCheck struct {
	identity, sourceCheckIdentity, analysisResultIdentity, changeIdentity   string
	state                                                                   DeterministicCheckState
	applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32
}

func NewDeterministicCheck(sourceCheckIdentity, analysisResultIdentity, changeIdentity string, state DeterministicCheckState, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32) (DeterministicCheck, error) {
	validBounds := applicableFiles <= maxDeterministicFiles && applicableFiles <= applicableRanges && applicableRanges <= maxDeterministicRanges && checkedFiles <= applicableFiles && checkedFiles <= checkedRanges && checkedRanges <= applicableRanges && matches <= maxDeterministicMatches && (applicableFiles == 0) == (applicableRanges == 0) && (checkedFiles == 0) == (checkedRanges == 0)
	complete := checkedFiles == applicableFiles && checkedRanges == applicableRanges
	validState := state == CheckPassed && applicableRanges > 0 && complete && matches == 0 || state == CheckFailed && applicableRanges > 0 && checkedRanges > 0 && matches > 0 || state == CheckIncomplete && applicableRanges > 0 && !complete && matches == 0 || state == CheckNotApplicable && applicableFiles == 0 && applicableRanges == 0 && checkedFiles == 0 && checkedRanges == 0 && matches == 0
	check := DeterministicCheck{sourceCheckIdentity: sourceCheckIdentity, analysisResultIdentity: analysisResultIdentity, changeIdentity: changeIdentity, state: state, applicableFiles: applicableFiles, applicableRanges: applicableRanges, checkedFiles: checkedFiles, checkedRanges: checkedRanges, matches: matches}
	if !validDigest(sourceCheckIdentity) || !validDigest(analysisResultIdentity) || !validDigest(changeIdentity) || state.String() == "" || !validBounds || !validState || sourceCheckIdentity != deriveSourceDeterministicCheckIdentity(check) {
		return DeterministicCheck{}, ErrInvalidSet
	}
	check.identity = deriveDiagnosticDeterministicCheckIdentity(check)
	return check, nil
}

func (c DeterministicCheck) Identity() string               { return c.identity }
func (c DeterministicCheck) SourceCheckIdentity() string    { return c.sourceCheckIdentity }
func (c DeterministicCheck) AnalysisResultIdentity() string { return c.analysisResultIdentity }
func (c DeterministicCheck) ChangeIdentity() string         { return c.changeIdentity }
func (c DeterministicCheck) Key() string                    { return deterministicCheckKey }
func (c DeterministicCheck) RuleVersion() uint16            { return deterministicCheckRuleVersion }
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
	rebuilt, err := NewDeterministicCheck(c.sourceCheckIdentity, c.analysisResultIdentity, c.changeIdentity, c.state, c.applicableFiles, c.applicableRanges, c.checkedFiles, c.checkedRanges, c.matches)
	if err != nil || rebuilt.identity != c.identity {
		return ErrInvalidSet
	}
	return nil
}

func deriveSourceDeterministicCheckIdentity(c DeterministicCheck) string {
	return hashDeterministicCheckValue(struct {
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
	}{"open-trestle/deterministic-check", 1, deterministicCheckKey, deterministicCheckRuleVersion, c.changeIdentity, c.state.String(), c.applicableFiles, c.applicableRanges, c.checkedFiles, c.checkedRanges, c.matches})
}

func deriveDiagnosticDeterministicCheckIdentity(c DeterministicCheck) string {
	return hashDeterministicCheckValue(struct {
		Contract         string `json:"contract"`
		Version          int    `json:"version"`
		SourceCheck      string `json:"source_check"`
		AnalysisResult   string `json:"analysis_result"`
		ChangeIdentity   string `json:"change_identity"`
		State            string `json:"state"`
		ApplicableFiles  uint32 `json:"applicable_files"`
		ApplicableRanges uint32 `json:"applicable_ranges"`
		CheckedFiles     uint32 `json:"checked_files"`
		CheckedRanges    uint32 `json:"checked_ranges"`
		Matches          uint32 `json:"matches"`
	}{"open-trestle/diagnostic-deterministic-check", 1, c.sourceCheckIdentity, c.analysisResultIdentity, c.changeIdentity, c.state.String(), c.applicableFiles, c.applicableRanges, c.checkedFiles, c.checkedRanges, c.matches})
}

func hashDeterministicCheckValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
