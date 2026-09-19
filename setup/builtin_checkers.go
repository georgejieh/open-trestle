package setup

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StateStorageChecker validates one private local directory without writing to it.
type StateStorageChecker struct{ path, configurationIdentity string }

// NewStateStorageChecker binds one exact local directory posture.
func NewStateStorageChecker(path string) (*StateStorageChecker, error) {
	if path == "" {
		return nil, ErrInvalidCheckerRuntime
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalidCheckerRuntime
	}
	checker := &StateStorageChecker{path: absolute}
	checker.configurationIdentity = checkerConfigIdentity(CheckStateStoragePostureValidated, absolute)
	return checker, nil
}
func (c *StateStorageChecker) Key() CheckKey { return CheckStateStoragePostureValidated }
func (c *StateStorageChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckStateStoragePostureValidated)
}
func (c *StateStorageChecker) Check(ctx context.Context, plan Plan) CheckResult {
	outcome := "valid"
	state := CheckBlocked
	if !fileOwnershipSupported() {
		outcome, state = "ownership_unavailable", CheckUnavailable
	} else if c == nil || ctx == nil || ctx.Err() != nil || plan.Validate() != nil {
		outcome = "invalid"
	} else if plan.profile != ProfileLocalSingleNode && plan.profile != ProfileAirGapped {
		outcome = "profile_mismatch"
	} else if !stablePrivateDirectory(c.path) {
		outcome = "unsafe"
	}
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckStateStoragePostureValidated), configurationIdentity, outcome)
	if outcome == "valid" {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(c.Key(), state, evidence)
}

func stablePrivateDirectory(path string) bool {
	type pinned struct {
		path string
		info os.FileInfo
	}
	chain := []pinned{}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		chain = append(chain, pinned{current, info})
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	if chain[0].info.Mode().Perm() != 0o700 || !fileOwnedByCurrentProcess(chain[0].info) {
		return false
	}
	for i := 1; i < len(chain); i++ {
		if !stableAncestorAuthority(chain[i].info, chain[i-1].info) {
			return false
		}
	}
	opened, err := os.Open(path)
	if err != nil {
		return false
	}
	openedInfo, statErr := opened.Stat()
	resolved, resolveErr := filepath.EvalSymlinks(path)
	closeErr := opened.Close()
	if statErr != nil || resolveErr != nil || closeErr != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm() != 0o700 || resolved != path || !os.SameFile(openedInfo, chain[0].info) {
		return false
	}
	for i, value := range chain {
		again, err := os.Lstat(value.path)
		if err != nil || !again.IsDir() || again.Mode()&os.ModeSymlink != 0 || !os.SameFile(again, value.info) {
			return false
		}
		if i > 0 && !stableAncestorAuthority(again, chain[i-1].info) {
			return false
		}
	}
	return true
}

func stableAncestorAuthority(parent, child os.FileInfo) bool {
	if !fileOwnedByTrustedProcessOrRoot(parent) {
		return false
	}
	if parent.Mode().Perm()&0o022 == 0 {
		return true
	}
	return parent.Mode()&os.ModeSticky != 0 && fileOwnedByCurrentProcess(child)
}

// ObserverCredentialPostureChecker checks bounded distinct operator and observer values without retaining them.
type ObserverCredentialPostureChecker struct {
	environment           func(string) string
	configurationIdentity string
}

// NewObserverCredentialPostureChecker binds the fixed daemon credential references.
func NewObserverCredentialPostureChecker(environment func(string) string) (*ObserverCredentialPostureChecker, error) {
	if environment == nil {
		return nil, ErrInvalidCheckerRuntime
	}
	return &ObserverCredentialPostureChecker{environment: environment, configurationIdentity: checkerConfigIdentity(CheckObserverCredentialPostureValidated, "OPEN_TRESTLE_API_TOKEN\x00OPEN_TRESTLE_OBSERVER_TOKEN")}, nil
}
func (c *ObserverCredentialPostureChecker) Key() CheckKey {
	return CheckObserverCredentialPostureValidated
}
func (c *ObserverCredentialPostureChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckObserverCredentialPostureValidated)
}
func (c *ObserverCredentialPostureChecker) Check(ctx context.Context, plan Plan) CheckResult {
	operatorValid, observerValid, distinct := false, false, false
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		operator := c.environment("OPEN_TRESTLE_API_TOKEN")
		observer := c.environment("OPEN_TRESTLE_OBSERVER_TOKEN")
		operatorValid = validSetupCredential(operator)
		observerValid = validSetupCredential(observer)
		operatorDigest := sha256.Sum256([]byte(operator))
		observerDigest := sha256.Sum256([]byte(observer))
		distinct = operatorValid && observerValid && subtle.ConstantTimeCompare(operatorDigest[:], observerDigest[:]) == 0
	}
	outcome := "valid"
	if !operatorValid || !observerValid || !distinct {
		outcome = "invalid"
	}
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckObserverCredentialPostureValidated), configurationIdentity, outcome)
	if outcome == "valid" {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(c.Key(), CheckBlocked, evidence)
}
func validSetupCredential(value string) bool {
	if len(value) < 32 || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
func checkerConfigIdentity(key CheckKey, value string) string {
	encoded, _ := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Key      CheckKey `json:"key"`
		Value    string   `json:"value"`
	}{"open-trestle/setup-checker-configuration", 1, key, value})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func checkerEvidenceIdentity(planIdentity, checkerIdentity, configurationIdentity, outcome string) string {
	encoded, _ := json.Marshal(struct {
		Contract              string `json:"contract"`
		Version               int    `json:"version"`
		PlanIdentity          string `json:"plan_identity"`
		CheckerIdentity       string `json:"checker_identity"`
		ConfigurationIdentity string `json:"configuration_identity"`
		Outcome               string `json:"outcome"`
	}{"open-trestle/setup-check-evidence", 1, planIdentity, checkerIdentity, configurationIdentity, outcome})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (c *StateStorageChecker) String() string   { return "setup state storage posture checker" }
func (c *StateStorageChecker) GoString() string { return "setup.StateStorageChecker{<redacted>}" }
func (c *StateStorageChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
func (c *ObserverCredentialPostureChecker) String() string {
	return "setup observer credential posture checker"
}
func (c *ObserverCredentialPostureChecker) GoString() string {
	return "setup.ObserverCredentialPostureChecker{<redacted>}"
}
func (c *ObserverCredentialPostureChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
