package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const localRecoveryPointContract = "open-trestle/local-recovery-point"
const maxLocalRecoveryPointBytes = 4 << 20
const maxLocalRecoveryPointEntries = 30000

// A recovery point records observations of one stopped state. It is not a
// signature, freshness proof, portable backup, or permission to restart.
type localRecoveryPoint struct {
	Contract            string               `json:"contract"`
	Version             int                  `json:"version"`
	StatePath           string               `json:"state_path"`
	SetupPath           string               `json:"setup_path"`
	RepositoryAuthority string               `json:"repository_authority"`
	RepositoryNamespace []string             `json:"repository_namespace"`
	RepositoryName      string               `json:"repository_name"`
	OwnerIdentity       string               `json:"owner_identity"`
	SetupIdentity       string               `json:"setup_identity"`
	Entries             []localRecoveryEntry `json:"entries"`
	GitEntries          []localRecoveryEntry `json:"git_entries"`
	Runs                []localRecoveryRun   `json:"runs"`
	Assets              []localRecoveryAsset `json:"assets"`
}
type localRecoveryEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type localRecoveryRun struct {
	Tenant     string `json:"tenant"`
	Repository string `json:"repository"`
	Run        string `json:"run"`
	Receipt    string `json:"receipt"`
	Diagnostic string `json:"diagnostic"`
	AuditHead  string `json:"audit_head"`
}

var errInvalidRecoveryPoint = errors.New("invalid local recovery point")

func (point localRecoveryPoint) validate() error {
	if point.Contract != localRecoveryPointContract || point.Version != 1 || !validLocalOwnerPath(point.StatePath) || !validLocalOwnerPath(point.SetupPath) || !daemonNonzeroDigest(point.OwnerIdentity) || !daemonNonzeroDigest(point.SetupIdentity) || len(point.Entries) > maxLocalRecoveryPointEntries || len(point.Runs) > 500 {
		return errInvalidRecoveryPoint
	}
	if _, err := evidence.NewRepositoryIdentity(point.RepositoryAuthority, point.RepositoryNamespace, point.RepositoryName); err != nil {
		return errInvalidRecoveryPoint
	}
	if point.SetupPath != filepath.Join(point.StatePath, "setup", "plan.json") {
		return errInvalidRecoveryPoint
	}
	if len(point.Assets) != len(localRecoveryAssetRoles) {
		return errInvalidRecoveryPoint
	}
	for i, role := range localRecoveryAssetRoles {
		asset := point.Assets[i]
		if asset.Role != role || !validLocalOwnerPath(asset.Path) || !daemonNonzeroDigest(asset.SHA256) {
			return errInvalidRecoveryPoint
		}
	}
	previous := ""
	for _, entry := range point.Entries {
		if entry.Path == "" || entry.Path <= previous || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || strings.Contains(entry.Path, "\\") || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || entry.Size < 0 || !(entry.Mode == 0o600 && daemonNonzeroDigest(entry.SHA256) || entry.Mode == 0o700 && entry.Size == 0 && entry.SHA256 == "") {
			return errInvalidRecoveryPoint
		}
		previous = entry.Path
	}
	if len(point.GitEntries) > maxLocalRecoveryPointEntries {
		return errInvalidRecoveryPoint
	}
	previous = ""
	for _, entry := range point.GitEntries {
		if entry.Path == "" || entry.Path <= previous || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || strings.Contains(entry.Path, "\\") || entry.Mode&^0o777 != 0 || entry.Mode&0o022 != 0 || entry.Size < 0 || !(daemonNonzeroDigest(entry.SHA256) || entry.SHA256 == "" && entry.Size == 0) {
			return errInvalidRecoveryPoint
		}
		previous = entry.Path
	}
	if !sort.SliceIsSorted(point.Runs, func(i, j int) bool { return recoveryRunKey(point.Runs[i]) < recoveryRunKey(point.Runs[j]) }) {
		return errInvalidRecoveryPoint
	}
	previous = ""
	for _, run := range point.Runs {
		if _, err := audit.NewReviewScope(run.Tenant, run.Repository, run.Run); err != nil {
			return errInvalidRecoveryPoint
		}
		key := recoveryRunKey(run)
		if run.Tenant == "" || run.Repository == "" || run.Run == "" || key <= previous || !daemonNonzeroDigest(run.Receipt) || run.Diagnostic != "" && !daemonNonzeroDigest(run.Diagnostic) || run.AuditHead != "" && !daemonNonzeroDigest(run.AuditHead) {
			return errInvalidRecoveryPoint
		}
		previous = key
	}
	return nil
}
func recoveryRunKey(run localRecoveryRun) string {
	return run.Tenant + "\x00" + run.Repository + "\x00" + run.Run
}
func parseLocalRecoveryPoint(raw []byte) (localRecoveryPoint, error) {
	var point localRecoveryPoint
	if len(raw) == 0 || len(raw) > maxLocalRecoveryPointBytes {
		return point, errInvalidRecoveryPoint
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&point); err != nil {
		return point, errInvalidRecoveryPoint
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return point, errInvalidRecoveryPoint
	}
	if err := point.validate(); err != nil {
		return point, err
	}
	canonical, err := encodeLocalRecoveryPoint(point)
	if err != nil || !bytes.Equal(raw, canonical) {
		return localRecoveryPoint{}, errInvalidRecoveryPoint
	}
	return point, nil
}
func encodeLocalRecoveryPoint(point localRecoveryPoint) ([]byte, error) {
	if err := point.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(point)
	if err != nil || len(raw)+1 > maxLocalRecoveryPointBytes {
		return nil, errInvalidRecoveryPoint
	}
	return append(raw, '\n'), nil
}
func localRecoveryBytesIdentity(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
