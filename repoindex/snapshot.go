package repoindex

import (
	"encoding/binary"
	"hash/crc32"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/varcodec"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Status says whether a file of a snapshot has an analysis, or why not.
type Status string

const (
	// StatusIndexed: the file has an analysis, which may carry gaps.
	StatusIndexed Status = "indexed"
	// StatusNotAnalysed: the file's role or language is not analysed:
	// vendored code, docs, config, other files and languages without an
	// analyzer.
	StatusNotAnalysed Status = "not_analysed"
	StatusBinary      Status = "binary"
	StatusSymlink     Status = "symlink"
	StatusSubmodule   Status = "submodule"
	// StatusUnavailable: the blob could not be read from the object store.
	StatusUnavailable Status = "unavailable"
	// The build stopped analysing at one of its limits.
	StatusFileLimit  Status = "file_limit"
	StatusByteLimit  Status = "byte_limit"
	StatusTimeLimit  Status = "time_limit"
	StatusStoreLimit Status = "store_limit"
	// StatusFailed: the analysis failed as a whole, by a deadline, a worker
	// failure or an unavailable analyzer. Nothing is stored, so the next
	// build tries again.
	StatusFailed Status = "analysis_failed"
)

var (
	statusCodes = []Status{StatusIndexed, StatusNotAnalysed, StatusBinary, StatusSymlink, StatusSubmodule, StatusUnavailable, StatusFileLimit, StatusByteLimit, StatusTimeLimit, StatusStoreLimit, StatusFailed}
	roleCodes   = []Role{RoleSource, RoleTest, RoleConfig, RoleDocs, RoleGenerated, RoleVendored, RoleOther}
)

// FileEntry is one file of a snapshot. Object is the hex blob ID.
type FileEntry struct {
	Path     string                  `json:"path"`
	Object   string                  `json:"object"`
	Role     Role                    `json:"role"`
	Language syntaxanalysis.Language `json:"language,omitempty"`
	Status   Status                  `json:"status"`
}

// BuildLimits bound one build. Reaching one is recorded in the snapshot:
// every file it left out carries the limit as its status.
type BuildLimits struct {
	// MaxEntries bounds the tree entries listed; the rest of the tree is
	// not seen and the coverage says the tree was truncated.
	MaxEntries int `json:"max_entries"`
	// MaxFiles and MaxBytes bound the files and bytes analysed in one
	// build; files reused from earlier builds do not count.
	MaxFiles int   `json:"max_files"`
	MaxBytes int64 `json:"max_bytes"`
	// MaxDuration bounds the analysis time of one build.
	MaxDuration time.Duration `json:"max_duration"`
}

// DefaultBuildLimits returns the limits a build uses unless configured.
func DefaultBuildLimits() BuildLimits {
	return BuildLimits{MaxEntries: 1_000_000, MaxFiles: 200_000, MaxBytes: 2 << 30, MaxDuration: 30 * time.Minute}
}

func (l BuildLimits) valid() bool {
	return l.MaxEntries > 0 && l.MaxFiles > 0 && l.MaxBytes > 0 && l.MaxDuration > 0
}

// Coverage records what a build saw and did.
type Coverage struct {
	TreeEntries   int  `json:"tree_entries"`
	TreeTruncated bool `json:"tree_truncated"`
	// InvalidPaths counts tree entries left out because their path is not
	// valid UTF-8 or is too long.
	InvalidPaths int `json:"invalid_paths"`
	// ModulesLeftOut counts go.mod files the build could not use.
	ModulesLeftOut int           `json:"modules_left_out"`
	Analysed       int           `json:"analysed"`
	Reused         int           `json:"reused"`
	AnalysedBytes  int64         `json:"analysed_bytes"`
	Duration       time.Duration `json:"duration"`
	Limits         BuildLimits   `json:"limits"`
}

// Snapshot is the index of one commit: every file of its tree with its
// role and status, its Go modules, and what the build covered.
type Snapshot struct {
	Algorithm string      `json:"algorithm"`
	Commit    string      `json:"commit"`
	BuiltAt   time.Time   `json:"built_at"`
	Files     []FileEntry `json:"files"`
	Modules   []GoModule  `json:"modules"`
	Coverage  Coverage    `json:"coverage"`
}

// GoModule is a go.mod file's directory and the module path it declares,
// with the longest path first, so that the innermost module wins.
type GoModule struct {
	Dir  string `json:"dir"`
	Path string `json:"path"`
}

// key returns the record key of an indexed file.
func (s Snapshot) key(f FileEntry) Key {
	return recordKey(s.Algorithm, f.Object, f.Language, f.Path)
}

const snapshotMagic = "OTIXSNP1"

func encodeSnapshot(s Snapshot, identity [32]byte) []byte {
	out := append([]byte(snapshotMagic), identity[:]...)
	out = varcodec.AppendString(out, s.Algorithm)
	out = varcodec.AppendString(out, s.Commit)
	out = varcodec.AppendUvarint(out, uint64(s.BuiltAt.UnixNano()))
	c := s.Coverage
	for _, v := range []int64{int64(c.TreeEntries), int64(c.InvalidPaths), int64(c.ModulesLeftOut), int64(c.Analysed), int64(c.Reused), c.AnalysedBytes, int64(c.Duration), int64(c.Limits.MaxEntries), int64(c.Limits.MaxFiles), c.Limits.MaxBytes, int64(c.Limits.MaxDuration)} {
		out = varcodec.AppendUvarint(out, uint64(v))
	}
	out = varcodec.AppendBool(out, c.TreeTruncated)
	out = varcodec.AppendUvarint(out, uint64(len(s.Modules)))
	for _, m := range s.Modules {
		out = varcodec.AppendString(out, m.Dir)
		out = varcodec.AppendString(out, m.Path)
	}
	out = varcodec.AppendUvarint(out, uint64(len(s.Files)))
	for _, f := range s.Files {
		out = varcodec.AppendString(out, f.Path)
		out = varcodec.AppendString(out, f.Object)
		out = append(out, byte(slices.Index(roleCodes, f.Role)), byte(slices.Index(statusCodes, f.Status)))
		out = varcodec.AppendString(out, string(f.Language))
	}
	return binary.LittleEndian.AppendUint32(out, crc32.Checksum(out, crcTable))
}

// maxSnapshotNumber bounds the counters of a decoded snapshot.
const maxSnapshotNumber = 1 << 62

func decodeSnapshot(data []byte, identity [32]byte) (Snapshot, error) {
	if len(data) < len(snapshotMagic)+32+4 || string(data[:len(snapshotMagic)]) != snapshotMagic {
		return Snapshot{}, errCorrupt
	}
	body, sum := data[:len(data)-4], binary.LittleEndian.Uint32(data[len(data)-4:])
	if crc32.Checksum(body, crcTable) != sum {
		return Snapshot{}, errCorrupt
	}
	if [32]byte(body[len(snapshotMagic):len(snapshotMagic)+32]) != identity {
		return Snapshot{}, errStale
	}
	r := varcodec.NewReader(body[len(snapshotMagic)+32:])
	s := Snapshot{Algorithm: r.String(), Commit: r.String(), BuiltAt: time.Unix(0, int64(r.Uvarint())).UTC()}
	n := make([]int64, 11)
	for i := range n {
		n[i] = int64(r.Uvarint())
		if n[i] < 0 || n[i] > maxSnapshotNumber {
			r.Fail()
		}
	}
	s.Coverage = Coverage{TreeEntries: int(n[0]), InvalidPaths: int(n[1]), ModulesLeftOut: int(n[2]), Analysed: int(n[3]), Reused: int(n[4]), AnalysedBytes: n[5], Duration: time.Duration(n[6]),
		Limits: BuildLimits{MaxEntries: int(n[7]), MaxFiles: int(n[8]), MaxBytes: n[9], MaxDuration: time.Duration(n[10])}}
	s.Coverage.TreeTruncated = r.Bool()
	s.Modules = make([]GoModule, r.Count(2))
	for i := range s.Modules {
		s.Modules[i] = GoModule{Dir: r.String(), Path: r.String()}
	}
	s.Files = make([]FileEntry, r.Count(5))
	for i := range s.Files {
		f := &s.Files[i]
		f.Path, f.Object = r.String(), r.String()
		role, status := int(r.Byte()), int(r.Byte())
		f.Language = syntaxanalysis.Language(r.String())
		if role >= len(roleCodes) || status >= len(statusCodes) || !utf8.ValidString(f.Path) || f.Language != "" && !f.Language.Valid() {
			return Snapshot{}, errCorrupt
		}
		f.Role, f.Status = roleCodes[role], statusCodes[status]
	}
	if r.Done() != nil || !validObject(s.Commit) || s.Algorithm != "sha1" && s.Algorithm != "sha256" {
		return Snapshot{}, errCorrupt
	}
	return s, nil
}

func validObject(v string) bool {
	if len(v) != 40 && len(v) != 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !(v[i] >= '0' && v[i] <= '9' || v[i] >= 'a' && v[i] <= 'f') {
			return false
		}
	}
	return true
}
