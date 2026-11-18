package thirdparty

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type patchedCopy struct {
	directory string
	module    string
	version   string
	patch     string
	// partialRoot marks a copy whose upstream root directory is not a
	// package used by the guest, so only rootFiles are kept from it.
	partialRoot bool
}

var copies = []patchedCopy{
	{"betterleaks", "github.com/betterleaks/betterleaks", "v1.8.1", "betterleaks-v1.8.1.patch", true},
	{"tiktoken-go", "github.com/pkoukk/tiktoken-go", "v0.1.8", "tiktoken-go-v0.1.8.patch", false},
}

// rootFiles are the only files a partial-root copy keeps from its upstream
// root directory: the license and the module definition. Every other copied
// directory keeps all of its upstream files except tests and dot files.
var rootFiles = map[string]bool{"LICENSE": true, "go.mod": true, "go.sum": true}

var update = flag.Bool("update", false, "rewrite each patch from the differences between its copy and upstream")

func TestCopiesEqualUpstreamWithTheirPatch(t *testing.T) {
	for _, copied := range copies {
		t.Run(copied.directory, func(t *testing.T) {
			upstream := downloadModule(t, copied.module, copied.version)
			if *update {
				if err := os.WriteFile(copied.patch, diffCopy(t, copied.directory, upstream), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			patch, err := os.ReadFile(copied.patch)
			if err != nil {
				t.Fatal(err)
			}
			changes, err := parsePatch(patch)
			if err != nil {
				t.Fatal(err)
			}
			files := copiedFiles(t, copied.directory)
			for _, relative := range files {
				got, err := os.ReadFile(filepath.Join(copied.directory, filepath.FromSlash(relative)))
				if err != nil {
					t.Fatal(err)
				}
				original, err := os.ReadFile(filepath.Join(upstream, filepath.FromSlash(relative)))
				change, patched := changes[relative]
				switch {
				case patched && change.created:
					if err == nil {
						t.Fatalf("%s: patch creates a file that exists upstream", relative)
					}
					original = nil
				case err != nil:
					t.Fatalf("%s: not an upstream file and not created by the patch", relative)
				}
				want := original
				if patched {
					if want, err = change.apply(original); err != nil {
						t.Fatalf("%s: %v", relative, err)
					}
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s differs from upstream %s %s with %s applied", relative, copied.module, copied.version, copied.patch)
				}
			}
			present := make(map[string]bool, len(files))
			for _, relative := range files {
				present[relative] = true
			}
			for relative := range changes {
				if !present[relative] {
					t.Fatalf("%s: patched file is missing from the copy", relative)
				}
			}
			for _, directory := range copiedDirectories(files) {
				for _, name := range upstreamFiles(t, filepath.Join(upstream, filepath.FromSlash(directory))) {
					relative := pathJoin(directory, name)
					partial := directory == "" && copied.partialRoot && !rootFiles[name]
					if partial || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") {
						if partial && present[relative] {
							t.Fatalf("%s: unexpected upstream root file in the copy", relative)
						}
						continue
					}
					if !present[relative] {
						t.Fatalf("%s: upstream file missing from a copied directory", relative)
					}
				}
			}
			if !present["LICENSE"] {
				t.Fatal("copy has no upstream license")
			}
		})
	}
}

// TestGuestEngineNeverReceivesReplaceAllString checks the one engine method
// the host interface does not provide. In the copied Betterleaks code only
// these files mention ReplaceAllString: the engine wrapper and its interface,
// and three files whose receivers are standard library regexps. A new caller
// fails this test and must be reviewed.
func TestGuestEngineNeverReceivesReplaceAllString(t *testing.T) {
	allowed := map[string]bool{
		"regexp/regexp.go":                  true,
		"regexp/internal/compiledregexp.go": true,
		"internal/exprruntime/celcompat.go": false,
		"report/print_pretty.go":            false,
		"sources/scm/clone.go":              false,
	}
	for _, relative := range copiedFiles(t, "betterleaks") {
		if !strings.HasSuffix(relative, ".go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join("betterleaks", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(content, []byte("ReplaceAllString(")) {
			continue
		}
		engineSide, known := allowed[relative]
		if !known {
			t.Fatalf("%s calls ReplaceAllString", relative)
		}
		if !engineSide && bytes.Contains(content, []byte(`"github.com/betterleaks/betterleaks/regexp"`)) {
			t.Fatalf("%s calls ReplaceAllString and imports the engine package", relative)
		}
	}
}

type moduleInventory struct {
	Modules []struct {
		Module        string `json:"module"`
		Version       string `json:"version"`
		PatchedCopies []struct {
			Path        string `json:"path"`
			Patch       string `json:"patch"`
			PatchSHA256 string `json:"patch_sha256"`
		} `json:"patched_copies"`
	} `json:"modules"`
}

// TestLicenseInventoryRecordsEveryPatchedCopy checks that the scanner's
// license inventory names each copy and the digest of its patch.
func TestLicenseInventoryRecordsEveryPatchedCopy(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "THIRD_PARTY_LICENSES", "secret-scanner", "MODULES.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory moduleInventory
	if err := json.Unmarshal(encoded, &inventory); err != nil {
		t.Fatal(err)
	}
	recorded := 0
	for _, entry := range inventory.Modules {
		for _, record := range entry.PatchedCopies {
			recorded++
			found := false
			for _, copied := range copies {
				if copied.module != entry.Module || copied.version != entry.Version {
					continue
				}
				found = true
				if record.Path != "workers/secret-scanner/third_party/"+copied.directory || record.Patch != "workers/secret-scanner/third_party/"+copied.patch {
					t.Fatalf("%s: inventory names %s and %s", copied.module, record.Path, record.Patch)
				}
				patch, err := os.ReadFile(copied.patch)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(patch)
				if record.PatchSHA256 != hex.EncodeToString(digest[:]) {
					t.Fatalf("%s: inventory patch digest is stale", copied.module)
				}
			}
			if !found {
				t.Fatalf("inventory records a patched copy of %s %s that does not exist", entry.Module, entry.Version)
			}
		}
	}
	if recorded != len(copies) {
		t.Fatalf("inventory records %d patched copies, want %d", recorded, len(copies))
	}
}

// TestScanGuestAndHelperModulesAreInTheLicenseInventory checks that every
// module the scan guest and the scan helper link has a reviewed entry in the
// scanner's license inventory, and that the guest replaces exactly the
// patched copies.
func TestScanGuestAndHelperModulesAreInTheLicenseInventory(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "THIRD_PARTY_LICENSES", "secret-scanner", "MODULES.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory moduleInventory
	if err := json.Unmarshal(encoded, &inventory); err != nil {
		t.Fatal(err)
	}
	reviewed := map[string]bool{}
	for _, entry := range inventory.Modules {
		reviewed[entry.Module+" "+entry.Version] = true
	}
	const format = "{{with .Module}}{{.Path}} {{.Version}}{{with .Replace}} => {{.Path}}{{end}}{{end}}"
	for _, linked := range []struct {
		directory string
		target    []string
		pkg       string
	}{
		{filepath.Join("..", "guest"), []string{"GOOS=wasip1", "GOARCH=wasm"}, "."},
		{"..", nil, "./cmd/open-trestle-scan-helper"},
	} {
		command := exec.Command("go", "list", "-deps", "-f", format, linked.pkg)
		command.Dir = linked.directory
		command.Env = append(append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0"), linked.target...)
		output, err := command.Output()
		if err != nil {
			t.Fatalf("go list in %s: %v", linked.directory, err)
		}
		replaced := map[string]string{}
		for _, line := range strings.Split(string(output), "\n") {
			module, replacement, isReplaced := strings.Cut(line, " => ")
			fields := strings.Fields(module)
			if len(fields) != 2 || strings.HasPrefix(fields[0], "github.com/georgejieh/open-trestle/") {
				continue
			}
			if !reviewed[fields[0]+" "+fields[1]] {
				t.Fatalf("%s links %s, which the license inventory does not review", linked.pkg, module)
			}
			if isReplaced {
				replaced[fields[0]] = replacement
			}
		}
		want := map[string]string{}
		if linked.target != nil {
			for _, copied := range copies {
				want[copied.module] = "../third_party/" + copied.directory
			}
		}
		if !reflect.DeepEqual(replaced, want) {
			t.Fatalf("%s replaces %v, want %v", linked.pkg, replaced, want)
		}
	}
}

// diffCopy returns the patch from the upstream files to the copy in directory:
// one unified diff per copied file that differs, in path order, with a/ and
// b/ labels and three lines of context. A file that is not upstream is
// diffed against an empty file, which makes it a created file. It runs diff,
// so -update needs a diff that writes unified diffs, such as GNU diff.
func diffCopy(t *testing.T, directory, upstream string) []byte {
	t.Helper()
	var patch bytes.Buffer
	for _, relative := range copiedFiles(t, directory) {
		original := filepath.Join(upstream, filepath.FromSlash(relative))
		if _, err := os.Stat(original); errors.Is(err, fs.ErrNotExist) {
			original = os.DevNull
		} else if err != nil {
			t.Fatal(err)
		}
		command := exec.Command("diff", "-u", "--label", "a/"+relative, "--label", "b/"+relative, original, filepath.Join(directory, filepath.FromSlash(relative)))
		output, err := command.Output()
		var exit *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exit) && exit.ExitCode() == 1:
			patch.Write(output)
		default:
			t.Fatalf("diff %s: %v", relative, err)
		}
	}
	return patch.Bytes()
}

func downloadModule(t *testing.T, module, version string) string {
	t.Helper()
	command := exec.Command("go", "mod", "download", "-json", module+"@"+version)
	command.Dir = ".."
	command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go mod download %s@%s: %v", module, version, err)
	}
	var result struct{ Dir, Error string }
	if err := json.Unmarshal(output, &result); err != nil || result.Dir == "" || result.Error != "" {
		t.Fatalf("go mod download %s@%s: %s %v", module, version, result.Error, err)
	}
	return result.Dir
}

func copiedFiles(t *testing.T, directory string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func copiedDirectories(files []string) []string {
	seen := map[string]bool{}
	for _, relative := range files {
		directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(relative)))
		if directory == "." {
			directory = ""
		}
		seen[directory] = true
	}
	directories := make([]string, 0, len(seen))
	for directory := range seen {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	return directories
}

// upstreamFiles lists the regular files directly in directory, or nothing
// when the directory exists only in the copy.
func upstreamFiles(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	return names
}

func pathJoin(directory, name string) string {
	if directory == "" {
		return name
	}
	return directory + "/" + name
}

// fileChange is the part of a unified diff for one file.
type fileChange struct {
	created bool
	hunks   []hunk
}

type hunk struct {
	oldStart, oldCount int
	lines              []string
}

// parsePatch reads a unified diff with a/ and b/ prefixes, as diff -ruN
// writes it. It accepts no fuzz and no files without a final newline.
func parsePatch(patch []byte) (map[string]*fileChange, error) {
	if !bytes.HasSuffix(patch, []byte("\n")) {
		return nil, fmt.Errorf("patch does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(patch), "\n"), "\n")
	changes := map[string]*fileChange{}
	var current *fileChange
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		switch {
		case strings.HasPrefix(line, "--- "):
			if index+1 >= len(lines) || !strings.HasPrefix(lines[index+1], "+++ b/") {
				return nil, fmt.Errorf("line %d: --- without +++ b/", index+1)
			}
			path := strings.TrimPrefix(lines[index+1], "+++ b/")
			if old := strings.TrimPrefix(line, "--- "); old != "a/"+path {
				return nil, fmt.Errorf("line %d: renamed or misnamed file %s", index+1, old)
			}
			if _, duplicate := changes[path]; duplicate {
				return nil, fmt.Errorf("%s appears twice", path)
			}
			current = &fileChange{}
			changes[path] = current
			index++
		case strings.HasPrefix(line, "@@ "):
			if current == nil {
				return nil, fmt.Errorf("line %d: hunk outside a file", index+1)
			}
			oldStart, oldCount, newCount, err := parseHunkHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", index+1, err)
			}
			if oldStart == 0 && oldCount == 0 {
				if len(current.hunks) != 0 {
					return nil, fmt.Errorf("line %d: file creation with several hunks", index+1)
				}
				current.created = true
			}
			body := hunk{oldStart: oldStart, oldCount: oldCount}
			oldSeen, newSeen := 0, 0
			for oldSeen < oldCount || newSeen < newCount {
				index++
				if index >= len(lines) || lines[index] == "" {
					return nil, fmt.Errorf("hunk at line %d is cut short", index+1)
				}
				switch lines[index][0] {
				case ' ':
					oldSeen++
					newSeen++
				case '-':
					oldSeen++
				case '+':
					newSeen++
				default:
					return nil, fmt.Errorf("line %d: unexpected hunk line", index+1)
				}
				body.lines = append(body.lines, lines[index])
			}
			if oldSeen != oldCount || newSeen != newCount {
				return nil, fmt.Errorf("hunk at line %d does not match its header", index+1)
			}
			current.hunks = append(current.hunks, body)
		default:
			return nil, fmt.Errorf("line %d: unexpected patch line", index+1)
		}
	}
	return changes, nil
}

func parseHunkHeader(line string) (int, int, int, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[3] != "@@" || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, 0, fmt.Errorf("bad hunk header %q", line)
	}
	oldStart, oldCount, err := parseRange(fields[1][1:])
	if err != nil {
		return 0, 0, 0, err
	}
	_, newCount, err := parseRange(fields[2][1:])
	return oldStart, oldCount, newCount, err
}

func parseRange(text string) (int, int, error) {
	startText, countText, hasCount := strings.Cut(text, ",")
	start, err := strconv.Atoi(startText)
	if err != nil {
		return 0, 0, err
	}
	count := 1
	if hasCount {
		if count, err = strconv.Atoi(countText); err != nil {
			return 0, 0, err
		}
	}
	return start, count, nil
}

// apply applies the change to original with every context and removed line
// required to match exactly at its stated position.
func (c *fileChange) apply(original []byte) ([]byte, error) {
	var lines []string
	if len(original) > 0 {
		if !bytes.HasSuffix(original, []byte("\n")) {
			return nil, fmt.Errorf("original does not end with a newline")
		}
		lines = strings.SplitAfter(string(original), "\n")
		lines = lines[:len(lines)-1]
	}
	var result strings.Builder
	next := 0
	for _, change := range c.hunks {
		start := change.oldStart - 1
		if change.oldCount == 0 {
			start = change.oldStart
		}
		if start < next || start > len(lines) {
			return nil, fmt.Errorf("hunk at line %d is out of order or out of range", change.oldStart)
		}
		for _, line := range lines[next:start] {
			result.WriteString(line)
		}
		position := start
		for _, line := range change.lines {
			text := line[1:] + "\n"
			switch line[0] {
			case ' ', '-':
				if position >= len(lines) || lines[position] != text {
					return nil, fmt.Errorf("hunk at line %d does not match at line %d", change.oldStart, position+1)
				}
				position++
				if line[0] == ' ' {
					result.WriteString(text)
				}
			case '+':
				result.WriteString(text)
			}
		}
		next = position
	}
	for _, line := range lines[next:] {
		result.WriteString(line)
	}
	return []byte(result.String()), nil
}

func TestPatchApplicationIsStrict(t *testing.T) {
	change, err := parsePatch([]byte("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := change["f"].apply([]byte("one\ntwo\nrest\n")); err != nil || string(got) != "one\nthree\nrest\n" {
		t.Fatalf("apply = %q, %v", got, err)
	}
	for _, original := range []string{"one\nTWO\n", "zero\none\ntwo\n", "one\n"} {
		if _, err := change["f"].apply([]byte(original)); err == nil {
			t.Fatalf("patch applied to %q", original)
		}
	}
	for _, malformed := range []string{
		"--- a/f\n+++ b/g\n@@ -1 +1 @@\n-a\n+b\n",
		"--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n-a\n+b\n",
		"--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b",
		"garbage\n",
	} {
		if _, err := parsePatch([]byte(malformed)); err == nil {
			t.Fatalf("malformed patch accepted: %q", malformed)
		}
	}
}
