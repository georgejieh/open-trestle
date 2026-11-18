// Package repoprofile describes a repository from its snapshot and its
// configuration files: its languages, how it tests itself and which checks
// its own CI enforces. It reads only the files and the snapshot its caller
// passes, as data, and executes nothing.
package repoprofile

import (
	"slices"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/repoindex"
)

// Profile describes a repository.
type Profile struct {
	Languages []LanguageShare `json:"languages"`
	Tests     Tests           `json:"tests"`
	Checks    []Check         `json:"checks"`
}

// LanguageShare is the analysed source and test files of one language.
type LanguageShare struct {
	Language string `json:"language"`
	Files    int    `json:"files"`
	Percent  int    `json:"percent"` // of all analysed files, rounded down
}

// Detect describes a repository. imports returns the import sources of an
// analysed file (nil when none); contents holds the files ConfigPaths named
// that could be read.
func Detect(files []repoindex.FileEntry, imports func(path string) []string, contents map[string][]byte) Profile {
	return Profile{Languages: languageShares(files), Tests: detectTests(files, imports), Checks: detectChecks(contents)}
}

// Classes returns the distinct classes of all the checks found, enforced or
// not, sorted. They are information.
func (p Profile) Classes() []string { return p.classes(false) }

// EnforcedClasses returns the distinct classes of the checks that CI runs on
// changes, sorted.
func (p Profile) EnforcedClasses() []string { return p.classes(true) }

func (p Profile) classes(enforcedOnly bool) []string {
	classes := []string{}
	for _, c := range p.Checks {
		if enforcedOnly && !c.Enforced {
			continue
		}
		if !slices.Contains(classes, c.Class) {
			classes = append(classes, c.Class)
		}
	}
	sort.Strings(classes)
	return classes
}

func languageShares(files []repoindex.FileEntry) []LanguageShare {
	counts := map[string]int{}
	total := 0
	for _, f := range files {
		if f.Status == repoindex.StatusIndexed && f.Language != "" && (f.Role == repoindex.RoleSource || f.Role == repoindex.RoleTest) {
			counts[string(f.Language)]++
			total++
		}
	}
	shares := make([]LanguageShare, 0, len(counts))
	for language, n := range counts {
		shares = append(shares, LanguageShare{Language: language, Files: n, Percent: n * 100 / total})
	}
	slices.SortFunc(shares, func(a, b LanguageShare) int {
		if a.Files != b.Files {
			return b.Files - a.Files
		}
		return strings.Compare(a.Language, b.Language)
	})
	return shares
}
