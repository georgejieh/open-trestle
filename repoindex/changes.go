package repoindex

import (
	"math"
	"path"
	"slices"
	"strings"
)

// Approximations of changed lines, recorded in Change.Approximation.
const (
	// ApproximationDiffBudget: the diff budget was spent before this file.
	ApproximationDiffBudget = "diff_budget"
	// ApproximationDiffUnavailable: the file's blobs could not be read or
	// diffed, as for a file past the diff's own limits.
	ApproximationDiffUnavailable = "diff_unavailable"
	// ApproximationUnmatchedMove: the file was deleted while another file
	// was added, and no rule matched them as a move, so a move and edit is
	// treated as a delete and an add.
	ApproximationUnmatchedMove = "unmatched_move"
)

// WholeFile is the line range of a change whose lines are not known.
var WholeFile = []LineRange{{Start: 1, End: math.MaxInt32}}

// DiffPair is a change whose lines a diff of its base and head blobs
// should narrow: Changes[Index] in a ChangedFiles result.
type DiffPair struct {
	Index      int
	Base, Head string
}

// ChangedFiles compares two snapshots' files. A file whose path and blob
// are unchanged is not a change. Deleted and added files are matched as
// moves one to one, in path order: first by equal blob, a move without an
// edit, which is not a change; then by equal base name when exactly one
// deleted and one added file have it, a move with an edit. Every change
// covers its whole file until a diff of its pair narrows it. A deletion
// left unmatched while an addition is also unmatched may be a move, and is
// marked so.
func ChangedFiles(base, head []FileEntry) ([]Change, []DiffPair) {
	changes, pairs, _ := compareFiles(base, head)
	return changes, pairs
}

// UneditedMoves returns a change for each file ChangedFiles matched as a
// move without an edit: the file removed from its base path. Such a move
// changes nothing in the file, but can break the files that imported it or
// move it to another package.
func UneditedMoves(base, head []FileEntry) []Change {
	_, _, moves := compareFiles(base, head)
	return moves
}

func compareFiles(base, head []FileEntry) (changes []Change, pairs []DiffPair, moves []Change) {
	baseByPath, headByPath := map[string]FileEntry{}, map[string]FileEntry{}
	for _, f := range base {
		baseByPath[f.Path] = f
	}
	for _, f := range head {
		headByPath[f.Path] = f
	}
	changes, pairs, moves = []Change{}, []DiffPair{}, []Change{}
	modify := func(b, h FileEntry) {
		pairs = append(pairs, DiffPair{Index: len(changes), Base: b.Object, Head: h.Object})
		changes = append(changes, Change{Path: h.Path, BasePath: b.Path, HeadLines: WholeFile, BaseLines: WholeFile})
	}
	deleted, added := []FileEntry{}, []FileEntry{}
	for _, f := range head {
		if b, existed := baseByPath[f.Path]; !existed {
			added = append(added, f)
		} else if b.Object != f.Object {
			modify(b, f)
		}
	}
	for _, f := range base {
		if _, kept := headByPath[f.Path]; !kept {
			deleted = append(deleted, f)
		}
	}
	deleted, added = matchMoves(deleted, added, func(f FileEntry) string { return f.Object }, false, func(d, _ FileEntry) {
		moves = append(moves, Change{BasePath: d.Path, BaseLines: WholeFile})
	})
	deleted, added = matchMoves(deleted, added, func(f FileEntry) string { return path.Base(f.Path) }, true, modify)
	for _, a := range added {
		changes = append(changes, Change{Path: a.Path, HeadLines: WholeFile})
	}
	for _, d := range deleted {
		change := Change{BasePath: d.Path, BaseLines: WholeFile}
		if len(added) > 0 {
			change.Approximation = ApproximationUnmatchedMove
		}
		changes = append(changes, change)
	}
	return changes, pairs, moves
}

// matchMoves pairs deleted and added files with the same key, one to one in
// path order, or with unique only when exactly one of each has the key. It
// calls pair for each pair and returns the files left.
func matchMoves(deleted, added []FileEntry, key func(FileEntry) string, unique bool, pair func(d, a FileEntry)) ([]FileEntry, []FileEntry) {
	byKey, deletedPerKey := map[string][]int{}, map[string]int{}
	for i, a := range added {
		byKey[key(a)] = append(byKey[key(a)], i)
	}
	for _, d := range deleted {
		deletedPerKey[key(d)]++
	}
	used := make([]bool, len(added))
	left := []FileEntry{}
	for _, d := range deleted {
		k := key(d)
		queue := byKey[k]
		if len(queue) == 0 || unique && (len(queue) != 1 || deletedPerKey[k] != 1) {
			left = append(left, d)
			continue
		}
		used[queue[0]], byKey[k] = true, queue[1:]
		pair(d, added[queue[0]])
	}
	rest := []FileEntry{}
	for i, a := range added {
		if !used[i] {
			rest = append(rest, a)
		}
	}
	return left, rest
}

// SortChanges orders changes by path, for output.
func SortChanges(changes []Change) {
	slices.SortStableFunc(changes, func(a, b Change) int {
		return strings.Compare(a.Path+"\x00"+a.BasePath, b.Path+"\x00"+b.BasePath)
	})
}
