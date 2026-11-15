package scm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	// maxCommitRangeReads bounds the commit objects one range walk reads.
	maxCommitRangeReads = 1024
	// maxCommitRangeMessageBytes bounds the retained prefix of one message;
	// the original size is kept so a consumer can mark the truncation.
	maxCommitRangeMessageBytes = 4 << 10
)

// ErrCommitRangeUnavailable reports a base or head commit that cannot be read.
var ErrCommitRangeUnavailable = errors.New("commit range unavailable")

// RangeCommit is one commit of a reviewed range: its revision, the retained
// prefix of its exact message bytes (at most 4 KiB) and the message's full size.
type RangeCommit struct {
	Revision     evidence.RevisionIdentity
	Message      []byte
	MessageBytes int
}

// CommitRange is the commits reachable from head and not from base, oldest
// first: the range git log base..head lists, ordered by commit time.
type CommitRange struct {
	Commits []RangeCommit
	// Incomplete is set when the walk stopped before it had separated the
	// whole range from the base's history: it reached its read bound, or a
	// parent object was missing (a shallow checkout). Older range commits may
	// then be missing; every listed commit is still in the range.
	Incomplete bool
}

type commitObjectReader interface {
	ReadCommit(context.Context, evidence.RevisionIdentity) ([]byte, error)
}

// ReadCommitRange walks base..head over verified commit objects. It reads at
// most 1024 commits, follows every parent, and never reads a tree or blob.
func (s *LocalGitObjectStore) ReadCommitRange(ctx context.Context, base, head evidence.RevisionIdentity) (CommitRange, error) {
	if s == nil || s.objectsRoot == nil {
		return CommitRange{}, ErrCommitRangeUnavailable
	}
	return readCommitRange(ctx, s, base, head)
}

const (
	paintHead uint8 = 1 << iota
	paintBase
)

type rangeNode struct {
	revision   evidence.RevisionIdentity
	parents    []evidence.RevisionIdentity
	commitTime int64
	message    []byte
	size       int
	paint      uint8
	popped     bool
	order      int
}

// readCommitRange paints commits reachable from head and from base, newest
// commit time first, as git's merge-base walk does. A commit is in the range
// when only head reaches it. The walk ends when every queued commit is
// reachable from base. Clock skew between commits can, as in git, misplace a
// commit near the boundary; the order is still deterministic.
func readCommitRange(ctx context.Context, reader commitObjectReader, base, head evidence.RevisionIdentity) (CommitRange, error) {
	if ctx == nil || reader == nil {
		return CommitRange{}, ErrCommitRangeUnavailable
	}
	if !canonicalCommitRevision(base) || !canonicalCommitRevision(head) || base.Algorithm() != head.Algorithm() {
		return CommitRange{}, ErrCommitRangeUnavailable
	}
	nodes := map[string]*rangeNode{}
	reads := 0
	incomplete := false
	var queue []*rangeNode
	load := func(revision evidence.RevisionIdentity, required bool) (*rangeNode, error) {
		if node, ok := nodes[revision.Digest()]; ok {
			return node, nil
		}
		if reads >= maxCommitRangeReads {
			incomplete = true
			return nil, nil
		}
		reads++
		content, err := reader.ReadCommit(ctx, revision)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if !required && errors.Is(err, os.ErrNotExist) {
				incomplete = true
				return nil, nil
			}
			return nil, ErrCommitRangeUnavailable
		}
		verification, err := evidence.VerifyGitCommitObject(revision, content)
		if err != nil {
			return nil, ErrCommitRangeUnavailable
		}
		commit, err := evidence.ParseVerifiedGitCommit(revision, verification, content)
		if err != nil {
			return nil, ErrCommitRangeUnavailable
		}
		message := content[len(content)-commit.MessageSizeBytes():]
		retained := append([]byte(nil), message[:min(len(message), maxCommitRangeMessageBytes)]...)
		node := &rangeNode{revision: revision, parents: commit.Parents(), commitTime: committerTime(content[:len(content)-commit.MessageSizeBytes()]), message: retained, size: len(message)}
		nodes[revision.Digest()] = node
		return node, nil
	}
	var paint func(*rangeNode, uint8)
	paint = func(node *rangeNode, flag uint8) {
		if node.paint&flag == flag {
			return
		}
		node.paint |= flag
		if !node.popped {
			queue = append(queue, node)
			return
		}
		// Skew: a commit popped before a newer path from base reached it.
		// Carry the base paint down to the parents already loaded.
		for _, parent := range node.parents {
			if loaded, ok := nodes[parent.Digest()]; ok {
				paint(loaded, flag)
			}
		}
	}
	headNode, err := load(head, true)
	if err != nil || headNode == nil {
		return CommitRange{}, errorOr(err, ErrCommitRangeUnavailable)
	}
	baseNode, err := load(base, true)
	if err != nil || baseNode == nil {
		return CommitRange{}, errorOr(err, ErrCommitRangeUnavailable)
	}
	paint(headNode, paintHead)
	paint(baseNode, paintBase)
	popped := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return CommitRange{}, err
		}
		live := false
		for _, node := range queue {
			if node.paint&paintBase == 0 {
				live = true
				break
			}
		}
		if !live {
			break
		}
		sort.Slice(queue, func(i, j int) bool {
			if queue[i].commitTime != queue[j].commitTime {
				return queue[i].commitTime > queue[j].commitTime
			}
			return queue[i].revision.Digest() < queue[j].revision.Digest()
		})
		node := queue[0]
		queue = queue[1:]
		node.popped = true
		node.order = popped
		popped++
		for _, parent := range node.parents {
			loaded, err := load(parent, false)
			if err != nil {
				return CommitRange{}, err
			}
			if loaded == nil {
				continue
			}
			paint(loaded, node.paint)
		}
	}
	var inRange []*rangeNode
	for _, node := range nodes {
		if node.popped && node.paint == paintHead {
			inRange = append(inRange, node)
		}
	}
	// Newest first is the pop order; the range is listed oldest first.
	sort.Slice(inRange, func(i, j int) bool { return inRange[i].order > inRange[j].order })
	result := CommitRange{Commits: make([]RangeCommit, len(inRange)), Incomplete: incomplete}
	for index, node := range inRange {
		result.Commits[index] = RangeCommit{Revision: node.revision, Message: node.message, MessageBytes: node.size}
	}
	return result, nil
}

// committerTime reads the Unix time of the committer header, or 0.
func committerTime(header []byte) int64 {
	for _, line := range bytes.Split(header, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("committer ")) {
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) < 3 {
			return 0
		}
		value, err := strconv.ParseInt(string(fields[len(fields)-2]), 10, 64)
		if err != nil {
			return 0
		}
		return value
	}
	return 0
}

func canonicalCommitRevision(revision evidence.RevisionIdentity) bool {
	canonical, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	return err == nil && revision.Kind() == evidence.RevisionKindGitCommit && revisionIdentityValuesEqual(revision, canonical)
}

func errorOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func (r CommitRange) String() string { return fmt.Sprintf("commit range (%d commits)", len(r.Commits)) }
