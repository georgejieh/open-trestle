package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const (
	physicalPacketEntryLimit         = 20001
	physicalPacketNameLimit          = 160
	physicalPacketExpectationLimit   = 1024
	physicalCombinedExpectationLimit = 4096
	physicalPacketFileLimit          = 22 << 20 // Keep aligned with artifact.maxEncodedArtifactBytes.
	physicalPacketTotalLimit         = 64 << 20
)

var errPhysicalPacketObservationUncertain = errors.New("historical packet physical observation uncertain")

type physicalPacketRole uint8

const (
	physicalRolePacket physicalPacketRole = iota
	physicalRoleRequest
	physicalRoleReceipt
	physicalRoleInput
)

type physicalPacketExpectation struct {
	scope      audit.ReviewScope
	descriptor controlplane.ContextPacketDescriptor
	role       physicalPacketRole
	input      controlplane.ContextInputArtifactDescriptor
}
type physicalPacketObservationKind uint8

const (
	physicalPacketIntact physicalPacketObservationKind = iota + 1
	physicalPacketMissing
	physicalPacketMismatch
)

type physicalPacketObservation struct {
	expectation physicalPacketExpectation
	kind        physicalPacketObservationKind
}
type physicalPacketLeaf struct {
	info   os.FileInfo
	raw    []byte
	digest [sha256.Size]byte
}

func physicalPacketDigest(s string) bool {
	if len(s) != 64 || s == strings.Repeat("0", 64) {
		return false
	}
	for _, b := range []byte(s) {
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return false
		}
	}
	return true
}
func physicalPacketName(name string) bool {
	if len(name) != 143 || !strings.HasSuffix(name, ".artifact.json") || name[64] != '-' {
		return false
	}
	return physicalPacketDigest(name[:64]) && physicalPacketDigest(name[65:129])
}
func physicalPacketInfo(info os.FileInfo) bool {
	return info != nil && info.Mode() == 0600 && info.Size() > 0 && info.Size() <= physicalPacketFileLimit &&
		fileauthority.TrustedOwner(info) && ownerConstructorLockInfo(info)
}
func physicalPacketSame(a, b os.FileInfo) bool {
	return physicalPacketInfo(a) && physicalPacketInfo(b) && a.Mode() == b.Mode() && a.Size() == b.Size() && physicalPacketInodeOwnerSame(a, b)
}
func physicalPacketRootSame(a, b os.FileInfo) bool {
	return ownerDirectoryInfo(a) && ownerDirectoryInfo(b) && a.Mode() == b.Mode() && a.Size() == b.Size() && physicalPacketInodeOwnerSame(a, b)
}
func physicalPacketLockSame(a, b os.FileInfo) bool {
	return ownerConstructorLockInfo(a) && ownerConstructorLockInfo(b) && a.Mode() == b.Mode() && a.Size() == b.Size() && physicalPacketInodeOwnerSame(a, b)
}
func physicalPacketScan(ctx context.Context, root *os.Root, closeFile func(*os.File) error) (map[string]os.FileInfo, os.FileInfo, error) {
	if ctx.Err() != nil {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	before, err := root.Stat(".")
	if err != nil || !ownerDirectoryInfo(before) {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	opened, statErr := dir.Stat()
	entries, readErr := dir.ReadDir(physicalPacketEntryLimit + 1)
	closeErr := closeFile(dir)
	if statErr != nil || !physicalPacketRootSame(before, opened) || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > physicalPacketEntryLimit {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	found := make(map[string]os.FileInfo, len(entries))
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, nil, errPhysicalPacketObservationUncertain
		}
		name := entry.Name()
		if len(name) == 0 || len(name) > physicalPacketNameLimit || name != ".artifact-writer.lock" && !physicalPacketName(name) {
			return nil, nil, errPhysicalPacketObservationUncertain
		}
		if _, duplicate := found[name]; duplicate {
			return nil, nil, errPhysicalPacketObservationUncertain
		}
		info, statErr := root.Lstat(name)
		if statErr != nil || name == ".artifact-writer.lock" && !ownerConstructorLockInfo(info) || name != ".artifact-writer.lock" && !physicalPacketInfo(info) {
			return nil, nil, errPhysicalPacketObservationUncertain
		}
		found[name] = info
	}
	if found[".artifact-writer.lock"] == nil {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	after, err := root.Stat(".")
	if err != nil || !ownerDirectoryInfo(after) || !physicalPacketRootSame(before, after) || ctx.Err() != nil {
		return nil, nil, errPhysicalPacketObservationUncertain
	}
	return found, before, nil
}
func physicalPacketScanEqual(a, b map[string]os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for name, info := range a {
		current := b[name]
		if name == ".artifact-writer.lock" {
			if !physicalPacketLockSame(info, current) {
				return false
			}
		} else if !physicalPacketSame(info, current) {
			return false
		}
	}
	return true
}

// This borrowed root is only a physical witness. Only a caller's live owned-root
// lease and its postchecks can supply provenance; this function grants none.
func observeBorrowedHistoricalPacketFiles(ctx context.Context, borrowed *os.Root, expected []physicalPacketExpectation, after func([]physicalPacketObservation) error) error {
	if len(expected) > physicalPacketExpectationLimit {
		return errPhysicalPacketObservationUncertain
	}
	return observeBorrowedHistoricalFilesWithClose(ctx, borrowed, expected, after, (*os.File).Close)
}

// The per-call closer supports checked-close fault injection without global hooks.
// A supplied closer must close its file even when returning an injected error.
func observeBorrowedHistoricalPacketFilesWithClose(ctx context.Context, borrowed *os.Root, expected []physicalPacketExpectation, after func([]physicalPacketObservation) error, closeFile func(*os.File) error) error {
	if len(expected) > physicalPacketExpectationLimit {
		return errPhysicalPacketObservationUncertain
	}
	return observeBorrowedHistoricalFilesWithClose(ctx, borrowed, expected, after, closeFile)
}

func observeBorrowedHistoricalFilesWithClose(ctx context.Context, borrowed *os.Root, expected []physicalPacketExpectation, after func([]physicalPacketObservation) error, closeFile func(*os.File) error) error {
	if runtime.GOOS != "linux" || ctx == nil || borrowed == nil || after == nil || closeFile == nil || ctx.Err() != nil || len(expected) > physicalCombinedExpectationLimit {
		return errPhysicalPacketObservationUncertain
	}
	names := make([]string, len(expected))
	unique := make(map[string]physicalPacketExpectation, len(expected))
	for i, e := range expected {
		if e.scope.Validate() != nil || !physicalExpectationValid(e) {
			return errPhysicalPacketObservationUncertain
		}
		identity := e.descriptor.ArtifactIdentity
		if e.role != physicalRolePacket {
			identity = e.input.ArtifactIdentity
		}
		name := e.scope.Identity() + "-" + identity + ".artifact.json"
		if prior, ok := unique[name]; ok && !reflect.DeepEqual(prior, e) {
			return errPhysicalPacketObservationUncertain
		}
		unique[name] = e
		names[i] = name
	}
	if len(unique) > physicalCombinedExpectationLimit {
		return errPhysicalPacketObservationUncertain
	}
	first, rootInfo, scanErr := physicalPacketScan(ctx, borrowed, closeFile)
	if scanErr != nil {
		return scanErr
	}
	// Budget the entire set before allocating even one file buffer.
	total := int64(0)
	for name := range unique {
		if info := first[name]; info != nil {
			total += info.Size()
			if total > physicalPacketTotalLimit {
				return errPhysicalPacketObservationUncertain
			}
		}
	}
	leaves := make(map[string]*physicalPacketLeaf, len(unique))
	defer func() {
		for _, leaf := range leaves {
			if leaf != nil {
				leaf.raw = nil
			}
		}
	}()
	kinds := make(map[string]physicalPacketObservationKind, len(unique))
	for name, e := range unique {
		if ctx.Err() != nil {
			return errPhysicalPacketObservationUncertain
		}
		info := first[name]
		if info == nil {
			_, statErr := borrowed.Lstat(name)
			if !errors.Is(statErr, os.ErrNotExist) {
				return errPhysicalPacketObservationUncertain
			}
			kinds[name] = physicalPacketMissing
			continue
		}
		raw, readErr := physicalPacketRead(ctx, borrowed, name, info, closeFile)
		if readErr != nil {
			return readErr
		}
		leaves[name] = &physicalPacketLeaf{info: info, raw: raw, digest: sha256.Sum256(raw)}
		kinds[name] = physicalPacketMismatch
		parsed, parseErr := artifact.Parse(raw)
		if parseErr != nil {
			continue
		}
		canonical, encodeErr := artifact.Encode(parsed)
		valid := encodeErr == nil && bytes.Equal(canonical, raw) && physicalExpectationMatches(parsed, e)
		canonical = nil
		if valid {
			kinds[name] = physicalPacketIntact
		}
	}
	observations := make([]physicalPacketObservation, len(expected))
	for i, e := range expected {
		observations[i] = physicalPacketObservation{expectation: e, kind: kinds[names[i]]}
	}
	callbackErr := after(observations)
	// Every present leaf is reread even if the callback fails or an earlier leaf drifts.
	var structural error
	for name := range unique {
		leaf := leaves[name]
		if leaf == nil {
			_, statErr := borrowed.Lstat(name)
			if !errors.Is(statErr, os.ErrNotExist) {
				structural = errors.Join(structural, errPhysicalPacketObservationUncertain)
			}
			continue
		}
		raw, readErr := physicalPacketRead(ctx, borrowed, name, leaf.info, closeFile)
		if readErr != nil || !bytes.Equal(raw, leaf.raw) || sha256.Sum256(raw) != leaf.digest {
			structural = errors.Join(structural, errPhysicalPacketObservationUncertain)
		}
		raw = nil
		leaf.raw = nil
	}
	second, secondRoot, scanErr := physicalPacketScan(ctx, borrowed, closeFile)
	if scanErr != nil || !physicalPacketRootSame(rootInfo, secondRoot) || !physicalPacketScanEqual(first, second) || ctx.Err() != nil {
		structural = errors.Join(structural, errPhysicalPacketObservationUncertain)
	}
	return errors.Join(callbackErr, structural)
}
func physicalPacketRead(ctx context.Context, root *os.Root, name string, baseline os.FileInfo, closeFile func(*os.File) error) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errPhysicalPacketObservationUncertain
	}
	before, err := root.Lstat(name)
	if err != nil || !physicalPacketSame(baseline, before) {
		return nil, errPhysicalPacketObservationUncertain
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errPhysicalPacketObservationUncertain
	}
	var raw []byte
	opened, statErr := file.Stat()
	if statErr == nil && physicalPacketSame(before, opened) && opened.Size() <= physicalPacketFileLimit && ctx.Err() == nil {
		raw = make([]byte, int(opened.Size()))
		_, err = io.ReadFull(file, raw)
		var extra [1]byte
		n, eofErr := file.Read(extra[:])
		end, endErr := file.Stat()
		if err != nil || n != 0 || !errors.Is(eofErr, io.EOF) || endErr != nil || !physicalPacketSame(before, end) || ctx.Err() != nil {
			statErr = errPhysicalPacketObservationUncertain
		}
	} else {
		statErr = errPhysicalPacketObservationUncertain
	}
	closeErr := closeFile(file)
	after, afterErr := root.Lstat(name)
	if statErr != nil || closeErr != nil || afterErr != nil || !physicalPacketSame(before, after) || ctx.Err() != nil {
		return nil, errPhysicalPacketObservationUncertain
	}
	return raw, nil
}
func physicalPacketMatches(a artifact.Artifact, e physicalPacketExpectation) bool {
	d := e.descriptor
	return a.Scope().Identity() == e.scope.Identity() && a.Identity() == d.ArtifactIdentity && a.PayloadDigest() == d.PayloadDigest &&
		a.Kind() == artifact.KindContextPacket && a.MediaType() == "application/json" && a.Origin() == artifact.OriginHost &&
		a.Protection() == artifact.ProtectionProcessPrivate && d.Protection == "process_private" && a.Classification().String() == d.Classification &&
		reflect.DeepEqual(a.Provenance(), d.Provenance) && a.CreatedAt().UnixMilli() == d.CreatedAtMilliseconds && a.ExpiresAt().UnixMilli() == d.ExpiresAtMilliseconds
}

// Match the descriptor's content-addressed identity before deriving any filename.
// This repeats the private controlplane preimage without treating it as authority.
func physicalPacketDescriptorValid(e physicalPacketExpectation) bool {
	d := e.descriptor
	if !physicalPacketDigest(e.scope.Identity()) || !physicalPacketDigest(d.ArtifactIdentity) || !physicalPacketDigest(d.PayloadDigest) ||
		!physicalPacketDigest(d.LeaseIdentity) || !physicalPacketDigest(d.LeaseEventIdentity) || !physicalPacketDigest(d.SourceRootIdentity) || !physicalPacketDigest(d.SnapshotIdentity) ||
		d.Protection != "process_private" || d.CreatedAtMilliseconds <= 0 || d.ExpiresAtMilliseconds <= d.CreatedAtMilliseconds ||
		d.ExpiresAtMilliseconds > 253402300799999 || d.ExpiresAtMilliseconds-d.CreatedAtMilliseconds > int64(10*365*24*60*60*1000) ||
		len(d.Provenance) == 0 || len(d.Provenance) > 32 || len(d.DependencyIdentities) == 0 || len(d.DependencyIdentities) > 32 {
		return false
	}
	switch d.Classification {
	case "public", "internal", "confidential", "restricted":
	default:
		return false
	}
	for i, p := range d.Provenance {
		if !physicalPacketDigest(p) || i > 0 && d.Provenance[i-1] >= p {
			return false
		}
	}
	for i, p := range d.DependencyIdentities {
		if !physicalPacketDigest(p) || i > 0 && d.DependencyIdentities[i-1] >= p || !slices.Contains(d.Provenance, p) {
			return false
		}
	}
	preimage := struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{e.scope.Identity(), "context_packet", "application/json", d.Classification, "host", d.Protection, d.Provenance, d.PayloadDigest, d.CreatedAtMilliseconds, d.ExpiresAtMilliseconds}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	return d.ArtifactIdentity == hex.EncodeToString(digest[:])
}

func physicalInputKind(role physicalPacketRole) artifact.Kind {
	switch role {
	case physicalRoleRequest:
		return artifact.KindSanitizedModelRequest
	case physicalRoleReceipt:
		return artifact.KindSanitizedEgressReceipt
	case physicalRoleInput:
		return artifact.KindTaskInput
	default:
		return 0
	}
}

func physicalExpectationValid(e physicalPacketExpectation) bool {
	if e.role == physicalRolePacket {
		return reflect.DeepEqual(e.input, controlplane.ContextInputArtifactDescriptor{}) && physicalPacketDescriptorValid(e)
	}
	kind := physicalInputKind(e.role)
	d := e.input
	if kind == 0 || !reflect.DeepEqual(e.descriptor, controlplane.ContextPacketDescriptor{}) ||
		!physicalPacketDigest(e.scope.Identity()) || !physicalPacketDigest(d.ArtifactIdentity) || !physicalPacketDigest(d.PayloadDigest) ||
		d.Protection != "process_private" || d.CreatedAtMilliseconds <= 0 || d.ExpiresAtMilliseconds <= d.CreatedAtMilliseconds ||
		d.ExpiresAtMilliseconds > 253402300799999 || d.ExpiresAtMilliseconds-d.CreatedAtMilliseconds > int64(10*365*24*60*60*1000) ||
		len(d.Provenance) == 0 || len(d.Provenance) > 32 {
		return false
	}
	switch d.Classification {
	case "public", "internal", "confidential", "restricted":
	default:
		return false
	}
	for i, parent := range d.Provenance {
		if !physicalPacketDigest(parent) || i > 0 && d.Provenance[i-1] >= parent {
			return false
		}
	}
	preimage := struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{e.scope.Identity(), kind.String(), "application/json", d.Classification, "host", d.Protection, d.Provenance, d.PayloadDigest, d.CreatedAtMilliseconds, d.ExpiresAtMilliseconds}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	return d.ArtifactIdentity == hex.EncodeToString(digest[:])
}

func physicalExpectationMatches(a artifact.Artifact, e physicalPacketExpectation) bool {
	if e.role == physicalRolePacket {
		return physicalPacketMatches(a, e)
	}
	d := e.input
	return a.Scope().Identity() == e.scope.Identity() && a.Identity() == d.ArtifactIdentity && a.PayloadDigest() == d.PayloadDigest &&
		a.Kind() == physicalInputKind(e.role) && a.MediaType() == "application/json" && a.Origin() == artifact.OriginHost &&
		a.Protection() == artifact.ProtectionProcessPrivate && a.Classification().String() == d.Classification &&
		reflect.DeepEqual(a.Provenance(), d.Provenance) && a.CreatedAt().UnixMilli() == d.CreatedAtMilliseconds && a.ExpiresAt().UnixMilli() == d.ExpiresAtMilliseconds
}
