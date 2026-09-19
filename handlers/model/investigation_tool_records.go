package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

const (
	toolRecordPayloadLimit         = 64 << 10
	toolRecordHeadLimit            = 16 << 20
	toolRecordContextLimit         = 8 << 20
	toolRecordTurnLimit            = 16 << 20
	toolRecordSourceLimit          = 128
	toolRecordSuppliedPayloadLimit = 32 << 20
)

var errToolRecord = errors.New("investigation tool witness unavailable or inconsistent")

// InvestigationToolEvidence contains host-held immutable data, not issuer authority.
type InvestigationToolEvidence struct {
	Policy          review.InvestigationPolicy
	ReaderLimits    source.SnapshotReadLimits
	Context         review.InvestigationGenerationContext
	ContextArtifact artifact.Artifact
	HeadArtifact    artifact.Artifact
	TurnArtifact    artifact.Artifact
	SourceArtifacts []artifact.Artifact
}

// InvestigationToolExpectations must be pinned by the host before candidate readback.
type InvestigationToolExpectations struct {
	Scope                                                            audit.ReviewScope
	Deadline                                                         time.Time
	SessionIdentity, PolicyIdentity, OwnerIdentity                   string
	ContextArtifactIdentity, ContextIdentity, RequestIdentity        string
	HeadArtifactIdentity, HeadSnapshotIdentity, HeadManifestIdentity string
	TurnArtifactIdentity, TurnIdentity, PreviousTurnIdentity         string
	OutcomeIdentity, ResponseIdentity                                string
	SourceArtifactIdentities                                         []string
	OperationIdentity, InvocationIdentity, ResultArtifactIdentity    string
}

type toolRecordFile struct {
	Digest   string `json:"digest"`
	Artifact string `json:"file_artifact_identity"`
	Path     string `json:"path" limit:"4096"`
	Ref      string `json:"ref"`
	Size     int    `json:"size_bytes"`
}

type toolRecordSource struct {
	Binding      string `json:"binding_identity"`
	Content      string `json:"content" limit:"65536"`
	End          int    `json:"end_line"`
	FileRef      string `json:"file_ref"`
	Path         string `json:"path" limit:"4096"`
	FileDigest   string `json:"repository_file_digest"`
	FileIdentity string `json:"repository_file_identity"`
	SliceBytes   int    `json:"slice_bytes"`
	SliceDigest  string `json:"slice_digest"`
	Start        int    `json:"start_line"`
}

type toolRecordSourceReference struct {
	value artifact.Artifact
	file  source.FileReference
}

type toolRecordTurnHeader struct {
	Owner    string `json:"owner_identity"`
	Session  string `json:"session_identity"`
	Policy   string `json:"policy_identity"`
	Scope    string `json:"scope_identity"`
	Ordinal  uint8  `json:"ordinal"`
	Role     string `json:"role"`
	Deadline int64  `json:"deadline_milliseconds"`
	Finished int64  `json:"finished_milliseconds"`
}

type toolRecordContextHeader struct {
	Version int    `json:"schema_version"`
	Scope   string `json:"review_scope_identity"`
	Task    string `json:"task"`
	Tools   string `json:"tool_calls"`
	Sources []struct {
		Path string `json:"path"`
	} `json:"sources"`
	Investigation struct {
		Session      string `json:"session_identity"`
		Policy       string `json:"policy_identity"`
		Mode         string `json:"routing_mode"`
		Pin          string `json:"generation_route_record_identity"`
		HeadArtifact string `json:"snapshot_artifact_identity"`
		Head         string `json:"snapshot_identity"`
		Manifest     string `json:"manifest_identity"`
		SnapshotRef  string `json:"snapshot_ref"`
		Turn         uint8  `json:"turn"`
		ToolCalls    uint8  `json:"tool_calls_used"`
	} `json:"investigation"`
}

// InvestigationToolOperation is a replay key and retained data, never an admission.
type InvestigationToolOperation struct {
	identity                                    string
	expected                                    InvestigationToolExpectations
	policy                                      review.InvestigationPolicy
	limits                                      source.SnapshotReadLimits
	proposal                                    review.InvestigationProposal
	turn                                        gateway.InvestigationTurnRecord
	header                                      toolRecordTurnHeader
	context                                     review.InvestigationGenerationContext
	contextArtifact, headArtifact, turnArtifact artifact.Artifact
	sources                                     []toolRecordSourceReference
	files                                       []toolRecordFile
	fileRefs                                    []string
	headCount                                   int
	created, expires                            time.Time
}

func (o InvestigationToolOperation) Identity() string    { return o.identity }
func (o InvestigationToolOperation) Tool() string        { return o.proposal.Tool() }
func (o InvestigationToolOperation) SnapshotRef() string { return o.proposal.SnapshotRef() }
func (o InvestigationToolOperation) FileRef() string     { return o.proposal.FileRef() }
func (o InvestigationToolOperation) StartLine() int      { return o.proposal.StartLine() }
func (o InvestigationToolOperation) EndLine() int        { return o.proposal.EndLine() }
func (o InvestigationToolOperation) FileRefs() []string  { return append([]string{}, o.fileRefs...) }
func (o InvestigationToolOperation) Literal() string     { return o.proposal.Literal() }
func (o InvestigationToolOperation) String() string      { return "investigation tool operation" }
func (o InvestigationToolOperation) GoString() string {
	return "model.InvestigationToolOperation{<redacted>}"
}
func (o InvestigationToolOperation) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation tool operation"))
}

func toolRecordDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func toolRecordIdentity(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return toolRecordDigest(encoded)
}
func toolRecordValidID(value string) bool {
	if len(value) != 64 || strings.Trim(value, "0") == "" {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'f' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
func toolRecordSortedIDs(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	for i, value := range values {
		if !toolRecordValidID(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}
func toolRecordLimits(l source.SnapshotReadLimits, p review.InvestigationPolicy) bool {
	return l.MaxFiles > 0 && uint64(l.MaxFiles) <= p.MaxFiles() && l.MaxFiles <= 64 &&
		l.MaxLines > 0 && uint64(l.MaxLines) <= p.MaxLinesPerRead() && l.MaxLines <= 256 &&
		l.MaxResultBytes > 0 && uint64(l.MaxResultBytes) <= p.MaxResultBytes() && l.MaxResultBytes <= toolRecordPayloadLimit &&
		l.MaxMatches > 0 && uint64(l.MaxMatches) <= p.MaxMatches() && l.MaxMatches <= 64 &&
		l.MaxScannedBytes > 0 && l.MaxScannedBytes <= p.MaxScannedBytes() && l.MaxScannedBytes <= 16<<20
}
func toolRecordCurrent(value artifact.Artifact, expected string, scope audit.ReviewScope, kind artifact.Kind, origin artifact.Origin, maximum int, at time.Time) bool {
	return toolRecordValidID(expected) && value.Identity() == expected && value.Scope() == scope && value.Kind() == kind &&
		value.Origin() == origin && value.MediaType() == "application/json" && value.Classification().String() != "" &&
		value.Protection() == artifact.ProtectionProcessPrivate && value.PayloadSizeBytes() > 0 && value.PayloadSizeBytes() <= maximum &&
		value.CreatedAt().UnixMilli() > 0 && !at.Before(value.CreatedAt()) && at.Before(value.ExpiresAt())
}
func toolRecordBounds(e InvestigationToolExpectations, at time.Time) bool {
	if e.Scope.Validate() != nil || at.UnixMilli() <= 0 || e.Deadline.UnixMilli() <= 0 || e.Deadline.UnixMilli() > 253402300799999 || !at.Before(e.Deadline) || !toolRecordSortedIDs(e.SourceArtifactIdentities, toolRecordSourceLimit) {
		return false
	}
	for _, id := range []string{e.SessionIdentity, e.PolicyIdentity, e.OwnerIdentity, e.ContextArtifactIdentity, e.ContextIdentity, e.RequestIdentity, e.HeadArtifactIdentity, e.HeadSnapshotIdentity, e.HeadManifestIdentity, e.TurnArtifactIdentity, e.TurnIdentity, e.OutcomeIdentity, e.ResponseIdentity} {
		if !toolRecordValidID(id) {
			return false
		}
	}
	return e.PreviousTurnIdentity == "" || toolRecordValidID(e.PreviousTurnIdentity)
}
func toolRecordFileValue(value source.SnapshotFileRef) toolRecordFile {
	return toolRecordFile{Digest: value.Digest(), Artifact: value.ArtifactIdentity(), Path: value.Path(), Ref: value.Ref(), Size: value.SizeBytes()}
}
func (o InvestigationToolOperation) file(ref string) (toolRecordFile, bool) {
	for _, file := range o.files {
		if file.Ref == ref {
			return file, true
		}
	}
	return toolRecordFile{}, false
}
func (o InvestigationToolOperation) hasSource(id string) bool {
	for _, s := range o.sources {
		if s.value.Identity() == id {
			return true
		}
	}
	return false
}
func (o InvestigationToolOperation) selected() []toolRecordFile {
	switch o.Tool() {
	case "snapshot.list":
		return append([]toolRecordFile(nil), o.files...)
	case "snapshot.read":
		value, ok := o.file(o.FileRef())
		if ok {
			return []toolRecordFile{value}
		}
	case "snapshot.search":
		result := make([]toolRecordFile, 0, len(o.fileRefs))
		for _, ref := range o.fileRefs {
			file, ok := o.file(ref)
			if !ok {
				return nil
			}
			result = append(result, file)
		}
		return result
	}
	return nil
}
func (o InvestigationToolOperation) operationIdentity() string {
	e := o.expected
	return toolRecordIdentity([]any{"open-trestle/investigation-tool-operation", 1, e.Scope.Identity(), e.SessionIdentity, e.PolicyIdentity, e.HeadArtifactIdentity, e.HeadSnapshotIdentity, e.HeadManifestIdentity, o.SnapshotRef(), o.Tool(), o.FileRef(), o.StartLine(), o.EndLine(), o.FileRefs(), o.Literal()})
}
func (o InvestigationToolOperation) Validate() error {
	if !toolRecordValidID(o.identity) || o.policy.Validate() != nil || o.proposal.Validate() != nil || !toolRecordLimits(o.limits, o.policy) || o.expected.PolicyIdentity != o.policy.Identity() || o.expected.Scope.Validate() != nil || len(o.files) > 64 || len(o.sources) > toolRecordSourceLimit || o.headCount < len(o.files) || o.headCount > 65536 || !o.created.Before(o.expires) || o.header.Role != "generation" || o.turn.Identity() != o.expected.TurnIdentity || o.context.Identity() != o.expected.ContextIdentity || o.identity != o.operationIdentity() {
		return errToolRecord
	}
	if !toolRecordBounds(o.expected, o.created) || o.expected.OperationIdentity != "" || o.expected.InvocationIdentity != "" || o.expected.ResultArtifactIdentity != "" || o.header.Owner != o.expected.OwnerIdentity || o.header.Session != o.expected.SessionIdentity || o.header.Policy != o.expected.PolicyIdentity || o.header.Scope != o.expected.Scope.Identity() || o.header.Deadline != o.expected.Deadline.UnixMilli() || o.contextArtifact.Identity() != o.expected.ContextArtifactIdentity || o.headArtifact.Identity() != o.expected.HeadArtifactIdentity || o.turnArtifact.Identity() != o.expected.TurnArtifactIdentity || o.created.UnixMilli() < o.header.Finished {
		return errToolRecord
	}
	selected := o.selected()
	if o.Tool() != "snapshot.list" && len(selected) == 0 {
		return errToolRecord
	}
	var scanned uint64
	for _, file := range selected {
		if !o.hasSource(file.Artifact) || file.Size < 0 {
			return errToolRecord
		}
		if o.Tool() != "snapshot.list" {
			scanned += uint64(file.Size)
		}
	}
	if scanned > o.limits.MaxScannedBytes || o.Tool() == "snapshot.read" && (o.EndLine()-o.StartLine()+1 > o.limits.MaxLines) {
		return errToolRecord
	}
	return nil
}

// NewInvestigationToolOperation validates held metadata and derives only the owned proposal.
func NewInvestigationToolOperation(b InvestigationToolEvidence, e InvestigationToolExpectations, at time.Time) (InvestigationToolOperation, error) {
	if e.OperationIdentity != "" || e.InvocationIdentity != "" || e.ResultArtifactIdentity != "" || !toolRecordBounds(e, at) || b.Policy.Validate() != nil || b.Policy.Identity() != e.PolicyIdentity || !toolRecordLimits(b.ReaderLimits, b.Policy) || len(b.SourceArtifacts) > toolRecordSourceLimit || len(b.SourceArtifacts) != len(e.SourceArtifactIdentities) {
		return InvestigationToolOperation{}, errToolRecord
	}
	if !toolRecordCurrent(b.HeadArtifact, e.HeadArtifactIdentity, e.Scope, artifact.KindSourceSnapshot, artifact.OriginRepository, toolRecordHeadLimit, at) || !toolRecordCurrent(b.ContextArtifact, e.ContextArtifactIdentity, e.Scope, artifact.KindContextPacket, artifact.OriginHost, toolRecordContextLimit, at) || !toolRecordCurrent(b.TurnArtifact, e.TurnArtifactIdentity, e.Scope, artifact.KindInvestigationTurn, artifact.OriginHost, toolRecordTurnLimit, at) || b.Context.Identity() != e.ContextIdentity || b.ContextArtifact.PayloadDigest() != e.ContextIdentity {
		return InvestigationToolOperation{}, errToolRecord
	}
	classification := b.HeadArtifact.Classification()
	if b.ContextArtifact.Classification() != classification || b.TurnArtifact.Classification() != classification {
		return InvestigationToolOperation{}, errToolRecord
	}
	// Only index metadata is parsed here; no source-file payload is opened or validated.
	if !toolJSONPreflight(b.HeadArtifact.Payload(), toolHeadShape, toolRecordHeadLimit) {
		return InvestigationToolOperation{}, errToolRecord
	}
	head, err := source.ParseSnapshotArtifact(b.HeadArtifact)
	if err != nil || head.Identity() != e.HeadSnapshotIdentity || head.ManifestIdentity() != e.HeadManifestIdentity || head.FileCount() > 65536 {
		return InvestigationToolOperation{}, errToolRecord
	}
	if b.ContextArtifact.Validate() != nil {
		return InvestigationToolOperation{}, errToolRecord
	}
	request, err := b.Context.ProviderRequest()
	if err != nil || request.Identity() != e.RequestIdentity || request.Capability() != provider.CapabilityReviewV1 || request.MediaType() != "application/json" {
		return InvestigationToolOperation{}, errToolRecord
	}
	contextBytes := b.ContextArtifact.Payload()
	if !bytes.Equal(request.Payload(), contextBytes) {
		return InvestigationToolOperation{}, errToolRecord
	}
	var contextHeader toolRecordContextHeader
	if json.Unmarshal(contextBytes, &contextHeader) != nil {
		return InvestigationToolOperation{}, errToolRecord
	}
	c := contextHeader.Investigation
	wantRef := toolRecordIdentity([]any{"open-trestle/investigation-snapshot-ref", 1, e.SessionIdentity, e.Scope.Identity(), e.HeadArtifactIdentity, e.HeadSnapshotIdentity})
	if contextHeader.Version != 4 || contextHeader.Scope != e.Scope.Identity() || contextHeader.Task != "candidate_generation" || contextHeader.Tools != "host_admitted_snapshot_read_v1" || c.Mode != "fixed_generation_route_v1" || c.Session != e.SessionIdentity || c.Policy != e.PolicyIdentity || c.HeadArtifact != e.HeadArtifactIdentity || c.Head != e.HeadSnapshotIdentity || c.Manifest != e.HeadManifestIdentity || c.SnapshotRef != wantRef {
		return InvestigationToolOperation{}, errToolRecord
	}
	if b.TurnArtifact.Validate() != nil {
		return InvestigationToolOperation{}, errToolRecord
	}
	turnBytes := b.TurnArtifact.Payload()
	turn, err := gateway.ParseInvestigationTurnRecord(turnBytes)
	if err != nil || turn.Identity() != e.TurnIdentity || turn.RequestIdentity() != e.RequestIdentity || turn.PreviousTurnIdentity() != e.PreviousTurnIdentity || turn.Outcome().Identity() != e.OutcomeIdentity || turn.Dispatch().Response().Identity() != e.ResponseIdentity || turn.Authorization().ReviewScopeIdentity() != e.Scope.Identity() || turn.Authorization().RouteRecordIdentity() != c.Pin {
		return InvestigationToolOperation{}, errToolRecord
	}
	var header toolRecordTurnHeader
	if json.Unmarshal(turnBytes, &header) != nil || header.Owner != e.OwnerIdentity || header.Session != e.SessionIdentity || header.Policy != e.PolicyIdentity || header.Scope != e.Scope.Identity() || header.Role != "generation" || header.Ordinal != c.Turn || header.Deadline != e.Deadline.UnixMilli() || c.ToolCalls != c.Turn-1 {
		return InvestigationToolOperation{}, errToolRecord
	}
	response := turn.Dispatch().Response()
	if response.Capability() != provider.CapabilityReviewV1 || response.FinishReason() != provider.ResponseFinishStop || response.PartCount() != 1 {
		return InvestigationToolOperation{}, errToolRecord
	}
	part := response.Parts()[0]
	if part.Kind() != provider.ResponsePartStructuredData || part.MediaType() != "application/json" || part.SizeBytes() <= 0 || part.SizeBytes() > toolRecordPayloadLimit {
		return InvestigationToolOperation{}, errToolRecord
	}
	proposal, err := review.ParseInvestigationProposal(part.Payload())
	if err != nil || proposal.SnapshotRef() != wantRef {
		return InvestigationToolOperation{}, errToolRecord
	}
	e.SourceArtifactIdentities = append([]string(nil), e.SourceArtifactIdentities...)
	o := InvestigationToolOperation{expected: e, policy: b.Policy, limits: b.ReaderLimits, proposal: proposal, turn: turn, header: header, context: b.Context, contextArtifact: b.ContextArtifact, headArtifact: b.HeadArtifact, turnArtifact: b.TurnArtifact, headCount: head.FileCount(), created: time.UnixMilli(header.Finished), expires: e.Deadline, fileRefs: append([]string{}, proposal.FileRefs()...)}
	slices.Sort(o.fileRefs)
	for _, value := range []artifact.Artifact{b.HeadArtifact, b.ContextArtifact, b.TurnArtifact} {
		if value.CreatedAt().After(o.created) {
			o.created = value.CreatedAt()
		}
		if value.ExpiresAt().Before(o.expires) {
			o.expires = value.ExpiresAt()
		}
	}
	files := head.Files()
	byID := make(map[string]source.FileReference, len(files))
	byPath := make(map[string]string, len(files))
	for i, file := range files {
		byID[file.ArtifactIdentity()] = file
		byPath[file.Path()] = file.ArtifactIdentity()
		if i < b.ReaderLimits.MaxFiles {
			ref := toolRecordIdentity([]any{"open-trestle/snapshot-file-ref", 1, e.Scope.Identity(), head.ArtifactIdentity(), head.Identity(), head.AcquisitionExecutionIdentity(), file.ArtifactIdentity(), file.Path(), file.Digest(), file.SizeBytes()})
			o.files = append(o.files, toolRecordFile{Digest: file.Digest(), Artifact: file.ArtifactIdentity(), Path: file.Path(), Ref: ref, Size: file.SizeBytes()})
		}
	}
	seen := make(map[string]bool, len(b.SourceArtifacts))
	var suppliedBytes, suppliedPayloadBytes uint64
	for _, value := range b.SourceArtifacts {
		file, ok := byID[value.Identity()]
		if !ok || seen[value.Identity()] || !slices.Contains(e.SourceArtifactIdentities, value.Identity()) || !toolRecordCurrent(value, value.Identity(), e.Scope, artifact.KindSourceFile, artifact.OriginRepository, 16<<20, at) || value.Classification() != classification || !slices.Contains(value.Provenance(), head.AcquisitionExecutionIdentity()) || file.SizeBytes() < 0 {
			return InvestigationToolOperation{}, errToolRecord
		}
		seen[value.Identity()] = true
		suppliedBytes += uint64(file.SizeBytes())
		suppliedPayloadBytes += uint64(value.PayloadSizeBytes())
		if suppliedBytes > b.Policy.MaxScannedBytes() || suppliedPayloadBytes > toolRecordSuppliedPayloadLimit {
			return InvestigationToolOperation{}, errToolRecord
		}
		o.sources = append(o.sources, toolRecordSourceReference{value: value, file: file})
		if value.CreatedAt().After(o.created) {
			o.created = value.CreatedAt()
		}
		if value.ExpiresAt().Before(o.expires) {
			o.expires = value.ExpiresAt()
		}
	}
	for _, item := range contextHeader.Sources {
		if !seen[byPath[item.Path]] {
			return InvestigationToolOperation{}, errToolRecord
		}
	}
	o.identity = o.operationIdentity()
	if o.Validate() != nil || at.Before(o.created) || !at.Before(o.expires) {
		return InvestigationToolOperation{}, errToolRecord
	}
	return o, nil
}

func toolOperationWire(o InvestigationToolOperation) map[string]any {
	e := o.expected
	return map[string]any{"contract": "open-trestle/investigation-tool-operation", "schema_version": 1, "identity": o.identity, "scope_identity": e.Scope.Identity(), "session_identity": e.SessionIdentity, "policy_identity": e.PolicyIdentity, "snapshot_artifact_identity": e.HeadArtifactIdentity, "snapshot_identity": e.HeadSnapshotIdentity, "manifest_identity": e.HeadManifestIdentity, "snapshot_ref": o.SnapshotRef(), "tool": o.Tool(), "file_ref": o.FileRef(), "start_line": o.StartLine(), "end_line": o.EndLine(), "file_refs": o.FileRefs(), "literal": o.Literal()}
}
func EncodeInvestigationToolOperation(o InvestigationToolOperation) ([]byte, error) {
	if o.Validate() != nil {
		return nil, errToolRecord
	}
	encoded, err := json.Marshal(toolOperationWire(o))
	if err != nil || len(encoded) > toolRecordPayloadLimit {
		return nil, errToolRecord
	}
	return encoded, nil
}

// InvestigationToolInvocation retains a private association captured by the host.
// Its content identity does not prove execution, negative search or atomic admission.
type InvestigationToolInvocation struct {
	identity          string
	operation         InvestigationToolOperation
	ordinal           uint64
	started, finished time.Time
	limits            source.SnapshotReadLimits
	sourceIDs         []string
	listing           source.SnapshotListing
	read              source.SnapshotSlice
	search            source.SnapshotSearchResult
	selectedRefs      []source.SnapshotFileRef
	variant           string
	projection        string
}

func (i InvestigationToolInvocation) Identity() string { return i.identity }
func (i InvestigationToolInvocation) String() string   { return "investigation tool invocation" }
func (i InvestigationToolInvocation) GoString() string {
	return "model.InvestigationToolInvocation{<redacted>}"
}
func (i InvestigationToolInvocation) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation tool invocation"))
}

type toolReaderFileWire struct {
	Ref      string `json:"ref"`
	Path     string `json:"path"`
	Digest   string `json:"digest"`
	Size     int    `json:"size_bytes"`
	Artifact string `json:"file_artifact_identity"`
}
type toolReaderSliceWire struct {
	File    toolReaderFileWire `json:"file"`
	Start   int                `json:"start_line"`
	End     int                `json:"end_line"`
	Binding string             `json:"binding_identity"`
	Content string             `json:"content"`
}

func toolReaderFile(value source.SnapshotFileRef) toolReaderFileWire {
	return toolReaderFileWire{value.Ref(), value.Path(), value.Digest(), value.SizeBytes(), value.ArtifactIdentity()}
}
func toolReaderSlice(value source.SnapshotSlice) toolReaderSliceWire {
	span := value.Binding().SourceRange()
	return toolReaderSliceWire{toolReaderFile(value.File()), span.StartLine(), span.EndLine(), value.Binding().Identity(), string(value.Content())}
}
func toolRepositoryMetadataID(path, digest string, size int) string {
	return toolRecordIdentity(struct {
		Contract string `json:"contract"`
		Version  int    `json:"schema_version"`
		Path     string `json:"path"`
		Digest   string `json:"digest"`
		Size     int    `json:"size_bytes"`
	}{"open-trestle/repository-file", 1, path, digest, size})
}
func toolSliceMetadataID(value toolRecordSource) string {
	return toolRecordIdentity(struct {
		Contract    string `json:"contract"`
		Version     int    `json:"version"`
		File        string `json:"file"`
		FileDigest  string `json:"file_digest"`
		Path        string `json:"path"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		SliceDigest string `json:"slice_digest"`
		SliceBytes  int    `json:"slice_bytes"`
	}{"open-trestle/source-slice-binding", 1, value.FileIdentity, value.FileDigest, value.Path, value.Start, value.End, value.SliceDigest, value.SliceBytes})
}
func toolSourceValue(value source.SnapshotSlice) toolRecordSource {
	b := value.Binding()
	span := b.SourceRange()
	return toolRecordSource{Binding: b.Identity(), Content: string(value.Content()), End: span.EndLine(), FileRef: value.File().Ref(), Path: span.Path(), FileDigest: b.RepositoryFileDigest(), FileIdentity: b.RepositoryFileIdentity(), SliceBytes: b.SliceBytes(), SliceDigest: b.SliceDigest(), Start: span.StartLine()}
}
func toolCheckSlice(o InvestigationToolOperation, value source.SnapshotSlice) bool {
	b := value.Binding()
	span := b.SourceRange()
	if b.SliceBytes() <= 0 || b.SliceBytes() > o.limits.MaxResultBytes || b.Validate() != nil || span.StartLine() < 1 || span.EndLine() < span.StartLine() || span.EndLine() > 1000000 {
		return false
	}
	file, ok := o.file(value.File().Ref())
	if !ok || toolRecordFileValue(value.File()) != file || !o.hasSource(file.Artifact) || span.Path() != file.Path || b.RepositoryFileDigest() != file.Digest || b.RepositoryFileIdentity() != toolRepositoryMetadataID(file.Path, file.Digest, file.Size) || b.SliceBytes() > file.Size || value.ScannedBytes() != uint64(file.Size) || value.SerializedBytes() == 0 || value.SerializedBytes() > uint64(o.limits.MaxResultBytes) {
		return false
	}
	content := value.Content()
	return len(content) == b.SliceBytes() && utf8.Valid(content) && bytes.IndexByte(content, 0) < 0 && toolRecordDigest(content) == b.SliceDigest()
}
func (i InvestigationToolInvocation) outputs() ([]source.SnapshotFileRef, []source.SnapshotSlice, int, uint64, uint64, bool) {
	switch i.variant {
	case "snapshot.list":
		if i.listing.SerializedBytes() == 0 || i.listing.SerializedBytes() > uint64(i.limits.MaxResultBytes) {
			return nil, nil, 0, 0, 0, false
		}
		return i.listing.Files(), nil, i.listing.OmittedCount(), 0, i.listing.SerializedBytes(), true
	case "snapshot.read":
		if i.read.SerializedBytes() == 0 || i.read.SerializedBytes() > uint64(i.limits.MaxResultBytes) {
			return nil, nil, 0, 0, 0, false
		}
		return []source.SnapshotFileRef{i.read.File()}, []source.SnapshotSlice{i.read}, 0, i.read.ScannedBytes(), i.read.SerializedBytes(), true
	case "snapshot.search":
		if len(i.selectedRefs) == 0 || len(i.selectedRefs) > 64 || len(i.selectedRefs) > i.limits.MaxFiles || i.search.SerializedBytes() == 0 || i.search.SerializedBytes() > uint64(i.limits.MaxResultBytes) || !i.search.Complete() {
			return nil, nil, 0, 0, 0, false
		}
		// Typed reader output has at most64 matches; its byte bound is checked before copying.
		matches := i.search.Matches()
		return append([]source.SnapshotFileRef(nil), i.selectedRefs...), matches, 0, i.search.ScannedBytes(), i.search.SerializedBytes(), true
	}
	return nil, nil, 0, 0, 0, false
}
func (i InvestigationToolInvocation) inspect() ([]source.SnapshotFileRef, []source.SnapshotSlice, []toolRecordFile, []byte, int, uint64, uint64, error) {
	o := i.operation
	if o.Validate() != nil || i.variant != o.Tool() || i.ordinal == 0 || i.ordinal > o.policy.MaxToolCalls() || i.limits != o.limits || !toolRecordSortedIDs(i.sourceIDs, 64) || i.started.Before(o.created) || i.finished.Before(i.started) || !i.finished.Before(o.expires) || i.started.UnixMilli() <= 0 {
		return nil, nil, nil, nil, 0, 0, 0, errToolRecord
	}
	files, sources, omitted, scanned, serialized, ok := i.outputs()
	if !ok || len(files) > 64 || len(sources) > i.limits.MaxMatches || omitted < 0 || omitted > 65536 {
		return nil, nil, nil, nil, 0, 0, 0, errToolRecord
	}
	var sliceBytes uint64
	for _, value := range sources {
		size := value.Binding().SliceBytes()
		if size <= 0 || size > i.limits.MaxResultBytes {
			return nil, nil, nil, nil, 0, 0, 0, errToolRecord
		}
		sliceBytes += uint64(size)
		if sliceBytes > uint64(i.limits.MaxResultBytes) {
			return nil, nil, nil, nil, 0, 0, 0, errToolRecord
		}
	}
	selected := o.selected()
	expectedIDs := []string{}
	var wantScanned uint64
	if i.variant != "snapshot.list" {
		for _, file := range selected {
			expectedIDs = append(expectedIDs, file.Artifact)
			wantScanned += uint64(file.Size)
		}
	}
	slices.Sort(expectedIDs)
	if !slices.Equal(expectedIDs, i.sourceIDs) || scanned != wantScanned || scanned > i.limits.MaxScannedBytes {
		return nil, nil, nil, nil, 0, 0, 0, errToolRecord
	}
	if i.variant == "snapshot.list" {
		if len(files) != len(selected) || omitted != o.headCount-len(selected) {
			return nil, nil, nil, nil, 0, 0, 0, errToolRecord
		}
		for index, file := range files {
			if toolRecordFileValue(file) != selected[index] {
				return nil, nil, nil, nil, 0, 0, 0, errToolRecord
			}
		}
	} else if i.variant == "snapshot.read" {
		if len(sources) != 1 || !toolCheckSlice(o, sources[0]) || sources[0].File().Ref() != o.FileRef() || sources[0].Binding().SourceRange().StartLine() != o.StartLine() || sources[0].Binding().SourceRange().EndLine() != o.EndLine() {
			return nil, nil, nil, nil, 0, 0, 0, errToolRecord
		}
	} else {
		if len(files) != len(selected) {
			return nil, nil, nil, nil, 0, 0, 0, errToolRecord
		}
		for index, file := range files {
			if toolRecordFileValue(file) != selected[index] {
				return nil, nil, nil, nil, 0, 0, 0, errToolRecord
			}
		}
		lastFile, lastLine := -1, 0
		for _, value := range sources {
			if !toolCheckSlice(o, value) {
				return nil, nil, nil, nil, 0, 0, 0, errToolRecord
			}
			position := slices.Index(o.fileRefs, value.File().Ref())
			span := value.Binding().SourceRange()
			if position < 0 || span.StartLine() != span.EndLine() || position < lastFile || position == lastFile && span.StartLine() <= lastLine || !bytes.Contains(value.Content(), []byte(o.Literal())) {
				return nil, nil, nil, nil, 0, 0, 0, errToolRecord
			}
			lastFile, lastLine = position, span.StartLine()
		}
	}
	var projection []byte
	var err error
	switch i.variant {
	case "snapshot.list":
		wires := make([]toolReaderFileWire, 0, len(files))
		for _, file := range files {
			wires = append(wires, toolReaderFile(file))
		}
		projection, err = json.Marshal(struct {
			Files   []toolReaderFileWire `json:"files"`
			Omitted int                  `json:"omitted_file_count"`
		}{wires, omitted})
	case "snapshot.read":
		projection, err = json.Marshal(struct {
			Source  toolReaderSliceWire `json:"source"`
			Scanned uint64              `json:"scanned_bytes"`
		}{toolReaderSlice(i.read), scanned})
	case "snapshot.search":
		wires := make([]toolReaderSliceWire, 0, len(sources))
		for _, value := range sources {
			wires = append(wires, toolReaderSlice(value))
		}
		projection, err = json.Marshal(struct {
			Matches  []toolReaderSliceWire `json:"matches"`
			Complete bool                  `json:"complete"`
			Scanned  uint64                `json:"scanned_bytes"`
		}{wires, true, scanned})
	}
	if err != nil || len(projection) > i.limits.MaxResultBytes || uint64(len(projection)) != serialized {
		return nil, nil, nil, nil, 0, 0, 0, errToolRecord
	}
	return files, sources, selected, projection, omitted, scanned, serialized, nil
}
func (i InvestigationToolInvocation) deriveIdentity() string {
	l := i.limits
	return toolRecordIdentity([]any{"open-trestle/investigation-tool-invocation", 1, i.operation.Identity(), i.operation.expected.TurnIdentity, i.ordinal, i.started.UnixMilli(), i.finished.UnixMilli(), []any{l.MaxFiles, l.MaxLines, l.MaxResultBytes, l.MaxMatches, l.MaxScannedBytes}, i.sourceIDs, toolRecordDigest([]byte(i.projection))})
}
func (i InvestigationToolInvocation) Validate() error {
	_, _, _, projection, _, _, _, err := i.inspect()
	if err != nil || !toolRecordValidID(i.identity) || string(projection) != i.projection || i.identity != i.deriveIdentity() {
		return errToolRecord
	}
	return nil
}
func captureToolInvocation(i InvestigationToolInvocation, turn gateway.InvestigationTurnRecord) (InvestigationToolInvocation, error) {
	i.started = time.UnixMilli(i.started.UnixMilli()).UTC()
	i.finished = time.UnixMilli(i.finished.UnixMilli()).UTC()
	// Full turn bytes were validated when the operation was built. These immutable
	// causal identities must agree; retained artifact identity binds non-hashed metadata.
	if turn.Identity() != i.operation.expected.TurnIdentity || turn.RequestIdentity() != i.operation.expected.RequestIdentity || turn.Dispatch().Identity() != i.operation.turn.Dispatch().Identity() || turn.Outcome().Identity() != i.operation.expected.OutcomeIdentity || turn.Authorization().Identity() != i.operation.turn.Authorization().Identity() {
		return InvestigationToolInvocation{}, errToolRecord
	}
	_, _, _, projection, _, _, _, err := i.inspect()
	if err != nil {
		return InvestigationToolInvocation{}, errToolRecord
	}
	i.sourceIDs = append([]string{}, i.sourceIDs...)
	i.selectedRefs = append([]source.SnapshotFileRef(nil), i.selectedRefs...)
	i.projection = string(projection)
	i.identity = i.deriveIdentity()
	return i, nil
}
func newInvestigationListingInvocation(o InvestigationToolOperation, turn gateway.InvestigationTurnRecord, ordinal uint64, limits source.SnapshotReadLimits, ids []string, started, finished time.Time, result source.SnapshotListing) (InvestigationToolInvocation, error) {
	return captureToolInvocation(InvestigationToolInvocation{operation: o, ordinal: ordinal, limits: limits, sourceIDs: ids, started: started, finished: finished, listing: result, variant: "snapshot.list"}, turn)
}
func newInvestigationReadInvocation(o InvestigationToolOperation, turn gateway.InvestigationTurnRecord, ordinal uint64, limits source.SnapshotReadLimits, ids []string, started, finished time.Time, result source.SnapshotSlice) (InvestigationToolInvocation, error) {
	return captureToolInvocation(InvestigationToolInvocation{operation: o, ordinal: ordinal, limits: limits, sourceIDs: ids, started: started, finished: finished, read: result, variant: "snapshot.read"}, turn)
}
func newInvestigationSearchInvocation(o InvestigationToolOperation, turn gateway.InvestigationTurnRecord, ordinal uint64, limits source.SnapshotReadLimits, ids []string, started, finished time.Time, refs []source.SnapshotFileRef, result source.SnapshotSearchResult) (InvestigationToolInvocation, error) {
	return captureToolInvocation(InvestigationToolInvocation{operation: o, ordinal: ordinal, limits: limits, sourceIDs: ids, started: started, finished: finished, search: result, selectedRefs: refs, variant: "snapshot.search"}, turn)
}

type toolResultWire struct {
	CallID           string             `json:"call_id"`
	Complete         bool               `json:"complete"`
	ContextArtifact  string             `json:"context_artifact_identity"`
	Context          string             `json:"context_identity"`
	Contract         string             `json:"contract"`
	End              int                `json:"end_line"`
	FileRef          string             `json:"file_ref"`
	FileRefs         []string           `json:"file_refs" limit:"64"`
	Files            []toolRecordFile   `json:"files" limit:"64"`
	Identity         string             `json:"identity,omitempty"`
	Invocation       string             `json:"invocation_identity"`
	Literal          string             `json:"literal" limit:"256"`
	Manifest         string             `json:"manifest_identity"`
	Omitted          int                `json:"omitted_file_count"`
	Operation        string             `json:"operation_identity"`
	Outcome          string             `json:"outcome_identity"`
	Owner            string             `json:"owner_identity"`
	Policy           string             `json:"policy_identity"`
	Previous         string             `json:"previous_turn_identity"`
	Proposal         json.RawMessage    `json:"proposal" proposal:"true"`
	ProposalIdentity string             `json:"proposal_identity"`
	Response         string             `json:"proposal_response_identity"`
	ReaderBytes      uint64             `json:"reader_serialized_bytes"`
	Request          string             `json:"request_identity"`
	Scanned          uint64             `json:"scanned_bytes"`
	Version          int                `json:"schema_version"`
	Scope            string             `json:"scope_identity"`
	Session          string             `json:"session_identity"`
	HeadArtifact     string             `json:"snapshot_artifact_identity"`
	Head             string             `json:"snapshot_identity"`
	SnapshotRef      string             `json:"snapshot_ref"`
	Sources          []toolRecordSource `json:"sources" limit:"64"`
	Start            int                `json:"start_line"`
	Tool             string             `json:"tool"`
	TurnArtifact     string             `json:"turn_artifact_identity"`
	Turn             string             `json:"turn_identity"`
}

// InvestigationToolResult requires a held invocation; encoded claims cannot restore it.
type InvestigationToolResult struct {
	identity, payload    string
	operation            InvestigationToolOperation
	invocation           InvestigationToolInvocation
	files                []source.SnapshotFileRef
	sources              []review.ContextSource
	omitted              int
	scanned, readerBytes uint64
}

func (r InvestigationToolResult) Identity() string           { return r.identity }
func (r InvestigationToolResult) OperationIdentity() string  { return r.operation.Identity() }
func (r InvestigationToolResult) InvocationIdentity() string { return r.invocation.Identity() }
func (r InvestigationToolResult) Tool() string               { return r.operation.Tool() }
func (r InvestigationToolResult) CallID() string             { return r.operation.proposal.CallID() }
func (r InvestigationToolResult) RequestIdentity() string {
	return r.operation.expected.RequestIdentity
}
func (r InvestigationToolResult) ProposalIdentity() string { return r.operation.proposal.Identity() }
func (r InvestigationToolResult) ResponseIdentity() string {
	return r.operation.expected.ResponseIdentity
}
func (r InvestigationToolResult) TurnIdentity() string { return r.operation.expected.TurnIdentity }
func (r InvestigationToolResult) OutcomeIdentity() string {
	return r.operation.expected.OutcomeIdentity
}
func (r InvestigationToolResult) Files() []source.SnapshotFileRef {
	return append([]source.SnapshotFileRef(nil), r.files...)
}
func (r InvestigationToolResult) Sources() []review.ContextSource {
	return append([]review.ContextSource(nil), r.sources...)
}
func (r InvestigationToolResult) ScannedBytes() uint64          { return r.scanned }
func (r InvestigationToolResult) ReaderSerializedBytes() uint64 { return r.readerBytes }
func (r InvestigationToolResult) Complete() bool                { return r.identity != "" }
func (r InvestigationToolResult) OmittedFileCount() int         { return r.omitted }
func (r InvestigationToolResult) String() string                { return "investigation tool result" }
func (r InvestigationToolResult) GoString() string {
	return "model.InvestigationToolResult{<redacted>}"
}
func (r InvestigationToolResult) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation tool result"))
}

func toolRecordSamePins(a, b InvestigationToolExpectations) bool {
	if a.Deadline.UnixMilli() != b.Deadline.UnixMilli() || !slices.Equal(a.SourceArtifactIdentities, b.SourceArtifactIdentities) {
		return false
	}
	a.Deadline = b.Deadline
	a.SourceArtifactIdentities = nil
	b.SourceArtifactIdentities = nil
	a.OperationIdentity = ""
	a.InvocationIdentity = ""
	a.ResultArtifactIdentity = ""
	b.OperationIdentity = ""
	b.InvocationIdentity = ""
	b.ResultArtifactIdentity = ""
	return reflect.DeepEqual(a, b)
}
func toolRecordSameArtifact(a, b artifact.Artifact) bool {
	return a.Identity() == b.Identity() && a.Scope() == b.Scope() && a.Kind() == b.Kind() && a.MediaType() == b.MediaType() && a.Classification() == b.Classification() && a.Protection() == b.Protection() && a.Origin() == b.Origin() && a.PayloadDigest() == b.PayloadDigest() && a.PayloadSizeBytes() == b.PayloadSizeBytes() && a.CreatedAt().Equal(b.CreatedAt()) && a.ExpiresAt().Equal(b.ExpiresAt()) && slices.Equal(a.Provenance(), b.Provenance())
}
func toolRecordMatches(o InvestigationToolOperation, b InvestigationToolEvidence, e InvestigationToolExpectations, at time.Time) bool {
	if o.Validate() != nil || !toolRecordBounds(e, at) || !toolRecordSamePins(e, o.expected) || at.Before(o.created) || !at.Before(o.expires) || b.Context.Identity() != o.context.Identity() || b.Policy.Identity() != o.policy.Identity() || b.ReaderLimits != o.limits || len(b.SourceArtifacts) != len(o.sources) || len(b.SourceArtifacts) > toolRecordSourceLimit {
		return false
	}
	if !toolRecordSameArtifact(b.ContextArtifact, o.contextArtifact) || !toolRecordSameArtifact(b.HeadArtifact, o.headArtifact) || !toolRecordSameArtifact(b.TurnArtifact, o.turnArtifact) {
		return false
	}
	seen := make(map[string]bool, len(b.SourceArtifacts))
	for _, value := range b.SourceArtifacts {
		if seen[value.Identity()] {
			return false
		}
		seen[value.Identity()] = true
		found := false
		for _, original := range o.sources {
			if toolRecordSameArtifact(value, original.value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func toolResultWireValue(o InvestigationToolOperation, i InvestigationToolInvocation, selected []toolRecordFile, sources []source.SnapshotSlice, omitted int, scanned, serialized uint64) (toolResultWire, error) {
	proposal, err := review.EncodeInvestigationProposal(o.proposal)
	if err != nil {
		return toolResultWire{}, errToolRecord
	}
	entries := make([]toolRecordSource, 0, len(sources))
	for _, value := range sources {
		entries = append(entries, toolSourceValue(value))
	}
	files := append([]toolRecordFile{}, selected...)
	e := o.expected
	return toolResultWire{CallID: o.proposal.CallID(), Complete: true, ContextArtifact: e.ContextArtifactIdentity, Context: e.ContextIdentity, Contract: "open-trestle/investigation-tool-result", End: o.EndLine(), FileRef: o.FileRef(), FileRefs: o.FileRefs(), Files: files, Invocation: i.Identity(), Literal: o.Literal(), Manifest: e.HeadManifestIdentity, Omitted: omitted, Operation: o.Identity(), Outcome: e.OutcomeIdentity, Owner: e.OwnerIdentity, Policy: e.PolicyIdentity, Previous: e.PreviousTurnIdentity, Proposal: proposal, ProposalIdentity: o.proposal.Identity(), Response: e.ResponseIdentity, ReaderBytes: serialized, Request: e.RequestIdentity, Scanned: scanned, Version: 1, Scope: e.Scope.Identity(), Session: e.SessionIdentity, HeadArtifact: e.HeadArtifactIdentity, Head: e.HeadSnapshotIdentity, SnapshotRef: o.SnapshotRef(), Sources: entries, Start: o.StartLine(), Tool: o.Tool(), TurnArtifact: e.TurnArtifactIdentity, Turn: e.TurnIdentity}, nil
}
func buildToolResult(o InvestigationToolOperation, i InvestigationToolInvocation) (InvestigationToolResult, error) {
	if i.Identity() == "" || i.operation.Identity() != o.Identity() || !toolRecordSamePins(i.operation.expected, o.expected) || i.limits != o.limits {
		return InvestigationToolResult{}, errToolRecord
	}
	files, slices, selected, projection, omitted, scanned, serialized, err := i.inspect()
	if err != nil || i.identity != i.deriveIdentity() || string(projection) != i.projection {
		return InvestigationToolResult{}, errToolRecord
	}
	wire, err := toolResultWireValue(o, i, selected, slices, omitted, scanned, serialized)
	if err != nil {
		return InvestigationToolResult{}, errToolRecord
	}
	preimage, err := json.Marshal(wire)
	if err != nil || len(preimage) > toolRecordPayloadLimit {
		return InvestigationToolResult{}, errToolRecord
	}
	wire.Identity = toolRecordDigest(preimage)
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > toolRecordPayloadLimit || uint64(len(payload)) > o.policy.MaxResultBytes() {
		return InvestigationToolResult{}, errToolRecord
	}
	sources := make([]review.ContextSource, 0, len(slices))
	for _, value := range slices {
		binding := value.Binding()
		item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), binding.SourceRange())
		if err != nil {
			return InvestigationToolResult{}, errToolRecord
		}
		bound, err := review.NewBoundContextSource(review.ContextStageRepositoryContext, memory.TaintRepositoryControlled, item, value.Content(), binding)
		if err != nil {
			return InvestigationToolResult{}, errToolRecord
		}
		sources = append(sources, bound)
	}
	return InvestigationToolResult{identity: wire.Identity, payload: string(payload), operation: o, invocation: i, files: append([]source.SnapshotFileRef(nil), files...), sources: sources, omitted: omitted, scanned: scanned, readerBytes: serialized}, nil
}
func (r InvestigationToolResult) Validate() error {
	if !toolRecordValidID(r.identity) || len(r.payload) == 0 || len(r.payload) > toolRecordPayloadLimit {
		return errToolRecord
	}
	canonical, err := buildToolResult(r.operation, r.invocation)
	if err != nil || canonical.identity != r.identity || canonical.payload != r.payload || canonical.scanned != r.scanned || canonical.readerBytes != r.readerBytes || canonical.omitted != r.omitted || !slices.Equal(canonical.files, r.files) || len(canonical.sources) != len(r.sources) {
		return errToolRecord
	}
	for index, value := range r.sources {
		if value.Identity() != canonical.sources[index].Identity() {
			return errToolRecord
		}
	}
	return nil
}
func EncodeInvestigationToolResult(r InvestigationToolResult) ([]byte, error) {
	if r.Validate() != nil {
		return nil, errToolRecord
	}
	return []byte(r.payload), nil
}
func toolResultProvenance(o InvestigationToolOperation, i InvestigationToolInvocation) ([]string, error) {
	e := o.expected
	ids := []string{e.HeadArtifactIdentity, o.Identity(), e.TurnIdentity, e.ResponseIdentity, e.ContextArtifactIdentity, e.TurnArtifactIdentity}
	for _, file := range o.selected() {
		ids = append(ids, file.Artifact)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if !toolRecordSortedIDs(ids, 32) {
		return nil, errToolRecord
	}
	return ids, nil
}
func newToolResultArtifact(variant string, o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (artifact.Artifact, error) {
	if variant != o.Tool() || e.ResultArtifactIdentity != "" || e.OperationIdentity != o.Identity() || e.InvocationIdentity == "" || e.InvocationIdentity != i.Identity() || !toolRecordMatches(o, b, e, at) || at.Before(i.finished) {
		return artifact.Artifact{}, errToolRecord
	}
	result, err := buildToolResult(o, i)
	if err != nil {
		return artifact.Artifact{}, errToolRecord
	}
	provenance, err := toolResultProvenance(o, i)
	if err != nil {
		return artifact.Artifact{}, errToolRecord
	}
	value, err := artifact.New(e.Scope, artifact.KindInvestigationToolResult, "application/json", o.headArtifact.Classification(), artifact.OriginDeterministicTool, o.headArtifact.Protection(), provenance, []byte(result.payload), at, o.expires)
	if err != nil {
		return artifact.Artifact{}, errToolRecord
	}
	encoded, err := artifact.Encode(value)
	if err != nil || uint64(len(encoded)) > o.policy.MaxReturnedBytes() {
		return artifact.Artifact{}, errToolRecord
	}
	return value, nil
}
func parseToolResultArtifact(variant string, value artifact.Artifact, o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (InvestigationToolResult, error) {
	if variant != o.Tool() || e.OperationIdentity != o.Identity() || e.InvocationIdentity == "" || e.InvocationIdentity != i.Identity() || !toolRecordMatches(o, b, e, at) || !toolRecordCurrent(value, e.ResultArtifactIdentity, e.Scope, artifact.KindInvestigationToolResult, artifact.OriginDeterministicTool, toolRecordPayloadLimit, at) || uint64(value.PayloadSizeBytes()) > o.policy.MaxResultBytes() || value.CreatedAt().Before(i.finished) || value.ExpiresAt().After(o.expires) || value.Classification() != o.headArtifact.Classification() || value.Protection() != o.headArtifact.Protection() {
		return InvestigationToolResult{}, errToolRecord
	}
	provenance, err := toolResultProvenance(o, i)
	if err != nil || !slices.Equal(value.Provenance(), provenance) || value.Validate() != nil {
		return InvestigationToolResult{}, errToolRecord
	}
	payload := value.Payload()
	if validateInvestigationToolResultPayload(payload) != nil {
		return InvestigationToolResult{}, errToolRecord
	}
	result, err := buildToolResult(o, i)
	if err != nil || result.payload != string(payload) {
		return InvestigationToolResult{}, errToolRecord
	}
	encoded, err := artifact.Encode(value)
	if err != nil || uint64(len(encoded)) > o.policy.MaxReturnedBytes() {
		return InvestigationToolResult{}, errToolRecord
	}
	return result, nil
}
func NewInvestigationListToolResultArtifact(o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (artifact.Artifact, error) {
	return newToolResultArtifact("snapshot.list", o, b, i, e, at)
}
func NewInvestigationReadToolResultArtifact(o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (artifact.Artifact, error) {
	return newToolResultArtifact("snapshot.read", o, b, i, e, at)
}
func NewInvestigationSearchToolResultArtifact(o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (artifact.Artifact, error) {
	return newToolResultArtifact("snapshot.search", o, b, i, e, at)
}
func ParseInvestigationListToolResultArtifact(value artifact.Artifact, o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (InvestigationToolResult, error) {
	return parseToolResultArtifact("snapshot.list", value, o, b, i, e, at)
}
func ParseInvestigationReadToolResultArtifact(value artifact.Artifact, o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (InvestigationToolResult, error) {
	return parseToolResultArtifact("snapshot.read", value, o, b, i, e, at)
}
func ParseInvestigationSearchToolResultArtifact(value artifact.Artifact, o InvestigationToolOperation, b InvestigationToolEvidence, i InvestigationToolInvocation, e InvestigationToolExpectations, at time.Time) (InvestigationToolResult, error) {
	return parseToolResultArtifact("snapshot.search", value, o, b, i, e, at)
}

type toolHeadFileWire struct {
	Path     string `json:"path" limit:"4096"`
	Digest   string `json:"digest"`
	Size     int    `json:"size_bytes"`
	Artifact string `json:"artifact_identity"`
}
type toolHeadWire struct {
	Contract   string             `json:"contract"`
	Version    int                `json:"schema_version"`
	Identity   string             `json:"identity"`
	Request    string             `json:"acquisition_request_identity"`
	Receipt    string             `json:"acquisition_receipt_identity"`
	Execution  string             `json:"acquisition_execution_identity"`
	Repository string             `json:"repository_identity"`
	Revision   string             `json:"revision_identity"`
	Adapter    string             `json:"source_adapter_identity"`
	Manifest   string             `json:"manifest_identity"`
	Files      []toolHeadFileWire `json:"files" limit:"65536"`
}

type toolJSONShape struct {
	kind        reflect.Kind
	bits, limit int
	proposal    bool
	fields      []toolJSONField
	element     *toolJSONShape
}
type toolJSONField struct {
	prefix string
	shape  *toolJSONShape
}

var toolResultShape = makeToolJSONShape(reflect.TypeOf(toolResultWire{}), "")
var toolHeadShape = makeToolJSONShape(reflect.TypeOf(toolHeadWire{}), "")

func makeToolJSONShape(value reflect.Type, tag reflect.StructTag) *toolJSONShape {
	shape := &toolJSONShape{kind: value.Kind(), proposal: tag.Get("proposal") == "true"}
	if shape.proposal {
		return shape
	}
	switch value.Kind() {
	case reflect.Struct:
		shape.fields = make([]toolJSONField, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			shape.fields[index] = toolJSONField{prefix: `"` + key + `":`, shape: makeToolJSONShape(field.Type, field.Tag)}
		}
	case reflect.Slice:
		shape.element = makeToolJSONShape(value.Elem(), "")
	case reflect.String:
		shape.limit = 64
	case reflect.Int, reflect.Uint64:
		shape.bits = value.Bits()
	}
	if limit := tag.Get("limit"); limit != "" {
		shape.limit, _ = strconv.Atoi(limit)
	}
	return shape
}

type toolJSONScan struct {
	data   []byte
	offset int
}

func toolJSONPreflight(data []byte, shape *toolJSONShape, maximum int) bool {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return false
	}
	s := toolJSONScan{data: data}
	return s.value(shape, 0) && s.offset == len(data)
}
func (s *toolJSONScan) take(value string) bool {
	if len(s.data)-s.offset < len(value) || !bytes.Equal(s.data[s.offset:s.offset+len(value)], []byte(value)) {
		return false
	}
	s.offset += len(value)
	return true
}
func (s *toolJSONScan) value(shape *toolJSONShape, depth int) bool {
	if depth > 16 || s.offset >= len(s.data) {
		return false
	}
	if shape.proposal {
		return s.proposal()
	}
	switch shape.kind {
	case reflect.Struct:
		if !s.take("{") {
			return false
		}
		for index, field := range shape.fields {
			if index > 0 && !s.take(",") {
				return false
			}
			if !s.take(field.prefix) || !s.value(field.shape, depth+1) {
				return false
			}
		}
		return s.take("}")
	case reflect.Slice:
		if !s.take("[") {
			return false
		}
		if s.take("]") {
			return true
		}
		for count := 0; ; count++ {
			if count >= shape.limit || !s.value(shape.element, depth+1) {
				return false
			}
			if s.take("]") {
				return true
			}
			if !s.take(",") {
				return false
			}
		}
	case reflect.String:
		return s.text(shape.limit)
	case reflect.Bool:
		return s.take("true") || s.take("false")
	case reflect.Int, reflect.Uint64:
		start := s.offset
		if shape.kind == reflect.Int && s.data[s.offset] == '-' {
			s.offset++
		}
		digits := s.offset
		for s.offset < len(s.data) && s.data[s.offset] >= '0' && s.data[s.offset] <= '9' {
			s.offset++
			if s.offset-start > 20 {
				return false
			}
		}
		if s.offset == digits || s.data[digits] == '0' && (s.offset-digits > 1 || digits != start) {
			return false
		}
		if shape.kind == reflect.Int {
			_, err := strconv.ParseInt(string(s.data[start:s.offset]), 10, shape.bits)
			return err == nil
		}
		_, err := strconv.ParseUint(string(s.data[start:s.offset]), 10, shape.bits)
		return err == nil
	}
	return false
}
func toolJSONHex(raw []byte) (rune, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	var value rune
	for _, char := range raw[:4] {
		var digit byte
		switch {
		case char >= '0' && char <= '9':
			digit = char - '0'
		case char >= 'a' && char <= 'f':
			digit = char - 'a' + 10
		case char >= 'A' && char <= 'F':
			digit = char - 'A' + 10
		default:
			return 0, false
		}
		value = value*16 + rune(digit)
	}
	return value, true
}
func (s *toolJSONScan) text(maximum int) bool {
	if !s.take(`"`) {
		return false
	}
	start, decoded := s.offset, 0
	for s.offset < len(s.data) && s.offset-start <= 6*maximum {
		char := s.data[s.offset]
		s.offset++
		if char == '"' {
			return decoded <= maximum
		}
		if char < 0x20 {
			return false
		}
		if char != '\\' {
			decoded++
		} else {
			if s.offset >= len(s.data) {
				return false
			}
			escape := s.data[s.offset]
			s.offset++
			switch escape {
			case '"', '\\', 'b', 'f', 'n', 'r', 't':
				decoded++
			case 'u':
				value, ok := toolJSONHex(s.data[s.offset:])
				if !ok {
					return false
				}
				s.offset += 4
				if value >= 0xd800 && value <= 0xdbff {
					if !s.take(`\u`) {
						return false
					}
					low, ok := toolJSONHex(s.data[s.offset:])
					if !ok || low < 0xdc00 || low > 0xdfff {
						return false
					}
					s.offset += 4
					value = 0x10000 + (value-0xd800)*0x400 + low - 0xdc00
				} else if value >= 0xdc00 && value <= 0xdfff {
					return false
				}
				decoded += utf8.RuneLen(value)
			default:
				return false
			}
		}
		if decoded > maximum {
			return false
		}
	}
	return false
}
func (s *toolJSONScan) proposal() bool {
	start := s.offset
	if !s.take("{") {
		return false
	}
	depth := 1
	for s.offset < len(s.data) && s.offset-start <= toolRecordPayloadLimit {
		char := s.data[s.offset]
		if char == '"' {
			// The existing proposal parser applies its smaller decoded-field bounds.
			if !s.text(toolRecordPayloadLimit) {
				return false
			}
			continue
		}
		s.offset++
		switch char {
		case '{', '[':
			depth++
			if depth > 4 {
				return false
			}
		case '}', ']':
			depth--
			if depth == 0 {
				encoded := s.data[start:s.offset]
				proposal, err := review.ParseInvestigationProposal(encoded)
				if err != nil {
					return false
				}
				canonical, err := review.EncodeInvestigationProposal(proposal)
				return err == nil && bytes.Equal(canonical, encoded)
			}
		}
	}
	return false
}

func validateToolResultClaims(w toolResultWire) bool {
	if w.Contract != "open-trestle/investigation-tool-result" || w.Version != 1 || !w.Complete || w.ReaderBytes == 0 || w.ReaderBytes > toolRecordPayloadLimit || w.Scanned > 16<<20 || w.Omitted < 0 || w.Omitted > 65536 {
		return false
	}
	for _, id := range []string{w.Identity, w.Invocation, w.ContextArtifact, w.Context, w.Manifest, w.Operation, w.Outcome, w.Owner, w.Policy, w.ProposalIdentity, w.Response, w.Request, w.Scope, w.Session, w.HeadArtifact, w.Head, w.SnapshotRef, w.TurnArtifact, w.Turn} {
		if !toolRecordValidID(id) {
			return false
		}
	}
	if w.Previous != "" && !toolRecordValidID(w.Previous) {
		return false
	}
	proposal, err := review.ParseInvestigationProposal(w.Proposal)
	if err != nil || proposal.Identity() != w.ProposalIdentity || proposal.Tool() != w.Tool || proposal.CallID() != w.CallID || proposal.SnapshotRef() != w.SnapshotRef || proposal.FileRef() != w.FileRef || proposal.StartLine() != w.Start || proposal.EndLine() != w.End || proposal.Literal() != w.Literal {
		return false
	}
	refs := append([]string{}, proposal.FileRefs()...)
	slices.Sort(refs)
	if !slices.Equal(refs, w.FileRefs) || !toolRecordSortedIDs(w.FileRefs, 64) {
		return false
	}
	if w.Operation != toolRecordIdentity([]any{"open-trestle/investigation-tool-operation", 1, w.Scope, w.Session, w.Policy, w.HeadArtifact, w.Head, w.Manifest, w.SnapshotRef, w.Tool, w.FileRef, w.Start, w.End, w.FileRefs, w.Literal}) {
		return false
	}
	byRef := make(map[string]toolRecordFile, len(w.Files))
	artifacts := make(map[string]bool, len(w.Files))
	var scanned uint64
	for index, file := range w.Files {
		if !toolRecordValidID(file.Ref) || !toolRecordValidID(file.Digest) || !toolRecordValidID(file.Artifact) || file.Size < 0 || file.Size > 10<<20 || byRef[file.Ref].Ref != "" || artifacts[file.Artifact] {
			return false
		}
		if _, err := evidence.NewSourceRange(file.Path, 1, 1); err != nil {
			return false
		}
		byRef[file.Ref] = file
		artifacts[file.Artifact] = true
		if w.Tool != "snapshot.list" {
			scanned += uint64(file.Size)
		} else if index > 0 && w.Files[index-1].Path >= file.Path {
			return false
		}
	}
	if scanned != w.Scanned {
		return false
	}
	switch w.Tool {
	case "snapshot.list":
		if len(w.Sources) != 0 {
			return false
		}
	case "snapshot.read":
		if len(w.Files) != 1 || len(w.Sources) != 1 || w.Files[0].Ref != w.FileRef || w.Omitted != 0 {
			return false
		}
	case "snapshot.search":
		if len(w.Files) != len(w.FileRefs) || w.Omitted != 0 {
			return false
		}
		for index, file := range w.Files {
			if file.Ref != w.FileRefs[index] {
				return false
			}
		}
	default:
		return false
	}
	lastFile, lastLine := -1, 0
	for _, value := range w.Sources {
		file, ok := byRef[value.FileRef]
		if !ok || value.Path != file.Path || value.Start < 1 || value.End < value.Start || value.End > 1000000 || value.SliceBytes <= 0 || value.SliceBytes > toolRecordPayloadLimit || value.SliceBytes > file.Size || value.SliceBytes != len(value.Content) || !utf8.ValidString(value.Content) || strings.IndexByte(value.Content, 0) >= 0 || value.FileDigest != file.Digest || value.FileIdentity != toolRepositoryMetadataID(file.Path, file.Digest, file.Size) || value.SliceDigest != toolRecordDigest([]byte(value.Content)) || value.Binding != toolSliceMetadataID(value) {
			return false
		}
		if w.Tool == "snapshot.read" {
			if value.FileRef != w.FileRef || value.Start != w.Start || value.End != w.End {
				return false
			}
		} else {
			index := slices.Index(w.FileRefs, value.FileRef)
			if index < lastFile || index == lastFile && value.Start <= lastLine || value.Start != value.End || !strings.Contains(value.Content, w.Literal) {
				return false
			}
			lastFile, lastLine = index, value.Start
		}
	}
	readerFiles := make([]toolReaderFileWire, 0, len(w.Files))
	for _, file := range w.Files {
		readerFiles = append(readerFiles, toolReaderFileWire{file.Ref, file.Path, file.Digest, file.Size, file.Artifact})
	}
	readerSources := make([]toolReaderSliceWire, 0, len(w.Sources))
	for _, value := range w.Sources {
		file := byRef[value.FileRef]
		readerSources = append(readerSources, toolReaderSliceWire{toolReaderFileWire{file.Ref, file.Path, file.Digest, file.Size, file.Artifact}, value.Start, value.End, value.Binding, value.Content})
	}
	var readerBytes []byte
	switch w.Tool {
	case "snapshot.list":
		readerBytes, err = json.Marshal(struct {
			Files   []toolReaderFileWire `json:"files"`
			Omitted int                  `json:"omitted_file_count"`
		}{readerFiles, w.Omitted})
	case "snapshot.read":
		readerBytes, err = json.Marshal(struct {
			Source  toolReaderSliceWire `json:"source"`
			Scanned uint64              `json:"scanned_bytes"`
		}{readerSources[0], w.Scanned})
	case "snapshot.search":
		readerBytes, err = json.Marshal(struct {
			Matches  []toolReaderSliceWire `json:"matches"`
			Complete bool                  `json:"complete"`
			Scanned  uint64                `json:"scanned_bytes"`
		}{readerSources, true, w.Scanned})
	}
	if err != nil || uint64(len(readerBytes)) != w.ReaderBytes {
		return false
	}
	identity := w.Identity
	w.Identity = ""
	preimage, err := json.Marshal(w)
	return err == nil && identity == toolRecordDigest(preimage)
}

// This validates claims only. It returns no source or invocation witness.
func validateInvestigationToolResultPayload(encoded []byte) error {
	if !toolJSONPreflight(encoded, toolResultShape, toolRecordPayloadLimit) {
		return errToolRecord
	}
	var wire toolResultWire
	if json.Unmarshal(encoded, &wire) != nil || !validateToolResultClaims(wire) {
		return errToolRecord
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errToolRecord
	}
	return nil
}
