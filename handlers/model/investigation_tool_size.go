package model

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/review"
)

var errInvestigationToolSize = errors.New("invalid investigation tool size estimate")

type investigationToolSizeCount struct{ err error }

func (c *investigationToolSizeCount) add(values ...uint64) uint64 {
	if c.err != nil {
		return 0
	}
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			c.err = errInvestigationToolSize
			return 0
		}
		total += value
	}
	return total
}
func (c *investigationToolSizeCount) multiply(a, b uint64) uint64 {
	if c.err != nil {
		return 0
	}
	if b != 0 && a > math.MaxUint64/b {
		c.err = errInvestigationToolSize
		return 0
	}
	return a * b
}
func (c *investigationToolSizeCount) subtract(a, b uint64) uint64 {
	if c.err != nil {
		return 0
	}
	if b > a {
		c.err = errInvestigationToolSize
		return 0
	}
	return a - b
}
func (c *investigationToolSizeCount) text(value string) uint64 {
	encoded, err := json.Marshal(value)
	if err != nil {
		c.err = errInvestigationToolSize
		return 0
	}
	return uint64(len(encoded))
}
func (c *investigationToolSizeCount) number(value uint64) uint64 {
	return uint64(len(strconv.FormatUint(value, 10)))
}
func (c *investigationToolSizeCount) array(count, element uint64) uint64 {
	if count == 0 {
		return 2
	}
	return c.add(2, c.multiply(count, element), count-1)
}
func (c *investigationToolSizeCount) object(fields map[string]uint64) uint64 {
	total := uint64(2)
	for name, value := range fields {
		total = c.add(total, c.text(name), 1, value)
	}
	if len(fields) > 0 {
		total = c.add(total, uint64(len(fields)-1))
	}
	return total
}
func (c *investigationToolSizeCount) base64(value uint64) uint64 {
	return c.multiply(c.add(value, 2)/3, 4)
}

func (c *investigationToolSizeCount) file(file toolRecordFile) uint64 {
	return c.object(map[string]uint64{"digest": c.text(file.Digest), "file_artifact_identity": c.text(file.Artifact), "path": c.text(file.Path), "ref": c.text(file.Ref), "size_bytes": c.number(uint64(file.Size))})
}
func (c *investigationToolSizeCount) rows(files []toolRecordFile) uint64 {
	total := uint64(2)
	for i, file := range files {
		total = c.add(total, c.file(file))
		if i > 0 {
			total = c.add(total, 1)
		}
	}
	return total
}
func (c *investigationToolSizeCount) source(file toolRecordFile, start, end uint64, maximumSlice uint64) uint64 {
	return c.object(map[string]uint64{"binding_identity": 66, "content": 2, "end_line": c.number(end), "file_ref": c.text(file.Ref), "path": c.text(file.Path), "repository_file_digest": c.text(file.Digest), "repository_file_identity": 66, "slice_bytes": c.number(maximumSlice), "slice_digest": 66, "start_line": c.number(start)})
}
func (c *investigationToolSizeCount) projectionSource(file toolRecordFile, start, end uint64) uint64 {
	return c.object(map[string]uint64{"file": c.file(file), "start_line": c.number(start), "end_line": c.number(end), "binding_identity": 66, "content": 2})
}

// EstimateInvestigationToolResultArtifactBytes returns raw payload, encoded artifact
// and exact provenance-union bounds. Valid oversize is not admission or an error.
// It reads sealed operation metadata only; the controller must gate the actual reader.
func EstimateInvestigationToolResultArtifactBytes(operation InvestigationToolOperation) (payloadBytes, encodedArtifactBytes, provenanceCount uint64, err error) {
	if operation.Validate() != nil || !investigationToolSizeSchema(reflect.TypeOf(toolResultWire{}), reflect.TypeOf(toolRecordFile{}), reflect.TypeOf(toolRecordSource{}), reflect.TypeOf(toolReaderFileWire{}), reflect.TypeOf(toolReaderSliceWire{})) {
		return 0, 0, 0, errInvestigationToolSize
	}
	c := investigationToolSizeCount{}
	selected := operation.selected()
	var scanned uint64
	for _, file := range selected {
		if file.Size < 0 {
			return 0, 0, 0, errInvestigationToolSize
		}
		if operation.Tool() != "snapshot.list" {
			scanned = c.add(scanned, uint64(file.Size))
		}
	}
	projectionCap := uint64(operation.limits.MaxResultBytes)
	files := c.rows(selected)
	sources, projection := uint64(2), uint64(0)
	omitted := uint64(0)
	switch operation.Tool() {
	case "snapshot.list":
		omitted = uint64(operation.headCount - len(selected))
		projection = c.object(map[string]uint64{"files": files, "omitted_file_count": c.number(omitted)})
	case "snapshot.read":
		if len(selected) != 1 {
			return 0, 0, 0, errInvestigationToolSize
		}
		file := selected[0]
		start, end := uint64(operation.StartLine()), uint64(operation.EndLine())
		projectionMetadata := c.object(map[string]uint64{"source": c.projectionSource(file, start, end), "scanned_bytes": c.number(scanned)})
		content := uint64(0)
		if projectionCap > projectionMetadata {
			content = min(c.multiply(6, scanned), projectionCap-projectionMetadata)
		}
		projection = min(projectionCap, c.add(projectionMetadata, content))
		sources = c.add(c.array(1, c.source(file, start, end, min(scanned, projectionCap))), content)
	case "snapshot.search":
		base := c.object(map[string]uint64{"matches": 2, "complete": 4, "scanned_bytes": c.number(scanned)})
		maximumRow, maximumProjection, minimumProjection := uint64(0), uint64(0), uint64(math.MaxUint64)
		for _, file := range selected {
			line := min(uint64(file.Size), uint64(1000000))
			row := c.source(file, line, line, min(uint64(file.Size), projectionCap))
			projected := c.projectionSource(file, line, line)
			// One-digit source positions give a lower bound on per-match metadata.
			minimum := c.projectionSource(file, 1, 1)
			maximumRow = max(maximumRow, row)
			maximumProjection = max(maximumProjection, projected)
			minimumProjection = min(minimumProjection, minimum)
		}
		count := min(uint64(operation.limits.MaxMatches), scanned)
		if len(selected) == 0 || projectionCap < base {
			count = 0
		} else {
			numerator, denominator := c.add(projectionCap-base, 1), c.add(minimumProjection, 1)
			if c.err != nil || denominator == 0 {
				return 0, 0, 0, errInvestigationToolSize
			}
			count = min(count, numerator/denominator)
		}
		content := uint64(0)
		if count > 0 && projectionCap > c.add(base, minimumProjection) {
			// All match content shares ONE projection allowance, even with many rows.
			content = min(c.multiply(6, scanned), projectionCap-c.add(base, minimumProjection))
		}
		sources = c.add(c.array(count, maximumRow), content)
		projection = min(projectionCap, c.add(base, c.subtract(c.array(count, maximumProjection), 2), content))
	default:
		return 0, 0, 0, errInvestigationToolSize
	}
	proposal, encodeErr := review.EncodeInvestigationProposal(operation.proposal)
	if encodeErr != nil {
		return 0, 0, 0, errInvestigationToolSize
	}
	refs := uint64(2)
	for i, ref := range operation.fileRefs {
		refs = c.add(refs, c.text(ref))
		if i > 0 {
			refs = c.add(refs, 1)
		}
	}
	e := operation.expected
	payload := c.object(map[string]uint64{
		"call_id": c.text(operation.proposal.CallID()), "complete": 4, "context_artifact_identity": c.text(e.ContextArtifactIdentity), "context_identity": c.text(e.ContextIdentity),
		"contract": c.text("open-trestle/investigation-tool-result"), "end_line": c.number(uint64(operation.EndLine())), "file_ref": c.text(operation.FileRef()), "file_refs": refs, "files": files,
		"identity": 66, "invocation_identity": 66, "literal": c.text(operation.Literal()), "manifest_identity": c.text(e.HeadManifestIdentity), "omitted_file_count": c.number(omitted),
		"operation_identity": c.text(operation.Identity()), "outcome_identity": c.text(e.OutcomeIdentity), "owner_identity": c.text(e.OwnerIdentity), "policy_identity": c.text(e.PolicyIdentity),
		"previous_turn_identity": c.text(e.PreviousTurnIdentity), "proposal": uint64(len(proposal)), "proposal_identity": c.text(operation.proposal.Identity()), "proposal_response_identity": c.text(e.ResponseIdentity),
		"reader_serialized_bytes": c.number(projection), "request_identity": c.text(e.RequestIdentity), "scanned_bytes": c.number(scanned), "schema_version": 1, "scope_identity": c.text(e.Scope.Identity()),
		"session_identity": c.text(e.SessionIdentity), "snapshot_artifact_identity": c.text(e.HeadArtifactIdentity), "snapshot_identity": c.text(e.HeadSnapshotIdentity), "snapshot_ref": c.text(operation.SnapshotRef()),
		"sources": sources, "start_line": c.number(uint64(operation.StartLine())), "tool": c.text(operation.Tool()), "turn_artifact_identity": c.text(e.TurnArtifactIdentity), "turn_identity": c.text(e.TurnIdentity),
	})
	provenance := map[string]bool{}
	for _, id := range []string{e.HeadArtifactIdentity, operation.Identity(), e.TurnIdentity, e.ResponseIdentity, e.ContextArtifactIdentity, e.TurnArtifactIdentity} {
		provenance[id] = true
	}
	for _, file := range selected {
		provenance[file.Artifact] = true
	}
	provenanceBytes := uint64(2)
	for id := range provenance {
		provenanceBytes = c.add(provenanceBytes, c.text(id))
	}
	if len(provenance) > 0 {
		provenanceBytes = c.add(provenanceBytes, uint64(len(provenance)-1))
	}
	expires := operation.expires.UnixMilli()
	if expires <= 1 {
		return 0, 0, 0, errInvestigationToolSize
	}
	envelope := c.object(map[string]uint64{
		"contract": c.text("open-trestle/runtime-artifact"), "schema_version": 1, "identity": 66,
		"tenant_id": c.text(e.Scope.TenantID()), "repository_id": c.text(e.Scope.RepositoryID()), "review_run_id": c.text(e.Scope.ReviewRunID()),
		"kind": c.text(artifact.KindInvestigationToolResult.String()), "media_type": c.text("application/json"), "classification": c.text(operation.headArtifact.Classification().String()),
		"origin": c.text(artifact.OriginDeterministicTool.String()), "protection": c.text(operation.headArtifact.Protection().String()), "provenance": provenanceBytes, "payload_digest": 66,
		"payload": c.add(2, c.base64(payload)), "created_at_milliseconds": c.number(uint64(expires - 1)), "expires_at_milliseconds": c.number(uint64(expires)),
	})
	if c.err != nil {
		return 0, 0, 0, c.err
	}
	return payload, envelope, uint64(len(provenance)), nil
}

type investigationToolSizeField struct {
	name   string
	typeOf reflect.Type
	tag    reflect.StructTag
}

var investigationToolSizeFields = [][]investigationToolSizeField{
	{
		{"CallID", reflect.TypeOf(""), `json:"call_id"`},
		{"Complete", reflect.TypeOf(false), `json:"complete"`},
		{"ContextArtifact", reflect.TypeOf(""), `json:"context_artifact_identity"`},
		{"Context", reflect.TypeOf(""), `json:"context_identity"`},
		{"Contract", reflect.TypeOf(""), `json:"contract"`},
		{"End", reflect.TypeOf(int(0)), `json:"end_line"`},
		{"FileRef", reflect.TypeOf(""), `json:"file_ref"`},
		{"FileRefs", reflect.TypeOf([]string{}), `json:"file_refs" limit:"64"`},
		{"Files", reflect.TypeOf([]toolRecordFile{}), `json:"files" limit:"64"`},
		{"Identity", reflect.TypeOf(""), `json:"identity,omitempty"`},
		{"Invocation", reflect.TypeOf(""), `json:"invocation_identity"`},
		{"Literal", reflect.TypeOf(""), `json:"literal" limit:"256"`},
		{"Manifest", reflect.TypeOf(""), `json:"manifest_identity"`},
		{"Omitted", reflect.TypeOf(int(0)), `json:"omitted_file_count"`},
		{"Operation", reflect.TypeOf(""), `json:"operation_identity"`},
		{"Outcome", reflect.TypeOf(""), `json:"outcome_identity"`},
		{"Owner", reflect.TypeOf(""), `json:"owner_identity"`},
		{"Policy", reflect.TypeOf(""), `json:"policy_identity"`},
		{"Previous", reflect.TypeOf(""), `json:"previous_turn_identity"`},
		{"Proposal", reflect.TypeOf(json.RawMessage{}), `json:"proposal" proposal:"true"`},
		{"ProposalIdentity", reflect.TypeOf(""), `json:"proposal_identity"`},
		{"Response", reflect.TypeOf(""), `json:"proposal_response_identity"`},
		{"ReaderBytes", reflect.TypeOf(uint64(0)), `json:"reader_serialized_bytes"`},
		{"Request", reflect.TypeOf(""), `json:"request_identity"`},
		{"Scanned", reflect.TypeOf(uint64(0)), `json:"scanned_bytes"`},
		{"Version", reflect.TypeOf(int(0)), `json:"schema_version"`},
		{"Scope", reflect.TypeOf(""), `json:"scope_identity"`},
		{"Session", reflect.TypeOf(""), `json:"session_identity"`},
		{"HeadArtifact", reflect.TypeOf(""), `json:"snapshot_artifact_identity"`},
		{"Head", reflect.TypeOf(""), `json:"snapshot_identity"`},
		{"SnapshotRef", reflect.TypeOf(""), `json:"snapshot_ref"`},
		{"Sources", reflect.TypeOf([]toolRecordSource{}), `json:"sources" limit:"64"`},
		{"Start", reflect.TypeOf(int(0)), `json:"start_line"`},
		{"Tool", reflect.TypeOf(""), `json:"tool"`},
		{"TurnArtifact", reflect.TypeOf(""), `json:"turn_artifact_identity"`},
		{"Turn", reflect.TypeOf(""), `json:"turn_identity"`},
	},
	{
		{"Digest", reflect.TypeOf(""), `json:"digest"`},
		{"Artifact", reflect.TypeOf(""), `json:"file_artifact_identity"`},
		{"Path", reflect.TypeOf(""), `json:"path" limit:"4096"`},
		{"Ref", reflect.TypeOf(""), `json:"ref"`},
		{"Size", reflect.TypeOf(int(0)), `json:"size_bytes"`},
	},
	{
		{"Binding", reflect.TypeOf(""), `json:"binding_identity"`},
		{"Content", reflect.TypeOf(""), `json:"content" limit:"65536"`},
		{"End", reflect.TypeOf(int(0)), `json:"end_line"`},
		{"FileRef", reflect.TypeOf(""), `json:"file_ref"`},
		{"Path", reflect.TypeOf(""), `json:"path" limit:"4096"`},
		{"FileDigest", reflect.TypeOf(""), `json:"repository_file_digest"`},
		{"FileIdentity", reflect.TypeOf(""), `json:"repository_file_identity"`},
		{"SliceBytes", reflect.TypeOf(int(0)), `json:"slice_bytes"`},
		{"SliceDigest", reflect.TypeOf(""), `json:"slice_digest"`},
		{"Start", reflect.TypeOf(int(0)), `json:"start_line"`},
	},
	{
		{"Ref", reflect.TypeOf(""), `json:"ref"`},
		{"Path", reflect.TypeOf(""), `json:"path"`},
		{"Digest", reflect.TypeOf(""), `json:"digest"`},
		{"Size", reflect.TypeOf(int(0)), `json:"size_bytes"`},
		{"Artifact", reflect.TypeOf(""), `json:"file_artifact_identity"`},
	},
	{
		{"File", reflect.TypeOf(toolReaderFileWire{}), `json:"file"`},
		{"Start", reflect.TypeOf(int(0)), `json:"start_line"`},
		{"End", reflect.TypeOf(int(0)), `json:"end_line"`},
		{"Binding", reflect.TypeOf(""), `json:"binding_identity"`},
		{"Content", reflect.TypeOf(""), `json:"content"`},
	},
}

// Exact field/type/tag checks reject new or moved codec fields before arithmetic.
func investigationToolSizeSchema(types ...reflect.Type) bool {
	if len(types) != len(investigationToolSizeFields) {
		return false
	}
	for i, typ := range types {
		if typ == nil || typ.Kind() != reflect.Struct || typ.NumField() != len(investigationToolSizeFields[i]) {
			return false
		}
		for j, expected := range investigationToolSizeFields[i] {
			actual := typ.Field(j)
			if actual.Name != expected.name || actual.Type != expected.typeOf || actual.Tag != expected.tag || actual.Anonymous || actual.PkgPath != "" {
				return false
			}
			key, _, _ := strings.Cut(actual.Tag.Get("json"), ",")
			if key == "" {
				return false
			}
		}
	}
	return true
}
