package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// The sanitizable wire shapes are frozen: a field added to either context wire
// must be classified for scanning first. A removed_lines source's head_line is
// a number, not text, so it carries nothing to scan. Each stated_intent commit
// text is scanned as stated_intent_text; its commit ID, sizes and markers are
// host-derived. pattern_hygiene carries only kinds, curated rule IDs,
// host-issued source IDs and numbers, and context_manifest and
// repository_checks carry only host-issued source IDs, closed tokens and
// numbers, so they add no scanned field. Each check_runs run name, reason,
// regression ID, new-failure ID and stopped-running ID is repository text,
// scanned as check_run_text; its source, authority, commit IDs, scope,
// states and counts are host-derived.
const (
	generationSanitizableWireShapeIdentity   = "83799952c5ceaf3cdf9949c4cd4b5c876f2f8efd8050795c1ea7683c0c7df9c8"
	verificationSanitizableWireShapeIdentity = "e44e027d955433d371fa81cbc2ed5ac2178acb05ab387cb97b3f275f8794a22f"
)

func wireShapeIdentity(root reflect.Type) string {
	var describe func(reflect.Type) string
	describe = func(value reflect.Type) string {
		switch value.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			return value.Kind().String() + "(" + describe(value.Elem()) + ")"
		case reflect.Struct:
			parts := make([]string, value.NumField())
			for index := 0; index < value.NumField(); index++ {
				field := value.Field(index)
				parts[index] = field.Name + ":" + field.Tag.Get("json") + ":" + describe(field.Type)
			}
			return value.Name() + "{" + strings.Join(parts, ",") + "}"
		default:
			return value.Kind().String()
		}
	}
	digest := sha256.Sum256([]byte(describe(root)))
	return hex.EncodeToString(digest[:])
}

func sanitizedWireShapeIdentity() string {
	return wireShapeIdentity(reflect.TypeOf(contextPacketWire{}))
}
func verificationWireShapeIdentity() string {
	return wireShapeIdentity(reflect.TypeOf(verificationContextWire{}))
}

type sanitizedFieldReference struct {
	role  FieldRole
	value *string
}

type sanitizedRequestDocument struct {
	generation   *contextPacketWire
	verification *verificationContextWire
	fields       []sanitizedFieldReference
}

func parseSanitizableRequest(request provider.Request, reviewScopeIdentity string) (sanitizedRequestDocument, error) {
	if request.Validate() != nil || request.MediaType() != "application/json" {
		return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
	}
	var header struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
	}
	// Each contract is checked against its own version below too.
	if json.Unmarshal(request.Payload(), &header) != nil ||
		header.Contract == "open-trestle/review-context-packet" && header.SchemaVersion != modelGenerationContextVersion ||
		header.Contract == "open-trestle/verification-context-packet" && header.SchemaVersion != modelVerificationContextVersion {
		return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
	}
	switch header.Contract {
	case "open-trestle/review-context-packet":
		if sanitizedWireShapeIdentity() != generationSanitizableWireShapeIdentity || ValidateCandidateModelRequest(request, reviewScopeIdentity) != nil {
			return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
		}
		wire, err := decodeGenerationContextWire(request.Payload())
		// The specialist block carries only packaged profile identity fields, not
		// repository data, so it adds no scanned field; it is carried through the
		// projection unchanged. That exemption holds only for a block that
		// re-derives exactly from the embedded catalog, so any other block is
		// refused before egress.
		if err != nil || wire.Contract != header.Contract || wire.SchemaVersion != header.SchemaVersion || wire.Task != ContextTaskCandidateGeneration.String() || !validGenerationContextSpecialist(wire) {
			return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
		}
		document := sanitizedRequestDocument{generation: &wire}
		document.fields = appendContextFieldReferences(document.fields, &wire.Sources, &wire.SourceOmissions, &wire.Memory, wire.AdditionalMemory)
		document.fields = appendStatedIntentFieldReferences(document.fields, wire.StatedIntent)
		document.fields = appendCheckRunsFieldReferences(document.fields, wire.CheckRuns)
		return document, nil
	case "open-trestle/verification-context-packet":
		if verificationWireShapeIdentity() != verificationSanitizableWireShapeIdentity || ValidateVerificationModelRequest(request, reviewScopeIdentity) != nil {
			return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
		}
		wire, err := decodeVerificationContextWire(request.Payload())
		if err != nil || wire.SchemaVersion != modelVerificationContextVersion || wire.Task != "candidate_verification" {
			return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
		}
		document := sanitizedRequestDocument{verification: &wire}
		document.fields = appendContextFieldReferences(document.fields, &wire.Sources, &wire.SourceOmissions, &wire.Memory, wire.AdditionalMemory)
		document.fields = appendStatedIntentFieldReferences(document.fields, wire.StatedIntent)
		document.fields = appendCheckRunsFieldReferences(document.fields, wire.CheckRuns)
		for index := range wire.Candidates {
			candidate := &wire.Candidates[index]
			document.fields = append(document.fields,
				sanitizedFieldReference{FieldRoleCandidateTitle, &candidate.Title},
				sanitizedFieldReference{FieldRoleCandidateClaim, &candidate.Claim},
				sanitizedFieldReference{FieldRoleCandidatePath, &candidate.Path},
			)
		}
		return document, nil
	default:
		return sanitizedRequestDocument{}, ErrInvalidSanitizedModelRequest
	}
}

func appendContextFieldReferences(fields []sanitizedFieldReference, sources *[]contextSourceWire, omissions *[]contextSourceOmissionWire, memoryValue *contextMemoryWire, additional []contextMemoryWire) []sanitizedFieldReference {
	for index := range *sources {
		source := &(*sources)[index]
		fields = append(fields,
			sanitizedFieldReference{FieldRoleSourcePath, &source.Path},
			sanitizedFieldReference{FieldRoleSourceContent, &source.Content},
		)
	}
	for index := range *omissions {
		fields = append(fields, sanitizedFieldReference{FieldRoleSourceOmissionPath, &(*omissions)[index].Path})
	}
	fields = appendMemoryFieldReferences(fields, memoryValue)
	for index := range additional {
		fields = appendMemoryFieldReferences(fields, &additional[index])
	}
	return fields
}

// appendStatedIntentFieldReferences adds one field per commit that has text.
// Scanning can redact part of a message; the redacted text then no longer
// matches its recorded risk flags, which name what the host saw before egress.
func appendStatedIntentFieldReferences(fields []sanitizedFieldReference, intent *statedIntentWire) []sanitizedFieldReference {
	if intent == nil {
		return fields
	}
	for index := range intent.Commits {
		if intent.Commits[index].Text != "" {
			fields = append(fields, sanitizedFieldReference{FieldRoleStatedIntentText, &intent.Commits[index].Text})
		}
	}
	return fields
}

// appendCheckRunsFieldReferences adds, for each run in order, its name, its
// reason when it has one, then each regression, new-failure and
// stopped-running test ID.
// Masking keeps every value's length, so the object stays within its bounds
// after scanning.
func appendCheckRunsFieldReferences(fields []sanitizedFieldReference, runs *checkRunsWire) []sanitizedFieldReference {
	if runs == nil {
		return fields
	}
	for index := range runs.Runs {
		run := &runs.Runs[index]
		fields = append(fields, sanitizedFieldReference{FieldRoleCheckRunText, &run.Name})
		if run.Reason != "" {
			fields = append(fields, sanitizedFieldReference{FieldRoleCheckRunText, &run.Reason})
		}
		for _, ids := range [][]string{run.Regressions, run.NewFailures, run.StoppedRunning} {
			for idIndex := range ids {
				fields = append(fields, sanitizedFieldReference{FieldRoleCheckRunText, &ids[idIndex]})
			}
		}
	}
	return fields
}

func appendMemoryFieldReferences(fields []sanitizedFieldReference, memoryValue *contextMemoryWire) []sanitizedFieldReference {
	for itemIndex := range memoryValue.Items {
		item := &memoryValue.Items[itemIndex]
		fields = append(fields, sanitizedFieldReference{FieldRoleMemoryPath, &item.Path})
		for symbolIndex := range item.Symbols {
			fields = append(fields, sanitizedFieldReference{FieldRoleMemorySymbol, &item.Symbols[symbolIndex]})
		}
		fields = append(fields, sanitizedFieldReference{FieldRoleMemoryText, &item.Text})
	}
	return fields
}

func (document sanitizedRequestDocument) encode() ([]byte, error) {
	if document.generation != nil && document.verification == nil {
		return json.Marshal(document.generation)
	}
	if document.verification != nil && document.generation == nil {
		return json.Marshal(document.verification)
	}
	return nil, ErrInvalidSanitizedModelRequest
}

func projectSanitizedRequestPayload(raw provider.Request, reviewScopeIdentity string, fields []SanitizedField) ([]byte, error) {
	document, err := parseSanitizableRequest(raw, reviewScopeIdentity)
	if err != nil || len(document.fields) != len(fields) || len(document.fields) < 1 || len(document.fields) > maximumSanitizedFields {
		return nil, ErrInvalidSanitizedEgressArtifacts
	}
	for index, reference := range document.fields {
		field := fields[index]
		original := []byte(*reference.value)
		if field.Ordinal != index || field.Role != reference.role || field.ScannedByteCount != len(original) {
			return nil, ErrInvalidSanitizedEgressArtifacts
		}
		sanitized, redacted, ok := sanitizeReceiptField(original, field.Matches)
		if !ok || redacted != field.RedactedByteCount {
			return nil, ErrInvalidSanitizedEgressArtifacts
		}
		*reference.value = string(sanitized)
	}
	encoded, err := document.encode()
	if err != nil {
		return nil, ErrInvalidSanitizedEgressArtifacts
	}
	return encoded, nil
}

func validateSanitizedRequestProjection(raw provider.Request, request SanitizedModelRequest, receipt SanitizedEgressReceipt) error {
	expected, err := projectSanitizedRequestPayload(raw, request.ReviewScopeIdentity(), receipt.fields)
	if err != nil || !bytes.Equal(expected, request.request.Payload()) {
		return ErrInvalidSanitizedEgressArtifacts
	}
	return nil
}

func sanitizeReceiptField(original []byte, matches []secretscan.Match) ([]byte, int, bool) {
	if !utf8.Valid(original) || matches == nil {
		return nil, 0, false
	}
	sanitized := append([]byte(nil), original...)
	type interval struct{ start, end int }
	intervals := make([]interval, 0, len(matches))
	for _, match := range matches {
		if match.StartByte < 0 || match.EndByteExclusive <= match.StartByte || match.EndByteExclusive > len(original) || !sanitizedUTF8Boundary(original, match.StartByte) || !sanitizedUTF8Boundary(original, match.EndByteExclusive) {
			return nil, 0, false
		}
		next := interval{match.StartByte, match.EndByteExclusive}
		if len(intervals) == 0 || next.start > intervals[len(intervals)-1].end {
			intervals = append(intervals, next)
		} else if next.end > intervals[len(intervals)-1].end {
			intervals[len(intervals)-1].end = next.end
		}
	}
	redacted := 0
	for _, span := range intervals {
		for offset := span.start; offset < span.end; offset++ {
			if sanitized[offset] == '\r' || sanitized[offset] == '\n' {
				continue
			}
			sanitized[offset] = '*'
			redacted++
		}
	}
	return sanitized, redacted, utf8.Valid(sanitized)
}

func sanitizedUTF8Boundary(value []byte, offset int) bool {
	return offset == 0 || offset == len(value) || utf8.RuneStart(value[offset])
}
