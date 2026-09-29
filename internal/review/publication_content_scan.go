package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

var (
	ErrPublicationContentScanUnavailable = errors.New("publication content scan unavailable")
	ErrInvalidPublicationContentScan     = errors.New("invalid publication content scan receipt")
	ErrPublicationContentScanMismatch    = errors.New("publication content scan binding mismatch")
	ErrUnclassifiedPublishableField      = errors.New("unclassified publishable field")
)

// PublicationFieldKind identifies one model-authored string that a publisher can render.
type PublicationFieldKind uint8

const (
	PublicationFieldTitle PublicationFieldKind = iota + 1
	PublicationFieldClaim
	PublicationFieldPath
)

func (kind PublicationFieldKind) String() string {
	switch kind {
	case PublicationFieldTitle:
		return "title"
	case PublicationFieldClaim:
		return "claim"
	case PublicationFieldPath:
		return "path"
	default:
		return ""
	}
}

func (kind PublicationFieldKind) Validate() error {
	if kind.String() == "" {
		return ErrUnclassifiedPublishableField
	}
	return nil
}

type verifiedFindingStringFieldClass uint8

const (
	verifiedFindingIdentityField verifiedFindingStringFieldClass = iota + 1
	verifiedFindingPublishableField
	verifiedFindingStructuredField
)

var verifiedFindingStringFieldClasses = map[string]verifiedFindingStringFieldClass{
	"identity": verifiedFindingIdentityField, "fingerprint": verifiedFindingIdentityField,
	"independentReceiptIdentity": verifiedFindingIdentityField, "snapshotIdentity": verifiedFindingIdentityField,
	"candidateIdentity": verifiedFindingIdentityField, "verificationIdentity": verifiedFindingIdentityField,
	"title": verifiedFindingPublishableField, "claim": verifiedFindingPublishableField, "severity": verifiedFindingStructuredField,
}

func validateVerifiedFindingStringFieldFreeze() error {
	typeOfFinding := reflect.TypeOf(VerifiedFinding{})
	seen := make(map[string]struct{}, len(verifiedFindingStringFieldClasses))
	for index := 0; index < typeOfFinding.NumField(); index++ {
		field := typeOfFinding.Field(index)
		if field.Type.Kind() != reflect.String {
			continue
		}
		class, exists := verifiedFindingStringFieldClasses[field.Name]
		if !exists || class != verifiedFindingIdentityField && class != verifiedFindingPublishableField && class != verifiedFindingStructuredField {
			return ErrUnclassifiedPublishableField
		}
		seen[field.Name] = struct{}{}
	}
	for name := range verifiedFindingStringFieldClasses {
		if _, exists := seen[name]; !exists {
			return ErrUnclassifiedPublishableField
		}
	}
	return nil
}

// PublishableFinding is the frozen model-text projection shared by scanning and rendering.
type PublishableFinding struct {
	findingIdentity string
	title           string
	claim           string
	path            string
	severity        Severity
	startLine       int
	endLine         int
}

var publishableFindingStringFieldClasses = map[string]verifiedFindingStringFieldClass{
	"findingIdentity": verifiedFindingIdentityField,
	"title":           verifiedFindingPublishableField,
	"claim":           verifiedFindingPublishableField,
	"path":            verifiedFindingPublishableField,
	"severity":        verifiedFindingStructuredField,
}

func validatePublishableFindingFieldFreeze() error {
	typeOfFinding := reflect.TypeOf(PublishableFinding{})
	seen := make(map[string]struct{}, len(publishableFindingStringFieldClasses))
	for index := 0; index < typeOfFinding.NumField(); index++ {
		field := typeOfFinding.Field(index)
		if field.Type.Kind() != reflect.String {
			continue
		}
		class, exists := publishableFindingStringFieldClasses[field.Name]
		if !exists || class != verifiedFindingIdentityField && class != verifiedFindingPublishableField && class != verifiedFindingStructuredField {
			return ErrUnclassifiedPublishableField
		}
		seen[field.Name] = struct{}{}
	}
	for name := range publishableFindingStringFieldClasses {
		if _, exists := seen[name]; !exists {
			return ErrUnclassifiedPublishableField
		}
	}
	return nil
}

func (finding PublishableFinding) FindingIdentity() string { return finding.findingIdentity }
func (finding PublishableFinding) Title() string           { return finding.title }
func (finding PublishableFinding) Claim() string           { return finding.claim }
func (finding PublishableFinding) Path() string            { return finding.path }
func (finding PublishableFinding) Severity() Severity      { return finding.severity }
func (finding PublishableFinding) StartLine() int          { return finding.startLine }
func (finding PublishableFinding) EndLine() int            { return finding.endLine }

func publishableFindings(findings []VerifiedFinding) ([]PublishableFinding, error) {
	if err := validatePublishableFindingFieldFreeze(); err != nil {
		return nil, err
	}
	values := make([]PublishableFinding, len(findings))
	for index, finding := range findings {
		if finding.Validate() != nil {
			return nil, ErrUnclassifiedPublishableField
		}
		source := finding.SourceRange()
		values[index] = PublishableFinding{findingIdentity: finding.Identity(), title: finding.Title(), claim: finding.Claim(), path: source.Path(), severity: finding.Severity(), startLine: source.StartLine(), endLine: source.EndLine()}
	}
	return values, nil
}

type publicationField struct {
	kind            PublicationFieldKind
	ordinal         int
	findingIdentity string
	content         []byte
}

func publicationFields(selection PublicationSelection) ([]publicationField, error) {
	if err := validateVerifiedFindingStringFieldFreeze(); err != nil {
		return nil, err
	}
	if err := selection.Validate(); err != nil || selection.Status() != PublicationAdvisoryReady {
		return nil, ErrInvalidPublicationSelection
	}
	projection := append(selection.InlinePublishableFindings(), selection.SummaryOnlyPublishableFindings()...)
	fields := make([]publicationField, 0, len(projection)*3)
	for _, finding := range projection {
		values := []struct {
			kind  PublicationFieldKind
			value string
		}{
			{PublicationFieldTitle, finding.Title()},
			{PublicationFieldClaim, finding.Claim()},
			{PublicationFieldPath, finding.Path()},
		}
		for _, value := range values {
			fields = append(fields, publicationField{
				kind: value.kind, ordinal: len(fields), findingIdentity: finding.FindingIdentity(),
				content: []byte(value.value),
			})
		}
	}
	if len(fields) == 0 {
		return nil, ErrInvalidPublicationContentScan
	}
	return fields, nil
}

func clearPublicationFields(fields []publicationField) {
	for index := range fields {
		clear(fields[index].content)
	}
	clear(fields)
}

type PublicationScannedField struct {
	Kind             PublicationFieldKind
	Ordinal          int
	FindingIdentity  string
	ScannedByteCount int
}

type PublicationRiskField struct {
	Kind            PublicationFieldKind
	Ordinal         int
	FindingIdentity string
}

// PublicationContentScanReceipt is content-free evidence for all rendered model strings.
type PublicationContentScanReceipt struct {
	identity                    string
	reviewScopeIdentity         string
	verifiedFindingSetIdentity  string
	selectionIdentity           string
	publicationPolicyIdentity   string
	verificationContextIdentity string
	scannerAuthorityIdentity    string
	scanner                     ScannerProfile
	initial                     ScanCompletion
	residual                    ScanCompletion
	fields                      []PublicationScannedField
	instructionRiskEvidence     []string
	instructionRiskFields       []PublicationRiskField
}

func (receipt PublicationContentScanReceipt) Identity() string { return receipt.identity }
func (receipt PublicationContentScanReceipt) ReviewScopeIdentity() string {
	return receipt.reviewScopeIdentity
}
func (receipt PublicationContentScanReceipt) VerifiedFindingSetIdentity() string {
	return receipt.verifiedFindingSetIdentity
}
func (receipt PublicationContentScanReceipt) SelectionIdentity() string {
	return receipt.selectionIdentity
}
func (receipt PublicationContentScanReceipt) PolicyIdentity() string {
	return receipt.publicationPolicyIdentity
}
func (receipt PublicationContentScanReceipt) VerificationContextIdentity() string {
	return receipt.verificationContextIdentity
}
func (receipt PublicationContentScanReceipt) ScannerAuthorityIdentity() string {
	return receipt.scannerAuthorityIdentity
}
func (receipt PublicationContentScanReceipt) Scanner() ScannerProfile  { return receipt.scanner }
func (receipt PublicationContentScanReceipt) Initial() ScanCompletion  { return receipt.initial }
func (receipt PublicationContentScanReceipt) Residual() ScanCompletion { return receipt.residual }
func (receipt PublicationContentScanReceipt) Fields() []PublicationScannedField {
	return append([]PublicationScannedField(nil), receipt.fields...)
}
func (receipt PublicationContentScanReceipt) InstructionRiskEvidence() []string {
	return append([]string(nil), receipt.instructionRiskEvidence...)
}
func (receipt PublicationContentScanReceipt) InstructionRiskFields() []PublicationRiskField {
	return append([]PublicationRiskField(nil), receipt.instructionRiskFields...)
}
func (receipt PublicationContentScanReceipt) HasInstructionRisk() bool {
	return len(receipt.instructionRiskEvidence) != 0 || len(receipt.instructionRiskFields) != 0
}
func (receipt PublicationContentScanReceipt) String() string {
	return "publication content scan receipt"
}
func (receipt PublicationContentScanReceipt) GoString() string {
	return "review.PublicationContentScanReceipt{<redacted>}"
}
func (receipt PublicationContentScanReceipt) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, receipt.String(), receipt.GoString())
}

func (receipt PublicationContentScanReceipt) Validate() error {
	if !validCandidateDigest(receipt.identity) || !validCandidateDigest(receipt.reviewScopeIdentity) ||
		!validCandidateDigest(receipt.verifiedFindingSetIdentity) || !validCandidateDigest(receipt.selectionIdentity) || !validCandidateDigest(receipt.publicationPolicyIdentity) || !validCandidateDigest(receipt.verificationContextIdentity) || !validCandidateDigest(receipt.scannerAuthorityIdentity) ||
		!validScannerProfile(receipt.scanner) || receipt.scannerAuthorityIdentity != PublicationContentScannerIdentity(receipt.scanner) || len(receipt.fields) < 1 || len(receipt.fields) > maxCandidateFindings*3 {
		return ErrInvalidPublicationContentScan
	}
	totalBytes := 0
	for index, field := range receipt.fields {
		if field.Kind.Validate() != nil || field.Ordinal != index || !validCandidateDigest(field.FindingIdentity) ||
			field.ScannedByteCount < 1 || field.ScannedByteCount > maximumSanitizedFieldBytes {
			return ErrInvalidPublicationContentScan
		}
		totalBytes += field.ScannedByteCount
		if totalBytes > maximumSanitizedAggregateBytes {
			return ErrInvalidPublicationContentScan
		}
	}
	if !receipt.initial.Complete || !receipt.residual.Complete || receipt.initial.FieldCount != len(receipt.fields) ||
		receipt.residual.FieldCount != len(receipt.fields) || receipt.initial.ScannedByteCount != totalBytes ||
		receipt.residual.ScannedByteCount != totalBytes || receipt.initial.MatchCount < 0 || receipt.residual.MatchCount != 0 {
		return ErrInvalidPublicationContentScan
	}
	previous := ""
	for _, identity := range receipt.instructionRiskEvidence {
		if !validCandidateDigest(identity) || previous != "" && identity <= previous {
			return ErrInvalidPublicationContentScan
		}
		previous = identity
	}
	previousOrdinal := -1
	for _, field := range receipt.instructionRiskFields {
		if field.Kind.Validate() != nil || field.Ordinal <= previousOrdinal || field.Ordinal >= len(receipt.fields) || !validCandidateDigest(field.FindingIdentity) {
			return ErrInvalidPublicationContentScan
		}
		scanned := receipt.fields[field.Ordinal]
		if scanned.Kind != field.Kind || scanned.FindingIdentity != field.FindingIdentity {
			return ErrInvalidPublicationContentScan
		}
		previousOrdinal = field.Ordinal
	}
	if receipt.identity != derivePublicationContentScanReceiptIdentity(receipt) {
		return ErrInvalidPublicationContentScan
	}
	return nil
}

func (receipt PublicationContentScanReceipt) validateFor(independent IndependentVerificationReceipt, set VerifiedFindingSet, verificationContext PublicationVerificationContext, selection PublicationSelection) error {
	if receipt.Validate() != nil || independent.Validate() != nil || set.Validate() != nil || verificationContext.Validate() != nil || selection.Validate() != nil {
		return ErrPublicationContentScanMismatch
	}
	if receipt.reviewScopeIdentity != independent.ReviewScopeIdentity() || receipt.verifiedFindingSetIdentity != set.Identity() ||
		receipt.selectionIdentity != selection.Identity() || receipt.publicationPolicyIdentity != selection.PolicyIdentity() || selection.VerifiedFindingSetIdentity() != set.Identity() || selection.VerificationReceiptIdentity() != independent.Identity() ||
		receipt.verificationContextIdentity != verificationContext.Identity() || independent.VerificationContextIdentity() != verificationContext.Identity() ||
		set.IndependentReceiptIdentity() != independent.Identity() {
		return ErrPublicationContentScanMismatch
	}
	expectedFields, err := publicationFields(selection)
	if err != nil || len(expectedFields) != len(receipt.fields) {
		return ErrPublicationContentScanMismatch
	}
	for index, expected := range expectedFields {
		actual := receipt.fields[index]
		if actual.Kind != expected.kind || actual.Ordinal != expected.ordinal || actual.FindingIdentity != expected.findingIdentity ||
			actual.ScannedByteCount != len(expected.content) {
			return ErrPublicationContentScanMismatch
		}
	}
	if !equalPublicationRiskEvidence(receipt.instructionRiskEvidence, publicationInstructionRiskEvidence(verificationContext)) ||
		!equalPublicationRiskFields(receipt.instructionRiskFields, publicationInstructionRiskFields(expectedFields)) {
		return ErrPublicationContentScanMismatch
	}
	return nil
}

func publicationInstructionRiskEvidence(context PublicationVerificationContext) []string {
	values := make([]string, 0)
	switch value := context.(type) {
	case VerificationContextPacket:
		for _, source := range value.generationContext.sources {
			if source.HasRisk(ContextRiskInstructionLikeText) || source.HasRisk(ContextRiskHiddenUnicode) {
				item := source.EvidenceItem()
				values = append(values, publicationRiskEvidenceIdentity(item.Digest(), item.SourceRange().Path(), item.SourceRange().StartLine(), item.SourceRange().EndLine()))
			}
		}
	case VerificationRequestContext:
		wire, err := decodeVerificationContextWire([]byte(value.payload))
		if err != nil {
			return []string{"invalid"}
		}
		for _, source := range wire.Sources {
			if len(source.RiskFlags) != 0 {
				values = append(values, publicationRiskEvidenceIdentity(source.EvidenceDigest, source.Path, source.StartLine, source.EndLine))
			}
		}
	default:
		return []string{"invalid"}
	}
	sort.Strings(values)
	if len(values) == 0 {
		return nil
	}
	return values
}
func publicationRiskEvidenceIdentity(digest, path string, startLine, endLine int) string {
	encoded, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Digest    string `json:"digest"`
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}{"open-trestle/publication-instruction-risk-evidence", 1, digest, path, startLine, endLine})
	identity := sha256.Sum256(encoded)
	return hex.EncodeToString(identity[:])
}

func equalPublicationRiskEvidence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func publicationInstructionRiskFields(fields []publicationField) []PublicationRiskField {
	values := make([]PublicationRiskField, 0)
	for _, field := range fields {
		if detectContextRisks(string(field.content)) != 0 {
			values = append(values, PublicationRiskField{Kind: field.kind, Ordinal: field.ordinal, FindingIdentity: field.findingIdentity})
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func equalPublicationRiskFields(left, right []PublicationRiskField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// PublicationVerificationContext is the validated verifier evidence boundary used by publication checks.
type PublicationVerificationContext interface {
	Identity() string
	ReviewScopeIdentity() string
	Validate() error
}

// NewPublicationContentScanReceipt records a completed content-free scan for exact verified fields.
func NewPublicationContentScanReceipt(independent IndependentVerificationReceipt, set VerifiedFindingSet, verificationContext PublicationVerificationContext, selection PublicationSelection, scanner ScannerProfile, initial, residual ScanCompletion) (PublicationContentScanReceipt, error) {
	if independent.Validate() != nil || set.Validate() != nil || verificationContext == nil || verificationContext.Validate() != nil || selection.Validate() != nil || !validScannerProfile(scanner) {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	fields, err := publicationFields(selection)
	if err != nil {
		return PublicationContentScanReceipt{}, err
	}
	defer clearPublicationFields(fields)
	receiptFields := make([]PublicationScannedField, len(fields))
	for index, field := range fields {
		receiptFields[index] = PublicationScannedField{Kind: field.kind, Ordinal: field.ordinal, FindingIdentity: field.findingIdentity, ScannedByteCount: len(field.content)}
	}
	receipt := PublicationContentScanReceipt{
		reviewScopeIdentity: independent.ReviewScopeIdentity(), verifiedFindingSetIdentity: set.Identity(), selectionIdentity: selection.Identity(), publicationPolicyIdentity: selection.PolicyIdentity(),
		verificationContextIdentity: verificationContext.Identity(), scannerAuthorityIdentity: PublicationContentScannerIdentity(scanner), scanner: scanner, initial: initial, residual: residual,
		fields: receiptFields, instructionRiskEvidence: publicationInstructionRiskEvidence(verificationContext), instructionRiskFields: publicationInstructionRiskFields(fields),
	}
	receipt.identity = derivePublicationContentScanReceiptIdentity(receipt)
	if receipt.validateFor(independent, set, verificationContext, selection) != nil {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	return receipt, nil
}

// PublicationContentScanner scans the exact publishable projection without changing source artifacts.
type PublicationContentScanner interface {
	Identity() string
	Scan(context.Context, IndependentVerificationReceipt, VerifiedFindingSet, PublicationVerificationContext, PublicationSelection) (PublicationContentScanReceipt, error)
}

type FixedPublicationContentScanner struct {
	client   sanitizedScanClient
	identity string
}

func NewFixedPublicationContentScanner() *FixedPublicationContentScanner {
	return newFixedPublicationContentScanner(fixedSecretScanClient{client: secretscan.NewClient()})
}

func newFixedPublicationContentScanner(client sanitizedScanClient) *FixedPublicationContentScanner {
	value := &FixedPublicationContentScanner{client: client}
	value.identity = derivePublicationContentScannerIdentity(value.expectedDigests())
	return value
}

func (scanner *FixedPublicationContentScanner) expectedDigests() ScannerBinaryDigests {
	if scanner == nil || scanner.client == nil {
		return ScannerBinaryDigests{}
	}
	launcher, worker := scanner.client.BinaryDigests()
	return ScannerBinaryDigests{LauncherSHA256: launcher, WorkerSHA256: worker}
}

func (scanner *FixedPublicationContentScanner) Identity() string {
	if scanner == nil {
		return ""
	}
	return scanner.identity
}

func (scanner *FixedPublicationContentScanner) Scan(ctx context.Context, independent IndependentVerificationReceipt, set VerifiedFindingSet, verificationContext PublicationVerificationContext, selection PublicationSelection) (PublicationContentScanReceipt, error) {
	if scanner == nil || scanner.client == nil || ctx == nil || ctx.Err() != nil || scanner.identity != derivePublicationContentScannerIdentity(scanner.expectedDigests()) || !scanner.expectedDigests().validate() || independent.Validate() != nil || set.Validate() != nil || verificationContext.Validate() != nil || selection.Validate() != nil {
		return PublicationContentScanReceipt{}, ErrPublicationContentScanUnavailable
	}
	if set.IndependentReceiptIdentity() != independent.Identity() || selection.VerifiedFindingSetIdentity() != set.Identity() || selection.VerificationReceiptIdentity() != independent.Identity() || selection.Status() != PublicationAdvisoryReady || independent.VerificationContextIdentity() != verificationContext.Identity() || independent.ReviewScopeIdentity() != verificationContext.ReviewScopeIdentity() {
		return PublicationContentScanReceipt{}, ErrPublicationContentScanMismatch
	}
	fields, err := publicationFields(selection)
	if err != nil {
		return PublicationContentScanReceipt{}, ErrPublicationContentScanUnavailable
	}
	defer clearPublicationFields(fields)
	sources := make([][]byte, len(fields))
	for index := range fields {
		sources[index] = append([]byte(nil), fields[index].content...)
	}
	defer clearSanitizerSources(sources)
	projection := scanner.client.Sanitize(ctx, sources)
	if !projection.Complete() {
		return PublicationContentScanReceipt{}, sanitizationError(projection.Failure())
	}
	initial, residual := projection.Initial(), projection.Residual()
	expected := scanner.expectedDigests()
	if !validProjectionMetadata(initial, expected, len(fields)) || !validProjectionMetadata(residual, expected, len(fields)) ||
		initial.ScannedByteCount != residual.ScannedByteCount || residual.MatchCount != 0 || initial.MatchCount != len(projection.Matches()) {
		return PublicationContentScanReceipt{}, ErrPublicationContentScanUnavailable
	}
	receipt, err := NewPublicationContentScanReceipt(
		independent, set, verificationContext, selection,
		ScannerProfile{WorkerProtocol: 1, Scanner: initial.Scanner, ScannerVersion: initial.ScannerVersion,
			ScannerCommit: initial.ScannerCommit, RulesetIdentity: initial.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount,
			BuildProfile: initial.BuildProfile, LauncherSHA256: initial.LauncherSHA256, WorkerSHA256: initial.WorkerSHA256},
		ScanCompletion{Complete: true, FieldCount: initial.SourceCount, ScannedByteCount: initial.ScannedByteCount, MatchCount: initial.MatchCount},
		ScanCompletion{Complete: true, FieldCount: residual.SourceCount, ScannedByteCount: residual.ScannedByteCount, MatchCount: residual.MatchCount},
	)
	if err != nil {
		return PublicationContentScanReceipt{}, ErrPublicationContentScanUnavailable
	}
	return receipt, nil
}

func PublicationContentScannerIdentity(profile ScannerProfile) string {
	return derivePublicationContentScannerIdentity(ScannerBinaryDigests{LauncherSHA256: profile.LauncherSHA256, WorkerSHA256: profile.WorkerSHA256})
}

func derivePublicationContentScannerIdentity(digests ScannerBinaryDigests) string {
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Scanner  string `json:"scanner"`
		Profile  string `json:"profile"`
		Launcher string `json:"launcher"`
		Worker   string `json:"worker"`
	}{"open-trestle/publication-content-scanner", 1, secretscan.ScannerName, secretscan.BuildProfile, digests.LauncherSHA256, digests.WorkerSHA256})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func derivePublicationContentScanReceiptIdentity(receipt PublicationContentScanReceipt) string {
	type scannerWire struct {
		WorkerProtocol   int    `json:"worker_protocol"`
		Scanner          string `json:"scanner"`
		ScannerVersion   string `json:"scanner_version"`
		ScannerCommit    string `json:"scanner_commit"`
		RulesetIdentity  string `json:"ruleset_identity"`
		RulesetRuleCount int    `json:"ruleset_rule_count"`
		BuildProfile     string `json:"build_profile"`
		LauncherSHA256   string `json:"launcher_sha256"`
		WorkerSHA256     string `json:"worker_sha256"`
	}
	type completionWire struct {
		Complete         bool `json:"complete"`
		FieldCount       int  `json:"field_count"`
		ScannedByteCount int  `json:"scanned_byte_count"`
		MatchCount       int  `json:"match_count"`
	}
	type fieldWire struct {
		Kind    string `json:"kind"`
		Ordinal int    `json:"ordinal"`
		Finding string `json:"finding"`
		Bytes   int    `json:"bytes"`
	}
	type riskFieldWire struct {
		Kind    string `json:"kind"`
		Ordinal int    `json:"ordinal"`
		Finding string `json:"finding"`
	}
	fields := make([]fieldWire, len(receipt.fields))
	for index, field := range receipt.fields {
		fields[index] = fieldWire{field.Kind.String(), field.Ordinal, field.FindingIdentity, field.ScannedByteCount}
	}
	riskFields := make([]riskFieldWire, len(receipt.instructionRiskFields))
	for index, field := range receipt.instructionRiskFields {
		riskFields[index] = riskFieldWire{field.Kind.String(), field.Ordinal, field.FindingIdentity}
	}
	scanner := receipt.scanner
	initial, residual := receipt.initial, receipt.residual
	encoded, _ := json.Marshal(struct {
		Contract              string          `json:"contract"`
		Version               int             `json:"version"`
		Scope                 string          `json:"scope"`
		Set                   string          `json:"set"`
		Selection             string          `json:"selection"`
		Policy                string          `json:"policy"`
		Context               string          `json:"context"`
		ScannerAuthority      string          `json:"scanner_authority"`
		Scanner               scannerWire     `json:"scanner"`
		Initial               completionWire  `json:"initial"`
		Residual              completionWire  `json:"residual"`
		Fields                []fieldWire     `json:"fields"`
		InstructionRisk       []string        `json:"instruction_risk"`
		InstructionRiskFields []riskFieldWire `json:"instruction_risk_fields"`
	}{
		"open-trestle/publication-content-scan-receipt", 1, receipt.reviewScopeIdentity,
		receipt.verifiedFindingSetIdentity, receipt.selectionIdentity, receipt.publicationPolicyIdentity, receipt.verificationContextIdentity, receipt.scannerAuthorityIdentity,
		scannerWire{scanner.WorkerProtocol, scanner.Scanner, scanner.ScannerVersion, scanner.ScannerCommit, scanner.RulesetIdentity, scanner.RulesetRuleCount, scanner.BuildProfile, scanner.LauncherSHA256, scanner.WorkerSHA256},
		completionWire{initial.Complete, initial.FieldCount, initial.ScannedByteCount, initial.MatchCount},
		completionWire{residual.Complete, residual.FieldCount, residual.ScannedByteCount, residual.MatchCount},
		fields, receipt.instructionRiskEvidence, riskFields,
	})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
