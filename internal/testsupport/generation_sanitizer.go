package testsupport

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

type CleanGenerationSanitizer struct{}
type CleanVerificationSanitizer struct{}

func NewCleanGenerationSanitizer() CleanGenerationSanitizer     { return CleanGenerationSanitizer{} }
func NewCleanVerificationSanitizer() CleanVerificationSanitizer { return CleanVerificationSanitizer{} }
func (CleanVerificationSanitizer) Identity() string             { return strings.Repeat("9", 64) }
func (CleanVerificationSanitizer) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	return review.ScannerBinaryDigests{HelperSHA256: strings.Repeat("b", 64)}
}
func (value CleanVerificationSanitizer) SanitizeVerification(_ context.Context, raw provider.Request, scopeIdentity string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	return cleanSanitizedRequest(raw, scopeIdentity, value.ExpectedBinaryDigests())
}
func (CleanGenerationSanitizer) PublicationContentScanner() review.PublicationContentScanner {
	return NewCleanPublicationScanner()
}
func (CleanGenerationSanitizer) Identity() string { return strings.Repeat("8", 64) }
func (CleanGenerationSanitizer) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	return review.ScannerBinaryDigests{HelperSHA256: strings.Repeat("b", 64)}
}
func (value CleanGenerationSanitizer) SanitizeGeneration(_ context.Context, raw provider.Request, scopeIdentity string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	return cleanSanitizedRequest(raw, scopeIdentity, value.ExpectedBinaryDigests())
}

func cleanSanitizedRequest(raw provider.Request, scopeIdentity string, expected review.ScannerBinaryDigests) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	type item struct {
		Path    string   `json:"path"`
		Symbols []string `json:"symbols"`
		Text    string   `json:"text"`
	}
	type memoryWire struct {
		Items []item `json:"items"`
	}
	var wire struct {
		Sources []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"sources"`
		SourceOmissions []struct {
			Path string `json:"path"`
		} `json:"source_omissions"`
		Memory           memoryWire   `json:"memory"`
		AdditionalMemory []memoryWire `json:"additional_memory"`
		StatedIntent     *struct {
			Commits []struct {
				Text string `json:"text"`
			} `json:"commits"`
		} `json:"stated_intent"`
		Candidates []struct {
			Title string `json:"title"`
			Claim string `json:"claim"`
			Path  string `json:"path"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw.Payload(), &wire); err != nil {
		return review.SanitizedModelRequest{}, review.SanitizedEgressReceipt{}, err
	}
	fields := make([]review.SanitizedField, 0)
	appendField := func(role review.FieldRole, text string) {
		fields = append(fields, review.SanitizedField{Role: role, Ordinal: len(fields), ScannedByteCount: len(text), Matches: []secretscan.Match{}})
	}
	appendMemory := func(memoryValue memoryWire) {
		for _, item := range memoryValue.Items {
			appendField(review.FieldRoleMemoryPath, item.Path)
			for _, symbol := range item.Symbols {
				appendField(review.FieldRoleMemorySymbol, symbol)
			}
			appendField(review.FieldRoleMemoryText, item.Text)
		}
	}
	for _, source := range wire.Sources {
		appendField(review.FieldRoleSourcePath, source.Path)
		appendField(review.FieldRoleSourceContent, source.Content)
	}
	for _, omission := range wire.SourceOmissions {
		appendField(review.FieldRoleSourceOmissionPath, omission.Path)
	}
	appendMemory(wire.Memory)
	for _, memoryValue := range wire.AdditionalMemory {
		appendMemory(memoryValue)
	}
	if wire.StatedIntent != nil {
		for _, commit := range wire.StatedIntent.Commits {
			if commit.Text != "" {
				appendField(review.FieldRoleStatedIntentText, commit.Text)
			}
		}
	}
	for _, candidate := range wire.Candidates {
		appendField(review.FieldRoleCandidateTitle, candidate.Title)
		appendField(review.FieldRoleCandidateClaim, candidate.Claim)
		appendField(review.FieldRoleCandidatePath, candidate.Path)
	}
	inner, err := provider.NewRequest(raw.Capability(), raw.MediaType(), raw.Payload())
	if err != nil {
		return review.SanitizedModelRequest{}, review.SanitizedEgressReceipt{}, err
	}
	request, err := review.NewSanitizedModelRequest(scopeIdentity, raw, inner)
	if err != nil {
		return review.SanitizedModelRequest{}, review.SanitizedEgressReceipt{}, err
	}
	total := 0
	for _, field := range fields {
		total += field.ScannedByteCount
	}
	receipt, err := review.NewSanitizedEgressReceipt(review.SanitizedEgressReceiptInput{
		ReviewScopeIdentity: scopeIdentity, RawRequestIdentity: raw.Identity(), SanitizedRequestIdentity: request.SanitizedRequestIdentity(),
		Scanner: review.ScannerProfile{WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile, HelperSHA256: expected.HelperSHA256},
		Initial: review.ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: total}, Residual: review.ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: total}, Fields: fields,
	})
	return request, receipt, err
}
