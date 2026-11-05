// Package agentprofile declares packaged specialist review-agent profiles and a
// deterministic router that plans which profiles to run for one change, at
// which difficulty tier, on which user-assigned exact route.
//
// The package is a planning layer only. It performs no model call, no network
// access, no tool execution, no publication, and no source mutation. Every
// planned profile is bound to candidate-only authority: its output is a set of
// candidates that still require independent verification on a separate route
// before they can become findings. A RoutingPlan never bypasses gateway
// eligibility; policy zones, local-only enforcement, capacity, and budgets are
// still enforced by internal/gateway at dispatch time.
package agentprofile

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidProfileID identifies an unknown or malformed profile identifier.
	ErrInvalidProfileID = errors.New("invalid agent profile ID")
	// ErrInvalidTier identifies an unknown difficulty tier.
	ErrInvalidTier = errors.New("invalid agent profile tier")
	// ErrInvalidSignal identifies an unknown change signal.
	ErrInvalidSignal = errors.New("invalid change signal")
	// ErrInvalidLanguage identifies an unknown language token.
	ErrInvalidLanguage = errors.New("invalid language")
	// ErrInvalidFileClass identifies an unknown file class token.
	ErrInvalidFileClass = errors.New("invalid file class")
	// ErrInvalidCondition identifies an unknown activation condition.
	ErrInvalidCondition = errors.New("invalid activation condition")
)

// ProfileID identifies one packaged specialist profile.
type ProfileID string

// Packaged profile identifiers in canonical (lexical) order.
const (
	ProfileBackend          ProfileID = "backend"
	ProfileBugHunter        ProfileID = "bug_hunter"
	ProfileDriftAuditor     ProfileID = "drift_auditor"
	ProfileFrontend         ProfileID = "frontend"
	ProfileKnowledgeGraph   ProfileID = "knowledge_graph"
	ProfileOrchestrator     ProfileID = "orchestrator"
	ProfileSecurityProbe    ProfileID = "security_probe"
	ProfileStyleConformance ProfileID = "style_conformance"
	ProfileTestAuthor       ProfileID = "test_author"
)

var knownProfileIDs = []ProfileID{
	ProfileBackend, ProfileBugHunter, ProfileDriftAuditor, ProfileFrontend, ProfileKnowledgeGraph,
	ProfileOrchestrator, ProfileSecurityProbe, ProfileStyleConformance, ProfileTestAuthor,
}

// ParseProfileID parses one exact packaged profile identifier.
func ParseProfileID(value string) (ProfileID, error) {
	for _, id := range knownProfileIDs {
		if string(id) == value {
			return id, nil
		}
	}
	return "", fmt.Errorf("parse profile ID: %w", ErrInvalidProfileID)
}

// Tier identifies a difficulty tier that a user maps to an exact route.
type Tier string

// Difficulty tiers in ascending order.
const (
	TierLight    Tier = "light"
	TierStandard Tier = "standard"
	TierDeep     Tier = "deep"
)

// Tiers returns the tiers in ascending difficulty order.
func Tiers() []Tier { return []Tier{TierLight, TierStandard, TierDeep} }

// ParseTier parses one exact tier token.
func ParseTier(value string) (Tier, error) {
	for _, tier := range Tiers() {
		if string(tier) == value {
			return tier, nil
		}
	}
	return "", fmt.Errorf("parse tier: %w", ErrInvalidTier)
}

func (t Tier) rank() int {
	for index, tier := range Tiers() {
		if tier == t {
			return index
		}
	}
	return -1
}

// ModelCall declares whether and when a profile needs a model.
type ModelCall string

const (
	// ModelCallNone identifies a fully deterministic profile.
	ModelCallNone ModelCall = "none"
	// ModelCallGapOnly identifies a profile that uses a model only for gaps in deterministic coverage.
	ModelCallGapOnly ModelCall = "gap_only"
	// ModelCallRequired identifies a profile whose review always needs a model.
	ModelCallRequired ModelCall = "required"
)

func (m ModelCall) valid() bool {
	return m == ModelCallNone || m == ModelCallGapOnly || m == ModelCallRequired
}

// Language identifies a path-derived source language.
type Language string

// Languages detected from file extensions.
const (
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
	LanguageCSharp     Language = "csharp"
	LanguageCSS        Language = "css"
	LanguageGo         Language = "go"
	LanguageHTML       Language = "html"
	LanguageJava       Language = "java"
	LanguageJavaScript Language = "javascript"
	LanguageJSON       Language = "json"
	LanguageKotlin     Language = "kotlin"
	LanguageMarkdown   Language = "markdown"
	LanguagePHP        Language = "php"
	LanguagePython     Language = "python"
	LanguageRuby       Language = "ruby"
	LanguageRust       Language = "rust"
	LanguageScala      Language = "scala"
	LanguageShell      Language = "shell"
	LanguageSQL        Language = "sql"
	LanguageSvelte     Language = "svelte"
	LanguageSwift      Language = "swift"
	LanguageTOML       Language = "toml"
	LanguageTypeScript Language = "typescript"
	LanguageVue        Language = "vue"
	LanguageYAML       Language = "yaml"
)

var knownLanguages = []Language{
	LanguageC, LanguageCPP, LanguageCSharp, LanguageCSS, LanguageGo, LanguageHTML, LanguageJava,
	LanguageJavaScript, LanguageJSON, LanguageKotlin, LanguageMarkdown, LanguagePHP, LanguagePython,
	LanguageRuby, LanguageRust, LanguageScala, LanguageShell, LanguageSQL, LanguageSvelte, LanguageSwift,
	LanguageTOML, LanguageTypeScript, LanguageVue, LanguageYAML,
}

func validLanguage(language Language) bool {
	for _, known := range knownLanguages {
		if known == language {
			return true
		}
	}
	return false
}

// programmingLanguages are languages whose files classify as source code.
var programmingLanguages = map[Language]struct{}{
	LanguageC: {}, LanguageCPP: {}, LanguageCSharp: {}, LanguageCSS: {}, LanguageGo: {}, LanguageHTML: {},
	LanguageJava: {}, LanguageJavaScript: {}, LanguageKotlin: {}, LanguagePHP: {}, LanguagePython: {},
	LanguageRuby: {}, LanguageRust: {}, LanguageScala: {}, LanguageShell: {}, LanguageSQL: {},
	LanguageSvelte: {}, LanguageSwift: {}, LanguageTypeScript: {}, LanguageVue: {},
}

// FileClass identifies a path-derived file role.
type FileClass string

// File classes derived deterministically from paths.
const (
	FileClassCIBuild            FileClass = "ci_build"
	FileClassConfig             FileClass = "config"
	FileClassDependencyManifest FileClass = "dependency_manifest"
	FileClassDocs               FileClass = "docs"
	FileClassGenerated          FileClass = "generated"
	FileClassOther              FileClass = "other"
	FileClassSource             FileClass = "source"
	FileClassTest               FileClass = "test"
	FileClassVendor             FileClass = "vendor"
)

var knownFileClasses = []FileClass{
	FileClassCIBuild, FileClassConfig, FileClassDependencyManifest, FileClassDocs, FileClassGenerated,
	FileClassOther, FileClassSource, FileClassTest, FileClassVendor,
}

func validFileClass(class FileClass) bool {
	for _, known := range knownFileClasses {
		if known == class {
			return true
		}
	}
	return false
}

// Signal identifies a closed change signal from paths or deterministic analyzers.
type Signal string

// Change signals. Security signals are the subset reported by IsSecurity.
const (
	SignalAuth               Signal = "auth"
	SignalCIConfig           Signal = "ci_config"
	SignalConcurrency        Signal = "concurrency"
	SignalCrypto             Signal = "crypto"
	SignalDependencyManifest Signal = "dependency_manifest"
	SignalDeserialization    Signal = "deserialization"
	SignalExec               Signal = "exec"
	SignalHTTP               Signal = "http"
	SignalPersistence        Signal = "persistence"
	SignalPublicAPI          Signal = "public_api"
	SignalSecrets            Signal = "secrets"
	SignalSQL                Signal = "sql"
	SignalWebhook            Signal = "webhook"
)

var knownSignals = []Signal{
	SignalAuth, SignalCIConfig, SignalConcurrency, SignalCrypto, SignalDependencyManifest,
	SignalDeserialization, SignalExec, SignalHTTP, SignalPersistence, SignalPublicAPI, SignalSecrets,
	SignalSQL, SignalWebhook,
}

// ParseSignal parses one exact signal token.
func ParseSignal(value string) (Signal, error) {
	for _, signal := range knownSignals {
		if string(signal) == value {
			return signal, nil
		}
	}
	return "", fmt.Errorf("parse signal: %w", ErrInvalidSignal)
}

// IsSecurity reports whether the signal marks a security-sensitive surface.
func (s Signal) IsSecurity() bool {
	switch s {
	case SignalAuth, SignalCIConfig, SignalCrypto, SignalDependencyManifest, SignalDeserialization,
		SignalExec, SignalHTTP, SignalSecrets, SignalSQL, SignalWebhook:
		return true
	default:
		return false
	}
}

func validSignal(signal Signal) bool {
	for _, known := range knownSignals {
		if known == signal {
			return true
		}
	}
	return false
}

// Condition identifies a change-wide activation condition.
type Condition string

const (
	// ConditionAlways activates a profile for every change.
	ConditionAlways Condition = "always"
	// ConditionIntentDeclared activates when a change description or linked docs are present.
	ConditionIntentDeclared Condition = "intent_declared"
	// ConditionDocsAndCodeChanged activates when docs and source change together.
	ConditionDocsAndCodeChanged Condition = "docs_and_code_changed"
	// ConditionDeclaredStyleMatches activates when a declared style intent governs a changed language.
	ConditionDeclaredStyleMatches Condition = "declared_style_matches"
)

func validCondition(condition Condition) bool {
	switch condition {
	case ConditionAlways, ConditionIntentDeclared, ConditionDocsAndCodeChanged, ConditionDeclaredStyleMatches:
		return true
	default:
		return false
	}
}
