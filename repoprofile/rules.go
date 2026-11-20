package repoprofile

// Check classes.
const (
	ClassFormatting        = "formatting"
	ClassLint              = "lint"
	ClassTypeCheck         = "type_check"
	ClassUnitTests         = "unit_tests"
	ClassRaceDetection     = "race_detection"
	ClassFuzzing           = "fuzzing"
	ClassStaticAnalysis    = "static_analysis"
	ClassVulnerabilityScan = "vulnerability_scan"
	ClassSecretScan        = "secret_scan"
	ClassCoverageGate      = "coverage_gate"
	ClassDependencyReview  = "dependency_review"
)

// Check sources: the kind of file a check was read from. Only a check that
// CI runs on changes is enforced, whatever its source.
const (
	SourceCI         = "ci"       // a GitHub Actions workflow
	SourceCIOther    = "ci_other" // another CI system, read as information
	SourceTaskRunner = "task_runner"
	SourcePreCommit  = "pre_commit"
	SourceConfig     = "config"
)

// toolClass is the closed set of known tools and the class of check each one
// gives. "golangci-lint:NAME" is a linter enabled in a golangci-lint
// configuration.
var toolClass = map[string]string{
	"gofmt": ClassFormatting, "goimports": ClassFormatting, "prettier": ClassFormatting,
	"black": ClassFormatting, "ruff-format": ClassFormatting, "rustfmt": ClassFormatting,

	"golangci-lint": ClassLint, "eslint": ClassLint, "ruff": ClassLint, "flake8": ClassLint,
	"clippy": ClassLint, "rubocop": ClassLint, "shellcheck": ClassLint,

	"tsc": ClassTypeCheck, "mypy": ClassTypeCheck, "pyright": ClassTypeCheck,

	"go-test": ClassUnitTests, "jest": ClassUnitTests, "vitest": ClassUnitTests, "pytest": ClassUnitTests,
	"cargo-test": ClassUnitTests, "rspec": ClassUnitTests, "junit": ClassUnitTests, "dotnet-test": ClassUnitTests,

	"go-test-race": ClassRaceDetection,
	"go-fuzz":      ClassFuzzing,

	"go-vet": ClassStaticAnalysis, "staticcheck": ClassStaticAnalysis, "gosec": ClassStaticAnalysis,
	"codeql": ClassStaticAnalysis, "semgrep": ClassStaticAnalysis,

	"govulncheck": ClassVulnerabilityScan, "cargo-audit": ClassVulnerabilityScan, "osv-scanner": ClassVulnerabilityScan,

	"gitleaks": ClassSecretScan, "trufflehog": ClassSecretScan, "detect-secrets": ClassSecretScan,

	"pytest-cov": ClassCoverageGate, "coverage-py": ClassCoverageGate,

	"dependency-review": ClassDependencyReview,

	"golangci-lint:errcheck": ClassLint, "golangci-lint:revive": ClassLint, "golangci-lint:gocritic": ClassLint,
	"golangci-lint:ineffassign": ClassLint, "golangci-lint:unused": ClassLint, "golangci-lint:misspell": ClassLint,
	"golangci-lint:errorlint": ClassLint, "golangci-lint:bodyclose": ClassLint,
	"golangci-lint:govet": ClassStaticAnalysis, "golangci-lint:staticcheck": ClassStaticAnalysis,
	"golangci-lint:gosec": ClassStaticAnalysis,
	"golangci-lint:gofmt": ClassFormatting, "golangci-lint:goimports": ClassFormatting,
}

// commandRule matches a command: its program is words[0], the following
// words are its next non-flag arguments in order, and when flags is set one
// of them is among its arguments.
type commandRule struct {
	words []string
	flags []string
	tool  string
}

var commandRules = []commandRule{
	{[]string{"go", "test"}, nil, "go-test"},
	{[]string{"go", "test"}, []string{"-race"}, "go-test-race"},
	{[]string{"go", "test"}, []string{"-fuzz"}, "go-fuzz"},
	{[]string{"go", "vet"}, nil, "go-vet"},
	{[]string{"gofmt"}, []string{"-l", "-d"}, "gofmt"},
	{[]string{"goimports"}, []string{"-l", "-d"}, "goimports"},
	{[]string{"golangci-lint", "run"}, nil, "golangci-lint"},
	{[]string{"staticcheck"}, nil, "staticcheck"},
	{[]string{"gosec"}, nil, "gosec"},
	{[]string{"govulncheck"}, nil, "govulncheck"},

	{[]string{"eslint"}, nil, "eslint"},
	{[]string{"prettier"}, []string{"--check", "-c", "--list-different", "-l"}, "prettier"},
	{[]string{"tsc"}, nil, "tsc"},
	{[]string{"jest"}, nil, "jest"},
	{[]string{"vitest"}, nil, "vitest"},

	{[]string{"ruff", "check"}, nil, "ruff"},
	{[]string{"ruff", "format"}, []string{"--check", "--diff"}, "ruff-format"},
	{[]string{"black"}, []string{"--check", "--diff"}, "black"},
	{[]string{"flake8"}, nil, "flake8"},
	{[]string{"mypy"}, nil, "mypy"},
	{[]string{"pyright"}, nil, "pyright"},
	{[]string{"pytest"}, nil, "pytest"},
	{[]string{"pytest"}, []string{"--cov-fail-under"}, "pytest-cov"},
	{[]string{"coverage", "report"}, []string{"--fail-under"}, "coverage-py"},

	{[]string{"cargo", "fmt"}, []string{"--check"}, "rustfmt"},
	{[]string{"rustfmt"}, []string{"--check"}, "rustfmt"},
	{[]string{"cargo", "clippy"}, nil, "clippy"},
	{[]string{"cargo", "test"}, nil, "cargo-test"},
	{[]string{"cargo", "nextest"}, nil, "cargo-test"},
	{[]string{"cargo", "audit"}, nil, "cargo-audit"},

	{[]string{"rubocop"}, nil, "rubocop"},
	{[]string{"rspec"}, nil, "rspec"},
	{[]string{"mvn", "test"}, nil, "junit"},
	{[]string{"mvn", "verify"}, nil, "junit"},
	{[]string{"gradle", "test"}, nil, "junit"},
	{[]string{"gradle", "check"}, nil, "junit"},
	{[]string{"dotnet", "test"}, nil, "dotnet-test"},

	{[]string{"shellcheck"}, nil, "shellcheck"},
	{[]string{"semgrep"}, nil, "semgrep"},
	{[]string{"gitleaks"}, nil, "gitleaks"},
	{[]string{"trufflehog"}, nil, "trufflehog"},
	{[]string{"osv-scanner"}, nil, "osv-scanner"},
}

// actionRules name the GitHub Actions that run a check. An action matches
// by name, ignoring its version, and a prefix also covers its sub-actions.
var actionRules = []struct{ prefix, tool string }{
	{"golangci/golangci-lint-action", "golangci-lint"},
	{"dominikh/staticcheck-action", "staticcheck"},
	{"securego/gosec", "gosec"},
	{"golang/govulncheck-action", "govulncheck"},
	{"returntocorp/semgrep-action", "semgrep"},
	{"github/codeql-action/analyze", "codeql"},
	{"gitleaks/gitleaks-action", "gitleaks"},
	{"trufflesecurity/trufflehog", "trufflehog"},
	{"google/osv-scanner-action", "osv-scanner"},
	{"actions/dependency-review-action", "dependency-review"},
}

// hookTools maps pre-commit hook ids to tools.
var hookTools = map[string]string{
	"ruff": "ruff", "ruff-format": "ruff-format", "black": "black", "flake8": "flake8", "mypy": "mypy",
	"pyright": "pyright", "eslint": "eslint", "prettier": "prettier", "gitleaks": "gitleaks",
	"detect-secrets": "detect-secrets", "shellcheck": "shellcheck", "golangci-lint": "golangci-lint",
	"go-fmt": "gofmt", "go-imports": "goimports", "go-vet": "go-vet", "rubocop": "rubocop",
	"trufflehog": "trufflehog", "semgrep": "semgrep", "clippy": "clippy", "pytest": "pytest",
}

// configTools maps the start of a configuration file name to the tool it
// configures.
var configTools = map[string]string{
	".golangci.": "golangci-lint", ".eslintrc": "eslint", "eslint.config.": "eslint", ".prettierrc": "prettier",
	"ruff.toml": "ruff", ".ruff.toml": "ruff", "mypy.ini": "mypy", ".rubocop.yml": "rubocop",
	"clippy.toml": "clippy", ".clippy.toml": "clippy", "rustfmt.toml": "rustfmt", ".rustfmt.toml": "rustfmt",
}

// pyprojectTables maps a pyproject.toml tool table, with its sub-tables, to
// the tool it configures.
var pyprojectTables = map[string]string{
	"tool.ruff": "ruff", "tool.mypy": "mypy", "tool.black": "black",
	"tool.pytest": "pytest", "tool.pyright": "pyright",
}
