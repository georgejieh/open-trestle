package repoprofile

import (
	"reflect"
	"slices"
	"testing"
)

const ciPath = ".github/workflows/ci.yml"

// workflow builds a workflow with one job and one step. jobExtra is a block
// of lines indented to the job's keys, and step may continue on lines
// indented to the step's keys.
func workflow(on, jobExtra, step string) string {
	return "on: " + on + "\njobs:\n  t:\n" + jobExtra + "    steps:\n      " + step + "\n"
}

// labels returns "tool/source/E" for each enforced check and "tool/source/-"
// for each other check, sorted.
func labels(files map[string]string) []string {
	contents := map[string][]byte{}
	for p, text := range files {
		contents[p] = []byte(text)
	}
	got := []string{}
	for _, c := range Detect(nil, nil, contents).Checks {
		mark := "-"
		if c.Enforced {
			mark = "E"
		}
		got = append(got, c.Tool+"/"+c.Source+"/"+mark)
	}
	slices.Sort(got)
	return got
}

func TestEnforcement(t *testing.T) {
	const schedule = "\n  schedule:\n    - cron: '0 3 * * *'"
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"go test -race on a pull request", map[string]string{ciPath: workflow("pull_request", "", "- run: go test -race ./...")},
			[]string{"go-test-race/ci/E", "go-test/ci/E"}},
		{"push, pull_request_target and merge_group", map[string]string{
			ciPath:                       workflow("[push]", "", "- run: go vet ./..."),
			".github/workflows/b.yaml":   workflow("{pull_request_target: {types: [opened]}}", "", "- run: gosec ./..."),
			".github/workflows/c.yml":    workflow("\n  merge_group:", "", "- run: govulncheck ./..."),
			".github/workflows/d.yml":    workflow("\n  push:\n    branches: [main]\n  schedule:\n    - cron: '1 1 * * 1'", "", "- run: staticcheck ./..."),
			".github/workflows/nest/e.y": workflow("push", "", "- run: shellcheck x"),
		}, []string{"go-vet/ci/E", "gosec/ci/E", "govulncheck/ci/E", "staticcheck/ci/E"}},

		{"echo of a tool", map[string]string{ciPath: workflow("push", "", "- run: echo govulncheck")}, []string{}},
		{"a tool as an argument", map[string]string{ciPath: workflow("push", "", "- run: git commit -m \"govulncheck; golangci-lint run\"")}, []string{}},
		{"commented command in a script", map[string]string{ciPath: workflow("push", "", "- run: |\n          # golangci-lint run\n          echo ok")}, []string{}},
		{"commented step", map[string]string{ciPath: workflow("push", "", "# - run: govulncheck ./...\n      - run: echo ok")}, []string{}},
		{"command after || true", map[string]string{ciPath: workflow("push", "", "- run: govulncheck ./... || true")}, []string{}},
		{"name and description are not commands", map[string]string{ciPath: workflow("push", "", "- name: golangci-lint run\n        run: echo ok")}, []string{}},
		{"a command in a multi-line script", map[string]string{ciPath: workflow("push", "", "- run: |\n          go mod download\n          go vet ./...\n          FOO=1 sudo gofmt -l .")},
			[]string{"gofmt/ci/E", "go-vet/ci/E"}},

		{"schedule only", map[string]string{ciPath: workflow(schedule, "", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"workflow_dispatch only", map[string]string{ciPath: workflow("workflow_dispatch", "", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"schedule and workflow_dispatch", map[string]string{ciPath: workflow("[schedule, workflow_dispatch]", "", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"workflow_call and workflow_run only", map[string]string{ciPath: workflow("[workflow_call, workflow_run]", "", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"no trigger", map[string]string{ciPath: "jobs:\n  t:\n    steps:\n      - run: go vet ./...\n"}, []string{"go-vet/ci/-"}},

		{"continue-on-error on the job", map[string]string{ciPath: workflow("push", "    continue-on-error: true\n", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"continue-on-error on the step", map[string]string{ciPath: workflow("push", "", "- run: go vet ./...\n        continue-on-error: true")}, []string{"go-vet/ci/-"}},
		{"continue-on-error by expression", map[string]string{ciPath: workflow("push", "    continue-on-error: ${{ matrix.experimental }}\n", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"continue-on-error false", map[string]string{ciPath: workflow("push", "    continue-on-error: false\n", "- run: go vet ./...\n        continue-on-error: ${{ false }}")}, []string{"go-vet/ci/E"}},
		{"if false on the job", map[string]string{ciPath: workflow("push", "    if: false\n", "- run: go vet ./...")}, []string{"go-vet/ci/-"}},
		{"if false on the step", map[string]string{ciPath: workflow("push", "", "- run: go vet ./...\n        if: false")}, []string{"go-vet/ci/-"}},
		{"if false as an expression", map[string]string{ciPath: workflow("push", "", "- run: go vet ./...\n        if: ${{ false }}")}, []string{"go-vet/ci/-"}},
		{"if on another condition", map[string]string{ciPath: workflow("push", "    if: github.ref == 'refs/heads/main'\n", "- run: go vet ./...\n        if: always()")}, []string{"go-vet/ci/E"}},

		{"uses action", map[string]string{ciPath: workflow("push", "", "- uses: golangci/golangci-lint-action@v6")}, []string{"golangci-lint/ci/E"}},
		{"uses action allowed to fail", map[string]string{ciPath: workflow("push", "", "- uses: golangci/golangci-lint-action@v6\n        continue-on-error: true")}, []string{"golangci-lint/ci/-"}},
		{"uses action in a schedule workflow", map[string]string{ciPath: workflow(schedule, "", "- uses: github/codeql-action/analyze@v3")}, []string{"codeql/ci/-"}},
		{"name that is not an action", map[string]string{ciPath: workflow("push", "", "- run: echo\n        name: golangci/golangci-lint-action@v6")}, []string{}},

		{"makefile target run by CI", map[string]string{
			ciPath:     workflow("push", "", "- run: make test"),
			"Makefile": ".PHONY: test lint\nlint:\n\tgolangci-lint run\n\ntest:\n\tgo vet ./...\n",
		}, []string{"go-vet/task_runner/E", "golangci-lint/task_runner/-"}},
		{"makefile default target and prerequisites", map[string]string{
			ciPath:     workflow("push", "", "- run: make"),
			"Makefile": "all: lint test\nlint:\n\tgolangci-lint run\ntest:\n\tgo test ./...\nfmt:\n\tgofmt -l .\n",
		}, []string{"go-test/task_runner/E", "golangci-lint/task_runner/E", "gofmt/task_runner/-"}},
		{"makefile recursion is followed one level", map[string]string{
			ciPath:     workflow("push", "", "- run: make ci"),
			"Makefile": "ci:\n\t$(MAKE) lint\n\nlint:\n\tgolangci-lint run\n\t$(MAKE) deep\n\ndeep:\n\tgo vet ./...\n",
		}, []string{"go-vet/task_runner/-", "golangci-lint/task_runner/E"}},
		{"makefile target with ignored failure", map[string]string{
			ciPath:     workflow("push", "", "- run: make lint"),
			"Makefile": "lint:\n\t-golangci-lint run\n\t@go vet ./...\n",
		}, []string{"go-vet/task_runner/E"}},
		{"makefile run by a step that is allowed to fail", map[string]string{
			ciPath:     workflow("push", "", "- run: make lint\n        continue-on-error: true"),
			"Makefile": "lint:\n\tgolangci-lint run\n",
		}, []string{"golangci-lint/task_runner/-"}},
		{"makefile in a schedule workflow", map[string]string{
			ciPath:     workflow(schedule, "", "- run: make lint"),
			"Makefile": "lint:\n\tgolangci-lint run\n",
		}, []string{"golangci-lint/task_runner/-"}},
		{"makefile selected by -C is not read", map[string]string{
			ciPath:     workflow("push", "", "- run: make -C sub lint"),
			"Makefile": "lint:\n\tgolangci-lint run\n",
		}, []string{"golangci-lint/task_runner/-"}},
		{"echo of make", map[string]string{
			ciPath:     workflow("push", "", "- run: echo make lint"),
			"Makefile": "lint:\n\tgolangci-lint run\n",
		}, []string{"golangci-lint/task_runner/-"}},

		{"package.json script run by CI", map[string]string{
			ciPath: workflow("push", "", "- run: npm run lint"),
			"package.json": `{"scripts": {"lint": "eslint .", "test": "vitest run", "fmt": "prettier --check ."},
				"devDependencies": {"jest": "1", "tsc": "1", "mypy": "1"}, "dependencies": {"eslint": "1"}}`,
		}, []string{"eslint/task_runner/E", "prettier/task_runner/-", "vitest/task_runner/-"}},
		{"npm test, pnpm and yarn", map[string]string{
			ciPath:         workflow("push", "", "- run: |\n          npm test\n          pnpm lint\n          yarn run fmt\n          pnpm install"),
			"package.json": `{"scripts": {"lint": "eslint .", "test": "vitest run", "fmt": "prettier --check .", "install": "jest"}}`,
		}, []string{"eslint/task_runner/E", "jest/task_runner/-", "prettier/task_runner/E", "vitest/task_runner/E"}},
		{"package.json script that runs another script", map[string]string{
			ciPath:         workflow("push", "", "- run: npm run check"),
			"package.json": `{"scripts": {"check": "npm run lint && tsc --noEmit", "lint": "eslint ."}}`,
		}, []string{"eslint/task_runner/E", "tsc/task_runner/E"}},
		{"package.json with the scripts not run", map[string]string{
			"package.json": `{"scripts": {"lint": "eslint ."}}`,
			ciPath:         workflow("push", "", "- run: npm ci"),
		}, []string{"eslint/task_runner/-"}},

		{"pyproject dependencies are not commands", map[string]string{
			"pyproject.toml": "[project]\ndependencies = [\"black>=24\", \"mypy\", \"ruff\"]\n\n[tool.black]\nline-length = 100\n",
		}, []string{"black/config/-"}},
		{"pyproject tool tables and coverage", map[string]string{
			ciPath:           workflow("push", "", "- run: pytest"),
			"pyproject.toml": "[tool.ruff.lint]\nselect = []\n[tool.mypy]\n[tool.pytest.ini_options]\naddopts = \"--cov-fail-under=80\"\n[tool.coverage.report]\nfail_under = 90\n",
		}, []string{"coverage-py/config/-", "mypy/config/-", "pytest-cov/config/-", "pytest/ci/E", "pytest/config/-", "ruff/config/-"}},

		{"pre-commit hooks run by CI", map[string]string{
			ciPath:                    workflow("pull_request", "", "- run: pre-commit run --all-files"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: ruff\n      - id: black\n      - id: unknown\n",
		}, []string{"black/pre_commit/E", "ruff/pre_commit/E"}},
		{"pre-commit hooks not run by CI", map[string]string{
			ciPath:                    workflow("pull_request", "", "- run: pre-commit install"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: ruff\n      - id: black\n",
		}, []string{"black/pre_commit/-", "ruff/pre_commit/-"}},
		{"pre-commit one hook", map[string]string{
			ciPath:                    workflow("pull_request", "", "- run: pre-commit run ruff --all-files"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: ruff\n      - id: black\n",
		}, []string{"black/pre_commit/-", "ruff/pre_commit/E"}},
		{"pre-commit hook stage", map[string]string{
			ciPath:                    workflow("pull_request", "", "- run: pre-commit run --hook-stage pre-push --all-files"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: ruff\n        stages: [pre-push]\n      - id: black\n        stages: [commit]\n",
		}, []string{"black/pre_commit/-", "ruff/pre_commit/E"}},
		{"pre-commit default stage", map[string]string{
			ciPath:                    workflow("pull_request", "", "- run: pre-commit run -a"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: ruff\n        stages: [manual]\n      - id: black\n",
		}, []string{"black/pre_commit/E", "ruff/pre_commit/-"}},
		{"pre-commit action", map[string]string{
			ciPath:                    workflow("push", "", "- uses: pre-commit/action@v3"),
			".pre-commit-config.yaml": "repos:\n  - repo: x\n    hooks:\n      - id: flake8\n",
		}, []string{"flake8/pre_commit/E"}},
		{"pre-commit local hook entry", map[string]string{
			ciPath:                    workflow("push", "", "- run: pre-commit run"),
			".pre-commit-config.yaml": "repos:\n  - repo: local\n    hooks:\n      - id: lint\n        entry: golangci-lint run\n        language: system\n",
		}, []string{"golangci-lint/pre_commit/E"}},
		{"hooks of husky and lefthook", map[string]string{
			".husky/pre-commit": "npx eslint .\n",
			"lefthook.yml":      "pre-commit:\n  commands:\n    lint:\n      run: gofmt -l .\n",
		}, []string{"eslint/pre_commit/-", "gofmt/pre_commit/-"}},

		{"another CI system", map[string]string{
			".gitlab-ci.yml":       "test:\n  script:\n    - go vet ./...\n    - echo gosec\n",
			".circleci/config.yml": "jobs:\n  t:\n    steps:\n      - run: go test -race ./...\n      - run:\n          command: staticcheck ./...\n",
			"Jenkinsfile":          "pipeline {\n  stages {\n    stage('x') {\n      steps {\n        sh 'govulncheck ./...'\n      }\n    }\n  }\n}\n",
		}, []string{"go-test-race/ci_other/-", "go-test/ci_other/-", "go-vet/ci_other/-", "govulncheck/ci_other/-", "staticcheck/ci_other/-"}},

		{"justfile recipe run by CI", map[string]string{
			ciPath:     workflow("push", "", "- run: just test"),
			"justfile": "set shell := [\"bash\", \"-c\"]\n\nlint:\n    golangci-lint run\n\ntest: lint\n    @go test ./...\n\nfmt:\n    gofmt -l .\n",
		}, []string{"go-test/task_runner/E", "golangci-lint/task_runner/E", "gofmt/task_runner/-"}},
		{"Taskfile task run by CI", map[string]string{
			ciPath:         workflow("push", "", "- run: task test"),
			"Taskfile.yml": "version: '3'\ntasks:\n  lint:\n    cmds:\n      - golangci-lint run\n  test:\n    deps: [lint]\n    cmds:\n      - go test ./...\n  fmt:\n    cmds:\n      - gofmt -l .\n",
		}, []string{"go-test/task_runner/E", "golangci-lint/task_runner/E", "gofmt/task_runner/-"}},
		{"tox environment run by CI", map[string]string{
			ciPath:    workflow("push", "", "- run: tox -e lint"),
			"tox.ini": "[tox]\nenvlist = lint, py\n\n[testenv]\ncommands = pytest\n\n[testenv:lint]\ncommands =\n    flake8 src\n    black --check src\n    -mypy src\n",
		}, []string{"black/task_runner/E", "flake8/task_runner/E", "pytest/task_runner/-"}},
		{"tox default environments", map[string]string{
			ciPath:    workflow("push", "", "- run: tox"),
			"tox.ini": "[tox]\nenvlist = py311\n[testenv]\ncommands = {envpython} -m pytest {posargs}\n",
		}, []string{"pytest/task_runner/E"}},
		{"nox session run by CI", map[string]string{
			ciPath:       workflow("push", "", "- run: nox -s mypy"),
			"noxfile.py": "import nox\n\n@nox.session\ndef mypy(session):\n    session.run('mypy')\n\n@nox.session\ndef pytest(session):\n    pass\n",
		}, []string{"mypy/task_runner/E", "pytest/task_runner/-"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			slices.Sort(tc.want)
			if got := labels(tc.files); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("checks = %v\nwant     %v", got, tc.want)
			}
		})
	}
}

func TestEnforcedClassesOnlyCountCIRuns(t *testing.T) {
	contents := map[string][]byte{
		ciPath:          []byte(workflow("push", "", "- run: go test ./...\n        continue-on-error: true")),
		"Makefile":      []byte("lint:\n\tgolangci-lint run\n"),
		".golangci.yml": []byte("linters:\n  enable:\n    - errcheck\n"),
	}
	p := Detect(nil, nil, contents)
	if got := p.EnforcedClasses(); len(got) != 0 {
		t.Errorf("enforced classes = %v", got)
	}
	if got := p.Classes(); !reflect.DeepEqual(got, []string{"lint", "unit_tests"}) {
		t.Errorf("classes = %v", got)
	}
}

func TestParseYAML(t *testing.T) {
	doc := parseYAML(`# header
on:
  push: {branches: [main, "dev branch"]}
  pull_request:
name: "a: b" # comment
jobs:
  t:
    steps:
      - run: |
          echo one
          echo two # kept in the script
      - run: >
          go test
          ./...
      - name: 'it''s'
        run: echo "x: y"
      -
        run: plain
          continues
      - [a, 'b, c', {d: e}]
`)
	if got := doc.get("name").str(); got != "a: b" {
		t.Errorf("name = %q", got)
	}
	push := doc.get("on").get("push")
	if got := push.get("branches").seq(); len(got) != 2 || got[1].str() != "dev branch" {
		t.Errorf("branches = %+v", got)
	}
	if doc.get("on").get("pull_request") == nil {
		t.Error("pull_request missing")
	}
	steps := doc.get("jobs").get("t").get("steps").seq()
	want := []string{"echo one\necho two # kept in the script", "go test ./...", "echo \"x: y\"", "plain continues"}
	for i, w := range want {
		if got := steps[i].get("run").str(); got != w {
			t.Errorf("step %d run = %q, want %q", i, got, w)
		}
	}
	if got := steps[1].get("run").str(); got != "go test ./..." {
		t.Errorf("folded = %q", got)
	}
	if got := steps[2].get("name").str(); got != "it's" {
		t.Errorf("name = %q", got)
	}
	if got := steps[4].seq(); len(got) != 3 || got[1].str() != "b, c" || got[2].get("d").str() != "e" {
		t.Errorf("flow = %+v", got)
	}
	if parseYAML("") != nil || parseYAML("a: [").get("a").str() != "[" {
		t.Error("an empty or malformed document")
	}
}
