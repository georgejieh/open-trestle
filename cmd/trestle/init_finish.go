package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

// initSetup describes a saved bootstrap directory in the terms the wizard shows.
type initSetup struct {
	remote                             bool
	provider                           initProviderInfo
	owner                              string
	credentials                        []string
	endpoints                          []string
	generationModel, verificationModel string
	// windowed is a setup whose privacy declaration has a review window.
	windowed bool
	// retention is the OpenRouter data-retention requirement, or "".
	retention string
}

type initOutcome struct {
	code          int
	ready         bool
	reviewCommand []string
	summary       string
}

// existingSetup reports whether the chosen directory already holds a finished
// setup. A folder with other content is never reused or cleaned up.
func (w *initWizard) existingSetup() (bool, error) {
	dir := w.a.directory
	if dir == "" {
		return false, nil
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.IsDir() {
		return false, initStopf(initExitUsage, "%s exists but is not a folder. Pass --directory with another path.", initDisplayPath(dir))
	}
	if _, err := os.Lstat(filepath.Join(dir, "bootstrap.json")); err == nil {
		return true, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, initStopf(initExitRefused, "cannot read %s. Pass --directory with a folder you own.", initDisplayPath(dir))
	}
	if len(entries) != 0 {
		return false, initStopf(initExitRefused, "%s already contains files but no finished Open Trestle setup (an earlier setup may have stopped part-way). Nothing was changed. Keep or inspect those files, then pass --directory with a new, empty folder.", initDisplayPath(dir))
	}
	if info.Mode().Perm() != 0o700 {
		return false, initStopf(initExitRefused, "%s exists but is not private (mode %04o). Run chmod 700 %s, or pass --directory with a new folder.", initDisplayPath(dir), info.Mode().Perm(), initShellQuote(dir))
	}
	return false, nil
}

func (w *initWizard) loadSetup() (initSetup, error) {
	dir := w.a.directory
	fail := func(reason string) (initSetup, error) {
		return initSetup{}, initStopf(initExitRefused, "%s holds an Open Trestle setup that could not be read (%s). Nothing was changed. Run `trestle setup bootstrap inspect --directory %s` for details, or pass --directory with a new folder.", dir, reason, initShellQuote(dir))
	}
	content, err := readSetupBootstrapFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		return fail("bootstrap.json is missing or not a protected 0600 file")
	}
	var header struct {
		Contract               string   `json:"contract"`
		Provider               string   `json:"provider"`
		CredentialEnvironments []string `json:"credential_environments"`
	}
	if json.Unmarshal(content, &header) != nil {
		return fail("bootstrap.json is not valid JSON")
	}
	setup := initSetup{credentials: header.CredentialEnvironments}
	switch header.Contract {
	case remoteBootstrapContract:
		key := header.Provider
		if initIsOpenRouterSetup(key) {
			key = "openrouter"
		}
		index := slices.IndexFunc(initProviders, func(p initProviderInfo) bool { return p.key == key })
		if index < 0 || header.Provider == "local" {
			return fail("unknown provider")
		}
		setup.remote, setup.provider = true, initProviders[index]
	case "open-trestle/local-first-bootstrap":
		setup.provider = initProviders[slices.IndexFunc(initProviders, func(p initProviderInfo) bool { return p.key == "local" })]
		plan, err := setupcore.InspectStateFile(w.ctx, filepath.Join(dir, "runs", "setup", "plan.json"))
		if err != nil {
			return fail("the setup plan cannot be inspected")
		}
		setup.owner = plan.RecoveryOwner()
	default:
		return fail("unknown setup kind")
	}
	_, policy, err := runtimeconfig.LoadProtectedConfiguration(w.ctx, filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy.json"))
	if err != nil {
		return fail("routes.json or policy.json is unprotected or invalid")
	}
	setup.retention = remoteDataRetention(policy)
	for _, connection := range policy.Connections() {
		switch connection.RequestProfile() {
		case runtimeconfig.OpenRouterZDRChatProfile, runtimeconfig.OpenCodeGoChatProfile:
			setup.windowed = true
		}
		if !slices.Contains(setup.endpoints, connection.Endpoint()) {
			setup.endpoints = append(setup.endpoints, connection.Endpoint())
		}
		if name := connection.CredentialEnvironment(); name != "" && !slices.Contains(setup.credentials, name) {
			setup.credentials = append(setup.credentials, name)
		}
	}
	if routes, err := readSetupBootstrapFile(filepath.Join(dir, "routes.json")); err == nil {
		var inventory struct {
			Routes []struct {
				AdapterID string `json:"adapter_id"`
				ModelID   string `json:"model_id"`
			} `json:"routes"`
		}
		if json.Unmarshal(routes, &inventory) == nil {
			for _, route := range inventory.Routes {
				if strings.HasSuffix(route.AdapterID, "-generation") {
					setup.generationModel = route.ModelID
				} else if strings.HasSuffix(route.AdapterID, "-verification") {
					setup.verificationModel = route.ModelID
				}
			}
		}
	}
	return setup, nil
}

func (s initSetup) destination() string {
	if s.remote {
		return s.provider.short + " (" + strings.Join(s.endpoints, ", ") + ")" + initRetentionNote(s.retention)
	}
	return "your local model server (" + strings.Join(s.endpoints, ", ") + ")"
}

// resume never re-initializes: it offers the existing check and review only.
func (w *initWizard) resume() (int, error) {
	setup, err := w.loadSetup()
	if err != nil {
		return 0, err
	}
	w.saved = true
	w.say("\nThis repository already has an Open Trestle setup. Nothing will be overwritten.")
	w.say("  Folder:   %s", initDisplayPath(w.a.directory))
	w.say("  Models:   finder %s, checker %s", setup.generationModel, setup.verificationModel)
	w.say("  Runs on:  %s", setup.destination())
	w.say("  To set up something different, run trestle init --directory NEW_FOLDER.")
	review := w.prompt == nil
	if w.prompt != nil {
		choice, err := w.prompt.choose("What would you like to do?", []string{"Re-run the setup checks", "Re-run the checks, then offer to run a review", "Quit without changes"})
		if err != nil {
			return 0, err
		}
		if choice == 2 {
			w.say("  Nothing was changed.")
			return initExitDone, nil
		}
		review = choice == 1
	}
	outcome, err := w.check(setup)
	if err != nil {
		return 0, err
	}
	if !review {
		w.writeNextSteps(setup, outcome)
		if !outcome.ready {
			return outcome.code, nil
		}
		w.say("\n  Review command:")
		w.sayVerbatim(initRenderCommand(outcome.reviewCommand))
		return initExitDone, nil
	}
	return w.finish(setup, outcome)
}

// --- Step 8: save and check -------------------------------------------------------

// reviewOutputTokens is the per-request review output allowance: 4096 unless
// --max-output-tokens was given. Bootstrap validates it against the declared
// output capacity.
func (w *initWizard) reviewOutputTokens() uint64 {
	if raw, ok := w.flags["max-output-tokens"]; ok {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return parsed
		}
	}
	return remoteReviewMaxOutputTokens
}

// reviewOutputArgs passes --max-output-tokens through only when it was given,
// so the default bootstrap arguments are unchanged.
func (w *initWizard) reviewOutputArgs() []string {
	if raw, ok := w.flags["max-output-tokens"]; ok {
		return []string{"--max-output-tokens", raw}
	}
	return nil
}

func (w *initWizard) bootstrapArgs() []string {
	a := w.a
	common := []string{"--directory", a.directory, "--tenant", a.tenant, "--repository", a.repository, "--checkout", w.checkout, "--base", a.base, "--head", a.head, "--repository-authority", a.authority, "--repository-namespace", a.namespace, "--repository-name", a.name, "--generation-model", a.generationModel, "--verification-model", a.verificationModel, "--context-tokens", a.contextTokens, "--output-tokens", a.outputTokens}
	if a.provider.key == "local" {
		args := append([]string{"init"}, common...)
		// The wizard prepares only the direct review it runs, so it does not
		// demand the daemon's private, loose-object source.
		args = append(args, "--scope", setupBootstrapDirectReviewScope, "--recovery-owner", a.owner, "--generation-endpoint", a.generationEndpoint, "--verification-endpoint", a.verificationEndpoint, "--transport", a.transport)
		if a.credentialEnv != "" {
			args = append(args, "--generation-credential-environment", a.credentialEnv, "--verification-credential-environment", a.credentialEnv)
		}
		args = append(args, w.reviewOutputArgs()...)
		return append(args, a.declarations...)
	}
	providerName := a.provider.key
	if providerName == "openrouter" {
		providerName = w.openRouterBootstrapProvider()
	}
	args := append([]string{"init", "--provider", providerName}, common...)
	if a.provider.key == ollamaSigninProvider {
		// No key: the local Ollama uses its own `ollama signin` account.
		if a.generationEndpoint != ollamaSigninDefaultBaseURL {
			args = append(args, "--endpoint", a.generationEndpoint)
		}
	} else {
		args = append(args, "--generation-credential-environment", a.credentialEnv)
	}
	args = append(args, "--declared-by", a.owner, "--input-micro-usd-per-million-tokens", a.inputPrice, "--output-micro-usd-per-million-tokens", a.outputPrice, "--max-cost-micro-usd", a.maxCost)
	args = append(args, w.reviewOutputArgs()...)
	args = append(args, a.extra...)
	return append(args, a.declarations...)
}

func (w *initWizard) stepWrite() (int, error) {
	w.header(6, "Save and check")
	dir := w.a.directory
	if dir == "" {
		return 0, initStopf(initExitUsage, "cannot find your home folder for the default setup folder. Pass --directory PATH.")
	}
	created := false
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return 0, initStopf(initExitRefused, "could not create %s. Pass --directory with a folder you can write.", initDisplayPath(filepath.Dir(dir)))
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return 0, initStopf(initExitRefused, "could not create %s. Pass --directory with a folder you can write.", initDisplayPath(dir))
		}
		created = true
	}
	var out, errOut bytes.Buffer
	ctx := w.ctx
	if w.openRouter != nil {
		ctx = withOpenRouterObservation(ctx, w.openRouter)
	}
	code := runSetupBootstrapWithContext(ctx, w.bootstrapArgs(), &out, &errOut, w.clock)
	if (code == initExitRefused || code == initExitUsage || code == initExitFailed) && !w.setupWritten() {
		reason := w.refusalReason(out.Bytes(), errOut.String())
		cleanup := ""
		if created {
			if os.Remove(dir) == nil {
				cleanup = " Nothing was left behind."
			} else {
				cleanup = fmt.Sprintf(" Some files were written to %s before the refusal; keep or inspect them and use a new --directory.", initDisplayPath(dir))
			}
		}
		if code == initExitFailed {
			return 0, initStopf(initExitFailed, "saving the setup failed: %s.%s", reason, cleanup)
		}
		return 0, initStopf(initExitRefused, "setup was refused: %s.%s", reason, cleanup)
	}
	w.saved = true
	w.say("  %s Saved protected configuration in %s", w.ok, initDisplayPath(dir))
	setup, err := w.loadSetup()
	if err != nil {
		return 0, err
	}
	outcome, err := w.check(setup)
	if err != nil {
		return 0, err
	}
	return w.finish(setup, outcome)
}

// setupWritten reports whether the bootstrap saved a setup in the chosen folder.
// The bootstrap writes bootstrap.json last, and a re-run resumes any folder that
// holds it, so the setup is saved even when the bootstrap's own check then
// refused, for example the scanner check of a development build.
func (w *initWizard) setupWritten() bool {
	_, err := os.Lstat(filepath.Join(w.a.directory, "bootstrap.json"))
	return err == nil
}

// rerunCommand is the `trestle init` command that finds this setup again.
func (w *initWizard) rerunCommand(program string) string {
	command := program + " init"
	if w.a.directory != w.defaultDirectory() {
		command += " --directory " + initShellQuote(w.a.directory)
	}
	return command
}

// explainSavedWithoutScanner says what a saved remote setup still needs when
// this trestle cannot send source at all, and how a re-run continues it.
func (w *initWizard) explainSavedWithoutScanner(setup initSetup, block string) {
	if block == "platform" {
		w.say("  Your setup is saved, but this machine cannot send source to %s: the sandboxed secret scanner that checks every request runs only on Linux.", setup.provider.short)
		return
	}
	w.say("  Your setup is saved, but this development build cannot send source to %s.", setup.provider.short)
	w.say("  Build and install the packaged trestle from a clean checkout (docs/operations.md):")
	w.sayPackagingSteps()
	w.say("  Then run this in the repository; it finds this setup and re-checks it:")
	w.sayVerbatim("    " + w.rerunCommand("/usr/local/bin/trestle"))
}

func (w *initWizard) refusalReason(out []byte, errText string) string {
	var remote remoteBootstrapResult
	if json.Unmarshal(out, &remote) == nil && remote.Contract == remoteBootstrapResultContract && len(remote.Messages) != 0 {
		return strings.Join(remote.Messages, "; ")
	}
	if w.a.provider.key != "local" {
		if text := strings.TrimSpace(errText); text != "" {
			return text
		}
		return "the bootstrap gave no reason"
	}
	if reason, ok := strings.CutPrefix(strings.TrimSpace(errText), "trestle setup bootstrap: "); ok {
		return reason
	}
	// The local bootstrap usually refuses without a reason. The source was already read
	// successfully before any question, so the setup folder is the likely cause.
	return "the local bootstrap does not say why; likely cause: the setup folder and every parent folder must be owned by you and not writable by other accounts"
}

// localProbeConsent asks once for the optional synthetic test requests. They go
// only to the configured loopback servers and carry fixed sample code, never
// source. A probe that already passed is not repeated.
func (w *initWizard) localProbeConsent() (bool, error) {
	if w.bools["allow-local-probe"] {
		return true, nil
	}
	if w.prompt == nil {
		return false, nil
	}
	if plan, err := setupcore.InspectStateFile(w.ctx, filepath.Join(w.a.directory, "runs", "setup", "plan.json")); err == nil {
		for _, requirement := range plan.Requirements() {
			if requirement.Key() == setupcore.CheckLocalInferenceValidated && requirement.State() == setupcore.CheckPassed {
				return false, nil
			}
		}
	}
	w.say("\n  Optional: send two tiny test requests (fixed sample code, never your source) to your local servers to check that both models answer in the expected format.")
	return w.prompt.confirm("Send the two test requests?", false)
}

func (w *initWizard) check(setup initSetup) (initOutcome, error) {
	args := []string{"check", "--directory", w.a.directory}
	if !setup.remote {
		args = append(args, "--approved-by", setup.owner, "--scope", setupBootstrapDirectReviewScope)
		probe, err := w.localProbeConsent()
		if err != nil {
			return initOutcome{}, err
		}
		if probe {
			args = append(args, "--allow-local-probe")
		}
	}
	w.say("\n  Setup checks:")
	var out, errOut bytes.Buffer
	code := runSetupBootstrapWithContext(w.ctx, args, &out, &errOut, w.clock)
	if code == initExitFailed || code == initExitUsage {
		return initOutcome{}, initStopf(initExitFailed, "the setup check could not run (%s)", strings.TrimSpace(errOut.String()))
	}
	if setup.remote {
		var result remoteBootstrapResult
		if json.Unmarshal(out.Bytes(), &result) != nil {
			return initOutcome{}, initStopf(initExitFailed, "the setup check returned an unreadable result")
		}
		summary := w.renderRemote(result, setup)
		return initOutcome{code: code, ready: result.Ready, reviewCommand: result.ReviewCommand, summary: summary}, nil
	}
	var result setupBootstrapResult
	if json.Unmarshal(out.Bytes(), &result) != nil {
		return initOutcome{}, initStopf(initExitFailed, "the setup check returned an unreadable result")
	}
	summary := w.renderLocal(result.Messages)
	// The direct-review scope reports ready only when every check the review
	// relies on passed; the daemon-only items are not part of it.
	return initOutcome{code: code, ready: result.Ready && result.Scope == setupBootstrapDirectReviewScope && len(result.EphemeralReviewCommand) > 3, reviewCommand: result.EphemeralReviewCommand, summary: summary}, nil
}

func (w *initWizard) mark(state string) string {
	switch state {
	case "passed":
		return w.ok
	case "refused":
		return w.bad
	case "optional":
		return w.optional
	}
	return w.wait
}

type initTally map[string]int

func (t initTally) String() string {
	parts := []string{}
	for _, entry := range []struct{ state, text string }{{"passed", "passed"}, {"refused", "need a fix"}, {"pending", "waiting"}, {"skipped", "not checked yet"}, {"optional", "optional items not set up"}} {
		if n := t[entry.state]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, entry.text))
		}
	}
	return strings.Join(parts, ", ")
}

func (w *initWizard) renderRemote(result remoteBootstrapResult, setup initSetup) string {
	tally := initTally{}
	keys := []string{}
	if setup.windowed {
		keys = append(keys, "privacy_declaration_current")
	}
	keys = append(keys, "dispatch_catalog_validated")
	if setup.provider.key == ollamaSigninProvider {
		keys = append(keys, "ollama_cloud_models_listed")
	} else {
		keys = append(keys, "credential_environment_present")
	}
	keys = append(keys, "sanitized_egress_scanner")
	names := strings.Join(setup.credentials, ", ")
	labels := map[string]string{
		"privacy_declaration_current":    "Your declared privacy review window is current",
		"dispatch_catalog_validated":     "The saved configuration loads into the model dispatcher",
		"credential_environment_present": "API key variable " + names + " is set",
		"ollama_cloud_models_listed":     "Your local Ollama lists both models as Ollama Cloud models",
		"sanitized_egress_scanner":       "The secret scanner is installed (it checks every request before it leaves)",
	}
	state := func(key string) string {
		switch {
		case slices.Contains(result.Refused, key):
			return "refused"
		case slices.Contains(result.Pending, key):
			return "pending"
		case key == "dispatch_catalog_validated" && slices.Contains(keys, "privacy_declaration_current") && state0(result, "privacy_declaration_current") != "passed":
			return "skipped"
		}
		return "passed"
	}
	scannerDetail := ""
	for _, message := range result.Messages {
		if strings.Contains(message, "cannot sanitize remote egress") {
			if start, end := strings.Index(message, "("), strings.Index(message, ")"); start >= 0 && end > start {
				scannerDetail = " Detail: " + message[start+1:end] + "."
			}
		}
	}
	hints := map[string]string{
		"privacy_declaration_current/pending":    "Your declared review window has not started. Wait for it, then run `trestle init` again.",
		"privacy_declaration_current/refused":    "Your declared review window has ended. Review the provider terms and your account again, then run trestle init --directory NEW_FOLDER.",
		"dispatch_catalog_validated/refused":     "The saved files could not be prepared for sending. Set up again with trestle init --directory NEW_FOLDER.",
		"dispatch_catalog_validated/skipped":     "Checked once the review window is current.",
		"credential_environment_present/pending": "Export the key in this shell without showing it, then run `trestle init` again in this repository:",
		"ollama_cloud_models_listed/pending":     "Start Ollama on this machine (`ollama serve`, or the Ollama app), then run `trestle init` again in this repository.",
		"ollama_cloud_models_listed/refused":     "A chosen model is no longer listed as an Ollama Cloud model by your local Ollama. Set up again with trestle init --directory NEW_FOLDER.",
		"sanitized_egress_scanner/pending":       "Install the scanner from a packaged release: sudo ./open-trestle-linux-amd64.pyz install (docs/remote-model-review.md#prerequisite-1-a-scanner-bound-binary-and-installed-scanner).",
		"sanitized_egress_scanner/refused":       "This trestle is a development build without the scanner fingerprints, so it refuses to send source. Build and install the packaged binary: python3 tools/package_secret_scanner.py --output .container, then follow docs/remote-model-review.md#prerequisite-1-a-scanner-bound-binary-and-installed-scanner." + scannerDetail,
	}
	for _, key := range keys {
		current := state(key)
		tally[current]++
		w.say("    %s %s", w.mark(current), labels[key])
		if hint := hints[key+"/"+current]; hint != "" {
			w.hint("        " + hint)
		}
		if key == "credential_environment_present" && current == "pending" {
			for _, name := range setup.credentials {
				if os.Getenv(name) == "" {
					w.sayVerbatim("          read -rs " + name + " && export " + name)
				}
			}
		}
	}
	for _, key := range append(append([]string{}, result.Pending...), result.Refused...) {
		if !slices.Contains(keys, key) {
			tally[state(key)]++
			w.say("    %s %s", w.mark(state(key)), key)
			w.hint("        " + strings.Join(result.Messages, " "))
		}
	}
	switch result.DataRetention {
	case "required_per_request":
		w.say("    %s Zero data retention is required on every request", w.ok)
	case "not_required_by_open_trestle":
		w.say("    %s Zero data retention is not required by Open Trestle (your OpenRouter account or key settings may still enforce it); a model provider may keep prompts under its own terms", w.optional)
	}
	return tally.String()
}

func state0(result remoteBootstrapResult, key string) string {
	switch {
	case slices.Contains(result.Refused, key):
		return "refused"
	case slices.Contains(result.Pending, key):
		return "pending"
	}
	return "passed"
}

var initLocalCheckText = map[setupcore.CheckKey][2]string{
	setupcore.CheckProfileSelected:              {"Setup profile chosen (single machine)", ""},
	setupcore.CheckScopeValid:                   {"Tenant and repository names are valid", ""},
	setupcore.CheckEffectPostureLocked:          {"Publishing is off: results stay on this machine", ""},
	setupcore.CheckRecoveryOwnerNamed:           {"Setup owner recorded", ""},
	setupcore.CheckStateStoragePostureValidated: {"The setup folder is private", "Keep the setup folder and its parents owned by you and not writable by others."},
	setupcore.CheckLocalAdministratorValidated:  {"You are the setup owner", "Run trestle init as the same account that created this setup."},
	setupcore.CheckPolicyValidated:              {"Model configuration approved", "Runs after the items above pass."},
	setupcore.CheckDryRunValidated:              {"Dry run without models", "Runs after the items above pass."},
	setupcore.CheckLocalInferenceValidated:      {"Both models answered a tiny test request", "A model did not answer the test request in the expected format. Check that both servers are running and the model IDs are exact, then run `trestle init` again and allow the test requests."},
}

// Checks that only the optional background daemon needs; the direct review
// never reads them, and the direct-review check does not run them.
var initDaemonOnlyChecks = []setupcore.CheckKey{setupcore.CheckObserverCredentialPostureValidated, setupcore.CheckBackupValidated}

// renderLocal prints each local setup check. A refused test request that the
// bootstrap check named (messages) shows that fixed reason instead of the
// generic advice.
func (w *initWizard) renderLocal(messages []string) string {
	tally := initTally{}
	plan, err := setupcore.InspectStateFile(w.ctx, filepath.Join(w.a.directory, "runs", "setup", "plan.json"))
	if err != nil {
		w.say("    %s The setup plan could not be read back.", w.bad)
		return "the setup plan could not be read back"
	}
	daemonOnly := false
	for _, requirement := range plan.Requirements() {
		if slices.Contains(initDaemonOnlyChecks, requirement.Key()) {
			daemonOnly = daemonOnly || requirement.State() != setupcore.CheckPassed
			continue
		}
		text, known := initLocalCheckText[requirement.Key()]
		if !known {
			text = [2]string{string(requirement.Key()), ""}
		}
		state := "pending"
		switch requirement.State() {
		case setupcore.CheckPassed:
			state = "passed"
		case setupcore.CheckBlocked, setupcore.CheckUnavailable:
			state = "refused"
		}
		if requirement.Key() == setupcore.CheckLocalInferenceValidated && state == "pending" {
			state, text = "optional", [2]string{"Test requests to both models (optional; not sent)", ""}
		}
		if requirement.Key() == setupcore.CheckLocalInferenceValidated && state == "refused" {
			for _, message := range messages {
				reason, ok := strings.CutPrefix(message, string(setupcore.CheckLocalInferenceValidated)+": ")
				if !ok {
					continue
				}
				// A server that answered with a reply the adapter refused did
				// not refuse the request; the check's own advice fits it.
				if detail, _, _ := strings.Cut(reason, ": "); detail == localreview.FailureDetailProviderResponseInvalid {
					text[1] = "A model server answered the test request, but its reply was not in the expected format (" + detail + "). Check that both servers are running and the model IDs are exact, then run `trestle init` again and allow the test requests."
					continue
				}
				text[1] = "A model server refused the test request (" + strings.Replace(reason, ": ", "): ", 1) + "."
			}
		}
		tally[state]++
		w.say("    %s %s", w.mark(state), text[0])
		if state != "passed" && text[1] != "" {
			w.hint("        " + text[1])
		}
	}
	if daemonOnly {
		tally["optional"]++
		w.say("    %s Background-service tokens and backup (only for the optional daemon; not needed here)", w.optional)
	}
	return tally.String()
}

// --- Finish: show the command, then review only with consent ---------------------

func (w *initWizard) finish(setup initSetup, outcome initOutcome) (int, error) {
	w.writeNextSteps(setup, outcome)
	if !outcome.ready {
		w.say("\n  Setup checks: %s.", outcome.summary)
		if block := initScannerBlock(); setup.remote && block != "" {
			w.explainSavedWithoutScanner(setup, block)
			return outcome.code, nil
		}
		w.say("  Not ready for a review yet. Fix the items marked %s or %s above, then run `trestle init` again in this repository: it finds this setup and re-checks it.", w.wait, w.bad)
		return outcome.code, nil
	}
	w.say("\n%s", w.style.paint(initToneHeading, "Ready for the first review"))
	w.say("%s", w.style.paint(initToneRule, strings.Repeat("─", 26)))
	w.say("  Review command (each argument quoted for a POSIX shell; run it yourself any time):")
	w.sayVerbatim(initRenderCommand(outcome.reviewCommand))
	run := w.bools["run-review"]
	if w.prompt != nil && !run {
		var err error
		w.say("\n  Setup checks: %s (details above).", outcome.summary)
		w.say("  A review sends the selected source to %s.", setup.destination())
		if run, err = w.prompt.confirm("Run the first review now?", false); err != nil {
			return 0, err
		}
	}
	if !run {
		w.say("  No review was run. Run the command above when you are ready, or `trestle init` again.")
		return initExitDone, nil
	}
	return w.review(outcome.reviewCommand), nil
}

// initHangingWrap wraps one "label: value" result line to width, indenting
// continuation lines under the value so a long hint or limitation list does
// not read as a new field. A line without a short lowercase label, or whose
// label leaves too little room, wraps flush.
func initHangingWrap(line string, width int) []string {
	label, value, found := strings.Cut(line, ": ")
	indent := len(label) + 2
	if !found || label == "" || indent > width/3 || strings.TrimFunc(label, func(r rune) bool { return r >= 'a' && r <= 'z' || r == ' ' || r == '_' }) != "" {
		return initWrapWords(line, width)
	}
	parts := initWrapWords(value, width-indent)
	lines := make([]string, len(parts))
	for i, part := range parts {
		if i == 0 {
			lines[i] = label + ": " + part
		} else {
			lines[i] = strings.Repeat(" ", indent) + part
		}
	}
	return lines
}

func (w *initWizard) review(command []string) int {
	if len(command) < 4 || strings.Join(command[:3], " ") != "trestle local-git model-review" {
		fmt.Fprintln(w.errOut, "trestle init: the setup did not produce a usable review command")
		return initExitFailed
	}
	w.say("\n  Running the review. This can take several minutes; press Ctrl-C to stop.")
	var out, errOut bytes.Buffer
	code := runLocalGitModelReview(w.ctx, command[3:], &out, &errOut)
	status, findings := "", 0
	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		for _, part := range initHangingWrap(line, initWidth-4) {
			w.sayVerbatim("  │ " + part)
		}
		if value, ok := strings.CutPrefix(line, "status: "); ok && status == "" {
			status = value
		}
		if strings.HasPrefix(line, "finding: ") {
			findings++
		}
	}
	if text := strings.TrimSpace(errOut.String()); text != "" {
		w.say("  │ %s", text)
	}
	w.say("")
	switch status {
	case "findings":
		w.say("  %s Review finished: %d confirmed finding%s above. Each was proposed by the finder and confirmed by the checker. Treat them like a colleague's comments; the review is not a complete audit (comprehensive clearance: false).", w.ok, findings, initPlural(findings))
		return initExitDone
	case "no_candidates":
		w.say("  %s Review finished: no problems were found and confirmed for this change. That is not proof the change is correct; it is not a complete audit.", w.ok)
		return initExitDone
	case "incomplete":
		w.say("  %s The review could not cover everything; see coverage and omissions above.", w.wait)
		return initExitPending
	case "canceled":
		w.say("  %s The review was stopped before it finished.", w.wait)
		return initExitPending
	case "refused":
		w.say("  %s The review was refused before it started. Run `trestle init` again to re-check the setup, and check that the selected commits still exist.", w.bad)
		return initExitRefused
	}
	w.say("  %s The review failed (exit %d). Check that the models are reachable, then run the review command above again.", w.bad, code)
	return initExitFailed
}

func (w *initWizard) writeNextSteps(setup initSetup, outcome initOutcome) {
	dir := w.a.directory
	path := filepath.Join(dir, "NEXT-STEPS.txt")
	if _, err := os.Lstat(path); err == nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Open Trestle next steps\n\nRepository: %s\nSetup folder: %s\n", w.checkout, dir)
	fmt.Fprintf(&b, "Models: finder %s, checker %s\nRuns on: %s\n", setup.generationModel, setup.verificationModel, setup.destination())
	if len(setup.credentials) != 0 {
		fmt.Fprintf(&b, "API key variable: %s (export it in the shell that runs the review; the value is never stored)\n", strings.Join(setup.credentials, ", "))
	}
	fmt.Fprintf(&b, "\nRe-run the setup checks: run `trestle init` again in the repository, or\n")
	check := []string{"trestle", "setup", "bootstrap", "check", "--directory", dir}
	if !setup.remote {
		check = append(check, "--approved-by", setup.owner, "--scope", setupBootstrapDirectReviewScope)
	}
	fmt.Fprintf(&b, "%s\n", initRenderCommand(check))
	if len(outcome.reviewCommand) != 0 {
		fmt.Fprintf(&b, "\nRun a review (sends the selected source to %s):\n%s\n", setup.destination(), initRenderCommand(outcome.reviewCommand))
	}
	fmt.Fprintf(&b, "\nGuide: docs/getting-started.md\n")
	if err := fileauthority.WriteNewProtectedFile(w.ctx, path, []byte(b.String()), 65536); err != nil {
		w.say("  (Could not save %s; the steps are shown here.)", initDisplayPath(path))
		return
	}
	w.say("\n  Saved these next steps to %s", initDisplayPath(path))
}

const initShellSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"

func initShellQuote(value string) string {
	if value != "" && strings.Trim(value, initShellSafe) == "" {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// initRenderCommand renders an argument array for a POSIX shell, one flag and
// its value per line. It is for reading and copying; nothing here executes it.
func initRenderCommand(args []string) string {
	lines := []string{}
	start := min(len(args), 3)
	if len(args) > 0 && args[0] == "trestle" && len(args) > 3 && args[1] == "setup" {
		start = min(len(args), 4)
	}
	head := []string{}
	for _, arg := range args[:start] {
		head = append(head, initShellQuote(arg))
	}
	lines = append(lines, "    "+strings.Join(head, " "))
	for i := start; i < len(args); i++ {
		part := initShellQuote(args[i])
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			part += " " + initShellQuote(args[i+1])
			i++
		}
		lines = append(lines, "      "+part)
	}
	return strings.Join(lines, " \\\n")
}
