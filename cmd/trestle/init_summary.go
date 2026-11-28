package main

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Everything `trestle init` can work out for itself is filled in without a
// question and shown in one settings panel with the consent: the names from
// the Git remote or folder, the owner from $USER, the key variable name, and
// the limits and prices the provider or model list reported. Each value stays
// a default: a flag overrides it, and answering no at the panel changes it.

// initRemoteIdentity reads origin's configured URL (read-only, no rewriting
// from global configuration) and returns its host, namespace and name as
// labels. Credentials in the URL are never read into a label.
func initRemoteIdentity(raw string) (authority, namespace, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	host, path := "", ""
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.Scheme != "https" && parsed.Scheme != "http" && parsed.Scheme != "ssh" && parsed.Scheme != "git" {
			return "", "", "", false
		}
		host, path = parsed.Hostname(), parsed.Path
	} else if colon := strings.Index(raw, ":"); colon > 0 && !strings.ContainsAny(raw[:colon], "/\\") {
		// scp-like syntax: [user@]host:owner/name.git
		host, path = raw[:colon], raw[colon+1:]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
	} else {
		return "", "", "", false
	}
	segments := strings.Split(strings.TrimSuffix(strings.Trim(path, "/"), ".git"), "/")
	if host == "" || len(segments) < 2 || len(segments) > 8 {
		return "", "", "", false
	}
	labels := []string{}
	for _, segment := range segments {
		label := initLabel(segment, "")
		if label == "" {
			return "", "", "", false
		}
		labels = append(labels, label)
	}
	authority = strings.ToLower(host)
	namespace, name = strings.Join(labels[:len(labels)-1], "/"), labels[len(labels)-1]
	if _, err := evidence.NewRepositoryIdentity(authority, labels[:len(labels)-1], name); err != nil {
		return "", "", "", false
	}
	return authority, namespace, name, true
}

// initOwner is the operator recorded as making the declarations: $USER, else
// the account name.
func initOwner() string {
	if name := initLabel(os.Getenv("USER"), ""); name != "" {
		return name
	}
	if current, err := user.Current(); err == nil {
		return initLabel(current.Username, "owner")
	}
	return "owner"
}

// initNameDefaults are the proposed labels, from the Git remote when origin
// names a host, otherwise from the folder name and owner.
func (w *initWizard) initNameDefaults() map[string]string {
	owner := initOwner()
	values := map[string]string{"owner": owner, "tenant": "personal", "repository": w.repoName, "repository-authority": "local", "repository-namespace": owner, "repository-name": w.repoName}
	if remote, _, err := initGit(w.ctx, w.checkout, "config", "--get", "remote.origin.url"); err == nil {
		if authority, namespace, name, ok := initRemoteIdentity(remote); ok {
			values["repository-authority"], values["repository-namespace"], values["repository-name"], values["repository"] = authority, namespace, name, name
		}
	}
	return values
}

var initNameQuestions = []struct{ flag, question string }{
	{"owner", "Owner (recorded as making the declarations)"},
	{"tenant", "Tenant (a group name for your setups)"},
	{"repository", "Repository ID"},
	{"repository-authority", "Host label (where the code lives)"},
	{"repository-namespace", "Namespace (owner or team on that host)"},
	{"repository-name", "Repository name on that host"},
}

// autoNames sets every name from its flag or its default, without a question.
func (w *initWizard) autoNames() error {
	defaults := w.initNameDefaults()
	values := map[string]string{}
	for _, name := range initNameQuestions {
		value := defaults[name.flag]
		if raw, ok := w.flags[name.flag]; ok {
			validated, err := initValidLabel(raw)
			if err != nil {
				return initStopf(initExitUsage, "--%s: %v", name.flag, err)
			}
			value = validated
		}
		values[name.flag] = value
	}
	return w.setLabels(values)
}

// askNames asks each name again, proposing the current value.
func (w *initWizard) askNames() error {
	current := map[string]string{"owner": w.a.owner, "tenant": w.a.tenant, "repository": w.a.repository, "repository-authority": w.a.authority, "repository-namespace": w.a.namespace, "repository-name": w.a.name}
	values := map[string]string{}
	for _, name := range initNameQuestions {
		value, err := w.prompt.ask(name.question, current[name.flag], initValidLabel)
		if err != nil {
			return err
		}
		values[name.flag] = value
	}
	return w.setLabels(values)
}

// summaryRows lists every setting, asked or filled in, in plain words.
func (w *initWizard) summaryRows() [][2]string {
	a := w.a
	commits := initShort(a.source.base) + " → " + initShort(a.source.head)
	runsOn := a.provider.short
	switch {
	case a.provider.key == "local":
		runsOn = a.generationEndpoint
		if a.verificationEndpoint != a.generationEndpoint {
			runsOn += ", " + a.verificationEndpoint
		}
	case a.provider.key == ollamaSigninProvider:
		runsOn += " (" + a.generationEndpoint + ")"
	case a.provider.key == "openrouter" && w.zdr:
		runsOn += ", zero data retention required on every request"
	case a.provider.key == "openrouter":
		runsOn += ", zero data retention not required by Open Trestle"
	}
	checker := a.verificationModel
	if family := initSameFamily(a.generationModel, a.verificationModel); family != "" {
		checker += " (same " + family + " family as the finder; a different family is recommended)"
	}
	rows := [][2]string{{"Review", commits}, {"Runs on", runsOn}, {"Finder", a.generationModel}, {"Checker", checker}}
	if w.specialists() == specialistModeNone {
		rows = append(rows, [2]string{"Specialists", "off: the general review only (--specialists auto turns them on)"})
	} else {
		rows = append(rows, [2]string{"Specialists", fmt.Sprintf("on: the general review, then up to %d specialist reviews picked from the change, each a full review (--specialists none turns them off)", defaultMaxSpecialists)})
	}
	if a.contextTokens != "" {
		rows = append(rows, [2]string{"Limits", "context " + a.contextTokens + " · output " + a.outputTokens + " tokens"})
	}
	if a.provider.key != "local" && a.maxCost != "" {
		input, _ := strconv.ParseUint(a.inputPrice, 10, 64)
		output, _ := strconv.ParseUint(a.outputPrice, 10, 64)
		limit, _ := strconv.ParseUint(a.maxCost, 10, 64)
		prices := initFormatUSD(input) + " in · " + initFormatUSD(output) + " out per million tokens"
		if input+output == 0 {
			prices = "no per-token charge"
		}
		// The per-request bound is set for you; it is shown, not asked.
		rows = append(rows, [2]string{"Cost", prices + " · " + initCostBound(limit, w.specialists() != specialistModeNone)})
	}
	if row, ok := w.spendingRow(); ok {
		rows = append(rows, [2]string{"Spending", row})
	}
	switch state := providerKeyStatus(a.credentialEnv); {
	case a.credentialEnv == "":
		rows = append(rows, [2]string{"Key", "none"})
	case state.source == providerKeyFromSession && slices.Contains(w.enteredKeys, a.credentialEnv):
		rows = append(rows, [2]string{"Key", a.credentialEnv + " (to be saved in " + providerCredentialDisplayDirectory() + " with the setup)"})
	case state.available():
		rows = append(rows, [2]string{"Key", a.credentialEnv + " (" + state.where() + ")"})
	default:
		rows = append(rows, [2]string{"Key", a.credentialEnv + " (not set yet)"})
	}
	rows = append(rows,
		[2]string{"Source", a.authority + "/" + a.namespace + "/" + a.name},
		[2]string{"Names", "tenant " + a.tenant + " · repository " + a.repository + " · owner " + a.owner},
		[2]string{"Folder", initDisplayPath(a.directory)})
	return rows
}

// stepSummary shows every setting in one panel with the declarations under
// it, and one answer confirms them all. Answering no offers what to change,
// then shows both again.
func (w *initWizard) stepSummary() error {
	if w.prompt == nil && len(w.missing) != 0 {
		// --no-input without every answer: the list of missing flags follows.
		return nil
	}
	for range initMaxTries {
		w.say("%s", "")
		for _, line := range w.style.framed(initPanel("Setup summary", w.summaryRows(), w.style.ascii)) {
			w.sayVerbatim(line)
		}
		w.showDeclarations()
		if w.prompt == nil {
			for _, d := range w.pending {
				if !w.bools[d.flag] {
					w.missing = append(w.missing, "--"+d.flag)
				}
			}
			w.confirmDeclarations()
			return nil
		}
		yes, err := w.prompt.confirm("Confirm all of the above and save this setup?", true)
		if err != nil {
			return err
		}
		if yes {
			w.confirmDeclarations()
			return nil
		}
		if err := w.changeSettings(); err != nil {
			return err
		}
	}
	return errInitTooManyTries
}

// confirmDeclarations records the confirmed declarations as their bootstrap
// flags.
func (w *initWizard) confirmDeclarations() {
	for _, d := range w.pending {
		w.a.declarations = append(w.a.declarations, "--"+d.flag)
	}
}

func (w *initWizard) stopUnconfirmed() error {
	return initStopf(initExitRefused, "stopped: you did not confirm the setup. Nothing was written. Open Trestle will not record facts you have not confirmed. Run `trestle init` again when you are ready.")
}

func (w *initWizard) changeSettings() error {
	options := []string{"The commits to review", "The names", "Nothing; stop without saving"}
	actions := []func() error{w.changeCommits, w.askNames, w.stopUnconfirmed}
	if w.a.credentialEnv != "" {
		options = append(options[:2:2], "The API key variable", options[2])
		actions = append(actions[:2:2], w.changeCredential, w.stopUnconfirmed)
	}
	if w.a.contextTokens != "" {
		last := len(options) - 1
		options = append(append(options[:last:last], "The limits and prices"), options[last])
		actions = append(append(actions[:last:last], w.changeLimits), w.stopUnconfirmed)
	}
	index, err := w.prompt.choose("What would you like to change?", options, 0)
	if err != nil {
		return err
	}
	return actions[index]()
}

func (w *initWizard) changeCommits() error {
	normalize := func(value string) (string, error) { return initNormalizeSelection(w.ctx, w.checkout, value) }
	for range initMaxTries {
		base, err := w.prompt.ask("Base: the starting point to compare against", w.a.base, normalize)
		if err != nil {
			return err
		}
		head, err := w.prompt.ask("Head: the commit with your changes", w.a.head, normalize)
		if err != nil {
			return err
		}
		source, problem := w.resolvePair(base, head)
		if problem != "" {
			w.say("  %s %s", w.bad, problem)
			continue
		}
		w.printSelection(base, "", head, source, initSummarizeChange(w.ctx, w.checkout, source.base, source.head))
		w.a.base, w.a.head, w.a.source = base, head, source
		return w.sourcePreflight()
	}
	return errInitTooManyTries
}

func (w *initWizard) changeCredential() error {
	name, err := w.prompt.ask("Environment variable that holds the key", w.a.credentialEnv, initCredentialName)
	if err == nil {
		w.a.credentialEnv = name
	}
	return err
}

func (w *initWizard) changeLimits() error {
	context, err := w.prompt.ask("Context window in tokens", w.a.contextTokens, initTokens(8192, 1<<31, "The context must be at least 8192 tokens."))
	if err != nil {
		return err
	}
	limit, _ := strconv.ParseUint(context, 10, 64)
	output, err := w.prompt.ask("Output limit in tokens", w.a.outputTokens, initTokens(4096, limit, fmt.Sprintf("The output limit must be from 4096 to %d tokens (the context).", limit)))
	if err != nil {
		return err
	}
	w.a.contextTokens, w.a.outputTokens = context, output
	if written, _ := strconv.ParseUint(output, 10, 64); w.a.reviewOutput > written {
		// The allowance never exceeds the output limit it is written within.
		w.a.reviewOutput = written
	}
	if w.a.provider.key == "local" {
		return nil
	}
	dollars := func(micro string) string {
		n, _ := strconv.ParseUint(micro, 10, 64)
		return strings.TrimPrefix(initFormatUSD(n), "$")
	}
	if w.a.inputPrice, err = w.prompt.ask("Input price, USD per million tokens", dollars(w.a.inputPrice), initUSD); err != nil {
		return err
	}
	if w.a.outputPrice, err = w.prompt.ask("Output price, USD per million tokens", dollars(w.a.outputPrice), initUSD); err != nil {
		return err
	}
	return w.costLimit()
}

// initCostBound words the most one request and one review can cost. A review
// sends two requests, and each specialist review is a review of its own.
func initCostBound(limit uint64, specialists bool) string {
	bound := "up to " + initFormatUSD(limit) + " a request and " + initFormatUSD(2*limit) + " a review"
	if specialists {
		bound += fmt.Sprintf(", or %s with %d specialist reviews", initFormatUSD(2*limit*(1+defaultMaxSpecialists)), defaultMaxSpecialists)
	}
	return bound
}
