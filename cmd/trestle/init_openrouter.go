package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

// The OpenRouter part of `trestle init`. Setup reads OpenRouter's public model
// list and zero-data-retention (ZDR) endpoint list once and fills in every
// model fact from them. It asks only what the operator alone can decide: the
// two models, whether to require ZDR (recommended, the default), a cost limit
// and consent to send source. Nothing asked here is evidence, a timestamp or a
// provider slug.

func (w *initWizard) openRouterModels() error {
	if raw, ok := w.flags["provider"]; ok && raw == "openrouter-zdr" && w.bools["without-zdr"] {
		return initStopf(initExitUsage, "--provider openrouter-zdr requires zero data retention; --without-zdr cannot be combined with it. Use --provider openrouter --without-zdr instead.")
	}
	w.openRouter = w.readOpenRouter()
	if err := w.pickPair(w.openRouter.catalog, w.openRouter.catalog); err != nil {
		return err
	}
	if w.a.generationModel == "" || w.a.verificationModel == "" {
		// --no-input without both models: name what the facts cannot supply.
		needed := []string{"max-cost-micro-usd"}
		if w.openRouter.err != nil {
			needed = append(slices.Clone(remoteBootstrapOpenRouterDetected), needed...)
		}
		for _, name := range needed {
			if _, given := w.flags[name]; !given {
				w.missing = append(w.missing, "--"+name)
			}
		}
		return nil
	}
	w.openRouterSummary()
	if err := w.openRouterChooseZDR(); err != nil {
		return err
	}
	return w.openRouterLimits()
}

func (w *initWizard) readOpenRouter() *openRouterObservation {
	if w.prompt != nil {
		w.say("  Reading OpenRouter's public model list and zero-data-retention endpoint list")
		w.say("  (two requests to openrouter.ai; no key or code is sent) ...")
	}
	observation := readOpenRouterObservation(w.ctx, w.clock)
	if observation.err != nil {
		w.say("  %s Could not read OpenRouter's API: %v.", w.wait, observation.err)
		w.say("  Type each model ID exactly (format: %s); its limits and prices are asked instead.", w.a.provider.example)
		return observation
	}
	w.say("  %s %d models listed; %d have zero-data-retention endpoints.", w.ok, len(observation.catalog), observation.zdrModelCount)
	return observation
}

func (w *initWizard) roleModel(role string) string {
	if role == "generation" {
		return w.a.generationModel
	}
	return w.a.verificationModel
}

// openRouterSummary shows what the API reported for both models, in two
// lines each.
func (w *initWizard) openRouterSummary() {
	observation := w.openRouter
	if observation.err != nil {
		return
	}
	w.say("\n  From OpenRouter's API (as reported at %s; not checked by you):", observation.retrievedAt.Format(time.RFC3339))
	for _, role := range []string{"generation", "verification"} {
		facts := observation.facts(w.roleModel(role))
		w.say("    %-8s %s", initRoleName(role)+":", facts.model)
		zdr := "no zero-data-retention endpoint"
		if facts.hasZDR() {
			slugs := facts.slugs()
			shown := strings.Join(slugs[:min(len(slugs), 3)], ", ")
			if len(slugs) > 3 {
				shown += fmt.Sprintf(" and %d more", len(slugs)-3)
			}
			zdr = fmt.Sprintf("zero data retention on %d endpoint%s (%s)", len(slugs), initPlural(len(slugs)), shown)
		} else if len(facts.safetyExcluded) != 0 {
			zdr += " without Safety Retention"
		}
		limits := ""
		if context, output, ok := facts.capacity(facts.hasZDR()); ok {
			limits = fmt.Sprintf("context %d, output %d", context, output)
		}
		if input, output, ok := facts.prices(facts.hasZDR()); ok {
			if limits != "" {
				limits += ", "
			}
			limits += fmt.Sprintf("up to %s in / %s out per million tokens", initFormatUSD(input), initFormatUSD(output))
		}
		if facts.structured(facts.hasZDR()) {
			limits += ", structured output"
		}
		w.say("             %s", zdr)
		if limits != "" {
			w.say("             %s", strings.TrimPrefix(limits, ", "))
		}
	}
	for _, role := range []string{"generation", "verification"} {
		if len(observation.facts(w.roleModel(role)).safetyExcluded) != 0 {
			w.say("  Endpoints that may keep prompts for Safety Retention are left out.")
			break
		}
	}
}

// openRouterChooseZDR decides whether every request requires zero data
// retention. With ZDR endpoints for both models it proposes yes; a model
// without one is warned about and, interactively, can be replaced.
func (w *initWizard) openRouterChooseZDR() error {
	observation := w.openRouter
	required := w.flags["provider"] == "openrouter-zdr"
	if observation.err != nil {
		w.say("\n  Without OpenRouter's API, Open Trestle cannot check which models have zero-data-retention")
		w.say("  endpoints. It can still require zero data retention on every request.")
		if w.bools["without-zdr"] {
			return w.declineZDR()
		}
		yes := true
		if !required {
			var err error
			if yes, err = w.confirm("Require zero data retention on every request (recommended)?", true, true); err != nil {
				return err
			}
		}
		if !yes {
			return w.declineZDR()
		}
		w.zdr = true
		w.say("  Requests to a model without a zero-data-retention endpoint will be refused by OpenRouter.")
		return nil
	}
	for range initMaxTries {
		missing := ""
		for _, role := range []string{"generation", "verification"} {
			if !observation.facts(w.roleModel(role)).hasZDR() {
				missing = role
				break
			}
		}
		if missing == "" {
			break
		}
		model := w.roleModel(missing)
		w.say("\n  %s %s has no zero-data-retention endpoint on OpenRouter. If your OpenRouter account or", w.wait, model)
		w.say("  key requires zero data retention, its requests will fail.")
		_, given := w.flags[missing+"-model"]
		if w.prompt == nil || given {
			if required {
				return initStopf(initExitUsage, "--provider openrouter-zdr needs zero-data-retention endpoints for both models, and %s has none (%s). Choose a model that lists them.", model, observation.label())
			}
			return w.declineZDR()
		}
		replace, err := w.prompt.confirm("Choose a model that has zero-data-retention endpoints instead (recommended)?", true)
		if err != nil {
			return err
		}
		if !replace {
			if required {
				return initStopf(initExitRefused, "stopped: --provider openrouter-zdr needs zero-data-retention endpoints for both models. Nothing was written.")
			}
			return w.declineZDR()
		}
		if err := w.repickWithZDR(missing); err != nil {
			return err
		}
		w.openRouterSummary()
	}
	for _, role := range []string{"generation", "verification"} {
		if !observation.facts(w.roleModel(role)).hasZDR() {
			return errInitTooManyTries
		}
	}
	w.say("\n  Both models have zero-data-retention endpoints.")
	if w.bools["without-zdr"] {
		return w.declineZDR()
	}
	yes := true
	if !required {
		var err error
		if yes, err = w.confirm("Require zero data retention on every request (recommended)?", true, true); err != nil {
			return err
		}
	}
	if !yes {
		return w.declineZDR()
	}
	w.zdr = true
	w.say("  Every request will require zero data retention and use only the endpoints listed above.")
	return nil
}

// repickWithZDR asks the role's model again from the models that have
// zero-data-retention endpoints.
func (w *initWizard) repickWithZDR(role string) error {
	candidates := []modelcatalog.Model{}
	for _, model := range w.openRouter.catalog {
		if w.openRouter.facts(model.Selector).hasZDR() {
			candidates = append(candidates, model)
		}
	}
	exclude := ""
	if role == "verification" {
		exclude = w.a.generationModel
	} else {
		exclude = w.a.verificationModel
	}
	question := "Finder model with zero data retention"
	if role == "verification" {
		question = "Checker model with zero data retention"
	}
	choice, err := w.pickModel(role+"-model", question, candidates, exclude)
	if err != nil {
		return err
	}
	if role == "generation" {
		w.a.generationModel = choice
	} else {
		w.a.verificationModel = choice
	}
	return nil
}

// declineZDR explains the route without zero data retention and continues
// after one yes (or --without-zdr).
func (w *initWizard) declineZDR() error {
	w.zdr = false
	w.say("  Without zero data retention, the model provider may keep your prompts under its own terms")
	w.say("  (%s). Open Trestle will not require it; your account or key settings still may.", openRouterDocsZDR)
	if w.bools["without-zdr"] {
		w.say("  Continuing without zero data retention (--without-zdr).")
		return nil
	}
	if w.prompt == nil {
		return initStopf(initExitUsage, "zero data retention is not available for these models. Pass --without-zdr to continue without it, or choose models that list zero-data-retention endpoints. Nothing was written.")
	}
	yes, err := w.prompt.confirm("Continue without zero data retention?", false)
	if err != nil {
		return err
	}
	if !yes {
		return initStopf(initExitRefused, "stopped: nothing was written. Run `trestle init` again and choose models with zero-data-retention endpoints.")
	}
	return nil
}

// openRouterLimits fills the context, output and prices from the API (flags
// win), asks for any the API did not report, and then the cost limit.
func (w *initWizard) openRouterLimits() error {
	facts := map[string]openRouterModelFacts{"generation": w.openRouter.facts(w.a.generationModel), "verification": w.openRouter.facts(w.a.verificationModel)}
	context, output, capacityKnown := uint64(1<<63), uint64(1<<63), true
	input, outputPrice, pricesKnown := uint64(0), uint64(0), true
	for _, role := range []string{"generation", "verification"} {
		c, o, ok := facts[role].capacity(w.zdr)
		context, output, capacityKnown = min(context, c), min(output, o), capacityKnown && ok
		i, p, known := facts[role].prices(w.zdr)
		input, outputPrice, pricesKnown = max(input, i), max(outputPrice, p), pricesKnown && known
	}
	output = min(output, context)
	if capacityKnown && (context < openRouterMinContext || output < openRouterMinOutput) {
		return initStopf(initExitUsage, "OpenRouter lists only %d tokens of context and %d of output for these models (%s); a review needs at least 8192 and 4096. Choose larger models.", context, output, w.openRouter.label())
	}
	if capacityKnown {
		// A flag wins over the detected value; the output stays within the context.
		if raw, given := w.flags["context-tokens"]; given {
			value, err := initTokens(8192, 1<<31, "The context must be at least 8192 tokens.")(raw)
			if err != nil {
				return initStopf(initExitUsage, "--context-tokens: %v", err)
			}
			context, _ = strconv.ParseUint(value, 10, 64)
			output = min(output, context)
		}
		if raw, given := w.flags["output-tokens"]; given {
			value, err := initTokens(4096, context, fmt.Sprintf("The output limit must be from 4096 to %d tokens (the context).", context))(raw)
			if err != nil {
				return initStopf(initExitUsage, "--output-tokens: %v", err)
			}
			output, _ = strconv.ParseUint(value, 10, 64)
		}
		w.a.contextTokens, w.a.outputTokens = strconv.FormatUint(context, 10), strconv.FormatUint(output, 10)
		source := ", the smaller of the two models"
		if _, given := w.flags["context-tokens"]; given {
			source = ""
		} else if _, given := w.flags["output-tokens"]; given {
			source = ""
		}
		w.say("\n  Limits: context %s and output %s tokens%s.", w.a.contextTokens, w.a.outputTokens, source)
	} else if err := w.capacities(); err != nil || w.a.contextTokens == "" {
		return err
	}
	flagged := false
	for _, name := range []string{"input-micro-usd-per-million-tokens", "output-micro-usd-per-million-tokens"} {
		_, given := w.flags[name]
		flagged = flagged || given
	}
	if !pricesKnown || flagged {
		return w.prices()
	}
	w.a.inputPrice, w.a.outputPrice = strconv.FormatUint(input, 10), strconv.FormatUint(outputPrice, 10)
	w.say("  Prices: up to %s input and %s output per million tokens, the higher of the two models.", initFormatUSD(input), initFormatUSD(outputPrice))
	return w.costLimit(true)
}

// openRouterConsent is the single consent of an OpenRouter setup: the facts
// came from the API, so the operator states only what only they know.
func (w *initWizard) openRouterConsent() error {
	retention := "every request requires zero data retention, so OpenRouter uses only zero-data-retention endpoints"
	if !w.zdr {
		retention = "Open Trestle does not require zero data retention, so a model provider may keep your prompts under its own terms"
	}
	w.a.extra = w.openRouterExtra()
	return w.declare("declare-remote-route", "sending your source to OpenRouter", "docs/remote-model-review.md#openrouter", []string{
		"each review sends the selected source, after secret scanning, to OpenRouter for " + w.a.generationModel + " and " + w.a.verificationModel,
		retention,
		"you have not turned on prompt logging for this key in your OpenRouter settings",
	})
}

// openRouterExtra passes slug overrides through to the bootstrap.
func (w *initWizard) openRouterExtra() []string {
	extra := []string{}
	for _, role := range []string{"generation", "verification"} {
		if raw, ok := w.flags[role+"-provider-slug"]; ok {
			extra = append(extra, "--"+role+"-provider-slug", raw)
		}
	}
	return extra
}

// openRouterBootstrapProvider is the bootstrap provider of the chosen route.
func (w *initWizard) openRouterBootstrapProvider() string {
	if w.zdr {
		return "openrouter-zdr"
	}
	return "openrouter"
}

// initOpenRouterSetupKeys are the bootstrap providers a saved OpenRouter
// setup may name.
var initOpenRouterSetupKeys = []string{"openrouter-zdr", "openrouter"}

func initIsOpenRouterSetup(provider string) bool {
	return slices.Contains(initOpenRouterSetupKeys, provider)
}

// initRetentionNote labels where a setup sends source with its OpenRouter
// data-retention requirement. It never claims what a provider retains.
func initRetentionNote(retention string) string {
	switch retention {
	case "required_per_request":
		return ", zero data retention required on every request"
	case "not_required_by_open_trestle":
		return ", zero data retention not required by Open Trestle"
	}
	return ""
}
