package main

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/georgejieh/open-trestle/modelcatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// ollamaSigninModels runs step 4 for "Ollama on this machine, signed in to
// Ollama Cloud": it reads the local daemon's model list (one bounded loopback
// GET), offers only the models the daemon relays to Ollama Cloud, and then
// offers the consented sign-in check.
func (w *initWizard) ollamaSigninModels() error {
	if w.prompt != nil {
		w.say("  Your local Ollama relays Ollama Cloud models (names ending in :cloud or -cloud) to")
		w.say("  ollama.com with the account you signed in with (`ollama signin`). Open Trestle talks")
		w.say("  only to Ollama on this machine and needs no API key, but your source does leave this")
		w.say("  machine: when you run a review it is secret-scanned, then sent to Ollama Cloud.")
	}
	endpoint, err := w.answer(initQuestion{flag: "endpoint", question: "Local Ollama address", proposed: ollamaSigninDefaultBaseURL, acceptProposal: true, validate: func(value string) (string, error) {
		value = strings.TrimRight(value, "/")
		if !runtimeconfig.ValidOllamaSigninEndpoint(value) {
			return "", errors.New("Type Ollama's address on this machine as http://127.0.0.1:PORT/v1, such as http://127.0.0.1:11434/v1.")
		}
		return value, nil
	}})
	if err != nil || endpoint == "" {
		return err
	}
	w.a.generationEndpoint, w.a.verificationEndpoint = endpoint, endpoint
	if _, err := ollamaLookPath(); err == nil {
		w.ollamaBinary = true
		w.say("  %s The ollama command is installed.", w.ok)
	} else {
		w.say("  %s The ollama command was not found on PATH. A running Ollama still works, but", w.wait)
		w.say("    Open Trestle cannot offer to run `ollama signin` for you (https://ollama.com/download).")
	}
	origin, _ := ollamaDaemonOrigin(endpoint)
	w.say("  Reading the model list from %s/api/tags (no code is sent) ...", origin)
	tags, _, err := ollamaReadTags(w.ctx, endpoint)
	if err != nil {
		return initStopf(initExitPending, "could not read the model list from Ollama at %s. Start Ollama on this machine (`ollama serve`, or the Ollama app), then run `trestle init` again. Nothing was written.", endpoint)
	}
	cloud := []modelcatalog.Model{}
	for _, tag := range tags {
		if !ollamaCloudTag(tag) {
			continue
		}
		metadata := json.RawMessage(`{}`)
		if tag.ContextLength > 0 {
			metadata, _ = json.Marshal(map[string]uint64{"context_length": tag.ContextLength})
		}
		cloud = append(cloud, modelcatalog.Model{Selector: tag.Name, Metadata: metadata})
	}
	if len(cloud) < 2 {
		return initStopf(initExitPending, "your local Ollama lists %d Ollama Cloud model%s, and a review needs two different ones. Add them first, for example `ollama pull gpt-oss:120b-cloud` and `ollama pull qwen3-coder:480b-cloud`, then run `trestle init` again. Nothing was written.", len(cloud), initPlural(len(cloud)))
	}
	w.say("  %s Found %d Ollama Cloud model%s. Models that run on this machine are not offered here.", w.ok, len(cloud), initPlural(len(cloud)))
	if err := w.pickPair(cloud, cloud); err != nil {
		return err
	}
	if w.a.generationModel == "" || w.a.verificationModel == "" {
		return nil
	}
	return w.ollamaSigninCheck()
}

// ollamaSigninCheck asks before sending the one fixed synthetic test message.
// On an authentication answer it offers to run `ollama signin` (y/N), then
// sends the same message once more. It never sends source.
func (w *initWizard) ollamaSigninCheck() error {
	if w.prompt == nil {
		return nil
	}
	model := w.a.generationModel
	w.say("\n  Sign-in check. Open Trestle can send one fixed test message, %q, to %s", ollamaSigninProbePrompt, model)
	w.say("  through your local Ollama. It contains none of your code, but Ollama sends it to Ollama")
	w.say("  Cloud and it uses your Ollama Cloud usage. If you are not signed in, Open Trestle can run")
	w.say("  `ollama signin` (only if you agree) and then send the same message once more.")
	send, err := w.prompt.confirm("Send the test message?", false)
	if err != nil {
		return err
	}
	if !send {
		w.say("  Not checked. If a review fails with an authentication error, run `ollama signin`.")
		return nil
	}
	for attempt := 1; attempt <= 2; attempt++ {
		w.say("  Sending the test message ...")
		outcome, detail := ollamaSigninProbe(w.ctx, w.a.generationEndpoint, model)
		switch outcome {
		case ollamaProbeSignedIn:
			w.say("  %s Your local Ollama is signed in: %s answered through Ollama Cloud.", w.ok, model)
			return nil
		case ollamaProbeNotSignedIn:
			w.say("  %s Your local Ollama is not signed in to Ollama Cloud (%s).", w.bad, detail)
			if attempt == 1 && w.ollamaBinary {
				run, err := w.prompt.confirm("Run `ollama signin` now? It shows a link to open in your browser", false)
				if err != nil {
					return err
				}
				if run {
					w.say("  Running ollama signin. Finish signing in in your browser; do not type here until it ends.")
					if err := ollamaRunSigninChild(w.ctx); err != nil {
						w.say("  %s ollama signin did not finish (%v).", w.wait, err)
						return w.continueWithoutSignin("Run `ollama signin` in a terminal on this machine")
					}
					w.say("  ollama signin finished. Checking again with the same test message.")
					continue
				}
			}
			return w.continueWithoutSignin("Run `ollama signin` in a terminal on this machine")
		default:
			w.say("  %s The test message failed (%s), so the sign-in could not be checked.", w.wait, detail)
			return w.continueWithoutSignin("Check that Ollama is running and that " + model + " is available")
		}
	}
	return w.continueWithoutSignin("Run `ollama signin` in a terminal on this machine")
}

func (w *initWizard) continueWithoutSignin(advice string) error {
	w.say("    %s. Then run `trestle init` again, or continue now and sign in before the first review.", advice)
	proceed, err := w.prompt.confirm("Continue setup now?", true)
	if err != nil {
		return err
	}
	if !proceed {
		return initStopf(initExitPending, "stopped before writing anything. Run `ollama signin`, then run `trestle init` again.")
	}
	return nil
}
