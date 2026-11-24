package main

import (
	"errors"
	"strings"

	"github.com/georgejieh/open-trestle/internal/credentialstore"
	"github.com/georgejieh/open-trestle/spending"
)

// Entering a provider API key in `trestle init`. When the chosen remote
// provider's key variable has no key in the environment or the credential
// store, and standard input is an interactive terminal, the wizard asks for
// the key with echo off. It checks the key with a call that costs nothing
// where the provider has one (OpenRouter's GET /api/v1/key), and keeps it in
// this process's memory until the setup is saved, then saves it.
// The key never appears on screen, in an argument, a log, a setup file or a
// result, and never in a model request: it is sent only as the bearer
// credential. Without a terminal nothing is asked and the
// environment-variable instructions stay as they were.

// initKeyCheck is the outcome of checking a typed key with the provider.
type initKeyCheck int

const (
	initKeyAccepted  initKeyCheck = iota // the provider accepted it
	initKeyRefused                       // the provider refused it (401 or 403)
	initKeyUnchecked                     // no free check exists, or it could not run
)

// checkProviderKey checks a key with the provider's free call when one
// exists. detail explains an unchecked or refused key in plain words.
func (w *initWizard) checkProviderKey(provider, key string) (initKeyCheck, string) {
	if provider != "openrouter" {
		return initKeyUnchecked, ""
	}
	_, err := spending.ReadOpenRouterKeyUsage(w.ctx, usageOpenRouterTransport, key)
	if err == nil {
		return initKeyAccepted, ""
	}
	var status spending.OpenRouterKeyStatusError
	if errors.As(err, &status) && status.KeyRefused() {
		return initKeyRefused, strings.TrimPrefix(status.Error(), spending.ErrOpenRouterKeyUnreadable.Error()+": ")
	}
	return initKeyUnchecked, strings.TrimPrefix(err.Error(), spending.ErrOpenRouterKeyUnreadable.Error()+": ")
}

// askProviderKey asks for the key of one variable with hidden input. With
// saveNow (a setup that is already saved) the key is saved at once;
// otherwise it is saved by saveEnteredKey after the setup.
func (w *initWizard) askProviderKey(name, provider, label string, saveNow bool) error {
	if w.prompt == nil || w.terminal == nil || name == "" || initSpendingProvider(provider) == "" {
		return nil
	}
	if state := providerKeyStatus(name); state.available() {
		w.say("  API key: %s is set (%s).", name, state.where())
		return nil
	} else if state.problem != nil {
		w.say("  %s %s: %s.", w.wait, name, state.where())
	}
	w.say("\n  API key: %s has no key in this shell or in %s. Paste the key from your %s account. %s It is saved there with the setup, and Open Trestle never logs it or puts it in a model request. Press Enter on an empty line to skip.", name, providerCredentialDisplayDirectory(), label, w.keyEntryNote())
	return w.enterProviderKey(name, provider, label, saveNow, "Skipped; no key was entered. The setup check says how to add one later.")
}

// keyEntryNote says how a typed key shows on screen.
func (w *initWizard) keyEntryNote() string {
	if w.prompt.keys != nil {
		return "Each character shows as *; afterwards only its length and last four characters are shown."
	}
	return "It stays hidden while you type; afterwards only its length and last four characters are shown."
}

// replaceProviderKey asks for a new key for a saved setup's variable and
// saves it at once; Enter on an empty line keeps the current key.
func (w *initWizard) replaceProviderKey(name, provider, label string) error {
	if w.terminal == nil {
		w.say("  Typing a key needs a terminal. Save it with `trestle keys set %s`.", name)
		return nil
	}
	if providerKeyStatus(name).source == providerKeyFromEnvironment {
		w.say("  Note: %s is set in this shell's environment, and that value is used before a saved key.", name)
	}
	w.say("\n  API key: paste the new key for %s from your %s account. %s It replaces the key saved in %s. Press Enter on an empty line to keep the current key.", name, label, w.keyEntryNote(), providerCredentialDisplayDirectory())
	return w.enterProviderKey(name, provider, label, true, "Kept the current key.")
}

// enterProviderKey reads, checks and keeps one key; skipped is said when
// Enter is pressed on an empty line.
func (w *initWizard) enterProviderKey(name, provider, label string, saveNow bool, skipped string) error {
	for attempt := 0; attempt < initMaxTries; attempt++ {
		key, err := w.prompt.askSecret("API key for "+label, w.terminal)
		if errors.Is(err, errInitSecretUnavailable) {
			w.say("  Hidden input is not available here, so no key was read. Save it later with `trestle keys set %s`, or export it in your shell.", name)
			return nil
		}
		if err != nil {
			return err
		}
		if key == "" {
			w.say("  %s", skipped)
			return nil
		}
		if credentialstore.ValidKey(key) != nil {
			w.say("  %s That is not a usable API key: it must be one line of printable characters without spaces. Paste it again, or press Enter to skip.", w.bad)
			continue
		}
		switch outcome, detail := w.checkProviderKey(provider, key); outcome {
		case initKeyRefused:
			w.say("  %s %s refused this key (%s). Check that you copied the whole key, then paste it again, or press Enter to skip.", w.bad, label, detail)
			continue
		case initKeyAccepted:
			w.say("  %s %s accepted the key (one GET /api/v1/key, which costs nothing and sends no source).", w.ok, label)
		default:
			if detail != "" {
				w.say("  %s The key could not be checked: %s. It is used as typed; the first review shows whether it works.", w.wait, detail)
			} else {
				w.say("  %s has no call that checks a key for free, so the key is not checked now; the first review shows whether it works.", label)
			}
		}
		setProviderSessionKey(name, key)
		if saveNow {
			w.saveKey(name, key)
			return nil
		}
		w.enteredKeys = append(w.enteredKeys, name)
		w.say("  It will be saved in %s (%s) once the setup is saved.", providerCredentialDisplayDirectory(), providerCredentialProtection())
		return nil
	}
	w.say("  Skipped after three tries; no key was saved. Save one later with `trestle keys set %s`.", name)
	return nil
}

// saveKey writes a key to the credential store and says where; a failure
// leaves the key in use for this session only.
func (w *initWizard) saveKey(name, key string) {
	store, err := providerCredentialStore()
	if err == nil {
		err = store.Set(w.ctx, name, key)
	}
	if err != nil {
		w.say("  %s The key could not be saved (%v). It is used for this session only; save it later with `trestle keys set %s`.", w.bad, err, name)
		return
	}
	w.say("  %s Saved the key for %s in %s (%s). To change it or remove it:", w.ok, name, providerCredentialDisplayDirectory(), providerCredentialProtection())
	w.sayVerbatim("    trestle keys set " + name)
	w.sayVerbatim("    trestle keys remove " + name)
}

// saveEnteredKey saves the typed keys once the setup is saved, so declining
// the setup writes nothing.
func (w *initWizard) saveEnteredKey() {
	for _, name := range w.enteredKeys {
		if key := providerSessionKey(name); key != "" {
			w.saveKey(name, key)
		}
	}
	w.enteredKeys = nil
}
