package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/internal/credentialstore"
	"github.com/georgejieh/open-trestle/spending"
)

// `trestle keys` manages the provider API keys Open Trestle can find:
//
//	trestle keys                 (or keys list) each key variable and where its key comes from
//	trestle keys set VAR         type the key with hidden input (or pipe it in) and save it
//	trestle keys remove VAR      delete the saved key
//
// A key is found in the environment first, then in the credential store.
// Nothing here prints a key: list shows the variable name, where the key
// comes from and at most its last four characters.

func writeKeysUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle keys [list]   (each API key variable and where its key comes from)")
	fmt.Fprintln(w, "       trestle keys set OPEN_TRESTLE_PROVIDER_NAME      (type the key, hidden, or pipe it in; it is checked and saved)")
	fmt.Fprintln(w, "       trestle keys remove OPEN_TRESTLE_PROVIDER_NAME   (delete the saved key)")
}

func keysFail(stderr io.Writer, code int, format string, values ...any) int {
	return commandFail(stderr, code, "keys", fmt.Sprintf(format, values...))
}

func runKeys(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		writeKeysUsage(stdout)
		return 0
	}
	if len(args) == 0 || len(args) == 1 && args[0] == "list" {
		return runKeysList(ctx, stdout, stderr)
	}
	if len(args) != 2 || args[0] != "set" && args[0] != "remove" {
		writeKeysUsage(stderr)
		return 2
	}
	name := args[1]
	if !credentialstore.ValidName(name) {
		example := "trestle keys " + args[0] + " OPEN_TRESTLE_PROVIDER_NAME"
		if _, err := initCredentialName(name); err != nil {
			return commandFail(stderr, 2, "keys", err.Error()+" Nothing was changed.", example)
		}
		return commandFail(stderr, 2, "keys", name+" is not an OPEN_TRESTLE_PROVIDER_ variable name. Nothing was changed.", example)
	}
	if args[0] == "remove" {
		return runKeysRemove(ctx, name, stdout, stderr)
	}
	return runKeysSet(ctx, name, stdin, stdout, stderr)
}

// keysMaskedSuffix shows the last four characters of a long key, so two keys
// can be told apart; a short key shows nothing.
func keysMaskedSuffix(key string) string {
	if len(key) < 24 {
		return ""
	}
	return "ends in …" + key[len(key)-4:]
}

// keysKnownNames are the variables worth listing: every saved key, every
// OPEN_TRESTLE_PROVIDER_ variable set in this shell, and the variables this
// repository's setup names.
func keysKnownNames(ctx context.Context, store *credentialstore.Store) ([]string, error) {
	names := []string{}
	saved, err := store.Names()
	names = append(names, saved...)
	for _, entry := range os.Environ() {
		if name, value, ok := strings.Cut(entry, "="); ok && value != "" && credentialstore.ValidName(name) {
			names = append(names, name)
		}
	}
	if setup, ok := currentRepositorySetup(ctx); ok {
		names = append(names, setup.credentials...)
	}
	slices.Sort(names)
	return slices.Compact(names), err
}

func runKeysList(ctx context.Context, stdout, stderr io.Writer) int {
	store, err := providerCredentialStore()
	if err != nil {
		return keysFail(stderr, 1, "the credential folder cannot be found (set HOME or XDG_CONFIG_HOME)")
	}
	names, listErr := keysKnownNames(ctx, store)
	if p := newOutPrinter(ctx, stdout); p.terminal {
		keysListTerminal(p, store, names, listErr)
		return 0
	}
	fmt.Fprintf(stdout, "API keys (the environment first, then the keys saved in %s):\n", providerCredentialDisplayDirectory())
	if listErr != nil {
		fmt.Fprintf(stdout, "  The saved keys cannot be read: %v\n", listErr)
	}
	if len(names) == 0 {
		fmt.Fprintln(stdout, "  No API key is set or saved.")
		fmt.Fprintln(stdout, "  Save one: trestle keys set OPEN_TRESTLE_PROVIDER_NAME   (for example OPEN_TRESTLE_PROVIDER_OPENROUTER)")
		return 0
	}
	width := 0
	for _, name := range names {
		width = max(width, len(name))
	}
	for _, name := range names {
		key, state := providerKey(name)
		where := state.where()
		if keysBothSet(store, name, state) {
			where += "; a saved key exists too, and the environment wins"
		}
		if suffix := keysMaskedSuffix(key); suffix != "" {
			where += " · " + suffix
		}
		fmt.Fprintf(stdout, "  %-*s  %s\n", width, name, where)
	}
	fmt.Fprintln(stdout, "Change one: trestle keys set NAME · delete a saved one: trestle keys remove NAME")
	return 0
}

// keysListTerminal is the key list for a person: one row per variable whose
// mark says whether a key is found, then the commands that change one.
func keysListTerminal(p outPrinter, store *credentialstore.Store, names []string, listErr error) {
	p.heading("API keys")
	p.hint("  The environment first, then the keys saved in " + providerCredentialDisplayDirectory() + ".")
	if listErr != nil {
		p.rows(outRow{mark: p.bad, value: fmt.Sprintf("The saved keys cannot be read: %v", listErr)})
	}
	if len(names) == 0 {
		p.rows(outRow{mark: p.optional, value: "No API key is set or saved."})
		p.next("trestle keys set OPEN_TRESTLE_PROVIDER_NAME   (for example OPEN_TRESTLE_PROVIDER_OPENROUTER)")
		return
	}
	rows := []outRow{}
	for _, name := range names {
		key, state := providerKey(name)
		row := outRow{mark: p.ok, label: name, value: state.where()}
		switch {
		case state.source == providerKeyFromStore:
			row.value = "saved"
		case !state.available():
			row.mark = p.bad
		}
		if keysBothSet(store, name, state) {
			row.value += "; a saved key too, and the environment wins"
		}
		if suffix := keysMaskedSuffix(key); suffix != "" {
			row.value += " · " + suffix
		}
		rows = append(rows, row)
	}
	p.rows(rows...)
	p.next("trestle keys set NAME", "trestle keys remove NAME")
}

// keysBothSet reports a key in the environment that is saved too.
func keysBothSet(store *credentialstore.Store, name string, state providerKeyState) bool {
	if state.source != providerKeyFromEnvironment {
		return false
	}
	_, saved, err := store.Get(name)
	return err == nil && saved
}

// readKeyInput reads the key: with hidden input on a terminal, or one line
// from a pipe. It returns "" for an empty answer.
func readKeyInput(ctx context.Context, name string, stdin io.Reader, stdout, stderr io.Writer) (string, error) {
	if terminal, ok := openEchoTerminal(stdin); ok {
		style := newInitStyle(stdout, false)
		prompt := newInitPrompter(ctx, stdin, stdout, style, func(line string) {
			for _, part := range initFit(line, initWidth) {
				fmt.Fprintln(stdout, part)
			}
		})
		defer prompt.close()
		fmt.Fprintf(stdout, "  Paste the key for %s. It stays hidden while you type; afterwards only its length and last four characters are shown.\n", name)
		return prompt.askSecret("API key for "+name, terminal)
	}
	line, err := readInitLine(bufio.NewReaderSize(stdin, initMaxAnswerBytes))
	if err != nil {
		return "", nil
	}
	if line == "\x00too-long" {
		return "", credentialstore.ErrInvalidKey
	}
	return line, nil
}

func runKeysSet(ctx context.Context, name string, stdin io.Reader, stdout, stderr io.Writer) int {
	store, err := providerCredentialStore()
	if err != nil {
		return keysFail(stderr, 1, "the credential folder cannot be found (set HOME or XDG_CONFIG_HOME). Nothing was changed.")
	}
	again := "trestle keys set " + name
	key, err := readKeyInput(ctx, name, stdin, stdout, stderr)
	switch {
	case errors.Is(err, errInitSecretUnavailable):
		return commandFail(stderr, 1, "keys", "hidden input is not available on this terminal, so no key was read. Nothing was changed. Pipe the key in instead:", "read -rs KEY && printf '%s\\n' \"$KEY\" | "+again)
	case errors.Is(err, errInitInputEnded) || errors.Is(err, errInitTooManyTries):
		return commandFail(stderr, 2, "keys", "no key was read. Nothing was changed.", again)
	case err != nil || key != "" && credentialstore.ValidKey(key) != nil:
		return commandFail(stderr, 2, "keys", "that is not a usable API key: it must be one line of printable characters without spaces. Nothing was changed.", again)
	case key == "":
		return commandFail(stderr, 2, "keys", "no key was given. Nothing was changed.", again)
	}
	p := newOutPrinter(ctx, stdout)
	if usageUsualProviders()[name] == "openrouter" {
		_, err := spending.ReadOpenRouterKeyUsage(ctx, usageOpenRouterTransport, key)
		var status spending.OpenRouterKeyStatusError
		switch {
		case err == nil:
			p.note(p.ok, "OpenRouter accepted the key (one GET /api/v1/key, which costs nothing and sends no source).")
		case errors.As(err, &status) && status.KeyRefused():
			return commandFail(stderr, 4, "keys", fmt.Sprintf("OpenRouter refused this key (HTTP %d); nothing was saved. Check that you copied the whole key and try again:", status.StatusCode), again)
		default:
			p.note(p.wait, fmt.Sprintf("The key could not be checked (%s); it is saved as typed, and the next review shows whether it works.", strings.TrimPrefix(err.Error(), spending.ErrOpenRouterKeyUnreadable.Error()+": ")))
		}
	} else {
		p.note(p.optional, "This provider has no call that checks a key for free, so the key is not checked now; the next review shows whether it works.")
	}
	if err := store.Set(ctx, name, key); err != nil {
		return keysFail(stderr, 1, "the key could not be saved (%v). Nothing was changed.", err)
	}
	p.note(p.ok, fmt.Sprintf("Saved the key for %s in %s (%s).", name, providerCredentialDisplayDirectory(), providerCredentialProtection()))
	if os.Getenv(name) != "" {
		p.note(p.wait, fmt.Sprintf("Note: %s is also set in this shell, and the environment wins over the saved key until you unset it.", name))
	}
	return 0
}

func runKeysRemove(ctx context.Context, name string, stdout, stderr io.Writer) int {
	store, err := providerCredentialStore()
	if err != nil {
		return keysFail(stderr, 1, "the credential folder cannot be found (set HOME or XDG_CONFIG_HOME). Nothing was changed.")
	}
	removed, err := store.Remove(ctx, name)
	if err != nil {
		return commandFail(stderr, 1, "keys", fmt.Sprintf("the saved key could not be removed (%v). See what is saved:", err), "trestle keys")
	}
	p := newOutPrinter(ctx, stdout)
	if removed {
		p.note(p.ok, "Removed the saved key for "+name+".")
	} else {
		p.note(p.optional, "No key is saved for "+name+"; nothing was changed.")
	}
	if os.Getenv(name) != "" {
		p.note(p.wait, name+" is still set in this shell; reviews from this shell keep using it.")
	}
	return 0
}
