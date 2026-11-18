package main

import (
	"os"
	"runtime"
	"sync"

	"github.com/georgejieh/open-trestle/internal/credentialstore"
)

// Provider API keys (the OPEN_TRESTLE_PROVIDER_* variables) are found in this
// order: the environment variable; then the key saved in the credential store
// by `trestle init` or `trestle keys set`; then a key typed into this
// `trestle init` run for this session only. Every reader of a provider key in
// this command uses the one lookup below: model dispatch, the setup checks,
// `trestle usage` and the wizard. Policies and setups still name only the
// variable, never its value, and the value is never printed.

// providerKeySource says where a provider key was found.
type providerKeySource int

const (
	providerKeyMissing providerKeySource = iota
	providerKeyFromEnvironment
	providerKeyFromStore
	providerKeyFromSession
)

// providerKeyState is where a key was found, without the key. problem is set
// when a saved key exists but cannot be used, such as a credential folder
// with broader permissions than 0700.
type providerKeyState struct {
	source  providerKeySource
	problem error
}

// providerCredentialDirectory names the credential folder. Tests leave it as
// is: TestMain points XDG_CONFIG_HOME at a private temporary folder.
var providerCredentialDirectory = func() (string, error) {
	return credentialstore.DefaultDirectory(os.Getenv)
}

func providerCredentialStore() (*credentialstore.Store, error) {
	dir, err := providerCredentialDirectory()
	if err != nil {
		return nil, err
	}
	return credentialstore.NewStore(dir)
}

// providerSessionKeys holds keys typed into this process that the operator
// chose not to save. They live only in this process's memory.
var providerSessionKeys = struct {
	sync.Mutex
	keys map[string]string
}{keys: map[string]string{}}

func setProviderSessionKey(name, key string) {
	providerSessionKeys.Lock()
	defer providerSessionKeys.Unlock()
	providerSessionKeys.keys[name] = key
}

func providerSessionKey(name string) string {
	providerSessionKeys.Lock()
	defer providerSessionKeys.Unlock()
	return providerSessionKeys.keys[name]
}

// providerKey returns the key for a provider variable and where it was found.
func providerKey(name string) (string, providerKeyState) {
	if value := os.Getenv(name); value != "" {
		return value, providerKeyState{source: providerKeyFromEnvironment}
	}
	var problem error
	if credentialstore.ValidName(name) {
		store, err := providerCredentialStore()
		if err == nil {
			var key string
			var found bool
			if key, found, err = store.Get(name); err == nil && found {
				return key, providerKeyState{source: providerKeyFromStore}
			}
		}
		problem = err
	}
	if value := providerSessionKey(name); value != "" {
		return value, providerKeyState{source: providerKeyFromSession}
	}
	return "", providerKeyState{problem: problem}
}

// providerCredentialLookup is the environment-shaped reader the credential
// resolvers take: the key for name, or "" when there is none.
func providerCredentialLookup(name string) string {
	value, _ := providerKey(name)
	return value
}

// providerKeyStatus is where the key for name is found, never the key.
func providerKeyStatus(name string) providerKeyState {
	_, state := providerKey(name)
	return state
}

func (s providerKeyState) available() bool { return s.source != providerKeyMissing }

// where names the key's source in a few words, for a summary row or a
// check line.
func (s providerKeyState) where() string {
	switch s.source {
	case providerKeyFromEnvironment:
		return "from the environment"
	case providerKeyFromStore:
		return "saved in " + providerCredentialDisplayDirectory()
	case providerKeyFromSession:
		return "entered for this session only"
	}
	if s.problem != nil {
		return "the saved key cannot be used: " + s.problem.Error()
	}
	return "not set"
}

// providerCredentialDisplayDirectory is the credential folder as shown on
// screen: ~ for the home folder, and a long path shortened in the middle.
func providerCredentialDisplayDirectory() string {
	dir, err := providerCredentialDirectory()
	if err != nil {
		return "~/.config/open-trestle/credentials"
	}
	return initDisplayPath(dir)
}

// providerCredentialProtection says how a saved key file is protected.
func providerCredentialProtection() string {
	if runtime.GOOS == "windows" {
		return "owner-only"
	}
	return "owner-only, mode 0600"
}
