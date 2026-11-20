package repochecks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// toolchain is what a check needs from the host: where its programs are,
// the read-only folders, and the environment that keeps it offline.
type toolchain struct {
	path     []string
	readOnly []string
	env      []string
}

// host abstracts the host lookups so tests can fake them.
type host struct {
	lookPath func(string) (string, error)
	getenv   func(string) string
	home     string
}

func realHost() host {
	home, _ := os.UserHomeDir()
	return host{lookPath: exec.LookPath, getenv: os.Getenv, home: home}
}

var errNotInstalled = errors.New("not installed")

// resolve finds the tool for check on the host. The program is run from
// the folder it was found in, which may hold a link to the real program, as
// npm's does. The toolchain of that folder and of the link's target are
// shown read-only.
func (h host) resolve(check Check) (string, toolchain, error) {
	program, located, target, err := h.find(check.Tool)
	if err != nil {
		return "", toolchain{}, err
	}
	bin := filepath.Dir(located)
	chain := toolchain{path: []string{bin}, readOnly: []string{h.toolchainRoot(bin)}}
	if other := h.toolchainRoot(filepath.Dir(target)); other != chain.readOnly[0] {
		chain.readOnly = append(chain.readOnly, other)
	}
	switch check.Stack {
	case "go":
		chain.env = []string{"GOCACHE=$HOME/.cache/go-build", "GOPATH=$HOME/go", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local",
			"GOTELEMETRY=off", "GOFLAGS=-mod=mod", "GOWORK=off", "CGO_ENABLED=0"}
		if cache := h.goModuleCache(); cache != "" {
			chain.readOnly = append(chain.readOnly, cache)
			chain.env = append(chain.env, "GOMODCACHE="+cache)
		}
	case "node":
		chain.env = []string{"npm_config_cache=$HOME/.npm", "npm_config_offline=true", "npm_config_update_notifier=false",
			"npm_config_audit=false", "npm_config_fund=false", "NO_UPDATE_NOTIFIER=1", "CI=1"}
	case "python":
		chain.env = []string{"PYTHONDONTWRITEBYTECODE=1", "PIP_NO_INDEX=1", "PYTHONUTF8=1"}
	case "rust":
		chain.env = []string{"CARGO_HOME=$HOME/.cargo", "CARGO_TARGET_DIR=$TMPDIR/target", "CARGO_NET_OFFLINE=true"}
		if rustup := h.getenv("RUSTUP_HOME"); rustup != "" {
			chain.readOnly = append(chain.readOnly, rustup)
			chain.env = append(chain.env, "RUSTUP_HOME="+rustup)
		} else if rustup := filepath.Join(h.home, ".rustup"); h.home != "" && isDir(rustup) {
			chain.readOnly = append(chain.readOnly, rustup)
			chain.env = append(chain.env, "RUSTUP_HOME="+rustup)
		}
	}
	return program, chain, nil
}

// toolchainRoot is the folder above a bin folder, unless that would be the
// home folder or a folder directly inside it, which can hold credentials;
// then it is the folder itself.
func (h host) toolchainRoot(folder string) string {
	if filepath.Base(folder) == "bin" && h.safeRoot(filepath.Dir(folder)) {
		return filepath.Dir(folder)
	}
	return folder
}

// find looks the tool up on the host and returns its name, where it was
// found, and the file that path leads to through any links. Python is
// python3 on most Unix systems and python on Windows.
func (h host) find(tool string) (string, string, string, error) {
	names := []string{tool}
	if tool == "python" {
		names = []string{"python3", "python"}
		if runtime.GOOS == "windows" {
			names = []string{"python", "python3"}
		}
	}
	for _, name := range names {
		located, err := h.lookPath(name)
		if err != nil {
			continue
		}
		if located, err = filepath.Abs(located); err != nil {
			continue
		}
		target, err := filepath.EvalSymlinks(located)
		if err != nil {
			target = located
		}
		return name, located, target, nil
	}
	return "", "", "", errNotInstalled
}

func (h host) safeRoot(folder string) bool {
	if h.home == "" {
		return true
	}
	relative, err := filepath.Rel(h.home, folder)
	if err != nil || !filepath.IsLocal(relative) {
		return relative != "."
	}
	return filepath.Dir(relative) != "."
}

// goModuleCache is the host's existing module cache, or "".
func (h host) goModuleCache() string {
	cache := h.getenv("GOMODCACHE")
	if cache == "" {
		gopath := filepath.SplitList(h.getenv("GOPATH"))
		switch {
		case len(gopath) > 0 && gopath[0] != "":
			cache = filepath.Join(gopath[0], "pkg", "mod")
		case h.home != "":
			cache = filepath.Join(h.home, "go", "pkg", "mod")
		}
	}
	if cache == "" || !isDir(cache) {
		return ""
	}
	return cache
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
