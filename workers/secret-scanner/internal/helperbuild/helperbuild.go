// Package helperbuild builds the scan guest and the scan helper.
//
// The guest is the guest module (guest/) built for GOOS=wasip1 GOARCH=wasm.
// The helper embeds it: the build replaces the committed empty
// cmd/open-trestle-scan-helper/guest.wasm with the built guest through a
// go build -overlay file, so the source tree is never written, and pins the
// guest's SHA-256 with -ldflags -X. Both builds use -trimpath and fixed
// linker flags and do not depend on the output directory.
package helperbuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	modulePath = "github.com/georgejieh/open-trestle/workers/secret-scanner"
	// GuestFile and HelperFile are the names of the outputs in the output
	// directory.
	GuestFile  = "open-trestle-scan-guest.wasm"
	HelperFile = "open-trestle-scan-helper"
	// placeholder is the embedded guest file the overlay replaces.
	placeholder = "cmd/open-trestle-scan-helper/guest.wasm"
)

// Target is the operating system and architecture a helper is built for.
type Target struct {
	GOOS   string
	GOARCH string
}

// HostTarget is the target of the running program.
func HostTarget() Target {
	return Target{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// Result names the built files.
type Result struct {
	Guest       string
	GuestSHA256 string
	Helper      string
}

// Build builds the guest and a helper for target that embeds it into
// outputDirectory. moduleDirectory is the scanner module's directory.
func Build(ctx context.Context, moduleDirectory, outputDirectory string, target Target) (Result, error) {
	guest, err := BuildGuest(ctx, moduleDirectory, outputDirectory)
	if err != nil {
		return Result{}, err
	}
	digest, err := fileSHA256(guest)
	if err != nil {
		return Result{}, err
	}
	return BuildHelperWithPin(ctx, moduleDirectory, guest, digest, outputDirectory, HelperFile, target)
}

// BuildGuest builds the guest into outputDirectory and returns its path.
func BuildGuest(ctx context.Context, moduleDirectory, outputDirectory string) (string, error) {
	moduleDirectory, outputDirectory, err := directories(moduleDirectory, outputDirectory)
	if err != nil {
		return "", err
	}
	guest := filepath.Join(outputDirectory, GuestFile)
	err = goBuild(ctx, filepath.Join(moduleDirectory, "guest"), []string{"GOOS=wasip1", "GOARCH=wasm"},
		"-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", guest, ".")
	return guest, err
}

// BuildHelper builds a helper for the host named name into outputDirectory
// that embeds the guest at guestPath and pins its digest.
func BuildHelper(ctx context.Context, moduleDirectory, guestPath, outputDirectory, name string) (Result, error) {
	digest, err := fileSHA256(guestPath)
	if err != nil {
		return Result{}, err
	}
	return BuildHelperWithPin(ctx, moduleDirectory, guestPath, digest, outputDirectory, name, HostTarget())
}

// BuildHelperWithPin builds a helper for target with the pinned guest digest
// given rather than computed, so that tests can build a helper whose pin
// does not match.
func BuildHelperWithPin(ctx context.Context, moduleDirectory, guestPath, guestSHA256, outputDirectory, name string, target Target) (Result, error) {
	moduleDirectory, outputDirectory, err := directories(moduleDirectory, outputDirectory)
	if err != nil {
		return Result{}, err
	}
	guestPath, err = filepath.Abs(guestPath)
	if err != nil {
		return Result{}, err
	}
	overlay, err := json.Marshal(map[string]map[string]string{
		"Replace": {filepath.Join(moduleDirectory, filepath.FromSlash(placeholder)): guestPath},
	})
	if err != nil {
		return Result{}, err
	}
	overlayPath := filepath.Join(outputDirectory, name+".overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		return Result{}, err
	}
	defer os.Remove(overlayPath)
	helper := filepath.Join(outputDirectory, name)
	if target.GOOS == "windows" {
		helper += ".exe"
	}
	err = goBuild(ctx, moduleDirectory, []string{"GOOS=" + target.GOOS, "GOARCH=" + target.GOARCH},
		"-trimpath", "-buildvcs=false", "-overlay="+overlayPath,
		"-ldflags=-s -w -buildid= -X main.expectedGuestSHA256="+guestSHA256,
		"-o", helper, "./cmd/open-trestle-scan-helper")
	if err != nil {
		return Result{}, err
	}
	return Result{Guest: guestPath, GuestSHA256: guestSHA256, Helper: helper}, nil
}

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func directories(moduleDirectory, outputDirectory string) (string, string, error) {
	moduleDirectory, err := filepath.Abs(moduleDirectory)
	if err != nil {
		return "", "", err
	}
	goMod, err := os.ReadFile(filepath.Join(moduleDirectory, "go.mod"))
	if err != nil || !strings.HasPrefix(string(goMod), "module "+modulePath+"\n") {
		return "", "", errors.New("not the secret scanner module directory: " + moduleDirectory)
	}
	outputDirectory, err = filepath.Abs(outputDirectory)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return "", "", err
	}
	return moduleDirectory, outputDirectory, nil
}

func goBuild(ctx context.Context, directory string, target []string, arguments ...string) error {
	command := exec.CommandContext(ctx, "go", append([]string{"build"}, arguments...)...)
	command.Dir = directory
	command.Env = append(buildEnvironment(), target...)
	command.Env = append(command.Env, "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=go1.26.11", "GOFLAGS=")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build in %s: %w: %s", directory, err, output)
	}
	return nil
}

// buildEnvironment is the caller's environment without the settings each
// build fixes itself.
func buildEnvironment() []string {
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOTOOLCHAIN", "GOFLAGS":
			continue
		}
		environment = append(environment, entry)
	}
	return environment
}
