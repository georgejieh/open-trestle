package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// runLocalRecoveryCommand emits a comparison record or compares restored state.
// It never builds the daemon; even matching active runs remain pending.
func runLocalRecoveryCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil || stderr == nil || len(args) == 0 {
		return ErrInvalidDaemonConfiguration
	}
	action := args[0]
	if action != "recovery-point" && action != "verify-restore" {
		return ErrInvalidDaemonConfiguration
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state-dir", "", "stopped private state root")
	recordPath := flags.String("record", "", "closed recovery-point comparison record")
	authority := flags.String("repository-authority", "", "local repository authority")
	namespace := flags.String("repository-namespace", "", "local repository namespace")
	name := flags.String("repository-name", "", "local repository name")
	assetPaths := make([]*string, 5)
	for i, role := range []string{"binary", "scanner", "scanner-worker", "route-inventory", "runtime-policy"} {
		assetPaths[i] = flags.String(role, "", "retained recovery input file")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *statePath == "" {
		return ErrInvalidDaemonConfiguration
	}
	absolute, err := filepath.Abs(*statePath)
	if err != nil {
		return err
	}
	repository, err := evidence.NewRepositoryIdentity(*authority, strings.Split(*namespace, "/"), *name)
	if err != nil {
		return err
	}
	var expected localRecoveryPoint
	if action == "verify-restore" {
		if *recordPath == "" {
			return ErrInvalidDaemonConfiguration
		}
		recordAbsolute, err := filepath.Abs(*recordPath)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(absolute, recordAbsolute)
		if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return ErrInvalidDaemonConfiguration
		}
		file, err := fileauthority.OpenReadOnly(*recordPath)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, maxLocalRecoveryPointBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		expected, err = parseLocalRecoveryPoint(raw)
		if err != nil {
			return err
		}
		if expected.StatePath != absolute || expected.RepositoryAuthority != *authority || !reflect.DeepEqual(expected.RepositoryNamespace, strings.Split(*namespace, "/")) || expected.RepositoryName != *name {
			return fmt.Errorf("%w: owner or repository", errRestoreObservationMismatch)
		}
	} else if *recordPath != "" {
		return ErrInvalidDaemonConfiguration
	}
	assets := make([]localRecoveryAsset, 5)
	for i, role := range []string{"binary", "scanner", "scanner-worker", "route-inventory", "runtime-policy"} {
		path, err := filepath.Abs(*assetPaths[i])
		if err != nil || *assetPaths[i] == "" {
			return ErrInvalidDaemonConfiguration
		}
		assets[i] = localRecoveryAsset{Role: role, Path: path}
	}
	beforeAssets, err := observeRecoveryAssets(ctx, assets)
	if err != nil {
		return err
	}
	observed, pending, err := observeLocalRecoveryPoint(ctx, absolute, repository)
	if err != nil {
		return err
	}
	afterAssets, err := observeRecoveryAssets(ctx, assets)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(beforeAssets, afterAssets) {
		return errRestoreObservationMismatch
	}
	observed.Assets = beforeAssets
	if action == "recovery-point" {
		raw, err := encodeLocalRecoveryPoint(observed)
		if err != nil {
			return err
		}
		_, err = stdout.Write(raw)
		return err
	}
	if err := compareLocalRecoveryPoint(expected, observed); err != nil {
		return err
	}
	status := "matched"
	if pending {
		status = "matched_pending"
	}
	// No restart eligibility or recovery authority is conveyed by this output.
	_, err = fmt.Fprintf(stdout, "{\"status\":\"%s\",\"restart_authorized\":false}\n", status)
	return err
}
