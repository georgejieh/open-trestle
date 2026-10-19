package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrScopeIntentUnresolved = errors.New("run scope effect is unresolved")

const scopeIntentSuffix = ".scope-intent.json"

// scopeIntentRecord pins a content-free effect identity; this is not itself
// evidence that the artifact or journal write committed.
type scopeIntentRecord struct {
	Version  int    `json:"version"`
	Scope    string `json:"scope"`
	Kind     string `json:"kind"`
	Expected string `json:"expected"`
}

func (j *FileRunJournal) scopeIntentPath(scope audit.ReviewScope) string {
	return filepath.Join(j.root, scope.Identity()+scopeIntentSuffix)
}

// WithScopeIntent holds the shared effect gate while it durably records intent,
// runs a synchronous effect, and requires the caller's exact physical
// verification before removing the marker. Errors leave the scope blocked.
func (j *FileRunJournal) WithScopeIntent(ctx context.Context, scope audit.ReviewScope, kind, expected string, effect, verify func(context.Context) error) error {
	return j.WithScopeIntentChecked(ctx, scope, kind, expected, nil, effect, verify)
}

// WithScopeIntentChecked runs a read-only preflight under the gate before
// recording intent. An ordinary conflict cannot poison an existing scope.
func (j *FileRunJournal) WithScopeIntentChecked(ctx context.Context, scope audit.ReviewScope, kind, expected string, preflight, effect, verify func(context.Context) error) error {
	if !validControlPlaneDigest(expected) {
		return ErrInvalidRunJournalEffectSection
	}
	return j.WithScopeIntentPrepared(ctx, scope, kind, func(inner context.Context) (string, error) {
		if preflight != nil {
			if err := preflight(inner); err != nil {
				return "", err
			}
		}
		return expected, nil
	}, effect, verify)
}

// WithScopeIntentPrepared derives the content-free expected identity in a
// trusted read-only preflight under the journal gate, before recording intent.
func (j *FileRunJournal) WithScopeIntentPrepared(ctx context.Context, scope audit.ReviewScope, kind string, preflight func(context.Context) (string, error), effect, verify func(context.Context) error) error {
	if j == nil || preflight == nil || effect == nil || verify == nil || scope.Validate() != nil || len(kind) == 0 || len(kind) > 64 || strings.ContainsAny(kind, "/\\\n\r") {
		return ErrInvalidRunJournalEffectSection
	}
	return j.WithScopeGate(ctx, scope, func(inner context.Context) error {
		expected, err := preflight(inner)
		if err != nil {
			return err
		}
		if !validControlPlaneDigest(expected) {
			return ErrInvalidRunJournalEffectSection
		}
		path := j.scopeIntentPath(scope)
		j.mu.Lock()
		if _, err := os.Lstat(path); err == nil {
			j.mu.Unlock()
			return ErrScopeIntentUnresolved
		} else if !errors.Is(err, os.ErrNotExist) {
			j.mu.Unlock()
			return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
		}
		encoded, err := json.Marshal(scopeIntentRecord{Version: 1, Scope: scope.Identity(), Kind: kind, Expected: expected})
		if err == nil {
			encoded = append(encoded, '\n')
		}
		if err != nil {
			j.mu.Unlock()
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			j.mu.Unlock()
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		_, writeErr := file.Write(encoded)
		syncErr := file.Sync()
		closeErr := file.Close()
		err = errors.Join(writeErr, syncErr, closeErr)
		if err == nil {
			err = j.syncRoot()
		}
		j.mu.Unlock()
		if err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := effect(inner); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := verify(inner); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := fileRunContextDone(inner); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		j.mu.Lock()
		defer j.mu.Unlock()
		if err := os.Remove(path); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		// The effect was already durably verified before removal. If a crash
		// restores this marker, restart conservatively asks for the same proof.
		// No fallible filesystem operation follows successful removal.
		return nil
	})
}

// ReconcileScopeIntent clears a recorded effect only after a trusted caller
// re-proves the exact expected physical outcome without writing or dispatching.
// A mismatch or failed proof retains the quarantine.
func (j *FileRunJournal) ReconcileScopeIntent(ctx context.Context, scope audit.ReviewScope, kind, expected string, verify func(context.Context) error) error {
	if j == nil || verify == nil || scope.Validate() != nil || !validControlPlaneDigest(expected) || len(kind) == 0 || len(kind) > 64 || strings.ContainsAny(kind, "/\\\n\r") {
		return ErrInvalidRunJournalEffectSection
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	return j.withEffectSection(ctx, func() error {
		j.mu.Lock()
		path := j.scopeIntentPath(scope)
		encoded, err := os.ReadFile(path)
		j.mu.Unlock()
		if err != nil || len(encoded) > 1024 {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		var actual scopeIntentRecord
		if err := json.Unmarshal(encoded, &actual); err != nil || actual != (scopeIntentRecord{Version: 1, Scope: scope.Identity(), Kind: kind, Expected: expected}) {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := verify(ctx); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := fileRunContextDone(ctx); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		j.mu.Lock()
		defer j.mu.Unlock()
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, encoded) {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := os.Remove(path); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		// The effect was already durably verified before removal. If a crash
		// restores this marker, restart conservatively asks for the same proof.
		// No fallible filesystem operation follows successful removal.
		return nil
	})
}
