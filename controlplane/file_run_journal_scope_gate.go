package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrScopeGateBusy = errors.New("journal scope gate busy")

type scopeGateContextKey struct{}
type scopeGateGrant struct {
	journal *FileRunJournal
	scope   string
	live    atomic.Bool
}

// WithScopeGate serializes a synchronous in-process effect with cancellation
// and prevents direct journal writes to its scope. It does not itself promise
// durability or effect reconciliation; those require operation-specific intent.
func (j *FileRunJournal) WithScopeGate(ctx context.Context, scope audit.ReviewScope, effect func(context.Context) error) error {
	if j == nil || effect == nil || scope.Validate() != nil {
		return ErrInvalidRunJournalEffectSection
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	return j.withEffectSection(ctx, func() error {
		grant := &scopeGateGrant{journal: j, scope: scope.Identity()}
		j.mu.Lock()
		if _, err := os.Lstat(j.scopeIntentPath(scope)); err == nil {
			j.mu.Unlock()
			return ErrScopeIntentUnresolved
		} else if !errors.Is(err, os.ErrNotExist) {
			j.mu.Unlock()
			return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
		}
		if j.scopeGateActive != nil {
			j.mu.Unlock()
			return ErrScopeGateBusy
		}
		j.scopeGateActive = grant
		grant.live.Store(true)
		j.mu.Unlock()
		defer func() {
			j.mu.Lock()
			grant.live.Store(false)
			j.scopeGateActive = nil
			j.mu.Unlock()
		}()
		return effect(context.WithValue(ctx, scopeGateContextKey{}, grant))
	})
}

func (j *FileRunJournal) checkScopeGate(ctx context.Context, scope audit.ReviewScope) error {
	if _, err := os.Lstat(j.scopeIntentPath(scope)); err == nil {
		if !j.insideScopeGate(ctx) {
			return ErrScopeIntentUnresolved
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	supplied, suppliedOK := ctx.Value(scopeGateContextKey{}).(*scopeGateGrant)
	if suppliedOK && (supplied.journal != j || !supplied.live.Load() || supplied.scope != scope.Identity()) {
		return ErrScopeGateBusy
	}
	if grant := j.scopeGateActive; grant != nil && grant.scope == scope.Identity() {
		if !suppliedOK || supplied != grant {
			return ErrScopeGateBusy
		}
	}
	return nil
}

func (j *FileRunJournal) insideScopeGate(ctx context.Context) bool {
	supplied, ok := ctx.Value(scopeGateContextKey{}).(*scopeGateGrant)
	return ok && supplied.journal == j && supplied.live.Load()
}
