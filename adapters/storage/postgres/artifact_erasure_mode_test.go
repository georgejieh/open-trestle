package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestErasureAdmissionModeRefusesInheritedLegacyEffects(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	authorization, err := artifact.NewDeletionAuthorization(f.value.Scope(), f.value.Identity(), strings.Repeat("5", 64), "operator", strings.Repeat("9", 64), artifact.DeletionTenantErasure, time.UnixMilli(900).UTC(), time.UnixMilli(8000).UTC())
	if err != nil || authorization.Validate() != nil || !authorization.Allows(f.value, time.UnixMilli(1000).UTC()) {
		t.Fatal("valid legacy authorization control", err)
	}
	envelope, ok := f.store.artifacts.(*artifact.EnvelopeStore)
	if !ok {
		t.Fatal("factory did not own the concrete envelope")
	}
	beforeSQL := len(f.s.Snapshot().Events)
	beforeCalls := f.external.Counts()
	beforeObjects := f.external.Snapshot()
	receipt, err := f.store.Delete(f.ctx, authorization, time.UnixMilli(1000).UTC())
	erasureRequireError(t, err, artifact.ErrErasureAuthorizationV2Required)
	if !reflect.DeepEqual(receipt, artifact.DeletionReceipt{}) {
		t.Fatal("indexed legacy Delete returned receipt")
	}
	receipt, err = envelope.Delete(f.ctx, authorization, time.UnixMilli(1000).UTC())
	erasureRequireError(t, err, artifact.ErrErasureAuthorizationV2Required)
	if !reflect.DeepEqual(receipt, artifact.DeletionReceipt{}) {
		t.Fatal("envelope legacy Delete returned receipt")
	}
	receipt, found, err := envelope.RecoverDeletion(f.ctx, f.value.Scope(), f.value.Identity())
	erasureRequireError(t, err, artifact.ErrErasureCertificationAPIRequired)
	if found || !reflect.DeepEqual(receipt, artifact.DeletionReceipt{}) {
		t.Fatal("legacy recovery claimed a receipt")
	}
	if len(f.s.Snapshot().Events) != beforeSQL || f.external.Counts() != beforeCalls || !reflect.DeepEqual(f.external.Snapshot(), beforeObjects) {
		t.Fatal("new mode entered legacy SQL or remote effect path")
	}
}
