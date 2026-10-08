package context

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPacketOnlyHandlerHasNoRouteAuthority(t *testing.T) {
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPacketOnlyHandler(store, contextTestClock{time.UnixMilli(100)})
	if err != nil || handler.Validate() != nil || handler.HandlerIdentity() == "" {
		t.Fatalf("packet handler=%#v err=%v", handler, err)
	}
	if handler.authorizer != nil || handler.sanitizer != nil || handler.pipeline != nil {
		t.Fatal("packet handler retained generation authority")
	}
	withAuthority := *handler
	withAuthority.authorizer = contextTestAuthorizer{identity: strings.Repeat("a", 64)}
	if withAuthority.Validate() == nil {
		t.Fatal("packet handler admitted route authority")
	}
	withWrongIdentity := *handler
	withWrongIdentity.identity = strings.Repeat("b", 64)
	if withWrongIdentity.Validate() == nil {
		t.Fatal("packet handler accepted mismatched identity")
	}
	if _, err := NewPacketOnlyHandler(nil, contextTestClock{time.UnixMilli(100)}); err == nil {
		t.Fatal("nil store accepted")
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	journaled, err := NewJournaledPacketOnlyHandler(store, contextTestClock{time.UnixMilli(100)}, coordinator)
	if err != nil || journaled.Validate() != nil || journaled.HandlerIdentity() == handler.HandlerIdentity() || journaled.preparer == nil {
		t.Fatalf("journaled packet handler=%#v err=%v", journaled, err)
	}
	if _, err := NewJournaledPacketOnlyHandler(store, contextTestClock{time.UnixMilli(100)}, nil); err == nil {
		t.Fatal("journaled handler accepted no durable preparer")
	}
}
