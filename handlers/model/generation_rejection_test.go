package model

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type rejectionStore struct {
	artifact.Store
	mode      string
	rejection artifact.Artifact
	readBack  bool
}

func (s *rejectionStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	if value.Kind() != artifact.KindGenerationRejection {
		return s.Store.Put(ctx, value, at)
	}
	s.rejection = value
	if s.mode == "put failure" {
		return false, errors.New("put refused")
	}
	stored, err := s.Store.Put(ctx, value, at)
	if s.mode == "uncertain put" {
		return stored, errors.New("put uncertain")
	}
	return stored, err
}
func (s *rejectionStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if id == s.rejection.Identity() {
		if s.mode == "read failure" {
			return artifact.Artifact{}, errors.New("read refused")
		}
		s.readBack = true
	}
	return s.Store.Get(ctx, scope, id, at)
}

type rejectionLedger struct {
	audit.Ledger
	store    *rejectionStore
	fail     bool
	observed bool
}

func (l *rejectionLedger) Append(ctx context.Context, previous string, event audit.Event) error {
	if event.Kind() == audit.EventGenerationRejected {
		l.observed = true
		if !l.store.readBack {
			return errors.New("rejection audited before readback")
		}
		if l.fail {
			return errors.New("audit refused")
		}
	}
	return l.Ledger.Append(ctx, previous, event)
}

func TestGenerationHandlerPersistsContentFreeRejectionAfterReadback(t *testing.T) {
	for _, mode := range []string{"complete", "put failure", "uncertain put", "read failure", "audit failure", "envelope rejection"} {
		t.Run(mode, func(t *testing.T) {
			scope, snapshot, packet, contextArtifact, raw := generationContextFixture(t)
			sanitized, _, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, raw, "")
			dispatchRequest, err := sanitized.ProviderRequest()
			if err != nil {
				t.Fatal(err)
			}
			authorization := generationAuthorization(t, scope, dispatchRequest)
			secret := "private-rejected-response-9f3c"
			part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"candidates":[{"claim":"`+secret+`"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			usage, _ := provider.NewRouteTokenUsage(10, 5, 0)
			finish := provider.ResponseFinishStop
			if mode == "envelope rejection" {
				finish = provider.ResponseFinishLength
			}
			response, err := provider.NewResponse(provider.CapabilityReviewV1, finish, []provider.ResponsePart{part}, usage)
			if err != nil {
				t.Fatal(err)
			}
			result, err := gateway.NewSuccessfulRouteDispatchResult(response)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := &recordingDispatcher{adapterID: "test-model", result: result}
			catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			memoryStore, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
			store := &rejectionStore{Store: memoryStore, mode: mode}
			ledger := &rejectionLedger{Ledger: audit.NewMemoryLedger(), store: store, fail: mode == "audit failure"}
			seedRouteSelection(t, ledger, scope, authorization)
			input, err := NewSanitizedGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, expected, authorization)
			if err != nil {
				t.Fatal(err)
			}
			inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []artifact.Artifact{contextArtifact, requestArtifact, receiptArtifact, inputArtifact} {
				if _, err := store.Put(context.Background(), value, time.UnixMilli(80)); err != nil {
					t.Fatal(err)
				}
			}
			handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)}, expected)
			if err != nil {
				t.Fatal(err)
			}
			request := generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1)
			completion := handler.Execute(context.Background(), request)
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInternal || completion.OutputIdentity() != "" || dispatcher.calls != 1 {
				t.Fatalf("unexpected failure: %s", completion.Failure())
			}
			events, err := ledger.Read(context.Background(), scope, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			want := 4
			if mode == "complete" {
				want = 5
			}
			if len(events) != want {
				t.Fatalf("events=%d want=%d", len(events), want)
			}
			if mode == "put failure" || mode == "uncertain put" || mode == "read failure" {
				if ledger.observed {
					t.Fatal("failed store operation audited rejection")
				}
			}
			if mode == "envelope rejection" && (store.rejection.Identity() != "" || ledger.observed) {
				t.Fatal("non-shape failure produced a rejection witness")
			}
			if mode != "complete" {
				return
			}
			event := events[4]
			if event.Kind() != audit.EventGenerationRejected || event.SubjectIdentity() != store.rejection.Identity() || !store.readBack {
				t.Fatal("rejection event missing stored readback identity")
			}
			value, err := memoryStore.Get(context.Background(), scope, event.SubjectIdentity(), time.UnixMilli(201))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := artifact.Encode(value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(value.Payload(), []byte(secret)) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) || bytes.Contains(value.Payload(), []byte(`"payload"`)) {
				t.Fatal("rejection retained provider content")
			}
			rejection, err := ParseGenerationRejectionArtifact(value, inputArtifact, contextArtifact)
			if err != nil || rejection.Attempt().Outcome().ResponseIdentity() != response.Identity() || rejection.Attempt().Authorization().Identity() != authorization.Identity() || rejection.HandlerIdentity() != handler.HandlerIdentity() {
				t.Fatalf("rejection lineage: %v", err)
			}
			if value.Origin() != artifact.OriginHost || value.Classification() != contextArtifact.Classification() || value.Protection() != contextArtifact.Protection() || !value.ExpiresAt().Equal(contextArtifact.ExpiresAt()) {
				t.Fatal("rejection changed protection or retention")
			}
			handler.Execute(context.Background(), request)
			if dispatcher.calls != 1 {
				t.Fatal("rejection replay dispatched")
			}
			after, _ := ledger.Read(context.Background(), scope, 0, 10)
			if len(after) != 5 {
				t.Fatal("rejection replay appended effects")
			}
			for _, badPayload := range [][]byte{
				append(value.Payload(), '\n'),
				bytes.Replace(value.Payload(), []byte(`"contract":`), []byte(`"unknown":1,"contract":`), 1),
				bytes.Replace(value.Payload(), []byte(`"failure_class":"candidate_document_shape"`), []byte(`"failure_class":"other"`), 1),
				bytes.Replace(value.Payload(), []byte(rejection.Identity()), []byte(strings.Repeat("f", 64)), 1),
				bytes.Replace(value.Payload(), []byte(inputArtifact.Identity()), []byte(strings.Repeat("f", 64)), 1),
			} {
				bad, err := artifact.New(scope, value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), badPayload, value.CreatedAt(), value.ExpiresAt())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseGenerationRejectionArtifact(bad, inputArtifact, contextArtifact); err == nil {
					t.Fatal("malformed rejection admitted")
				}
			}
		})
	}
}
