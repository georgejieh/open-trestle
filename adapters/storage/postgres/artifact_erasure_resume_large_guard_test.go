package postgres

import (
	"bytes"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

const resumeLargeArtifactPayloadBytes = 16 << 20

func newLargeResumeJournalFixture(t *testing.T) *resumeJournalGraph {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Millisecond)
	scope, err := audit.NewReviewScope("tenant-resume-large", "repo-resume-large", "run-resume-large")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("L"), resumeLargeArtifactPayloadBytes)
	value, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginMemory, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("b", 64)}, payload, at.Add(-time.Minute), at.Add(20*time.Minute))
	clear(payload)
	if err != nil {
		t.Fatal(err)
	}
	s := newResumeSQLService(t, newResumeCatalog(t))
	p := newResumePeerWithBodyProfile(t, s, resumePeerBodyProfile{RequestBodyBytes: 32 << 20, ReplyBodyBytes: 32 << 20})
	return newResumeJournalGraph(t, s, p, value, artifact.ProtectedErasurePolicy{}, at, "large-first")
}

func TestBudgetedResumeLargeArtifactPutGetPrepareResumeAndRecreatedRead(t *testing.T) {
	g := newBudgetedResumeGraph(t, newLargeResumeJournalFixture(t))
	if len(g.value.Payload()) != resumeLargeArtifactPayloadBytes {
		t.Fatal("large fixture did not use the maximum valid artifact payload")
	}
	admission, op, _ := g.Prepared()
	if admission.ArtifactIdentity() != g.value.Identity() || admission.PayloadDigest() != g.value.PayloadDigest() {
		t.Fatal("large admitted artifact identity changed")
	}
	payloadKey := g.Key().Key()
	beforeResume := g.peer.History(payloadKey)
	storedBytes := 0
	if len(beforeResume) == 1 {
		storedBytes = len(beforeResume[0].Body)
	}
	if len(beforeResume) != 1 || beforeResume[0].Marker || storedBytes <= 1<<20 || storedBytes > 32<<20 {
		t.Fatalf("large product object not stored within finite fixture profile: versions=%d bytes=%d", len(beforeResume), storedBytes)
	}
	original := beforeResume[0]
	allowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "large-artifact-resume", resumeMaximum())
	kms := g.peer.KMSCount(g.name)
	result, err := g.store.ResumeErasure(g.ResumeContext("large-resume"), op.Ref(), allowance)
	attestation := assertResumeCertified(t, g, op, result, err)
	if g.peer.KMSCount(g.name) != kms {
		t.Fatal("large Resume called KMS")
	}

	fenceBody := resumeExpectedFence(t, op)
	afterResume := g.peer.History(payloadKey)
	if len(afterResume) != 1 || afterResume[0].Marker || afterResume[0].ID == original.ID || !bytes.Equal(afterResume[0].Body, fenceBody) {
		t.Fatal("large original object was not replaced by the exact immutable fence")
	}
	fenceVersionID := afterResume[0].ID
	largeCurrentRead, createdFence, deletedOriginal, deletedFence := false, false, false, false
	for _, event := range g.peer.Events() {
		if event.Graph != g.name || event.Header.Get("X-Amz-Expected-Bucket-Owner") == "" {
			continue
		}
		if event.Method == "GET" && event.Key == payloadKey && event.Query == "" && event.Attempt != "" && event.MaximumResponse == 32<<20 && bytes.Equal(event.ResponseBody, original.Body) {
			largeCurrentRead = true
		}
		if event.Method == "PUT" && event.Key == payloadKey && event.Attempt != "" && (event.ResponseStatus == 200 || event.ResponseStatus == 201) && bytes.Equal(event.Body, fenceBody) {
			createdFence = true
		}
		if event.Method != "DELETE" || event.Key != payloadKey || event.Attempt == "" {
			continue
		}
		q, parseErr := url.ParseQuery(event.Query)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		switch q.Get("versionId") {
		case original.ID:
			deletedOriginal = true
		case fenceVersionID:
			deletedFence = true
		}
	}
	if !largeCurrentRead {
		t.Fatal("Resume did not perform an admitted current read of the large stored object")
	}
	if !createdFence {
		t.Fatal("Resume did not create the exact same-key fence")
	}
	if !deletedOriginal || deletedFence {
		t.Fatal("Resume did not purge the original non-fence version while preserving the fence")
	}

	s, p, value, policy, at := g.sql, g.peer, g.value, g.policy, g.clock.Value()
	if err := g.db.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := newBudgetedResumeGraph(t, newResumeJournalGraph(t, s, p, value, policy, at, "large-recreated-read"))
	fresh.peer.DisableKMS(fresh.name)
	p.Stop(t)
	events, samples, freshKMS, revision := len(p.Events()), fresh.clock.Samples(), p.KMSCount(fresh.name), s.Snapshot().Revision
	read, found, err := fresh.store.ReadErasure(fresh.Context("read-certified-large"), op.Ref())
	if err != nil || !found || read.State() != artifact.ErasureState(5) {
		t.Fatal("recreated graph did not read certified erasure", err)
	}
	again, ok := read.Attestation()
	if !ok || !reflect.DeepEqual(again, attestation) {
		t.Fatal("recreated graph read changed the certified attestation")
	}
	if len(p.Events()) != events || fresh.clock.Samples() != samples || p.KMSCount(fresh.name) != freshKMS || s.Snapshot().Revision != revision {
		t.Fatal("recreated graph ReadErasure performed work outside the immutable SQL snapshot")
	}
}
