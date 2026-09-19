package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

type resumeListResponseOracle struct {
	Event             resumeWireEvent
	Request           artifact.AttemptRequest
	Attempt           artifact.ErasureAttempt
	Response          artifact.AttemptResponseOptions
	ResponseRow       resumeFixtureRow
	UnknownRow        resumeFixtureRow
	ResponseTx        uint64
	UnknownTx         uint64
	ObservedAt        time.Time
	RawOverflow       bool
	CanonicalOverflow bool
	ExpectedPresent   []byte
}

func resumeAssertVersionListResponseOracle(t *testing.T, g *budgetedResumeGraph, op artifact.ErasureOperation, snapshot resumeFixtureSQLSnapshot, event resumeWireEvent, allowance artifact.ResumeAllowance, label string, observedUpper time.Time) resumeListResponseOracle {
	t.Helper()
	var requestRow resumeFixtureRow
	for _, row := range snapshot.Rows[resumeAttempts] {
		if row["attempt_identity"] == event.Attempt {
			requestRow = row
			break
		}
	}
	if requestRow == nil {
		t.Fatal("version-list has no durable reservation")
	}
	request, err := artifact.ParseAttemptRequest(requestRow["canonical_request"].([]byte), g.scope)
	if err != nil {
		t.Fatal("version-list request parse", err)
	}
	attempt, err := artifact.ParseErasureAttempt(requestRow["canonical_attempt"].([]byte), request)
	if err != nil {
		t.Fatal("version-list attempt parse", err)
	}
	if request.Kind() != artifact.AttemptVersionList || attempt.Identity() != event.Attempt || request.Key() != event.Key {
		t.Fatal("wire list is attached to the wrong durable attempt")
	}
	if allowance.Identity() != "" && request.AllowanceIdentity() != allowance.Identity() {
		t.Fatal("version-list used the wrong explicit allowance")
	}

	var responseRow, unknownRow resumeFixtureRow
	for _, row := range snapshot.Rows[resumeEvidence] {
		if row["attempt_identity"] != attempt.Identity() {
			continue
		}
		switch row["kind"] {
		case "response":
			responseRow = row
		case "unknown":
			unknownRow = row
		}
	}
	if responseRow == nil {
		t.Fatal("version-list attempt has no durable response state")
	}
	responseEvidence, err := artifact.ParseErasureEvidence(responseRow["canonical_evidence"].([]byte), op.Ref())
	if err != nil {
		t.Fatal("version-list response evidence parse", err)
	}
	response, err := artifact.ParseAttemptResponseEvidence(responseEvidence, attempt)
	if err != nil {
		t.Fatal("version-list response metadata parse", err)
	}
	observedMillis, ok := responseRow["observed_at_milliseconds"].(int64)
	observedAt := time.UnixMilli(observedMillis).UTC()
	if !ok || !response.ObservedAt.Equal(observedAt) || observedAt.Before(attempt.ReservedAt()) || observedAt.After(observedUpper) {
		t.Fatal("version-list response observation time outside reservation/invocation bounds")
	}
	out := resumeListResponseOracle{Event: event, Request: request, Attempt: attempt, Response: response, ResponseRow: responseRow, UnknownRow: unknownRow, ObservedAt: observedAt}
	out.ResponseTx = resumeEvidenceInsertTx(snapshot, responseRow["evidence_identity"], label)
	if out.ResponseTx == 0 || !resumeCommitted(snapshot.Events, g.name, label, out.ResponseTx) {
		t.Fatal("version-list response was not durably committed with a known reply")
	}
	out.RawOverflow = uint64(len(event.ResponseBody)) > uint64(request.MaximumResponseBytes())

	switch response.Code {
	case artifact.AttemptResponsePresent:
		if unknownRow != nil {
			t.Fatal("present version-list response also retained unknown evidence")
		}
		if event.ResponseStatus != 200 || len(event.ResponseBody) == 0 {
			t.Fatal("present version-list response lacks independent wire page data")
		}
		if out.RawOverflow {
			t.Fatal("overflowed version-list was retained as present page data")
		}
		page := resumePageFromWire(t, g.Key(), event.ResponseBody)
		if len(page.Entries) > int(request.PageLimit()) {
			t.Fatal("external page exceeded wire max-keys")
		}
		out.ExpectedPresent = resumeIndependentResponse(t, op, attempt, page, observedAt)
		out.CanonicalOverflow = len(out.ExpectedPresent) > 262144
		if out.CanonicalOverflow {
			t.Fatal("canonical-overflowed version-list was retained as present page data")
		}
		if !bytes.Equal(resumeEvidenceInner(t, responseRow["canonical_evidence"].([]byte)), out.ExpectedPresent) {
			t.Fatal("committed present page differs from independent wire-page canonical form")
		}
	case artifact.AttemptResponseUnavailable, artifact.AttemptResponseMalformed:
		if response.Code == artifact.AttemptResponseMalformed && event.ResponseStatus == 200 && len(event.ResponseBody) > 0 && !out.RawOverflow {
			page := resumePageFromWire(t, g.Key(), event.ResponseBody)
			if len(page.Entries) > int(request.PageLimit()) {
				t.Fatal("external page exceeded wire max-keys")
			}
			out.ExpectedPresent = resumeIndependentResponse(t, op, attempt, page, observedAt)
			out.CanonicalOverflow = len(out.ExpectedPresent) > 262144
		}
		if unknownRow == nil {
			t.Fatal("failed version-list response has no linked unknown evidence")
		}
		record := resumeDecodeObject(t, resumeEvidenceInner(t, responseRow["canonical_evidence"].([]byte)))
		if string(record["code"]) != "\""+response.Code.String()+"\"" || string(record["entries"]) != "[]" || string(record["record_hex"]) != "\"\"" || len(response.CanonicalRecord) != 0 || len(response.Page.Entries) != 0 || response.Page.Next != (artifact.VersionCursor{}) || response.Page.Truncated {
			t.Fatal("failed version-list retained usable page content")
		}
		unknownMillis, ok := unknownRow["observed_at_milliseconds"].(int64)
		if !ok {
			t.Fatal("unknown evidence missing observed time")
		}
		expectedUnknown := resumeExpectedUnknown(t, attempt, time.UnixMilli(unknownMillis).UTC())
		if !bytes.Equal(unknownRow["canonical_evidence"].([]byte), expectedUnknown) {
			t.Fatal("unknown evidence is not the exact linked canonical record")
		}
		out.UnknownTx = resumeEvidenceInsertTx(snapshot, unknownRow["evidence_identity"], label)
		if out.UnknownTx == 0 || out.ResponseTx != out.UnknownTx || !resumeCommitted(snapshot.Events, g.name, label, out.UnknownTx) {
			t.Fatal("failed response and unknown were not one known commit")
		}
	default:
		t.Fatal("version-list response was neither committed present page data nor failed uncertainty", response.Code)
	}
	return out
}

func resumeAssertLostListUncertainty(t *testing.T, g *budgetedResumeGraph, op artifact.ErasureOperation, allowance artifact.ResumeAllowance, snapshot resumeFixtureSQLSnapshot, event resumeWireEvent, label string) resumeListResponseOracle {
	t.Helper()
	out := resumeAssertVersionListResponseOracle(t, g, op, snapshot, event, allowance, label, g.clock.Value())
	if out.Response.Code != artifact.AttemptResponseUnavailable {
		t.Fatal("lost version-list response was not retained as unavailable uncertainty", out.Response.Code)
	}
	return out
}

func resumeEvidenceInsertTx(snapshot resumeFixtureSQLSnapshot, evidenceID any, label string) uint64 {
	for _, event := range snapshot.Events {
		if event.OperationLabel == label && event.StatementID == "evidence_insert" && len(event.Arguments) == 14 && event.Arguments[8] == evidenceID {
			return event.TransactionID
		}
	}
	return 0
}

func resumeSingleUsage(t *testing.T, progress artifact.ErasureProgress, allowance artifact.ResumeAllowance) artifact.AllowanceUsage {
	t.Helper()
	usages := progress.AllowanceUsages()
	if len(usages) != 1 || usages[0].AllowanceIdentity != allowance.Identity() {
		t.Fatal("progress did not return the requested allowance usage")
	}
	return usages[0]
}

func resumeAssertAllowanceUsageMatchesAttempts(t *testing.T, g *budgetedResumeGraph, snapshot resumeFixtureSQLSnapshot, allowance artifact.ResumeAllowance, usage artifact.AllowanceUsage) {
	t.Helper()
	sum := make([]uint64, len(resumeDimensions))
	count := uint64(0)
	for _, row := range snapshot.Rows[resumeAttempts] {
		if row["allowance_identity"] != allowance.Identity() {
			continue
		}
		request, err := artifact.ParseAttemptRequest(row["canonical_request"].([]byte), g.scope)
		if err != nil {
			t.Fatal("attempt request parse", err)
		}
		count++
		for i, n := range resumeBudgetVector(resumeCost(request)) {
			sum[i] += n
		}
	}
	spent := resumeBudgetVector(usage.Spent)
	for i, n := range sum {
		if spent[i] != n {
			t.Fatal("requested allowance usage does not match persisted attempts", resumeDimensions[i])
		}
	}
	if usage.NextSequence != count+1 {
		t.Fatal("requested allowance next sequence does not match persisted attempts", usage.NextSequence, count+1)
	}
}

func resumeAssertDeletesUseCommittedUsableObservations(t *testing.T, g *budgetedResumeGraph, op artifact.ErasureOperation, snapshot resumeFixtureSQLSnapshot, events []resumeWireEvent) {
	t.Helper()
	for _, event := range events {
		if event.Method != "DELETE" {
			continue
		}
		deleteRequest, deleteAttempt := resumeAttemptRequestByID(t, g, snapshot, event.Attempt)
		if deleteRequest.Kind() != artifact.AttemptVersionDelete || deleteRequest.ObservationIdentity() == "" {
			t.Fatal("delete event is not bound to an observed version-delete attempt")
		}
		observationRow := resumeEvidenceRowByIdentity(snapshot, deleteRequest.ObservationIdentity())
		if observationRow == nil || observationRow["kind"] != "response" {
			t.Fatal("delete is parented on missing or non-response observation")
		}
		observationRequest, observationAttempt := resumeAttemptRequestByID(t, g, snapshot, observationRow["attempt_identity"].(string))
		observationEvidence, err := artifact.ParseErasureEvidence(observationRow["canonical_evidence"].([]byte), op.Ref())
		if err != nil {
			t.Fatal("delete observation evidence parse", err)
		}
		observation, err := artifact.ParseAttemptResponseEvidence(observationEvidence, observationAttempt)
		if err != nil {
			t.Fatal("delete observation response parse", err)
		}
		if observation.Code != artifact.AttemptResponsePresent {
			t.Fatal("delete is parented on a failed or non-present observation", observation.Code)
		}
		version, err := artifact.NewObjectVersion(deleteRequest.NamespaceIdentity(), deleteRequest.Key(), deleteRequest.VersionKind(), deleteRequest.VersionID())
		if err != nil {
			t.Fatal("delete request version parse", err)
		}
		usable := false
		switch observationRequest.Kind() {
		case artifact.AttemptVersionList:
			for _, entry := range observation.Page.Entries {
				if entry.Version == version {
					usable = true
				}
			}
		case artifact.AttemptCurrentRead:
			usable = observation.Version == version
		}
		if !usable {
			t.Fatal("delete observation does not prove the deleted version")
		}
		committedBeforeDelete := false
		for _, insert := range snapshot.Events {
			if insert.StatementID != "evidence_insert" || len(insert.Arguments) != 14 || insert.Arguments[8] != deleteRequest.ObservationIdentity() {
				continue
			}
			for _, commit := range snapshot.Events {
				if commit.TransactionID == insert.TransactionID && commit.ReplyKnown && commit.StatementID == "COMMIT" && commit.Sequence <= event.SQLSequence {
					committedBeforeDelete = true
				}
			}
		}
		if !committedBeforeDelete || deleteAttempt.Identity() != event.Attempt {
			t.Fatal("deletion preceded its usable committed observation")
		}
	}
}

func resumeAttemptRequestByID(t *testing.T, g *budgetedResumeGraph, snapshot resumeFixtureSQLSnapshot, attemptID string) (artifact.AttemptRequest, artifact.ErasureAttempt) {
	t.Helper()
	for _, row := range snapshot.Rows[resumeAttempts] {
		if row["attempt_identity"] != attemptID {
			continue
		}
		request, err := artifact.ParseAttemptRequest(row["canonical_request"].([]byte), g.scope)
		if err != nil {
			t.Fatal("attempt request parse", err)
		}
		attempt, err := artifact.ParseErasureAttempt(row["canonical_attempt"].([]byte), request)
		if err != nil {
			t.Fatal("attempt parse", err)
		}
		return request, attempt
	}
	t.Fatal("missing durable attempt")
	return artifact.AttemptRequest{}, artifact.ErasureAttempt{}
}

func resumeEvidenceRowByIdentity(snapshot resumeFixtureSQLSnapshot, evidenceID string) resumeFixtureRow {
	for _, row := range snapshot.Rows[resumeEvidence] {
		if row["evidence_identity"] == evidenceID {
			return row
		}
	}
	return nil
}
