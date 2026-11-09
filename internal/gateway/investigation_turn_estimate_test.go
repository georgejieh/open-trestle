package gateway

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestInvestigationTurnEstimateVersion1RecordedBytesReadBackWithTheVersion1Formula(t *testing.T) {
	recorded, err := os.ReadFile("testdata/investigation-turn-estimate-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(recorded, []byte(`"system_channel_bytes"`)) || !bytes.Contains(recorded, []byte(`"estimate_version":1,`)) {
		t.Fatal("fixture is not a version 1 recording")
	}
	record, err := ParseInvestigationTurnRecord(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if record.EstimateVersion() != 1 || record.SystemChannelBytes() != 0 {
		t.Fatal("version 1 readback gained a system channel count")
	}
	turnEncodingAssertRoundTrip(t, record)
	// The recorded reservation is the version 1 formula: payload plus framing only.
	want := max(uint64(record.declaredInput), uint64(len(record.request.Payload()))+256)
	if got := uint64(record.Selection().CostBudget().EstimatedInputTokens()); got != want {
		t.Fatalf("version 1 reservation = %d, want %d", got, want)
	}
	// A recorded version 1 budget is never re-derived with the version 2
	// formula: relabeling it as version 2 with a system channel fails, and a
	// version 1 record cannot carry a count.
	for name, change := range map[string]func(*InvestigationTurnRecord){
		"version 2 with system channel": func(r *InvestigationTurnRecord) {
			r.estimateVersion, r.systemBytes = InvestigationBudgetEstimateVersion, investigationOwnerSystemBytes
		},
		"version 1 with system channel": func(r *InvestigationTurnRecord) { r.systemBytes = investigationOwnerSystemBytes },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			change(&changed)
			changed.identity = changed.deriveIdentity()
			if changed.Validate() == nil {
				t.Fatal("version 1 reservation re-derived under a system channel")
			}
		})
	}
	trimmed := bytes.TrimSuffix(recorded, []byte("}"))
	for name, encoded := range map[string][]byte{
		"zero count":     append(append([]byte(nil), trimmed...), []byte(`,"system_channel_bytes":0}`)...),
		"non-zero count": append(append([]byte(nil), trimmed...), []byte(`,"system_channel_bytes":1000}`)...),
	} {
		t.Run(name, func(t *testing.T) { turnEncodingRefuse(t, encoded) })
	}
}

func TestInvestigationTurnEstimateVersion2RecordsAndReadsBackTheSystemChannel(t *testing.T) {
	options, _, _, _ := investigationOwnerOptionsFixture(t, "", 100000, 2)
	var measured []string
	// Vary the count with the request so each turn records its own measurement.
	options.SystemChannelBytes = func(request provider.Request) uint32 {
		measured = append(measured, request.Identity())
		return uint32(1000 + len(request.Payload()))
	}
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	request := ownerRequest(t, "estimate-v2")
	record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
	if err != nil {
		t.Fatal(err)
	}
	system := uint32(1000 + len(request.Payload()))
	if len(measured) != 1 || measured[0] != request.Identity() || record.EstimateVersion() != InvestigationBudgetEstimateVersion || record.SystemChannelBytes() != system {
		t.Fatal("owner did not measure and record the dispatched request's system channel")
	}
	planned, err := InvestigationTurnCostBudget(options.Budget, request, system, record.Authorization().RemainingCostBeforeMicroUSD())
	if err != nil || record.Selection().CostBudget() != planned || record.Authorization().CostBudget() != planned {
		t.Fatal("recorded reservation differs from the shared version 2 budget")
	}
	if uint64(planned.EstimatedInputTokens()) != uint64(len(request.Payload()))+uint64(system)+256 {
		t.Fatal("version 2 reservation omitted the system channel")
	}
	decoded := turnEncodingAssertRoundTrip(t, record)
	if decoded.EstimateVersion() != InvestigationBudgetEstimateVersion || decoded.SystemChannelBytes() != system {
		t.Fatal("version 2 readback lost the recorded system channel")
	}
	encoded, err := EncodeInvestigationTurnRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	member := []byte(`,"system_channel_bytes":` + strconv.FormatUint(uint64(system), 10) + `}`)
	if !bytes.HasSuffix(encoded, member) {
		t.Fatal("version 2 encoding lacks its system channel count")
	}
	base := bytes.TrimSuffix(encoded, member)
	for name, changed := range map[string][]byte{
		"missing count":     append(append([]byte(nil), base...), '}'),
		"changed count":     append(append([]byte(nil), base...), []byte(`,"system_channel_bytes":`+strconv.FormatUint(uint64(system)+1, 10)+`}`)...),
		"null count":        append(append([]byte(nil), base...), []byte(`,"system_channel_bytes":null}`)...),
		"overflowing count": append(append([]byte(nil), base...), []byte(`,"system_channel_bytes":4294967296}`)...),
		"version 1 label":   bytes.Replace(encoded, []byte(`"estimate_version":2,`), []byte(`"estimate_version":1,`), 1),
	} {
		t.Run(name, func(t *testing.T) { turnEncodingRefuse(t, changed) })
	}
}
