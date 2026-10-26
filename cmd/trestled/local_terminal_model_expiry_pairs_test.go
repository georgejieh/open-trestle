package main

import (
	"github.com/georgejieh/open-trestle/artifact"
	"testing"
)

func TestTerminalExpiryRecordedPairsStayExact(t *testing.T) {
	cases := []struct {
		kind    artifact.Kind
		origin  artifact.Origin
		allowed bool
	}{
		{artifact.KindCandidateBatch, artifact.OriginModel, true},
		{artifact.KindCandidateBatch, artifact.OriginHost, false},
		{artifact.KindCandidateBatch, artifact.OriginDeterministicTool, false},
		{artifact.KindSanitizedModelRequest, artifact.OriginHost, true},
		{artifact.KindSanitizedModelRequest, artifact.OriginModel, false},
		{artifact.KindSanitizedEgressReceipt, artifact.OriginHost, true},
		{artifact.KindSanitizedEgressReceipt, artifact.OriginModel, false},
	}
	for _, c := range cases {
		if got := physicalRecordedPair(c.kind, c.origin); got != c.allowed {
			t.Fatalf("kind=%v origin=%v allowed=%v", c.kind, c.origin, got)
		}
	}
}
