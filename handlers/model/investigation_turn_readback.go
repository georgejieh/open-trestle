package model

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

var errRetainedInvestigationTurn = errors.New("retained investigation turn counts are not measured from its request")

// parseRetainedInvestigationTurn parses exact retained turn bytes and
// re-measures the system channel and any response_format count the turn
// reserved for from its own recorded request. internal/gateway cannot import
// internal/review, so it checks those counts only against the recorded budget
// and identity; every turn readback in this package parses through here and
// refuses a count the request does not support.
func parseRetainedInvestigationTurn(payload []byte) (gateway.InvestigationTurnRecord, error) {
	record, err := gateway.ParseInvestigationTurnRecord(payload)
	if err != nil {
		return gateway.InvestigationTurnRecord{}, err
	}
	system, format, err := review.RecordedInvestigationTurnTransportBytes(record.Request())
	recordedFormat, structured := record.ResponseFormatBytes()
	if err != nil || record.SystemChannelBytes() != system || structured && recordedFormat != format {
		return gateway.InvestigationTurnRecord{}, errRetainedInvestigationTurn
	}
	return record, nil
}
