package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var ErrInvalidInvestigationPolicy = errors.New("invalid snapshot investigation policy")

type investigationPolicyWire struct {
	Contract            string `json:"contract"`
	MaxCostMicroUSD     uint64 `json:"max_cost_micro_usd"`
	MaxFiles            uint64 `json:"max_files"`
	MaxLinesPerRead     uint64 `json:"max_lines_per_read"`
	MaxMatches          uint64 `json:"max_matches"`
	MaxModelTurns       uint64 `json:"max_model_turns"`
	MaxResultBytes      uint64 `json:"max_result_bytes"`
	MaxReturnedBytes    uint64 `json:"max_returned_bytes"`
	MaxScannedBytes     uint64 `json:"max_scanned_bytes"`
	MaxToolCalls        uint64 `json:"max_tool_calls"`
	Profile             string `json:"profile"`
	SchemaVersion       uint64 `json:"schema_version"`
	TimeoutMilliseconds uint64 `json:"timeout_milliseconds"`
}

// InvestigationPolicy is immutable host opt-in, not model execution authority.
type InvestigationPolicy struct {
	wire     investigationPolicyWire
	identity string
}

func ParseInvestigationPolicy(encoded []byte) (InvestigationPolicy, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return InvestigationPolicy{}, ErrInvalidInvestigationPolicy
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire investigationPolicyWire
	if decoder.Decode(&wire) != nil {
		return InvestigationPolicy{}, ErrInvalidInvestigationPolicy
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return InvestigationPolicy{}, ErrInvalidInvestigationPolicy
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || !validInvestigationPolicy(wire) {
		return InvestigationPolicy{}, ErrInvalidInvestigationPolicy
	}
	sum := sha256.Sum256(canonical)
	return InvestigationPolicy{wire: wire, identity: hex.EncodeToString(sum[:])}, nil
}

func EncodeInvestigationPolicy(value InvestigationPolicy) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidInvestigationPolicy
	}
	return json.Marshal(value.wire)
}

func validInvestigationPolicy(w investigationPolicyWire) bool {
	return w.Contract == "open-trestle/investigation-policy" && w.SchemaVersion == 1 && w.Profile == "snapshot-read-v1" &&
		w.MaxFiles > 0 && w.MaxFiles <= 64 && w.MaxLinesPerRead > 0 && w.MaxLinesPerRead <= 256 &&
		w.MaxMatches > 0 && w.MaxMatches <= 64 && w.MaxModelTurns > 0 && w.MaxModelTurns <= 8 &&
		w.MaxToolCalls > 0 && w.MaxToolCalls <= 6 && w.MaxResultBytes > 0 && w.MaxResultBytes <= 65536 &&
		w.MaxReturnedBytes > 0 && w.MaxReturnedBytes <= 262144 && w.MaxScannedBytes > 0 && w.MaxScannedBytes <= 16777216 &&
		w.TimeoutMilliseconds > 0 && w.TimeoutMilliseconds <= 900000
}

func (p InvestigationPolicy) Validate() error {
	if !validInvestigationPolicy(p.wire) {
		return ErrInvalidInvestigationPolicy
	}
	encoded, err := json.Marshal(p.wire)
	if err != nil {
		return ErrInvalidInvestigationPolicy
	}
	sum := sha256.Sum256(encoded)
	if p.identity != hex.EncodeToString(sum[:]) {
		return ErrInvalidInvestigationPolicy
	}
	return nil
}

func (p InvestigationPolicy) ValidateRuntimeBudget(budget provider.ModelCostBudget) error {
	if p.Validate() != nil || budget.Validate() != nil || p.wire.MaxCostMicroUSD > budget.MaxCostMicroUSD() {
		return ErrInvalidInvestigationPolicy
	}
	return nil
}

func (p InvestigationPolicy) Identity() string            { return p.identity }
func (p InvestigationPolicy) MaxCostMicroUSD() uint64     { return p.wire.MaxCostMicroUSD }
func (p InvestigationPolicy) MaxFiles() uint64            { return p.wire.MaxFiles }
func (p InvestigationPolicy) MaxLinesPerRead() uint64     { return p.wire.MaxLinesPerRead }
func (p InvestigationPolicy) MaxMatches() uint64          { return p.wire.MaxMatches }
func (p InvestigationPolicy) MaxModelTurns() uint64       { return p.wire.MaxModelTurns }
func (p InvestigationPolicy) MaxToolCalls() uint64        { return p.wire.MaxToolCalls }
func (p InvestigationPolicy) MaxResultBytes() uint64      { return p.wire.MaxResultBytes }
func (p InvestigationPolicy) MaxReturnedBytes() uint64    { return p.wire.MaxReturnedBytes }
func (p InvestigationPolicy) MaxScannedBytes() uint64     { return p.wire.MaxScannedBytes }
func (p InvestigationPolicy) TimeoutMilliseconds() uint64 { return p.wire.TimeoutMilliseconds }
