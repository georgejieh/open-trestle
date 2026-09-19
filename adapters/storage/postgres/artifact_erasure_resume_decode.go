package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func readResumeRows(ctx context.Context, tx *sql.Tx, query string, columns, maximum int, args ...any) ([][]any, error) {
	if columns < 1 || columns > 64 || maximum < 1 || maximum > 65 {
		return nil, ErrCorruptRecord
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classifyTransactionError(err)
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, classifyTransactionError(err)
	}
	if len(names) != columns {
		return nil, ErrCorruptRecord
	}
	var result [][]any
	size := 0
	for rows.Next() {
		if len(result) >= maximum {
			return nil, ErrCorruptRecord
		}
		row := make([]any, columns)
		dest := make([]any, columns)
		for i := range row {
			dest[i] = &row[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, classifyTransactionError(err)
		}
		for i, cell := range row {
			switch v := cell.(type) {
			case string:
				if len(v) > 1<<20 || size > 2<<20-len(v) {
					return nil, ErrCorruptRecord
				}
				size += len(v)
			case []byte:
				if len(v) > 1<<20 || size > 2<<20-len(v) {
					return nil, ErrCorruptRecord
				}
				size += len(v)
				row[i] = bytes.Clone(v)
			case int64, bool, nil:
			default:
				return nil, ErrCorruptRecord
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyTransactionError(err)
	}
	if err := rows.Close(); err != nil {
		return nil, classifyTransactionError(err)
	}
	return result, nil
}
func journalResumeBudgetVector(b artifact.ResumeBudget) [11]uint64 {
	return [11]uint64{uint64(b.Requests), uint64(b.Mutations), uint64(b.Reads), uint64(b.Lists), uint64(b.Creates), uint64(b.Deletes), uint64(b.Pages), uint64(b.Versions), b.ResponseBytes, b.ListBytes, b.WriteBytes}
}
func resumeVectorBudget(v [11]uint64) artifact.ResumeBudget {
	return artifact.ResumeBudget{Requests: uint32(v[0]), Mutations: uint32(v[1]), Reads: uint32(v[2]), Lists: uint32(v[3]), Creates: uint32(v[4]), Deletes: uint32(v[5]), Pages: uint32(v[6]), Versions: uint32(v[7]), ResponseBytes: v[8], ListBytes: v[9], WriteBytes: v[10]}
}
func resumeRequestCost(r artifact.AttemptRequest) artifact.ResumeBudget {
	b := artifact.ResumeBudget{Requests: 1, ResponseBytes: uint64(r.MaximumResponseBytes()) + 1}
	switch r.Kind() {
	case artifact.AttemptCurrentRead, artifact.AttemptIntentRead, artifact.AttemptAttestationRead:
		b.Reads = 1
	case artifact.AttemptVersionList:
		b.Lists = 1
		b.Pages = 1
		b.Versions = uint32(r.PageLimit())
		b.ListBytes = b.ResponseBytes
	case artifact.AttemptIntentCreate, artifact.AttemptFenceCreate, artifact.AttemptAttestationCreate:
		b.Mutations = 1
		b.Creates = 1
		b.WriteBytes = uint64(r.BodyBytes())
	case artifact.AttemptVersionDelete:
		b.Mutations = 1
		b.Deletes = 1
	}
	return b
}
func resumeBudgetCells(b artifact.ResumeBudget) []any {
	result := make([]any, 11)
	for i, v := range journalResumeBudgetVector(b) {
		result[i] = int64(v)
	}
	return result
}
func resumeReadBudget(row []any, offset int, maximum artifact.ResumeBudget) (artifact.ResumeBudget, error) {
	var v [11]uint64
	max := journalResumeBudgetVector(maximum)
	if offset < 0 || len(row) < offset+11 {
		return artifact.ResumeBudget{}, ErrCorruptRecord
	}
	for i := range v {
		x, ok := row[offset+i].(int64)
		if !ok || x < 0 || uint64(x) > max[i] {
			return artifact.ResumeBudget{}, ErrCorruptRecord
		}
		v[i] = uint64(x)
	}
	if v[0] != v[2]+v[3]+v[4]+v[5] || v[1] != v[4]+v[5] || v[6] != v[3] {
		return artifact.ResumeBudget{}, ErrCorruptRecord
	}
	return resumeVectorBudget(v), nil
}
func resumeScopeCells(op artifact.ErasureOperation) []any {
	s := op.Scope()
	return []any{s.TenantID(), s.RepositoryID(), s.ReviewRunID(), s.Identity(), op.NamespaceIdentity(), op.ArtifactIdentity(), op.AdmissionIdentity(), op.Identity()}
}
func resumeArgs(ref artifact.ErasureOperationRef, identity string) []any {
	return append(erasureReadArgs(ref.Scope(), ref.NamespaceIdentity(), ref.OperationIdentity()), identity)
}
func resumeCellsEqual(row, want []any) bool {
	if len(row) != len(want) {
		return false
	}
	for i, v := range want {
		if !reflect.DeepEqual(row[i], v) {
			return false
		}
	}
	return true
}
func resumeAllowanceCells(op artifact.ErasureOperation, a artifact.ResumeAllowance, policy []byte, at time.Time, spent artifact.ResumeBudget) ([]any, error) {
	raw, err := artifact.EncodeResumeAllowance(a)
	if err != nil {
		return nil, err
	}
	s := op.Scope()
	row := []any{s.TenantID(), s.RepositoryID(), s.ReviewRunID(), s.Identity(), op.NamespaceIdentity(), op.ArtifactIdentity(), op.AdmissionIdentity(), op.Identity(), a.Identity(), raw, erasureDigest(raw), policy, a.ProtectedPolicyIdentity(), at.UnixMilli()}
	row = append(row, resumeBudgetCells(a.Maximum())...)
	row = append(row, resumeBudgetCells(spent)...)
	return row, nil
}
func resumeDecodeAllowance(row []any, op artifact.ErasureOperation, ns artifact.StorageNamespace, authority, identity string) (artifact.ErasureAllowanceSnapshot, error) {
	var zero artifact.ErasureAllowanceSnapshot
	if len(row) != 36 {
		return zero, ErrCorruptRecord
	}
	raw, ok := erasureBytes(row, 9, 4096)
	if !ok {
		return zero, ErrCorruptRecord
	}
	a, err := artifact.ParseResumeAllowance(raw, op.Scope())
	if err != nil || a.Identity() != identity {
		return zero, ErrCorruptRecord
	}
	policyRaw, ok := erasureBytes(row, 11, 16384)
	if !ok {
		return zero, ErrCorruptRecord
	}
	p, err := parsePersistedErasurePolicy(policyRaw)
	if err != nil {
		return zero, ErrCorruptRecord
	}
	at := time.UnixMilli(erasureInt(row, 13)).UTC()
	if !validErasureInstant(at) || !a.AllowsOperation(op, at) || !p.allows(at) || !p.matchesNamespace(ns, authority) || p.Identity != a.ProtectedPolicyIdentity() || p.RecoveryPolicyIdentity != a.RecoveryPolicyIdentity() || p.ErasurePolicyIdentity != op.PolicyIdentity() || p.Protocol != op.ErasureProtocol() || p.Ownership != op.Ownership() {
		return zero, ErrCorruptRecord
	}
	spent, err := resumeReadBudget(row, 25, a.Maximum())
	if err != nil {
		return zero, err
	}
	expected, err := resumeAllowanceCells(op, a, policyRaw, at, spent)
	if err != nil || !resumeCellsEqual(row, expected) {
		return zero, ErrCorruptRecord
	}
	return artifact.ErasureAllowanceSnapshot{Allowance: a, AcceptedPolicyBytes: bytes.Clone(policyRaw), AcceptedAt: at, Usage: artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), Spent: spent, NextSequence: uint64(spent.Requests) + 1}}, nil
}
func resumeAttemptCells(op artifact.ErasureOperation, a artifact.ErasureAttempt) ([]any, error) {
	r := a.Request()
	request, err := artifact.EncodeAttemptRequest(r)
	if err != nil {
		return nil, err
	}
	raw, err := artifact.EncodeErasureAttempt(a)
	if err != nil {
		return nil, err
	}
	row := append(resumeScopeCells(op), r.AllowanceIdentity(), r.ReservationIdentity(), a.Identity(), r.Identity(), request, raw, int64(a.Sequence()), a.ReservedAt().UnixMilli())
	return append(row, resumeBudgetCells(resumeRequestCost(r))...), nil
}
func resumeDecodeAttempt(row []any, op artifact.ErasureOperation) (artifact.ErasureAttempt, error) {
	if len(row) != 27 {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	request, ok := erasureBytes(row, 12, 8192)
	if !ok {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	r, err := artifact.ParseAttemptRequest(request, op.Scope())
	if err != nil {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	raw, ok := erasureBytes(row, 13, 1024)
	if !ok {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	a, err := artifact.ParseErasureAttempt(raw, r)
	if err != nil {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	expected, err := resumeAttemptCells(op, a)
	if err != nil || !resumeCellsEqual(row, expected) {
		return artifact.ErasureAttempt{}, ErrCorruptRecord
	}
	return a, nil
}
func resumeEvidenceCells(op artifact.ErasureOperation, e artifact.ErasureEvidence) ([]any, error) {
	raw, err := artifact.EncodeErasureEvidence(e)
	if err != nil {
		return nil, err
	}
	var attempt any
	if e.Kind() == "response" || e.Kind() == "unknown" {
		attempt = e.AttemptIdentity()
	}
	return append(resumeScopeCells(op), e.Identity(), e.Slot(), e.Kind(), attempt, raw, e.ObservedAt().UnixMilli()), nil
}
func resumeDecodeEvidence(row []any, op artifact.ErasureOperation) (artifact.ErasureEvidence, error) {
	if len(row) != 14 {
		return artifact.ErasureEvidence{}, ErrCorruptRecord
	}
	raw, ok := erasureBytes(row, 12, 1<<20)
	if !ok {
		return artifact.ErasureEvidence{}, ErrCorruptRecord
	}
	e, err := artifact.ParseErasureEvidence(raw, op.Ref())
	if err != nil {
		return artifact.ErasureEvidence{}, ErrCorruptRecord
	}
	expected, err := resumeEvidenceCells(op, e)
	if err != nil || !resumeCellsEqual(row, expected) {
		return artifact.ErasureEvidence{}, ErrCorruptRecord
	}
	return e, nil
}
