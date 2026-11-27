// Package reviewschema embeds the canonical model output schemas.
package reviewschema

import _ "embed"

//go:embed model-candidate-batch-v2.schema.json
var candidateBatchV2 string

//go:embed model-verification-batch-v2.schema.json
var verificationBatchV2 string

// CandidateBatchV2 returns model-candidate-batch-v2, the output schema of
// generation contexts; VerificationBatch returns model-verification-batch-v2,
// that of verification contexts.
func CandidateBatchV2() []byte  { return []byte(candidateBatchV2) }
func VerificationBatch() []byte { return []byte(verificationBatchV2) }
