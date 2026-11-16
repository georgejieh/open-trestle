// Package reviewschema embeds the canonical model output schemas.
package reviewschema

import _ "embed"

//go:embed model-candidate-batch-v1.schema.json
var candidateBatch string

//go:embed model-candidate-batch-v2.schema.json
var candidateBatchV2 string

//go:embed model-verification-batch-v1.schema.json
var verificationBatch string

// CandidateBatch returns model-candidate-batch-v1, the output schema of
// generation contexts before version 7. It is kept for recorded readback.
func CandidateBatch() []byte { return []byte(candidateBatch) }

// CandidateBatchV2 returns model-candidate-batch-v2, the output schema of
// version 7 generation contexts.
func CandidateBatchV2() []byte  { return []byte(candidateBatchV2) }
func VerificationBatch() []byte { return []byte(verificationBatch) }
