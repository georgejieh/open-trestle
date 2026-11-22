// Package reviewschema embeds the canonical model output schemas.
package reviewschema

import _ "embed"

//go:embed model-candidate-batch-v2.schema.json
var candidateBatchV2 string

//go:embed model-verification-batch-v1.schema.json
var verificationBatch string

// CandidateBatchV2 returns model-candidate-batch-v2, the output schema of
// generation contexts.
func CandidateBatchV2() []byte  { return []byte(candidateBatchV2) }
func VerificationBatch() []byte { return []byte(verificationBatch) }
