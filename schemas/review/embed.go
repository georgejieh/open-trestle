// Package reviewschema embeds the canonical model output schemas.
package reviewschema

import _ "embed"

//go:embed model-candidate-batch-v1.schema.json
var candidateBatch string

//go:embed model-verification-batch-v1.schema.json
var verificationBatch string

func CandidateBatch() []byte    { return []byte(candidateBatch) }
func VerificationBatch() []byte { return []byte(verificationBatch) }
