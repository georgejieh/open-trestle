package reviewschema

import _ "embed"

//go:embed model-investigation-output-v1.schema.json
var investigationSchema string

//go:embed model-investigation-context-v4-instructions.txt
var investigationInstructions string

func InvestigationOutputSchema() []byte { return []byte(investigationSchema) }
func InvestigationInstructions() string { return investigationInstructions }
