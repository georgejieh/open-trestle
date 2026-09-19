package artifact

// PayloadSizeBytes reports stored length without validating identity or custody.
func (a Artifact) PayloadSizeBytes() int { return len(a.payload) }
