package localreview

// ProgressStage is the kind of model request a session is about to send.
type ProgressStage uint8

const (
	// ProgressModel is a request of an investigation, which has no finder and
	// checker split.
	ProgressModel ProgressStage = iota
	ProgressFinder
	ProgressChecker
)

// ProgressEvent reports that a model request is being sent. Retry is set for
// a request sent again after a failure or an answer that was not usable. It
// carries no request or answer content.
type ProgressEvent struct {
	Stage ProgressStage
	Retry bool
}
