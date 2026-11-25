package localreview

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

func TestObserverReportsStageAndRetry(t *testing.T) {
	var events []ProgressEvent
	o := &routeFailureObserver{progress: func(e ProgressEvent) { events = append(events, e) }}
	o.setStage(ProgressFinder)
	o.started(gateway.RouteAttemptAuthorization{})
	o.setStage(ProgressChecker)
	o.recordAnswerRetry()
	o.started(gateway.RouteAttemptAuthorization{})
	o.started(gateway.RouteAttemptAuthorization{})
	want := []ProgressEvent{{ProgressFinder, false}, {ProgressChecker, true}, {ProgressChecker, false}}
	if len(events) != len(want) || events[0] != want[0] || events[1] != want[1] || events[2] != want[2] {
		t.Fatalf("events %v, want %v", events, want)
	}
}
