package main

import (
	"testing"
	"time"
)

func TestGenerationRejectionWindow(t *testing.T) {
	created := time.UnixMilli(1000)
	expires := time.UnixMilli(2000)
	window := generationRejectionWindow{created: created, expires: expires}
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{{created.Add(-time.Millisecond), false}, {created, true}, {expires.Add(-time.Millisecond), true}, {expires, false}} {
		if got := window.live(tc.at); got != tc.want {
			t.Fatalf("window at %v: %v", tc.at, got)
		}
	}
	if (generationRejectionWindow{}).live(created) {
		t.Fatal("empty proof window live")
	}
}
