package main

import (
	"slices"
	"testing"

	"github.com/georgejieh/open-trestle/internal/repochecks"
)

func TestDiscardedCheckLinesGiveEachReason(t *testing.T) {
	got := discardedCheckLines([]repochecks.AuthoredResult{
		{Status: repochecks.AuthoredRegression, Path: "calc/trestle_check_1_test.go"},
		{Reason: "it did not show a regression"},
		{Reason: "its folder is in no Go module"},
	})
	want := []string{
		"Check 2 was discarded: it did not show a regression.",
		"Check 3 was discarded: its folder is in no Go module.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
