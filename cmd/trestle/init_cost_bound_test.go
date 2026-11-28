package main

import "testing"

func TestInitCostBoundCountsSpecialistReviews(t *testing.T) {
	if got, want := initCostBound(690_000, false), "up to $0.69 a request and $1.38 a review"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := initCostBound(690_000, true), "up to $0.69 a request and $1.38 a review, or $5.52 with 3 specialist reviews"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
