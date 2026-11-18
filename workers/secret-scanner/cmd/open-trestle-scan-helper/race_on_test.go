//go:build race

package main

// raceDetector reports that the test binary runs under the race detector,
// where the in-process native scanner misses its scan deadline on dense input.
const raceDetector = true
