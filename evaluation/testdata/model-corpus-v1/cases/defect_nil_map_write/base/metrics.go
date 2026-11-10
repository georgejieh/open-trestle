// Package metrics counts named events.
package metrics

import "sort"

// Recorder counts named events. Create one with NewRecorder.
type Recorder struct {
	totals map[string]int
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{totals: make(map[string]int)}
}

// Add records one occurrence of name.
func (r *Recorder) Add(name string) {
	r.totals[name]++
}

// Total returns how many times name was recorded.
func (r *Recorder) Total(name string) int {
	return r.totals[name]
}

// Names returns every recorded name in sorted order.
func (r *Recorder) Names() []string {
	names := make([]string, 0, len(r.totals))
	for name := range r.totals {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
