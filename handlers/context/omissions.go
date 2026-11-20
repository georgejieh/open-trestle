package context

import (
	"sort"

	"github.com/georgejieh/open-trestle/internal/review"
)

// maximumOmissionRecords bounds the omission records of a packet: each
// record's path is one of the 256 fields a sanitized request may carry, so a
// change with many files that cannot be analysed must not crowd out the
// sources.
const maximumOmissionRecords = 32

// collapseOmissions keeps the records as they are up to the bound. Past it,
// the records of each reason merge into one counted record at the reason's
// first path, so the counts stay exact and only the other paths are lost.
func collapseOmissions(values []review.ContextSourceOmission) ([]review.ContextSourceOmission, error) {
	if len(values) <= maximumOmissionRecords {
		return values, nil
	}
	type merged struct {
		path  string
		count uint32
	}
	byReason := map[string]*merged{}
	for _, value := range values {
		m, ok := byReason[value.Reason()]
		if !ok || value.Path() < m.path {
			if !ok {
				m = &merged{}
				byReason[value.Reason()] = m
			}
			m.path = value.Path()
		}
		m.count += value.Count()
	}
	reasons := make([]string, 0, len(byReason))
	for reason := range byReason {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	out := make([]review.ContextSourceOmission, 0, len(reasons))
	for _, reason := range reasons {
		m := byReason[reason]
		value, err := review.NewCountedContextSourceOmission(m.path, 0, 0, reason, m.count)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}
