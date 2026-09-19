package model

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func (c *Investigation) appendToolEvent(ctx context.Context, kind audit.EventKind, subject string, parents []string, operation string, at time.Time) error {
	parents = append([]string(nil), parents...)
	sort.Strings(parents)
	for attempt := 0; attempt < 3; attempt++ {
		if c.live(ctx) != nil {
			return ErrInvestigation
		}
		before, hadBefore, err := c.options.Ledger.Head(ctx, c.options.Scope)
		if err != nil {
			return ErrInvestigation
		}
		if hadBefore && before.Sequence() > 1000 {
			return ErrInvestigation
		}
		events, err := c.options.Ledger.Read(ctx, c.options.Scope, 0, 1000)
		if err != nil {
			return ErrInvestigation
		}
		if hadBefore && (len(events) != int(before.Sequence()) || len(events) == 0 || events[len(events)-1].Identity() != before.Identity()) {
			continue
		}
		if !hadBefore && len(events) != 0 {
			continue
		}
		previousEvent := ""
		claimFound := false
		claimParents := []string{c.binding.Identity(), c.head.Identity(), c.last.Identity(), c.last.Outcome().Identity(), c.last.Dispatch().Response().Identity()}
		sort.Strings(claimParents)
		for index, event := range events {
			if event.Validate() != nil || event.Scope() != c.options.Scope || event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previousEvent {
				return ErrInvestigation
			}
			previousEvent = event.Identity()
			if kind == audit.EventInvestigationToolCompleted && event.Kind() == audit.EventInvestigationToolClaimed && event.SubjectIdentity() == operation {
				if claimFound || !slices.Equal(event.CausalParentIdentities(), claimParents) {
					return ErrInvestigation
				}
				claimFound = true
			}
			if event.Kind() != kind {
				continue
			}
			if event.SubjectIdentity() == subject {
				return ErrInvestigation
			}
			if kind == audit.EventInvestigationToolCompleted && slices.Contains(event.CausalParentIdentities(), operation) {
				return ErrInvestigation
			}
		}
		if kind == audit.EventInvestigationToolCompleted && !claimFound {
			return ErrInvestigation
		}
		head, hasHead, err := c.options.Ledger.Head(ctx, c.options.Scope)
		if err != nil {
			return ErrInvestigation
		}
		if hasHead != hadBefore || hasHead && head.Identity() != before.Identity() {
			continue
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence = head.Sequence() + 1
			previous = head.Identity()
		}
		if sequence > 1000 {
			return ErrInvestigation
		}
		event, err := audit.NewEvent(c.options.Scope, sequence, previous, kind, subject, parents, at)
		if err != nil {
			return ErrInvestigation
		}
		err = c.options.Ledger.Append(ctx, previous, event)
		if err == nil {
			return nil
		}
		if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return ErrInvestigation
		}
	}
	return ErrInvestigation
}
