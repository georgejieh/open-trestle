package main

import (
	"context"
	"errors"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// daemonDeliveryRefusals reads the inbox refusal recorded by this daemon's
// webhook planner for the delivery that owns a run scope.
type daemonDeliveryRefusals struct {
	store           webhook.RefusalStore
	source          webhook.Source
	plannerIdentity string
}

func (r daemonDeliveryRefusals) DeliveryRefusal(ctx context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, bool, error) {
	key, webhookRun := strings.CutPrefix(scope.ReviewRunID(), "webhook-")
	if !webhookRun || len(key) != 64 {
		return webhook.RefusalRecord{}, false, nil
	}
	repository, err := webhook.NewRepositoryScope(scope.TenantID(), scope.RepositoryID())
	if err != nil {
		return webhook.RefusalRecord{}, false, nil
	}
	record, found, err := r.store.Refusal(ctx, repository, r.source, key, r.plannerIdentity)
	if errors.Is(err, webhook.ErrInvalidRefusalRecord) {
		return webhook.RefusalRecord{}, false, nil
	}
	return record, found, err
}
