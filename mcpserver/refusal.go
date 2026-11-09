package mcpserver

import (
	"context"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// RefusalService is optionally implemented by a Service that can read the
// refusal intake recorded for a webhook delivery whose run was never opened.
type RefusalService interface {
	GetDeliveryRefusal(context.Context, audit.ReviewScope) (webhook.RefusalRecord, error)
}

// refusalText reports a scope-bound recorded refusal: its fixed reason and the
// content-free refusal record. It reports false when none can be read.
func refusalText(ctx context.Context, service RunService, scope audit.ReviewScope) (string, bool) {
	reader, ok := service.(RefusalService)
	if !ok {
		return "", false
	}
	record, err := reader.GetDeliveryRefusal(ctx, scope)
	if err != nil || record.Validate() != nil || record.Scope().TenantID() != scope.TenantID() || record.Scope().RepositoryID() != scope.RepositoryID() || "webhook-"+record.DeduplicationKey() != scope.ReviewRunID() {
		return "", false
	}
	encoded, err := webhook.EncodeRefusalRecord(record)
	if err != nil {
		return "", false
	}
	return webhook.RefusalSummary(record) + "\n\nRefusal record:\n" + string(encoded), true
}
