package legacycaller

import (
	"context"

	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func forbidden(ctx context.Context, dispatcher gateway.RouteDispatcher, authorization gateway.RouteAttemptAuthorization, request provider.Request) {
	_, _ = gateway.DispatchAuthorizedSanitizedRoute(ctx, dispatcher, authorization, request, "receipt")
	_, _ = modelhandler.NewSanitizedDispatchProof()
	_ = modelhandler.SanitizedDispatchProof{receiptIdentity: "receipt"}
}
