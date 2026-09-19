package worker_test

import (
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/worker"
)

var _ worker.Control = (*client.Client)(nil)

var _ worker.NotificationControl = (*client.Client)(nil)
