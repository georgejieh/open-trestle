package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPostgresNotificationWaitNormalizesPreCanceledContext(t *testing.T) {
	database, mock := newMockDatabase(t)
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.WaitForTaskNotification(ctx); !errors.Is(err, controlplane.ErrTaskNotificationWaitCanceled) {
		t.Fatalf("pre-canceled wait=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
