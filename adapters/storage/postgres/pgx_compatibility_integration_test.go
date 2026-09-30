package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPgxSimpleProtocolKeepsPlaceholdersInsideDollarQuotesLiteral(t *testing.T) {
	dataSource := os.Getenv("OPEN_TRESTLE_TEST_POSTGRES_URL")
	if dataSource == "" {
		t.Skip("OPEN_TRESTLE_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := Open(ctx, dataSource, PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	connection, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.Raw(func(driverConnection any) error {
		stdlibConnection, ok := driverConnection.(*stdlib.Conn)
		if !ok {
			return fmt.Errorf("unexpected PostgreSQL driver connection %T", driverConnection)
		}
		tx, err := stdlibConnection.Conn().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		const table = "open_trestle_pgx_compat_canary"
		if _, err := tx.Exec(ctx, "create temporary table "+table+" (id text primary key)"); err != nil {
			return err
		}
		attackValue := "$tag$; drop table " + table + "; --"
		if _, err := tx.Exec(
			ctx,
			`select $tag$ $1 $tag$, $1`,
			pgx.QueryExecModeSimpleProtocol,
			attackValue,
		); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "select * from "+table)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
