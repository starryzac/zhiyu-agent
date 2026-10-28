package app

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Database transport failure says nothing about whether the last transaction
// committed. Retry only the durable worker step: its persisted keys, leases and
// permits decide what can run. Never replay a SQL statement or a bank request
// from this loop. Schema, permission and integrity errors remain fatal.
func backgroundDatabaseUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var application *Error
	if errors.As(err, &application) {
		return false
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return len(pg.Code) == 5 && (pg.Code[:2] == "08" || pg.Code == "57P01" || pg.Code == "57P02" || pg.Code == "57P03" || pg.Code == "53300")
	}
	var transport net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &transport) || pgconn.SafeToRetry(err)
}

func backgroundDatabaseBackoff(failures uint) time.Duration {
	if failures == 0 {
		return 250 * time.Millisecond
	}
	return min(250*time.Millisecond<<min(failures-1, 5), 5*time.Second)
}

func retryBackgroundDatabase(ctx context.Context, err error, failures *uint) bool {
	if !backgroundDatabaseUnavailable(err) {
		*failures = 0
		return false
	}
	*failures = min(*failures+1, 6)
	timer := time.NewTimer(backgroundDatabaseBackoff(*failures))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return true
}
