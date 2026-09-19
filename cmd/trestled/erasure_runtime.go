package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const (
	daemonErasureTrustedCAMaxBytes = 262144
	daemonErasureTrustedCAMaxPath  = 4096
)

type daemonDependencies struct {
	openPostgres func(context.Context, string, postgres.PoolOptions) (*sql.DB, error)
	clock        interface{ Now() time.Time }
}

type daemonErasureClock struct {
	inner interface{ Now() time.Time }
}

func (c daemonErasureClock) Now() time.Time {
	return c.inner.Now().UTC().Truncate(time.Millisecond)
}

func daemonNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}

func daemonValidErasureClockSample(instant time.Time) bool {
	_, offset := instant.Zone()
	if offset != 0 || instant.Year() < 1970 || instant.Year() > 9999 || instant.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	return instant.UnixMilli() > 0
}

func validateBudgetedErasureStartupPolicy(policy artifact.ProtectedErasurePolicy, backend *s3.ErasureBackend, expectedDatabaseAuthorityIdentity, prefix string, at time.Time) error {
	if backend == nil || backend.ValidateErasure() != nil || policy.Validate() != nil || !daemonValidErasureClockSample(at) || !policy.AllowsAt(at) {
		return ErrInvalidDaemonConfiguration
	}
	namespace, err := artifact.NewStorageNamespace(backend.ConfigurationIdentity(), prefix, policy.NamespaceEpochIdentity())
	if err != nil || namespace.Validate() != nil || namespace.Identity() != policy.NamespaceIdentity() {
		return ErrInvalidDaemonConfiguration
	}
	if policy.BackendConfigurationIdentity() != backend.ConfigurationIdentity() || policy.DatabaseAuthorityIdentity() != expectedDatabaseAuthorityIdentity || policy.Prefix() != prefix {
		return ErrInvalidDaemonConfiguration
	}
	return nil
}

func loadProtectedErasureTrustedCA(ctx context.Context, path string) ([]byte, error) {
	if daemonNilDependency(ctx) || ctx.Err() != nil || len(path) == 0 || len(path) > daemonErasureTrustedCAMaxPath || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidDaemonConfiguration
	}
	var original os.FileInfo
	var content []byte
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			clear(content)
			return nil, ErrInvalidDaemonConfiguration
		}
		file, err := fileauthority.OpenReadOnly(path)
		if err != nil || file == nil {
			if file != nil {
				_ = file.Close()
			}
			clear(content)
			return nil, ErrInvalidDaemonConfiguration
		}
		before, beforeErr := file.Stat()
		var value []byte
		if beforeErr == nil && before != nil && before.Mode().IsRegular() && fileauthority.TrustedOwner(before) && before.Size() > 0 && before.Size() <= daemonErasureTrustedCAMaxBytes {
			value, err = io.ReadAll(io.LimitReader(daemonContextReader{ctx: ctx, reader: file}, daemonErasureTrustedCAMaxBytes+1))
		} else {
			err = ErrInvalidDaemonConfiguration
		}
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if err != nil || beforeErr != nil || afterErr != nil || closeErr != nil || ctx.Err() != nil || len(value) == 0 || len(value) > daemonErasureTrustedCAMaxBytes || int64(len(value)) != before.Size() || !daemonStableProtectedFile(before, after) {
			clear(value)
			clear(content)
			return nil, ErrInvalidDaemonConfiguration
		}
		if pass == 0 {
			original, content = before, value
		} else if !daemonStableProtectedFile(original, before) || !bytes.Equal(content, value) {
			clear(value)
			clear(content)
			return nil, ErrInvalidDaemonConfiguration
		}
		if pass != 0 {
			clear(value)
		}
	}
	return content, nil
}

type daemonContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r daemonContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := r.reader.Read(buffer)
	if err == nil {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return count, contextErr
		}
	}
	return count, err
}

func daemonStableProtectedFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Mode().IsRegular() && b.Mode().IsRegular() && fileauthority.TrustedOwner(a) && fileauthority.TrustedOwner(b) && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
