// Package s3 provides a bounded AWS Signature Version 4 object backend for artifact storage.
package s3

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
)

var (
	// ErrInvalidCredentials identifies malformed S3 signing credentials.
	ErrInvalidCredentials = errors.New("invalid S3 credentials")
	// ErrCredentialsUnavailable identifies failed dynamic credential retrieval.
	ErrCredentialsUnavailable = errors.New("S3 credentials unavailable")
)

// Credentials contains one in-memory S3 signing credential.
type Credentials struct {
	accessKeyID, secretAccessKey, sessionToken string
}

// NewCredentials validates an access key, secret key, and optional session token.
func NewCredentials(accessKeyID, secretAccessKey, sessionToken string) (Credentials, error) {
	validAccess := validCredentialValue(accessKeyID, 8, 128)
	validSecret := validCredentialValue(secretAccessKey, 32, 512)
	validSession := sessionToken == "" || validCredentialValue(sessionToken, 16, 4096)
	if !validAccess || !validSecret || !validSession {
		return Credentials{}, ErrInvalidCredentials
	}
	return Credentials{
		accessKeyID: strings.Clone(accessKeyID), secretAccessKey: strings.Clone(secretAccessKey),
		sessionToken: strings.Clone(sessionToken),
	}, nil
}

func (c Credentials) validate() error {
	_, err := NewCredentials(c.accessKeyID, c.secretAccessKey, c.sessionToken)
	return err
}
func (c Credentials) String() string   { return "S3 credentials" }
func (c Credentials) GoString() string { return "s3.Credentials{<redacted>}" }
func (c Credentials) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "S3 credentials", "s3.Credentials{<redacted>}")
}

// CredentialsProvider retrieves current credentials for each request so rotation needs no restart.
type CredentialsProvider interface {
	Retrieve(context.Context) (Credentials, error)
}

type staticCredentialsProvider struct{ credentials Credentials }

// NewStaticCredentialsProvider holds one validated credential in process memory.
func NewStaticCredentialsProvider(credentials Credentials) (CredentialsProvider, error) {
	if credentials.validate() != nil {
		return nil, ErrInvalidCredentials
	}
	return &staticCredentialsProvider{credentials: credentials}, nil
}
func (p *staticCredentialsProvider) Retrieve(ctx context.Context) (Credentials, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.credentials.validate() != nil {
		return Credentials{}, ErrCredentialsUnavailable
	}
	return p.credentials, nil
}
func (p *staticCredentialsProvider) String() string { return "static S3 credentials provider" }
func (p *staticCredentialsProvider) GoString() string {
	return "s3.staticCredentialsProvider{<redacted>}"
}
func (p *staticCredentialsProvider) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "static S3 credentials provider", "s3.staticCredentialsProvider{<redacted>}")
}

func validCredentialValue(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate == 0x7f {
			return false
		}
	}
	return true
}
func nilProvider(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}
func writeRedacted(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}
