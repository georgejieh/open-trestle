package httpapi

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestStaticTokenAuthenticatorReturnsBoundedPrincipal(t *testing.T) {
	principal, err := NewPrincipal("operator-1", "tenant-a", []string{"repo-b", "repo-a"}, []Capability{CapabilityRunRead, CapabilityRunWrite})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewStaticTokenAuthenticator([]StaticToken{{Token: "01234567890123456789012345678901", Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := authenticator.Authenticate(context.Background(), "01234567890123456789012345678901")
	if err != nil || got.Identity() != "operator-1" || !got.AllowsRepository("repo-a") || got.AllowsRepository("repo-c") || !got.HasCapability(CapabilityRunWrite) {
		t.Fatalf("principal=(%#v,%v)", got, err)
	}
	if got.String() != "API principal" || fmt.Sprintf("%#v", got) != "httpapi.Principal{<redacted>}" {
		t.Fatalf("format leaked principal: %s %#v", got, got)
	}
}
func TestStaticTokenAuthenticatorRejectsUnsafeConfigurationAndCredentials(t *testing.T) {
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead})
	tests := []struct {
		name   string
		tokens []StaticToken
		want   error
	}{{"empty", nil, ErrInvalidAuthenticator}, {"short token", []StaticToken{{Token: "short", Principal: principal}}, ErrInvalidCredential}, {"duplicate token", []StaticToken{{Token: "01234567890123456789012345678901", Principal: principal}, {Token: "01234567890123456789012345678901", Principal: principal}}, ErrDuplicateCredential}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewStaticTokenAuthenticator(test.tokens)
			if !errors.Is(err, test.want) || got != nil {
				t.Fatalf("authenticator=(%#v,%v)", got, err)
			}
		})
	}
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: "01234567890123456789012345678901", Principal: principal}})
	for _, credential := range []string{"", "wrong", "01234567890123456789012345678902"} {
		if got, err := authenticator.Authenticate(context.Background(), credential); !errors.Is(err, ErrAuthenticationFailed) || got.Identity() != "" {
			t.Fatalf("credential accepted: (%#v,%v)", got, err)
		}
	}
}
func TestNewPrincipalRejectsInvalidAndDuplicateAuthority(t *testing.T) {
	tests := []struct {
		name, identity, tenant string
		repositories           []string
		capabilities           []Capability
	}{{"identity", "bad space", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead}}, {"tenant", "operator-1", "", []string{"repo-a"}, []Capability{CapabilityRunRead}}, {"repository", "operator-1", "tenant-a", []string{"repo-a", "repo-a"}, []Capability{CapabilityRunRead}}, {"capability", "operator-1", "tenant-a", []string{"repo-a"}, []Capability{99}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewPrincipal(test.identity, test.tenant, test.repositories, test.capabilities)
			if !errors.Is(err, ErrInvalidPrincipal) || got.Identity() != "" {
				t.Fatalf("principal=(%#v,%v)", got, err)
			}
		})
	}
}

func TestRuntimeReadCapabilityIsIndependent(t *testing.T) {
	principal, err := NewPrincipal("observer", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRuntimeRead})
	if err != nil || !principal.HasCapability(CapabilityRuntimeRead) || principal.HasCapability(CapabilityRunRead) || CapabilityRuntimeRead.String() != "runtime_read" {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
}
