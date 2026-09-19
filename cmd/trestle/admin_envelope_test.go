package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunEnvelopeAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"identity", "--tenant", "tenant-a", "--s3-endpoint", "https://s3.example.test", "--s3-region", "us-east-1", "--s3-bucket", "artifacts", "--s3-prefix", "reviews", "--kms-region", "us-east-1", "--kms-key-arn", tenantASetupKey}
	code := runEnvelopeAdmin(args, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/envelope-admin-result"`) || !strings.Contains(stdout.String(), `"envelope_storage_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, secret := range []string{"tenant-a", "s3.example.test", "artifacts", tenantASetupKey} {
		if strings.Contains(stdout.String(), secret) {
			t.Fatalf("output leaked %s", secret)
		}
	}
}

func TestEnvelopeAuthorityBindsKMSConnectionAndPrefix(t *testing.T) {
	configuration := setupEnvelopeConfigFixture()
	first, s3Identity, kmsIdentity, err := deriveSetupEnvelopeAuthority(configuration)
	if err != nil || first == "" || s3Identity == "" || kmsIdentity == "" {
		t.Fatalf("identity=%s err=%v", first, err)
	}
	same, _, _, _ := deriveSetupEnvelopeAuthority(configuration)
	configuration.kmsEndpoint = "https://other-kms.example.test"
	changedEndpoint, _, _, err := deriveSetupEnvelopeAuthority(configuration)
	if err != nil || changedEndpoint == first {
		t.Fatalf("endpoint=%s err=%v", changedEndpoint, err)
	}
	configuration = setupEnvelopeConfigFixture()
	configuration.s3Prefix = "other"
	changedPrefix, _, _, err := deriveSetupEnvelopeAuthority(configuration)
	if err != nil || changedPrefix == first || same != first {
		t.Fatalf("prefix=%s same=%s err=%v", changedPrefix, same, err)
	}
}
