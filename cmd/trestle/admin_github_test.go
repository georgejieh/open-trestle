package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunGitHubPermissionAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"permissions", "identity", "--api-endpoint", "https://api.github.com", "--api-version", "2026-03-10", "--installation-id", "42", "--repository-full-name", "owner/repo"}
	code := runGitHubAdmin(args, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/github-permission-admin-result"`) || !strings.Contains(stdout.String(), `"permission_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "owner/repo") || strings.Contains(stdout.String(), "api.github.com") {
		t.Fatal("configuration leaked")
	}
}

func TestRunGitHubWebhookAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"webhook", "identity", "--tenant", "tenant-a", "--repository", "repository-a", "--key-id", "primary-2026"}
	code := runGitHubAdmin(args, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/github-webhook-admin-result"`) || !strings.Contains(stdout.String(), `"webhook_authority_identity":"`) || !strings.Contains(stdout.String(), `"verifier_configuration_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "tenant-a") || strings.Contains(stdout.String(), "repository-a") || strings.Contains(stdout.String(), "primary-2026") {
		t.Fatal("configuration leaked")
	}
}
func TestRunGitHubWebhookAdminRejectsInvalidKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runGitHubAdmin([]string{"webhook", "identity", "--tenant", "tenant-a", "--repository", "repository-a", "--key-id", " bad "}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "administration failed") || stdout.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
