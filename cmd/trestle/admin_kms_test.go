package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunKMSAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"identity", "--tenant", "tenant-a", "--region", "us-east-1", "--key-arn", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-1234567890ab"}
	code := runKMSAdmin(args, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/kms-admin-result"`) || !strings.Contains(stdout.String(), `"kms_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "arn:aws") || strings.Contains(stdout.String(), "tenant-a") {
		t.Fatal("authority inputs leaked")
	}
	stdout.Reset()
	stderr.Reset()
	if code = runKMSAdmin([]string{"identity", "--tenant", "tenant-a"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("invalid=%d", code)
	}
}
