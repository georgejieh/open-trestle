package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	awskms "github.com/georgejieh/open-trestle/adapters/keys/awskms"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type setupEnvelopeConfiguration struct{ tenantID, s3Endpoint, s3Region, s3Bucket, s3Prefix, kmsRegion, kmsKeyARN, kmsEndpoint string }

func (c setupEnvelopeConfiguration) String() string { return "setup envelope storage configuration" }
func (c setupEnvelopeConfiguration) GoString() string {
	return "main.setupEnvelopeConfiguration{<redacted>}"
}
func (c setupEnvelopeConfiguration) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, c.String(), c.GoString())
}

func deriveSetupEnvelopeAuthority(value setupEnvelopeConfiguration) (string, string, string, error) {
	s3Identity, err := s3store.ConfigurationIdentity(value.s3Endpoint, value.s3Region, value.s3Bucket)
	if err != nil {
		return "", "", "", err
	}
	kmsIdentity, err := awskms.ConfigurationIdentity(value.kmsRegion, []awskms.TenantKey{{TenantID: value.tenantID, KeyARN: value.kmsKeyARN}})
	if err != nil {
		return "", "", "", err
	}
	kmsEndpoint := ""
	if value.kmsEndpoint != "" {
		parsed, parseErr := provider.ParseServiceEndpoint(value.kmsEndpoint)
		if parseErr != nil {
			return "", "", "", parseErr
		}
		if _, classifyErr := provider.ClassifyServiceEndpoint(value.kmsEndpoint); classifyErr != nil {
			return "", "", "", classifyErr
		}
		kmsEndpoint = parsed.String()
	}
	base, err := artifact.EnvelopeStorageAuthorityIdentity(value.tenantID, s3Identity, kmsIdentity, value.s3Prefix)
	if err != nil {
		return "", "", "", err
	}
	wire := struct {
		Contract                string   `json:"contract"`
		SchemaVersion           int      `json:"schema_version"`
		BaseAuthorityIdentity   string   `json:"base_authority_identity"`
		KMSEndpoint             string   `json:"kms_endpoint"`
		S3CredentialReferences  []string `json:"s3_credential_references"`
		KMSCredentialReferences []string `json:"kms_credential_references"`
		Transport               string   `json:"transport"`
		S3AttemptsPerRequest    int      `json:"s3_attempts_per_request"`
		KMSAttemptsPerOperation int      `json:"kms_attempts_per_operation"`
	}{"open-trestle/setup-envelope-storage-authority", 1, base, kmsEndpoint, []string{"OPEN_TRESTLE_S3_ACCESS_KEY_ID", "OPEN_TRESTLE_S3_SECRET_ACCESS_KEY", "OPEN_TRESTLE_S3_SESSION_TOKEN"}, []string{"OPEN_TRESTLE_AWS_ACCESS_KEY_ID", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY", "OPEN_TRESTLE_AWS_SESSION_TOKEN"}, "direct-no-proxy-tls12-bounded-v1", 1, 3}
	encoded, _ := json.Marshal(wire)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), s3Identity, kmsIdentity, nil
}
func runEnvelopeAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "identity" {
		writeAdminUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle admin envelope identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tenant := flags.String("tenant", "", "tenant identifier")
	s3Endpoint := flags.String("s3-endpoint", "", "exact S3 service endpoint")
	s3Region := flags.String("s3-region", "", "S3 region")
	s3Bucket := flags.String("s3-bucket", "", "S3 bucket")
	s3Prefix := flags.String("s3-prefix", "", "S3 object prefix")
	kmsRegion := flags.String("kms-region", "", "KMS region")
	kmsKeyARN := flags.String("kms-key-arn", "", "exact tenant KMS key ARN")
	kmsEndpoint := flags.String("kms-endpoint", "", "optional KMS service endpoint")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *tenant == "" || *s3Endpoint == "" || *s3Region == "" || *s3Bucket == "" || *s3Prefix == "" || *kmsRegion == "" || *kmsKeyARN == "" {
		writeAdminUsage(stderr)
		return 2
	}
	authority, s3Identity, kmsIdentity, err := deriveSetupEnvelopeAuthority(setupEnvelopeConfiguration{tenantID: *tenant, s3Endpoint: *s3Endpoint, s3Region: *s3Region, s3Bucket: *s3Bucket, s3Prefix: *s3Prefix, kmsRegion: *kmsRegion, kmsKeyARN: *kmsKeyARN, kmsEndpoint: *kmsEndpoint})
	if err != nil {
		fmt.Fprintln(stderr, "envelope storage administration failed")
		return 1
	}
	result := struct {
		Contract          string `json:"contract"`
		SchemaVersion     int    `json:"schema_version"`
		Status            string `json:"status"`
		Operation         string `json:"operation"`
		EnvelopeAuthority string `json:"envelope_storage_authority_identity"`
		S3Authority       string `json:"s3_authority_identity"`
		KMSAuthority      string `json:"kms_authority_identity"`
	}{"open-trestle/envelope-admin-result", 1, "valid", "identity", authority, s3Identity, kmsIdentity}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
