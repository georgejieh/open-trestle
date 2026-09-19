package main

import (
	"encoding/json"
	"flag"
	"fmt"
	awskms "github.com/georgejieh/open-trestle/adapters/keys/awskms"
	"io"
)

func runKMSAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "identity" {
		writeAdminUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle admin kms identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tenant := flags.String("tenant", "", "tenant identifier")
	region := flags.String("region", "", "AWS KMS region")
	keyARN := flags.String("key-arn", "", "exact symmetric KMS key ARN")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *tenant == "" || *region == "" || *keyARN == "" {
		writeAdminUsage(stderr)
		return 2
	}
	identity, err := awskms.ConfigurationIdentity(*region, []awskms.TenantKey{{TenantID: *tenant, KeyARN: *keyARN}})
	if err != nil {
		fmt.Fprintln(stderr, "KMS administration failed")
		return 1
	}
	result := struct {
		Contract             string `json:"contract"`
		SchemaVersion        int    `json:"schema_version"`
		Status               string `json:"status"`
		Operation            string `json:"operation"`
		KMSAuthorityIdentity string `json:"kms_authority_identity"`
	}{"open-trestle/kms-admin-result", 1, "valid", "identity", identity}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
