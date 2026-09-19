// Package awskms provides tenant-isolated AWS KMS envelope data keys.
package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxTenantKeys    = 1024
	maxKMSCiphertext = 16 << 10
	tenantContextKey = "open_trestle_tenant_binding"
)

var (
	// ErrInvalidKMSProvider identifies a missing client or malformed tenant-key registry.
	ErrInvalidKMSProvider = errors.New("invalid AWS KMS envelope key provider")
	// ErrTenantKeyNotAllowed identifies a tenant or key outside the immutable registry.
	ErrTenantKeyNotAllowed = errors.New("AWS KMS key not allowed for tenant")
	// ErrKMSUnavailable identifies a failed KMS operation without exposing provider details.
	ErrKMSUnavailable = errors.New("AWS KMS envelope key unavailable")
	// ErrKMSResponse identifies incomplete, cross-wired, or unsafe KMS output.
	ErrKMSResponse = errors.New("invalid AWS KMS response")
)

// Client is the exact AWS KMS API surface required by the provider.
type Client interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// TenantKey assigns one exact symmetric KMS key ARN to one tenant.
type TenantKey struct {
	TenantID string
	KeyARN   string
}

// Provider generates and unwraps keys through an immutable one-key-per-tenant registry.
type Provider struct {
	client                Client
	region                string
	keys                  map[string]string
	configurationIdentity string
}

// New validates an exact key ARN registry. One KMS key cannot be shared across tenants.
func New(client Client, region string, entries []TenantKey) (*Provider, error) {
	if nilClient(client) {
		return nil, ErrInvalidKMSProvider
	}
	keys, identity, err := validatedKMSRegistry(region, entries)
	if err != nil {
		return nil, err
	}
	return &Provider{client: client, region: strings.Clone(region), keys: keys, configurationIdentity: identity}, nil
}

// ConfigurationIdentity derives the canonical non-secret identity without constructing a KMS client.
func ConfigurationIdentity(region string, entries []TenantKey) (string, error) {
	_, identity, err := validatedKMSRegistry(region, entries)
	return identity, err
}
func validatedKMSRegistry(region string, entries []TenantKey) (map[string]string, string, error) {
	if !validRegion(region) || len(entries) == 0 || len(entries) > maxTenantKeys {
		return nil, "", ErrInvalidKMSProvider
	}
	keys := make(map[string]string, len(entries))
	owners := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !validTenant(entry.TenantID) || !validKeyARN(entry.KeyARN) || keyARNRegion(entry.KeyARN) != region || keys[entry.TenantID] != "" || owners[entry.KeyARN] {
			return nil, "", ErrInvalidKMSProvider
		}
		keys[strings.Clone(entry.TenantID)] = strings.Clone(entry.KeyARN)
		owners[entry.KeyARN] = true
	}
	return keys, deriveKMSConfigurationIdentity(region, keys), nil
}

// ConfigurationIdentity returns the canonical non-secret tenant-key registry identity.
func (p *Provider) ConfigurationIdentity() string {
	if p == nil {
		return ""
	}
	return p.configurationIdentity
}

// Validate verifies the immutable region, client, tenant-key registry, and configuration identity.
func (p *Provider) Validate() error {
	if p == nil || nilClient(p.client) || !validRegion(p.region) || len(p.keys) == 0 || len(p.keys) > maxTenantKeys {
		return ErrInvalidKMSProvider
	}
	owners := map[string]bool{}
	for tenant, key := range p.keys {
		if !validTenant(tenant) || !validKeyARN(key) || keyARNRegion(key) != p.region || owners[key] {
			return ErrInvalidKMSProvider
		}
		owners[key] = true
	}
	if p.configurationIdentity != deriveKMSConfigurationIdentity(p.region, p.keys) {
		return ErrInvalidKMSProvider
	}
	return nil
}
func deriveKMSConfigurationIdentity(region string, keys map[string]string) string {
	type entry struct {
		TenantID string `json:"tenant_id"`
		KeyARN   string `json:"key_arn"`
	}
	values := make([]entry, 0, len(keys))
	for tenant, key := range keys {
		values = append(values, entry{tenant, key})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].TenantID < values[j].TenantID })
	encoded, _ := json.Marshal(struct {
		Contract string  `json:"contract"`
		Version  int     `json:"version"`
		Region   string  `json:"region"`
		Keys     []entry `json:"keys"`
	}{"open-trestle/aws-kms-key-registry", 1, region, values})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// GenerateDataKey requests an AES-256 data key with a non-secret tenant binding.
func (p *Provider) GenerateDataKey(ctx context.Context, tenantID string) (artifact.EnvelopeDataKey, error) {
	keyARN, err := p.keyFor(ctx, tenantID)
	if err != nil {
		return artifact.EnvelopeDataKey{}, err
	}
	output, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: &keyARN, KeySpec: types.DataKeySpecAes256, EncryptionContext: tenantEncryptionContext(tenantID)})
	defer clearKMSOutput(output)
	if err != nil {
		return artifact.EnvelopeDataKey{}, ErrKMSUnavailable
	}
	if output == nil || output.KeyId == nil || *output.KeyId != keyARN || len(output.Plaintext) != 32 || len(output.CiphertextBlob) == 0 || len(output.CiphertextBlob) > maxKMSCiphertext {
		return artifact.EnvelopeDataKey{}, invalidKMSResponse()
	}
	var plaintext [32]byte
	copy(plaintext[:], output.Plaintext)
	clear(output.Plaintext)
	dataKey, err := artifact.NewEnvelopeDataKey(plaintext, keyARN, output.CiphertextBlob)
	clear(plaintext[:])
	if err != nil {
		return artifact.EnvelopeDataKey{}, invalidKMSResponse()
	}
	return dataKey, nil
}

// UnwrapDataKey decrypts only the exact key ARN assigned to the supplied tenant.
func (p *Provider) UnwrapDataKey(ctx context.Context, tenantID, keyReference string, wrapped []byte) ([32]byte, error) {
	keyARN, err := p.keyFor(ctx, tenantID)
	if err != nil {
		return [32]byte{}, err
	}
	if keyReference != keyARN || len(wrapped) == 0 || len(wrapped) > maxKMSCiphertext {
		return [32]byte{}, invalidTenantKey()
	}
	ciphertext := append([]byte(nil), wrapped...)
	defer clear(ciphertext)
	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{KeyId: &keyARN, CiphertextBlob: ciphertext, EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault, EncryptionContext: tenantEncryptionContext(tenantID)})
	defer clearKMSDecryptOutput(output)
	if err != nil {
		return [32]byte{}, ErrKMSUnavailable
	}
	if output == nil || output.KeyId == nil || *output.KeyId != keyARN || output.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault || len(output.Plaintext) != 32 {
		return [32]byte{}, invalidKMSResponse()
	}
	var plaintext [32]byte
	copy(plaintext[:], output.Plaintext)
	clear(output.Plaintext)
	allZero := true
	for _, value := range plaintext {
		allZero = allZero && value == 0
	}
	if allZero {
		clear(plaintext[:])
		return [32]byte{}, invalidKMSResponse()
	}
	return plaintext, nil
}

func (p *Provider) keyFor(ctx context.Context, tenantID string) (string, error) {
	if ctx == nil || ctx.Err() != nil || !validTenant(tenantID) || p.Validate() != nil {
		return "", ErrKMSUnavailable
	}
	keyARN, found := p.keys[tenantID]
	if !found {
		return "", invalidTenantKey()
	}
	return keyARN, nil
}
func tenantEncryptionContext(tenantID string) map[string]string {
	digest := sha256.Sum256([]byte("open-trestle/aws-kms-tenant/v1:" + tenantID))
	return map[string]string{tenantContextKey: hex.EncodeToString(digest[:])}
}
func invalidKMSResponse() error { return errors.Join(ErrKMSResponse, artifact.ErrInvalidEnvelopeKey) }
func invalidTenantKey() error {
	return errors.Join(ErrTenantKeyNotAllowed, artifact.ErrInvalidEnvelopeKey)
}
func validTenant(value string) bool {
	_, err := audit.NewReviewScope(value, "kms-key-scope", "kms-key-run")
	return err == nil
}
func validKeyARN(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || !validPartition(parts[1]) || !validRegion(parts[3]) || !validAccount(parts[4]) || !strings.HasPrefix(parts[5], "key/") {
		return false
	}
	keyID := strings.TrimPrefix(parts[5], "key/")
	if strings.HasPrefix(keyID, "mrk-") {
		return len(keyID) == 36 && validLowerHex(keyID[4:])
	}
	return validUUID(keyID)
}
func keyARNRegion(value string) string {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	return parts[3]
}

func validPartition(value string) bool {
	return value == "aws" || value == "aws-us-gov" || value == "aws-cn"
}
func validRegion(value string) bool {
	if len(value) < 5 || len(value) > 32 {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '-') {
			return false
		}
	}
	return true
}
func validAccount(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, candidate := range value {
		if candidate < '0' || candidate > '9' {
			return false
		}
	}
	return true
}
func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	return validLowerHex(strings.ReplaceAll(value, "-", ""))
}
func validLowerHex(value string) bool {
	if len(value) == 0 {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= '0' && candidate <= '9' || candidate >= 'a' && candidate <= 'f') {
			return false
		}
	}
	return true
}
func nilClient(client Client) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func clearKMSOutput(output *kms.GenerateDataKeyOutput) {
	if output != nil {
		clear(output.Plaintext)
		clear(output.CiphertextBlob)
	}
}
func clearKMSDecryptOutput(output *kms.DecryptOutput) {
	if output != nil {
		clear(output.Plaintext)
	}
}
func (p *Provider) String() string   { return "AWS KMS envelope key provider" }
func (p *Provider) GoString() string { return "awskms.Provider{<redacted>}" }
func (p *Provider) Format(state fmt.State, verb rune) {
	value := "AWS KMS envelope key provider"
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = "awskms.Provider{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}

var _ artifact.EnvelopeKeyProvider = (*Provider)(nil)
