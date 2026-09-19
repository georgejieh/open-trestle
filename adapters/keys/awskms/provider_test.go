package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/georgejieh/open-trestle/artifact"
)

const tenantAKey = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-1234567890ab"
const tenantBKey = "arn:aws:kms:us-east-1:123456789012:key/abcdefab-1234-1234-1234-1234567890ab"

type fakeKMSClient struct {
	generateInput  *kms.GenerateDataKeyInput
	decryptInput   *kms.DecryptInput
	generateOutput kms.GenerateDataKeyOutput
	decryptOutput  kms.DecryptOutput
	err            error
}

func (c *fakeKMSClient) GenerateDataKey(_ context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	c.generateInput = input
	return &c.generateOutput, c.err
}
func (c *fakeKMSClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	c.decryptInput = input
	return &c.decryptOutput, c.err
}
func TestProviderGeneratesAndUnwrapsTenantBoundKeys(t *testing.T) {
	keyID := tenantAKey
	plaintext := bytesOf(32, 1)
	wrapped := bytesOf(64, 2)
	client := &fakeKMSClient{generateOutput: kms.GenerateDataKeyOutput{KeyId: &keyID, Plaintext: append([]byte(nil), plaintext...), CiphertextBlob: append([]byte(nil), wrapped...)}, decryptOutput: kms.DecryptOutput{KeyId: &keyID, Plaintext: append([]byte(nil), plaintext...), EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault}}
	provider, err := New(client, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}})
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := provider.GenerateDataKey(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if client.generateInput == nil || *client.generateInput.KeyId != tenantAKey || client.generateInput.KeySpec != types.DataKeySpecAes256 {
		t.Fatalf("input=%#v", client.generateInput)
	}
	for key, value := range client.generateInput.EncryptionContext {
		if strings.Contains(value, "tenant-a") {
			t.Fatalf("context %s exposes tenant name", key)
		}
	}
	unwrapped, err := provider.UnwrapDataKey(context.Background(), "tenant-a", tenantAKey, wrapped)
	if err != nil || unwrapped != keyFromBytes(plaintext) {
		t.Fatalf("unwrap=(%x,%v)", unwrapped, err)
	}
	if client.decryptInput == nil || *client.decryptInput.KeyId != tenantAKey || client.decryptInput.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault {
		t.Fatalf("decrypt=%#v", client.decryptInput)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v", dataKey, dataKey, provider, provider)
	if strings.Contains(formatted, tenantAKey) || strings.Contains(formatted, string(plaintext)) {
		t.Fatal("formatting leaked key material")
	}
}
func TestProviderRejectsCrossTenantKeyAndUnexpectedKMSResponse(t *testing.T) {
	wrong := tenantBKey
	client := &fakeKMSClient{generateOutput: kms.GenerateDataKeyOutput{KeyId: &wrong, Plaintext: bytesOf(32, 1), CiphertextBlob: bytesOf(64, 2)}}
	provider, _ := New(client, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}, {TenantID: "tenant-b", KeyARN: tenantBKey}})
	if _, err := provider.GenerateDataKey(context.Background(), "tenant-a"); !errors.Is(err, ErrKMSResponse) || !errors.Is(err, artifact.ErrInvalidEnvelopeKey) {
		t.Fatalf("response err=%v", err)
	}
	client.decryptInput = nil
	if _, err := provider.UnwrapDataKey(context.Background(), "tenant-b", tenantAKey, bytesOf(64, 2)); !errors.Is(err, ErrTenantKeyNotAllowed) || !errors.Is(err, artifact.ErrInvalidEnvelopeKey) || client.decryptInput != nil {
		t.Fatalf("cross tenant err=%v input=%#v", err, client.decryptInput)
	}
}
func TestRegistryRejectsSharedOrAliasKeys(t *testing.T) {
	client := &fakeKMSClient{}
	tests := [][]TenantKey{
		{{TenantID: "tenant-a", KeyARN: "alias/shared"}},
		{{TenantID: "tenant-a", KeyARN: tenantAKey}, {TenantID: "tenant-b", KeyARN: tenantAKey}},
		{{TenantID: "tenant-a", KeyARN: tenantAKey}, {TenantID: "tenant-a", KeyARN: tenantBKey}},
		{{TenantID: "tenant-a", KeyARN: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-1234567890ab"}},
	}
	for _, entries := range tests {
		if provider, err := New(client, "us-east-1", entries); provider != nil || !errors.Is(err, ErrInvalidKMSProvider) {
			t.Fatalf("entries=%#v provider=%v err=%v", entries, provider, err)
		}
	}
}
func bytesOf(length int, value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), length))
}
func keyFromBytes(value []byte) (key [32]byte) { copy(key[:], value); return key }

func TestProviderConfigurationIdentityBindsCanonicalTenantKeyRegistry(t *testing.T) {
	client := &fakeKMSClient{}
	first, err := New(client, "us-east-1", []TenantKey{{TenantID: "tenant-b", KeyARN: tenantBKey}, {TenantID: "tenant-a", KeyARN: tenantAKey}})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := New(client, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}, {TenantID: "tenant-b", KeyARN: tenantBKey}})
	changed, _ := New(client, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}})
	pure, pureErr := ConfigurationIdentity("us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}, {TenantID: "tenant-b", KeyARN: tenantBKey}})
	if pureErr != nil || pure != first.ConfigurationIdentity() {
		t.Fatalf("pure=%s %v", pure, pureErr)
	}
	if first.ConfigurationIdentity() == "" || first.ConfigurationIdentity() != second.ConfigurationIdentity() || first.ConfigurationIdentity() == changed.ConfigurationIdentity() || first.Validate() != nil {
		t.Fatalf("identities=(%s,%s,%s)", first.ConfigurationIdentity(), second.ConfigurationIdentity(), changed.ConfigurationIdentity())
	}
	if strings.Contains(fmt.Sprintf("%#v", first), tenantAKey) {
		t.Fatal("formatter leaked key")
	}
}

func TestProviderClearsPartialPlaintextOutputsOnClientError(t *testing.T) {
	failure := errors.New("client failed")
	generated := bytesOf(32, 7)
	wrapped := bytesOf(64, 8)
	generateClient := &fakeKMSClient{generateOutput: kms.GenerateDataKeyOutput{Plaintext: generated, CiphertextBlob: wrapped}, err: failure}
	provider, _ := New(generateClient, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}})
	if _, err := provider.GenerateDataKey(context.Background(), "tenant-a"); !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("generate=%v", err)
	}
	if !allBytesZero(generated) || !allBytesZero(wrapped) {
		t.Fatal("generate output retained")
	}
	decrypted := bytesOf(32, 9)
	decryptClient := &fakeKMSClient{decryptOutput: kms.DecryptOutput{Plaintext: decrypted}, err: failure}
	provider, _ = New(decryptClient, "us-east-1", []TenantKey{{TenantID: "tenant-a", KeyARN: tenantAKey}})
	if _, err := provider.UnwrapDataKey(context.Background(), "tenant-a", tenantAKey, bytesOf(64, 2)); !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("decrypt=%v", err)
	}
	if !allBytesZero(decrypted) {
		t.Fatal("decrypt plaintext retained")
	}
}
func allBytesZero(value []byte) bool {
	for _, candidate := range value {
		if candidate != 0 {
			return false
		}
	}
	return true
}
