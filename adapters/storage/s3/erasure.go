package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
)

// ErasureConfig accepts inert explicit trust and immutable static credentials.
type ErasureConfig struct {
	Endpoint, Region, Bucket string
	Credentials              Credentials
	TrustedCAPEM             []byte
}

// ErasureBackend owns its transport, roots and signer. It grants no erasure
// authority and keeps no operation budget, scan history or completion state.
type ErasureBackend struct {
	base  *Backend
	roots *x509.CertPool
}

func NewErasureBackend(config ErasureConfig) (*ErasureBackend, error) {
	endpoint, identity, err := validatedS3Configuration(config.Endpoint, config.Region, config.Bucket)
	if err != nil || endpoint.Scheme != "https" || config.Credentials.validate() != nil {
		return nil, ErrInvalidConfig
	}
	roots, err := parseErasureRoots(config.TrustedCAPEM)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	credentials, err := NewCredentials(config.Credentials.accessKeyID, config.Credentials.secretAccessKey, config.Credentials.sessionToken)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	base := &Backend{
		endpoint: endpoint, region: strings.Clone(config.Region), bucket: strings.Clone(config.Bucket),
		credentials: &staticCredentialsProvider{credentials: credentials}, clock: systemClock{}, configurationIdentity: identity,
		httpClient: &http.Client{Timeout: defaultRequestTimeout, Jar: nil,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrS3Request },
			Transport:     &ownedOneShotRoundTripper{roots: roots, hostname: endpoint.Hostname()},
		},
	}
	return &ErasureBackend{base: base, roots: roots}, nil
}
func parseErasureRoots(raw []byte) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > 262144 {
		return nil, ErrInvalidConfig
	}
	rest := bytes.Clone(raw)
	roots := x509.NewCertPool()
	count := 0
	for {
		rest = bytes.Trim(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if count == 64 || !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalidConfig
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, ErrInvalidConfig
		}
		end += len("-----END CERTIFICATE-----")
		if end < len(rest) {
			newline := bytes.IndexByte(rest[end:], '\n')
			if newline < 0 {
				if len(bytes.Trim(rest[end:], " \t\r")) != 0 {
					return nil, ErrInvalidConfig
				}
				end = len(rest)
			} else {
				if len(bytes.Trim(rest[end:end+newline], " \t\r")) != 0 {
					return nil, ErrInvalidConfig
				}
				end += newline + 1
			}
		}
		// Decode only the first block, so pem.Decode cannot skip a malformed
		// earlier block and silently accept a later certificate.
		chunk := rest[:end]
		if bytes.Count(chunk, []byte("-----BEGIN")) != 1 {
			return nil, ErrInvalidConfig
		}
		block, tail := pem.Decode(chunk)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(tail) != 0 {
			return nil, ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(bytes.Clone(block.Bytes))
		if err != nil {
			return nil, ErrInvalidConfig
		}
		roots.AddCert(certificate)
		count++
		rest = rest[end:]
	}
	if count == 0 {
		return nil, ErrInvalidConfig
	}
	return roots, nil
}
func (b *ErasureBackend) ValidateErasure() error {
	if b == nil || b.base == nil || b.roots == nil || b.base.Validate() != nil || b.base.endpoint.Scheme != "https" {
		return ErrInvalidConfig
	}
	provider, ok := b.base.credentials.(*staticCredentialsProvider)
	if !ok || provider == nil || provider.credentials.validate() != nil {
		return ErrInvalidConfig
	}
	adapter, ok := b.base.httpClient.Transport.(*ownedOneShotRoundTripper)
	if !ok || adapter == nil || adapter.roots != b.roots || adapter.hostname != b.base.endpoint.Hostname() || b.base.httpClient.Jar != nil || b.base.httpClient.CheckRedirect == nil {
		return ErrInvalidConfig
	}
	if _, ok := b.base.clock.(systemClock); !ok {
		return ErrInvalidConfig
	}
	return nil
}
func (b *ErasureBackend) Validate() error { return b.ValidateErasure() }
func (b *ErasureBackend) ConfigurationIdentity() string {
	if b == nil || b.base == nil {
		return ""
	}
	return b.base.ConfigurationIdentity()
}
func (b *ErasureBackend) Create(ctx context.Context, key string, content []byte, digest string) (bool, error) {
	if b.ValidateErasure() != nil {
		return false, ErrInvalidConfig
	}
	if !validErasureContext(ctx) || len(content) > maximumObjectBytes {
		return false, ErrInvalidRequest
	}
	return b.base.Create(ctx, key, bytes.Clone(content), digest)
}
func (b *ErasureBackend) Read(ctx context.Context, key string, maximum int) (artifact.RemoteObject, error) {
	if b.ValidateErasure() != nil {
		return artifact.RemoteObject{}, ErrInvalidConfig
	}
	if !validErasureContext(ctx) {
		return artifact.RemoteObject{}, ErrInvalidRequest
	}
	return b.base.Read(ctx, key, maximum)
}
func (b *ErasureBackend) Delete(context.Context, string, string) (bool, error) {
	return false, artifact.ErrErasureBackendUnsupported
}
func (b *ErasureBackend) String() string             { return "S3 erasure backend" }
func (b *ErasureBackend) GoString() string           { return "s3.ErasureBackend{<redacted>}" }
func (b *ErasureBackend) Format(s fmt.State, v rune) { writeRedacted(s, v, b.String(), b.GoString()) }

func validErasureOwner(owner string) bool {
	if len(owner) != 12 || owner == "000000000000" {
		return false
	}
	for _, c := range owner {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validErasureVersionID(id string) bool {
	if len(id) < 1 || len(id) > 504 || !utf8.ValidString(id) || id == "null" {
		return false
	}
	for _, c := range id {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (b *ErasureBackend) erasurePreflight(ctx context.Context, key artifact.ExactObjectKey, owner string) error {
	if b.ValidateErasure() != nil {
		return ErrInvalidConfig
	}
	if !validErasureContext(ctx) || key.Validate() != nil || !validObjectKey(key.Key()) || !validErasureOwner(owner) {
		return ErrInvalidRequest
	}
	return nil
}
func (b *ErasureBackend) newErasureObjectRequest(ctx context.Context, method string, key artifact.ExactObjectKey, owner string, query url.Values, headers http.Header, body []byte, digest string) (*http.Request, error) {
	ownedHeaders := headers.Clone()
	if ownedHeaders == nil {
		ownedHeaders = make(http.Header)
	}
	ownedHeaders.Set("X-Amz-Expected-Bucket-Owner", owner)
	request, err := b.base.newRequest(ctx, method, key.Key(), query, ownedHeaders, bytes.Clone(body), digest)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	request.GetBody = nil
	request.Close = true
	request.ContentLength = int64(len(body))
	return request, nil
}

// readErasureResponse closes even nominal denial and conflict responses. A
// body failure has priority over any nominal status. The cap is body bytes,
// not framing, header, TLS, read-ahead, or physical wire bytes.
func readErasureResponse(response *http.Response, maximum uint32) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, ErrS3Request
	}
	// A switching-protocol body is duplex and has no supported finite EOF.
	if response.StatusCode == http.StatusSwitchingProtocols {
		if err := response.Body.Close(); err != nil {
			return nil, ErrS3Request
		}
		return nil, artifact.ErrRemoteObjectIntegrity
	}
	cap := maximum
	if response.StatusCode != http.StatusOK {
		cap = maximumErrorBodyBytes
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, int64(cap)+1))
	closeErr := response.Body.Close()
	if len(content) > int(cap) {
		clear(content)
		return nil, artifact.ErrRemoteObjectTooLarge
	}
	if readErr != nil || closeErr != nil {
		clear(content)
		return nil, ErrS3Request
	}
	if response.ContentLength > int64(cap) {
		clear(content)
		return nil, artifact.ErrRemoteObjectTooLarge
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode == http.StatusPartialContent ||
		len(erasureHeaderValues(response.Header, "Content-Range")) != 0 || len(erasureHeaderValues(response.Header, "Upgrade")) != 0 ||
		len(erasureHeaderValues(response.Header, "Trailer")) != 0 || len(response.Trailer) != 0 || response.Uncompressed {
		clear(content)
		return nil, artifact.ErrRemoteObjectIntegrity
	}
	encoding := erasureHeaderValues(response.Header, "Content-Encoding")
	if len(encoding) > 1 || len(encoding) == 1 && encoding[0] != "identity" {
		clear(content)
		return nil, artifact.ErrRemoteObjectIntegrity
	}
	return content, nil
}
func erasureHeaderValues(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}
func erasureStatusError(status int) error {
	switch status {
	case 403:
		return artifact.ErrErasureBlocked
	case 405, 409, 412:
		return artifact.ErrRemoteObjectConflict
	default:
		return ErrS3Request
	}
}
func erasureWholeChecksum(header http.Header, content []byte) error {
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-checksum-") && lower != "x-amz-checksum-sha256" && lower != "x-amz-checksum-type" {
			return artifact.ErrRemoteObjectIntegrity
		}
	}
	hashes := erasureHeaderValues(header, "X-Amz-Checksum-Sha256")
	types := erasureHeaderValues(header, "X-Amz-Checksum-Type")
	if len(hashes) == 0 && len(types) == 0 {
		return nil
	}
	if len(hashes) != 1 || len(types) != 1 || types[0] != "FULL_OBJECT" {
		return artifact.ErrRemoteObjectIntegrity
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(hashes[0])
	sum := sha256.Sum256(content)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != hashes[0] || !bytes.Equal(decoded, sum[:]) {
		return artifact.ErrRemoteObjectIntegrity
	}
	return nil
}

func (b *ErasureBackend) ReadErasureObject(ctx context.Context, key artifact.ExactObjectKey, owner string, maximum uint32) (artifact.ErasureObjectRead, error) {
	if err := b.erasurePreflight(ctx, key, owner); err != nil {
		return artifact.ErasureObjectRead{}, err
	}
	if maximum < 4096 || maximum > maximumObjectBytes {
		return artifact.ErasureObjectRead{}, ErrInvalidRequest
	}
	request, err := b.newErasureObjectRequest(ctx, http.MethodGet, key, owner, nil, http.Header{"X-Amz-Checksum-Mode": {"ENABLED"}}, nil, digestHex(nil))
	if err != nil {
		return artifact.ErasureObjectRead{}, err
	}
	response, content, err := b.erasureExchange(request, maximum)
	if err != nil {
		return artifact.ErasureObjectRead{}, err
	}
	versions := erasureHeaderValues(response.Header, "X-Amz-Version-Id")
	markers := erasureHeaderValues(response.Header, "X-Amz-Delete-Marker")
	if response.StatusCode == 200 {
		if len(content) == 0 || len(markers) != 0 || len(versions) != 1 || !validErasureVersionID(versions[0]) {
			clear(content)
			return artifact.ErasureObjectRead{}, artifact.ErrRemoteObjectIntegrity
		}
		if err := erasureWholeChecksum(response.Header, content); err != nil {
			clear(content)
			return artifact.ErasureObjectRead{}, err
		}
		return artifact.ErasureObjectRead{Kind: artifact.ErasureReadPresent, Object: artifact.RemoteObject{Content: content, Version: "version:" + versions[0], Digest: digestHex(content)}}, nil
	}
	defer clear(content)
	if response.StatusCode != 404 {
		return artifact.ErasureObjectRead{}, erasureStatusError(response.StatusCode)
	}
	if len(markers) == 0 {
		if len(versions) != 0 {
			return artifact.ErasureObjectRead{}, artifact.ErrRemoteObjectIntegrity
		}
		if !validErasureErrorXML(content, "NoSuchKey", b.base.bucket, key.Key(), "") {
			return artifact.ErasureObjectRead{}, ErrS3Request
		}
		return artifact.ErasureObjectRead{Kind: artifact.ErasureReadAbsent}, nil
	}
	if len(markers) != 1 || markers[0] != "true" || len(versions) != 1 || !validErasureVersionID(versions[0]) {
		return artifact.ErasureObjectRead{}, artifact.ErrRemoteObjectIntegrity
	}
	if len(content) != 0 && !validErasureErrorXML(content, "NoSuchKey", b.base.bucket, key.Key(), "") {
		return artifact.ErasureObjectRead{}, ErrS3Request
	}
	marker, err := artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), artifact.ObjectVersionDeleteMarker, versions[0])
	if err != nil {
		return artifact.ErasureObjectRead{}, artifact.ErrRemoteObjectIntegrity
	}
	return artifact.ErasureObjectRead{Kind: artifact.ErasureReadCurrentDeleteMarker, Marker: marker}, nil
}
func (b *ErasureBackend) CreateErasureObject(ctx context.Context, key artifact.ExactObjectKey, owner string, content []byte, digest string) (bool, error) {
	if err := b.erasurePreflight(ctx, key, owner); err != nil {
		return false, err
	}
	if len(content) == 0 || len(content) > 16384 || !validDigest(digest) {
		return false, ErrInvalidRequest
	}
	content = bytes.Clone(content)
	if digestHex(content) != digest {
		clear(content)
		return false, ErrInvalidRequest
	}
	defer clear(content)
	checksum, _ := hex.DecodeString(digest)
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "If-None-Match": {"*"}, "X-Amz-Checksum-Sha256": {base64.StdEncoding.EncodeToString(checksum)}}
	request, err := b.newErasureObjectRequest(ctx, http.MethodPut, key, owner, nil, headers, content, digest)
	if err != nil {
		return false, err
	}
	response, body, err := b.erasureExchange(request, 4096)
	if err != nil {
		return false, err
	}
	defer clear(body)
	switch response.StatusCode {
	case 200, 201:
		return true, nil
	case 412:
		return false, nil
	default:
		return false, erasureStatusError(response.StatusCode)
	}
}
func (b *ErasureBackend) DeleteObjectVersion(ctx context.Context, key artifact.ExactObjectKey, owner string, version artifact.ObjectVersion) (artifact.VersionDeleteOutcome, error) {
	if err := b.erasurePreflight(ctx, key, owner); err != nil {
		return 0, err
	}
	if version.Validate() != nil || version.NamespaceIdentity() != key.NamespaceIdentity() || version.Key() != key.Key() {
		return 0, ErrInvalidRequest
	}
	request, err := b.newErasureObjectRequest(ctx, http.MethodDelete, key, owner, url.Values{"versionId": {version.VersionID()}}, nil, nil, digestHex(nil))
	if err != nil {
		return 0, err
	}
	response, content, err := b.erasureExchange(request, 4096)
	if err != nil {
		return 0, err
	}
	defer clear(content)
	switch response.StatusCode {
	case 200, 204:
		return artifact.VersionDeleteDeleted, nil
	case 404:
		if !validErasureErrorXML(content, "NoSuchVersion", b.base.bucket, key.Key(), version.VersionID()) {
			return 0, ErrS3Request
		}
		return artifact.VersionDeleteNotFound, nil
	default:
		return 0, erasureStatusError(response.StatusCode)
	}
}

var _ artifact.ErasureObjectBackend = (*ErasureBackend)(nil)
