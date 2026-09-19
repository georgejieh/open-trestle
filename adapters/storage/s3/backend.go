package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
	providerconfig "github.com/georgejieh/open-trestle/internal/provider"
)

const (
	defaultRequestTimeout = 30 * time.Second
	maximumRequestTimeout = 2 * time.Minute
	maximumObjectBytes    = 32 << 20
	maximumObjectKeyBytes = 1024
	maximumErrorBodyBytes = 4096
)

var (
	// ErrInvalidConfig identifies an unsafe endpoint, bucket, region, client, or provider.
	ErrInvalidConfig = errors.New("invalid S3 backend configuration")
	// ErrInvalidRequest identifies a malformed object key, digest, version, or size bound.
	ErrInvalidRequest = errors.New("invalid S3 backend request")
	// ErrS3Request identifies a failed or unexpected S3 HTTP exchange.
	ErrS3Request = errors.New("S3 backend request failed")
)

// Clock supplies signing time.
type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Config selects one path-style S3-compatible bucket.
type Config struct {
	Endpoint    string
	Region      string
	Bucket      string
	Credentials CredentialsProvider
	HTTPClient  *http.Client
	Clock       Clock
}

// Backend implements artifact.RemoteObjectBackend with SigV4 and version-specific deletion.
type Backend struct {
	endpoint              *url.URL
	region                string
	bucket                string
	credentials           CredentialsProvider
	httpClient            *http.Client
	clock                 Clock
	configurationIdentity string
}

// New validates and copies S3 backend configuration without making a request.
func New(config Config) (*Backend, error) {
	endpoint, identity, err := validatedS3Configuration(config.Endpoint, config.Region, config.Bucket)
	if err != nil || nilProvider(config.Credentials) {
		return nil, ErrInvalidConfig
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultRequestTimeout}
	}
	clone := *client
	if clone.Timeout == 0 {
		clone.Timeout = defaultRequestTimeout
	}
	if clone.Timeout < 0 || clone.Timeout > maximumRequestTimeout {
		return nil, ErrInvalidConfig
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrS3Request }
	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	if nilProvider(clock) {
		return nil, ErrInvalidConfig
	}
	return &Backend{endpoint: endpoint, region: strings.Clone(config.Region), bucket: strings.Clone(config.Bucket), credentials: config.Credentials, httpClient: &clone, clock: clock, configurationIdentity: identity}, nil
}

// ConfigurationIdentity derives the effective non-secret S3 endpoint, region, and bucket identity.
func ConfigurationIdentity(endpoint, region, bucket string) (string, error) {
	_, identity, err := validatedS3Configuration(endpoint, region, bucket)
	return identity, err
}

// ConfigurationIdentity returns this backend's immutable non-secret authority identity.
func (b *Backend) ConfigurationIdentity() string {
	if b == nil {
		return ""
	}
	return b.configurationIdentity
}

// Validate verifies the immutable logical authority and bounded runtime dependencies.
func (b *Backend) Validate() error {
	if b == nil || b.endpoint == nil || nilProvider(b.credentials) || b.httpClient == nil || nilProvider(b.clock) {
		return ErrInvalidConfig
	}
	_, identity, err := validatedS3Configuration(b.endpoint.String(), b.region, b.bucket)
	if err != nil || identity != b.configurationIdentity || b.httpClient.Timeout <= 0 || b.httpClient.Timeout > maximumRequestTimeout {
		return ErrInvalidConfig
	}
	return nil
}
func validatedS3Configuration(raw, region, bucket string) (*url.URL, string, error) {
	endpoint, err := providerconfig.ParseServiceEndpoint(raw)
	if err != nil {
		return nil, "", ErrInvalidConfig
	}
	if _, err = providerconfig.ClassifyServiceEndpoint(raw); err != nil || !validEndpoint(endpoint) || !validRegion(region) || !validBucket(bucket) {
		return nil, "", ErrInvalidConfig
	}
	effective := *endpoint
	effective.Path, effective.RawPath = "", ""
	type authority struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Endpoint string `json:"endpoint"`
		Region   string `json:"region"`
		Bucket   string `json:"bucket"`
	}
	encoded, _ := json.Marshal(authority{"open-trestle/s3-authority", 1, effective.String(), region, bucket})
	sum := sha256.Sum256(encoded)
	return &effective, hex.EncodeToString(sum[:]), nil
}

// Create atomically writes one bounded object only when the key is absent.
func (b *Backend) Create(ctx context.Context, key string, content []byte, digest string) (bool, error) {
	validContent := len(content) > 0 && len(content) <= maximumObjectBytes
	if b == nil || ctx == nil || ctx.Err() != nil || !validObjectKey(key) || !validContent || !validDigest(digest) || digestHex(content) != digest {
		return false, ErrInvalidRequest
	}
	checksum, _ := hex.DecodeString(digest)
	headers := http.Header{
		"Content-Type":          []string{"application/octet-stream"},
		"If-None-Match":         []string{"*"},
		"X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(checksum)},
	}
	request, err := b.newRequest(ctx, http.MethodPut, key, nil, headers, content, digest)
	if err != nil {
		return false, err
	}
	response, err := b.httpClient.Do(request)
	if err != nil {
		return false, ErrS3Request
	}
	drainAndClose(response.Body)
	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return true, nil
	case http.StatusPreconditionFailed:
		return false, nil
	case http.StatusConflict:
		return false, artifact.ErrRemoteObjectConflict
	default:
		return false, ErrS3Request
	}
}

// Read returns one object only when a non-null S3 version identity is present.
func (b *Backend) Read(ctx context.Context, key string, maximum int) (artifact.RemoteObject, error) {
	if b == nil || ctx == nil || ctx.Err() != nil || !validObjectKey(key) || maximum <= 0 || maximum > maximumObjectBytes {
		return artifact.RemoteObject{}, ErrInvalidRequest
	}
	request, err := b.newRequest(ctx, http.MethodGet, key, nil, nil, nil, digestHex(nil))
	if err != nil {
		return artifact.RemoteObject{}, err
	}
	response, err := b.httpClient.Do(request)
	if err != nil {
		return artifact.RemoteObject{}, ErrS3Request
	}
	if response.StatusCode == http.StatusNotFound {
		code, parseErr := readS3ErrorCode(response)
		if parseErr != nil || code != "NoSuchKey" {
			return artifact.RemoteObject{}, ErrS3Request
		}
		return artifact.RemoteObject{}, artifact.ErrRemoteObjectNotFound
	}
	if response.StatusCode != http.StatusOK {
		drainAndClose(response.Body)
		return artifact.RemoteObject{}, ErrS3Request
	}
	if response.ContentLength > int64(maximum) {
		drainAndClose(response.Body)
		return artifact.RemoteObject{}, artifact.ErrRemoteObjectTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		clear(content)
		return artifact.RemoteObject{}, ErrS3Request
	}
	if len(content) == 0 {
		return artifact.RemoteObject{}, artifact.ErrRemoteObjectIntegrity
	}
	if len(content) > maximum {
		clear(content)
		return artifact.RemoteObject{}, artifact.ErrRemoteObjectTooLarge
	}
	version := response.Header.Get("x-amz-version-id")
	if !validVersion(version) || version == "null" {
		clear(content)
		return artifact.RemoteObject{}, artifact.ErrRemoteObjectConflict
	}
	digest := digestHex(content)
	if checksum := response.Header.Get("x-amz-checksum-sha256"); checksum != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(checksum)
		want, _ := hex.DecodeString(digest)
		if decodeErr != nil || !hmac.Equal(decoded, want) {
			clear(content)
			return artifact.RemoteObject{}, artifact.ErrRemoteObjectIntegrity
		}
	}
	return artifact.RemoteObject{Content: content, Version: "version:" + version, Digest: digest}, nil
}

// Delete removes only an exact version returned by Read.
func (b *Backend) Delete(ctx context.Context, key, version string) (bool, error) {
	if b == nil || ctx == nil || ctx.Err() != nil || !validObjectKey(key) || !strings.HasPrefix(version, "version:") {
		return false, ErrInvalidRequest
	}
	versionID := strings.TrimPrefix(version, "version:")
	if !validVersion(versionID) || versionID == "null" {
		return false, ErrInvalidRequest
	}
	query := url.Values{"versionId": []string{versionID}}
	request, err := b.newRequest(ctx, http.MethodDelete, key, query, nil, nil, digestHex(nil))
	if err != nil {
		return false, err
	}
	response, err := b.httpClient.Do(request)
	if err != nil {
		return false, ErrS3Request
	}
	drainAndClose(response.Body)
	switch response.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusConflict, http.StatusPreconditionFailed:
		return false, artifact.ErrRemoteObjectConflict
	default:
		return false, ErrS3Request
	}
}

func (b *Backend) newRequest(
	ctx context.Context,
	method, key string,
	query url.Values,
	headers http.Header,
	content []byte,
	payloadDigest string,
) (*http.Request, error) {
	credentials, err := b.credentials.Retrieve(ctx)
	if err != nil || credentials.validate() != nil {
		return nil, ErrCredentialsUnavailable
	}
	requestURL := *b.endpoint
	segments := strings.Split(b.bucket+"/"+key, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	requestURL.RawPath = "/" + strings.Join(segments, "/")
	requestURL.Path = "/" + b.bucket + "/" + key
	requestURL.RawQuery = canonicalQuery(query)
	var body io.Reader
	if content != nil {
		body = bytes.NewReader(content)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	at := b.clock.Now().UTC()
	if at.UnixMilli() <= 0 {
		return nil, ErrInvalidConfig
	}
	request.Header.Set("x-amz-date", at.Format("20060102T150405Z"))
	request.Header.Set("x-amz-content-sha256", payloadDigest)
	if credentials.sessionToken != "" {
		request.Header.Set("x-amz-security-token", credentials.sessionToken)
	}
	signRequest(request, credentials, b.region, at)
	return request, nil
}

func signRequest(request *http.Request, credentials Credentials, region string, at time.Time) {
	canonicalHeaders, signedHeaders := canonicalHeaders(request)
	canonicalRequest := strings.Join([]string{
		request.Method, request.URL.EscapedPath(), canonicalQuery(request.URL.Query()),
		canonicalHeaders, signedHeaders, request.Header.Get("x-amz-content-sha256"),
	}, "\n")
	date := at.UTC().Format("20060102")
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + request.Header.Get("x-amz-date") + "\n" + scope + "\n" + digestHex([]byte(canonicalRequest))
	dateKey := hmacSHA256([]byte("AWS4"+credentials.secretAccessKey), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "s3")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	clear(dateKey)
	clear(regionKey)
	clear(serviceKey)
	clear(signingKey)
	request.Header.Set(
		"Authorization",
		"AWS4-HMAC-SHA256 Credential="+credentials.accessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature,
	)
}

func canonicalHeaders(request *http.Request) (string, string) {
	values := make(map[string]string, len(request.Header)+1)
	values["host"] = request.URL.Host
	for name, entries := range request.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" {
			continue
		}
		canonical := make([]string, len(entries))
		for index, value := range entries {
			canonical[index] = strings.Join(strings.Fields(value), " ")
		}
		values[lower] = strings.Join(canonical, ",")
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var builder strings.Builder
	for _, name := range names {
		builder.WriteString(name)
		builder.WriteByte(':')
		builder.WriteString(values[name])
		builder.WriteByte('\n')
	}
	return builder.String(), strings.Join(names, ";")
}

func canonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	return strings.ReplaceAll(values.Encode(), "+", "%20")
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func validEndpoint(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.User != nil || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return false
	}
	if endpoint.Scheme == "https" {
		return true
	}
	address := net.ParseIP(endpoint.Hostname())
	return endpoint.Scheme == "http" && address != nil && address.IsLoopback()
}
func validRegion(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '-') {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}
func validBucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || strings.Contains(value, "..") {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '-' || candidate == '.') {
			return false
		}
	}
	return value[0] != '-' && value[0] != '.' && value[len(value)-1] != '-' && value[len(value)-1] != '.'
}
func validObjectKey(value string) bool {
	validLength := len(value) > 0 && len(value) <= maximumObjectKeyBytes && utf8.ValidString(value)
	validShape := !strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/") && !strings.Contains(value, "//")
	if !validLength || !validShape {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || segment == "" {
			return false
		}
		for _, candidate := range segment {
			alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9'
			if !alphaNumeric && candidate != '-' && candidate != '_' && candidate != '.' {
				return false
			}
		}
	}
	return true
}
func validVersion(value string) bool {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate == 0x7f {
			return false
		}
	}
	return true
}
func readS3ErrorCode(response *http.Response) (string, error) {
	if response == nil || response.Body == nil {
		return "", ErrS3Request
	}
	if response.ContentLength > maximumErrorBodyBytes {
		drainAndClose(response.Body)
		return "", ErrS3Request
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumErrorBodyBytes+1))
	closeErr := response.Body.Close()
	defer clear(content)
	if err != nil || closeErr != nil || len(content) == 0 || len(content) > maximumErrorBodyBytes {
		return "", ErrS3Request
	}
	var value struct {
		XMLName xml.Name `xml:"Error"`
		Codes   []string `xml:"Code"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	decoder.Strict = true
	if err = decoder.Decode(&value); err != nil || value.XMLName.Space != "" || value.XMLName.Local != "Error" || len(value.Codes) != 1 || value.Codes[0] == "" {
		return "", ErrS3Request
	}
	for {
		token, tokenErr := decoder.Token()
		if tokenErr == io.EOF {
			break
		}
		if tokenErr != nil {
			return "", ErrS3Request
		}
		characters, ok := token.(xml.CharData)
		if !ok || len(bytes.TrimSpace(characters)) != 0 {
			return "", ErrS3Request
		}
	}
	return value.Codes[0], nil
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maximumErrorBodyBytes))
	_ = body.Close()
}
func (b *Backend) String() string   { return "S3 artifact backend" }
func (b *Backend) GoString() string { return "s3.Backend{<redacted>}" }
func (b *Backend) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "S3 artifact backend", "s3.Backend{<redacted>}")
}

var _ artifact.RemoteObjectBackend = (*Backend)(nil)
