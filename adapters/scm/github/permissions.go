package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	providerconfig "github.com/georgejieh/open-trestle/internal/provider"
)

const (
	permissionAuthorityVersion              = 1
	maxPermissionResponseBytes              = 1 << 20
	maxInstallationPages                    = 10
	permissionPageSize                      = 100
	permissionRepositoryPageSize            = 2
	maxPermissionRequests                   = maxInstallationPages + 1
	maxObservedInstallations                = 1000
	permissionUserPath                      = "/user/installations"
	permissionRuntimePath                   = "/installation/repositories"
	permissionUserAgent                     = "open-trestle/setup-permission-inspector"
	permissionAccept                        = "application/vnd.github+json"
	permissionResponseMediaType             = "application/json"
	permissionDialTimeout                   = 10 * time.Second
	permissionTLSHandshakeTimeout           = 10 * time.Second
	permissionResponseHeaderTimeout         = 10 * time.Second
	permissionMaxResponseHeaderBytes        = int64(1 << 20)
	maxPermissionIdentifier          uint64 = 9_007_199_254_740_991
)

var (
	// ErrInvalidPermissionConfig identifies unsafe or incomplete permission-inspector configuration.
	ErrInvalidPermissionConfig = errors.New("invalid GitHub permission inspector configuration")
	ErrPermissionDenied        = errors.New("GitHub integration permission denied")
	ErrPermissionUnavailable   = errors.New("GitHub integration permission inspection unavailable")
	ErrPermissionMismatch      = errors.New("GitHub integration permission mismatch")
)

// PermissionConfig binds one GitHub installation permission inspection.
type PermissionConfig struct {
	APIEndpoint, APIVersion                                               string
	InstallationID                                                        uint64
	RepositoryFullName, UserCredentialIdentity, RuntimeCredentialIdentity string
	UserCredentials, RuntimeCredentials                                   TokenProvider
	Timeout                                                               time.Duration
	RuntimeBroker                                                         *InstallationTokenBroker
}

// PermissionInspector verifies user visibility and broker-issued installation authority.
// Broker-backed inspections can create installation tokens.
type PermissionInspector struct {
	endpoint                                                              *url.URL
	apiVersion                                                            string
	installationID                                                        uint64
	repositoryFullName, userCredentialIdentity, runtimeCredentialIdentity string
	userCredentials, runtimeCredentials                                   TokenProvider
	client                                                                *http.Client
	transport                                                             *http.Transport
	authorityIdentity                                                     string
	timeout                                                               time.Duration
	runtimeBroker                                                         *InstallationTokenBroker
}

// PermissionObservation is a content-free receipt for an exact admitted installation and repository.
type PermissionObservation struct {
	authorityIdentity                                   string
	installationID, repositoryID                        uint64
	identity                                            string
	brokerAuthority, issuanceAuthority, attemptIdentity string
	expiresAt                                           time.Time
	verified                                            bool
}

// NewPermissionInspector constructs an inspector without retrieving a token or making a request.
func NewPermissionInspector(config PermissionConfig) (*PermissionInspector, error) {
	endpoint, err := providerconfig.ParseServiceEndpoint(config.APIEndpoint)
	if err != nil {
		return nil, ErrInvalidPermissionConfig
	}
	if _, err = providerconfig.ClassifyServiceEndpoint(config.APIEndpoint); err != nil || !validPermissionAPIVersion(config.APIVersion) || config.InstallationID == 0 || config.InstallationID > maxPermissionIdentifier || !validRepositoryFullName(config.RepositoryFullName) || !validDigest(config.UserCredentialIdentity) || nilInterface(config.UserCredentials) || config.Timeout <= 0 || config.Timeout > time.Minute {
		return nil, ErrInvalidPermissionConfig
	}
	if config.RuntimeBroker == nil {
		if !validDigest(config.RuntimeCredentialIdentity) || config.UserCredentialIdentity == config.RuntimeCredentialIdentity || nilInterface(config.RuntimeCredentials) {
			return nil, ErrInvalidPermissionConfig
		}
	} else {
		broker := config.RuntimeBroker
		if config.RuntimeCredentials != nil || config.RuntimeCredentialIdentity != "" || broker.Validate() != nil || broker.Purpose() != IssuancePurposeSetup {
			return nil, ErrInvalidPermissionConfig
		}
		bound := broker.authority.config
		if strings.TrimSuffix(endpoint.String(), "/") != bound.APIEndpoint || config.APIVersion != bound.APIVersion || config.InstallationID != bound.InstallationID || config.RepositoryFullName != bound.RepositoryFullName {
			return nil, ErrInvalidPermissionConfig
		}
	}
	privateTransport := newPermissionTransport()
	client := &http.Client{Transport: privateTransport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrPermissionUnavailable }}
	effective := *endpoint
	effective.Path = strings.TrimSuffix(effective.Path, "/")
	effective.RawPath = ""
	value := &PermissionInspector{endpoint: &effective, apiVersion: config.APIVersion, installationID: config.InstallationID, repositoryFullName: config.RepositoryFullName, userCredentialIdentity: config.UserCredentialIdentity, runtimeCredentialIdentity: config.RuntimeCredentialIdentity, userCredentials: config.UserCredentials, runtimeCredentials: config.RuntimeCredentials, client: client, transport: privateTransport, timeout: config.Timeout, runtimeBroker: config.RuntimeBroker}
	value.authorityIdentity = derivePermissionAuthority(value)
	if value.Validate() != nil {
		return nil, ErrInvalidPermissionConfig
	}
	return value, nil
}

// AuthorityIdentity returns the exact non-secret inspection authority.
func (i *PermissionInspector) AuthorityIdentity() string {
	if i == nil {
		return ""
	}
	return i.authorityIdentity
}

// Validate verifies immutable inspection authority and runtime bounds.
func (i *PermissionInspector) Validate() error {
	if i == nil || i.endpoint == nil || !validPermissionAPIVersion(i.apiVersion) || i.installationID == 0 || i.installationID > maxPermissionIdentifier || !validRepositoryFullName(i.repositoryFullName) || !validDigest(i.userCredentialIdentity) || nilInterface(i.userCredentials) || i.client == nil || i.client.Jar != nil || i.transport == nil || i.client.Transport != i.transport || !validPermissionTransport(i.transport) || i.timeout <= 0 || i.timeout > time.Minute || i.client.Timeout != i.timeout || i.authorityIdentity != derivePermissionAuthority(i) {
		return ErrInvalidPermissionConfig
	}
	if i.runtimeBroker == nil {
		if !validDigest(i.runtimeCredentialIdentity) || i.userCredentialIdentity == i.runtimeCredentialIdentity || nilInterface(i.runtimeCredentials) {
			return ErrInvalidPermissionConfig
		}
	} else {
		broker := i.runtimeBroker
		bound := broker.authority.config
		if i.runtimeCredentials != nil || i.runtimeCredentialIdentity != "" || broker.authority.Validate() != nil || broker.Purpose() != IssuancePurposeSetup || i.endpoint.String() != bound.APIEndpoint || i.apiVersion != bound.APIVersion || i.installationID != bound.InstallationID || i.repositoryFullName != bound.RepositoryFullName {
			return ErrInvalidPermissionConfig
		}
	}
	return nil
}

// PermissionAuthorityIdentity derives authority without retaining a token or contacting GitHub.
func PermissionAuthorityIdentity(endpoint, apiVersion string, installationID uint64, repositoryFullName, userCredentialIdentity, runtimeCredentialIdentity string, timeout time.Duration) (string, error) {
	inspector, err := NewPermissionInspector(PermissionConfig{APIEndpoint: endpoint, APIVersion: apiVersion, InstallationID: installationID, RepositoryFullName: repositoryFullName, UserCredentialIdentity: userCredentialIdentity, RuntimeCredentialIdentity: runtimeCredentialIdentity, UserCredentials: &identityOnlyTokenProvider{}, RuntimeCredentials: &identityOnlyTokenProvider{}, Timeout: timeout})
	if err != nil {
		return "", err
	}
	return inspector.AuthorityIdentity(), nil
}

type identityOnlyTokenProvider struct{}

func (*identityOnlyTokenProvider) Retrieve(context.Context) (Token, error) {
	return Token{}, ErrInvalidToken
}
func newPermissionTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: permissionDialTimeout, KeepAlive: -1}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: false, Protocols: protocols, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: permissionTLSHandshakeTimeout, DisableKeepAlives: true, ResponseHeaderTimeout: permissionResponseHeaderTimeout, MaxResponseHeaderBytes: permissionMaxResponseHeaderBytes}
}
func validPermissionTransport(transport *http.Transport) bool {
	return transport != nil && transport.Proxy == nil && transport.DialContext != nil && transport.Dial == nil && transport.DialTLS == nil && transport.DialTLSContext == nil && transport.DisableKeepAlives && !transport.DisableCompression && !transport.ForceAttemptHTTP2 && transport.Protocols != nil && transport.Protocols.HTTP1() && !transport.Protocols.HTTP2() && !transport.Protocols.UnencryptedHTTP2() && len(transport.TLSNextProto) == 0 && transport.TLSClientConfig != nil && transport.TLSClientConfig.MinVersion == tls.VersionTLS12 && !transport.TLSClientConfig.InsecureSkipVerify && transport.TLSClientConfig.RootCAs == nil && transport.TLSClientConfig.ClientCAs == nil && transport.TLSClientConfig.ServerName == "" && transport.TLSClientConfig.KeyLogWriter == nil && transport.TLSClientConfig.GetClientCertificate == nil && transport.TLSClientConfig.VerifyPeerCertificate == nil && transport.TLSClientConfig.VerifyConnection == nil && len(transport.TLSClientConfig.Certificates) == 0 && len(transport.TLSClientConfig.NextProtos) == 0 && transport.TLSHandshakeTimeout == permissionTLSHandshakeTimeout && transport.ResponseHeaderTimeout == permissionResponseHeaderTimeout && transport.MaxResponseHeaderBytes == permissionMaxResponseHeaderBytes
}
func derivePermissionAuthority(i *PermissionInspector) string {
	if i == nil || i.endpoint == nil {
		return ""
	}
	if i.runtimeBroker != nil {
		identity, _ := BrokeredPermissionAuthorityIdentity(i.runtimeBroker.authority, i.userCredentialIdentity, i.timeout)
		return identity
	}
	wire := struct {
		Contract                    string            `json:"contract"`
		Version                     int               `json:"version"`
		Endpoint                    string            `json:"endpoint"`
		APIVersion                  string            `json:"api_version"`
		InstallationID              uint64            `json:"installation_id"`
		RepositoryFullName          string            `json:"repository_full_name"`
		UserCredentialIdentity      string            `json:"user_credential_identity"`
		RuntimeCredentialIdentity   string            `json:"runtime_credential_identity"`
		TimeoutMillis               int64             `json:"timeout_millis"`
		MaxResponseBytes            int               `json:"max_response_bytes"`
		MaxInstallationPages        int               `json:"max_installation_pages"`
		InstallationPageSize        int               `json:"installation_page_size"`
		InstallationFirstPage       int               `json:"installation_first_page"`
		RepositoryPageSize          int               `json:"repository_page_size"`
		RepositoryPage              int               `json:"repository_page"`
		MaxRequests                 int               `json:"max_requests"`
		MaxIdentifier               uint64            `json:"max_identifier"`
		UserMethod                  string            `json:"user_method"`
		UserPath                    string            `json:"user_path"`
		RuntimeMethod               string            `json:"runtime_method"`
		RuntimePath                 string            `json:"runtime_path"`
		Accept                      string            `json:"accept"`
		AuthorizationScheme         string            `json:"authorization_scheme"`
		APIVersionHeader            string            `json:"api_version_header"`
		PaginationParameters        []string          `json:"pagination_parameters"`
		ResponseMediaType           string            `json:"response_media_type"`
		SuccessStatus               int               `json:"success_status"`
		UserAgent                   string            `json:"user_agent"`
		ProxyEnabled                bool              `json:"proxy_enabled"`
		KeepAlivesEnabled           bool              `json:"keep_alives_enabled"`
		HTTP2Enabled                bool              `json:"http2_enabled"`
		CookiesEnabled              bool              `json:"cookies_enabled"`
		TCPKeepAliveEnabled         bool              `json:"tcp_keep_alive_enabled"`
		CompressionEnabled          bool              `json:"compression_enabled"`
		TLSMinimumVersion           uint16            `json:"tls_minimum_version"`
		DialTimeoutMillis           int64             `json:"dial_timeout_millis"`
		TLSHandshakeTimeoutMillis   int64             `json:"tls_handshake_timeout_millis"`
		SystemTrustRoots            bool              `json:"system_trust_roots"`
		ResponseHeaderTimeoutMillis int64             `json:"response_header_timeout_millis"`
		MaxResponseHeaderBytes      int64             `json:"max_response_header_bytes"`
		MaxInstallations            int               `json:"max_installations"`
		RepositorySelection         string            `json:"repository_selection"`
		Permissions                 map[string]string `json:"permissions"`
		Events                      []string          `json:"events"`
	}{Contract: "open-trestle/github-permission-authority", Version: permissionAuthorityVersion, Endpoint: i.endpoint.String(), APIVersion: i.apiVersion, InstallationID: i.installationID, RepositoryFullName: i.repositoryFullName, UserCredentialIdentity: i.userCredentialIdentity, RuntimeCredentialIdentity: i.runtimeCredentialIdentity, TimeoutMillis: i.timeout.Milliseconds(), MaxResponseBytes: maxPermissionResponseBytes, MaxInstallationPages: maxInstallationPages, InstallationPageSize: permissionPageSize, InstallationFirstPage: 1, RepositoryPageSize: permissionRepositoryPageSize, RepositoryPage: 1, MaxRequests: maxPermissionRequests, MaxIdentifier: maxPermissionIdentifier, UserMethod: http.MethodGet, UserPath: permissionUserPath, RuntimeMethod: http.MethodGet, RuntimePath: permissionRuntimePath, Accept: permissionAccept, AuthorizationScheme: "Bearer", APIVersionHeader: "X-GitHub-Api-Version", PaginationParameters: []string{"page", "per_page"}, ResponseMediaType: permissionResponseMediaType, SuccessStatus: http.StatusOK, UserAgent: permissionUserAgent, ProxyEnabled: false, KeepAlivesEnabled: false, HTTP2Enabled: false, CookiesEnabled: false, TCPKeepAliveEnabled: false, CompressionEnabled: true, TLSMinimumVersion: tls.VersionTLS12, DialTimeoutMillis: permissionDialTimeout.Milliseconds(), TLSHandshakeTimeoutMillis: permissionTLSHandshakeTimeout.Milliseconds(), SystemTrustRoots: true, ResponseHeaderTimeoutMillis: permissionResponseHeaderTimeout.Milliseconds(), MaxResponseHeaderBytes: permissionMaxResponseHeaderBytes, MaxInstallations: maxObservedInstallations, RepositorySelection: "selected", Permissions: requiredGitHubPermissions(), Events: []string{"pull_request"}}
	encoded, _ := json.Marshal(wire)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Inspect requires a broker-proven runtime grant as well as user installation visibility.
func (i *PermissionInspector) Inspect(ctx context.Context) (PermissionObservation, error) {
	if nilInterface(ctx) || ctx.Err() != nil || i.Validate() != nil {
		return PermissionObservation{}, ErrPermissionUnavailable
	}
	if i.runtimeBroker == nil {
		return PermissionObservation{}, ErrPermissionMismatch
	}
	op, err := i.runtimeBroker.beginInspection(ctx, i.runtimeBroker.AuthorityIdentity())
	if err != nil {
		return PermissionObservation{}, brokerPermissionError(err)
	}
	defer op.Close()
	i.runtimeBroker.mu.Lock()
	op.permissionAuthority = i.authorityIdentity
	i.runtimeBroker.mu.Unlock()
	ctx = op.Context()
	userToken, err := i.userCredentials.Retrieve(ctx)
	if err != nil || userToken.Validate() != nil {
		return PermissionObservation{}, ErrPermissionDenied
	}
	installation, err := i.findInstallation(ctx, userToken)
	if err != nil {
		return PermissionObservation{}, err
	}
	if !installation.valid(i.installationID, i.repositoryFullName) {
		return PermissionObservation{}, ErrPermissionMismatch
	}
	lease, err := i.runtimeBroker.borrow(op)
	if err != nil {
		return PermissionObservation{}, brokerPermissionError(err)
	}
	defer lease.release()
	i.runtimeBroker.mu.Lock()
	sameCredential := lease.grant != nil && samePermissionToken(userToken, lease.grant.token)
	i.runtimeBroker.mu.Unlock()
	if sameCredential {
		return PermissionObservation{}, ErrPermissionDenied
	}
	observation, err := lease.permissionObservation(i.authorityIdentity)
	if err != nil {
		return PermissionObservation{}, brokerPermissionError(err)
	}
	return observation, nil
}

func brokerPermissionError(err error) error {
	if errors.Is(err, ErrBrokerUnavailable) || errors.Is(err, ErrBrokerCloseIncomplete) {
		return ErrPermissionUnavailable
	}
	if errors.Is(err, ErrBrokerMismatch) || errors.Is(err, ErrInvalidBrokerConfig) || errors.Is(err, ErrIssuanceFenced) {
		return ErrPermissionMismatch
	}
	return ErrPermissionDenied
}

// BrokeredPermissionAuthorityIdentity binds configuration, not an observed grant.
func BrokeredPermissionAuthorityIdentity(authority InstallationBrokerAuthority, userCredentialIdentity string, timeout time.Duration) (string, error) {
	if authority.Validate() != nil || !validDigest(userCredentialIdentity) || timeout <= 0 || timeout > time.Minute {
		return "", ErrInvalidPermissionConfig
	}
	lane, err := NewIssuanceAuthority(authority, IssuancePurposeSetup)
	if err != nil {
		return "", ErrInvalidPermissionConfig
	}
	return brokerDigest("open-trestle/github-permission-authority/v2", struct {
		Broker, SetupLane, UserCredentialIdentity string
		TimeoutNanos                              int64
		Policy                                    string
	}{authority.Identity(), lane.Identity(), userCredentialIdentity, int64(timeout), "user-installation-visibility;native-broker-grant;selected-singleton-repository;contents=read;metadata=read;pull_requests=read;pull_request;unsuspended;bounded-user-query-v1"}), nil
}

type permissionInstallation struct {
	id                                uint64
	accountLogin, repositorySelection string
	permissions                       map[string]string
	events                            []string
	suspended                         bool
	suspensionPresent                 bool
}

func samePermissionToken(left, right Token) bool {
	return left.Validate() == nil && right.Validate() == nil && len(left.value) == len(right.value) && subtle.ConstantTimeCompare([]byte(left.value), []byte(right.value)) == 1
}
func (i *PermissionInspector) findInstallation(ctx context.Context, token Token) (permissionInstallation, error) {
	seen := 0
	matches := []permissionInstallation{}
	seenIDs := map[uint64]bool{}
	expectedTotal := -1
	for page := 1; page <= maxInstallationPages; page++ {
		content, err := i.get(ctx, token, permissionUserPath, url.Values{"per_page": {strconv.Itoa(permissionPageSize)}, "page": {strconv.Itoa(page)}})
		if err != nil {
			return permissionInstallation{}, err
		}
		total, entries, err := parseInstallationPage(content)
		clear(content)
		if err != nil || total < 0 || len(entries) > permissionPageSize || expectedTotal != -1 && total != expectedTotal {
			return permissionInstallation{}, ErrPermissionMismatch
		}
		if total > maxObservedInstallations {
			return permissionInstallation{}, ErrPermissionUnavailable
		}
		expectedTotal = total
		seen += len(entries)
		for _, entry := range entries {
			if seenIDs[entry.id] {
				return permissionInstallation{}, ErrPermissionMismatch
			}
			seenIDs[entry.id] = true
			if entry.id == i.installationID {
				matches = append(matches, entry)
			}
		}
		if seen >= total {
			break
		}
		if len(entries) == 0 || page == maxInstallationPages {
			return permissionInstallation{}, ErrPermissionUnavailable
		}
	}
	if seen != expectedTotal || len(matches) != 1 {
		return permissionInstallation{}, ErrPermissionMismatch
	}
	return matches[0], nil
}
func (i *PermissionInspector) inspectRepositories(ctx context.Context, token Token) (uint64, error) {
	path := permissionRuntimePath
	content, err := i.get(ctx, token, path, url.Values{"per_page": {strconv.Itoa(permissionRepositoryPageSize)}, "page": {"1"}})
	if err != nil {
		return 0, err
	}
	defer clear(content)
	total, entries, err := parseRepositoryPage(content)
	if err != nil || total != 1 || len(entries) != 1 || entries[0].id == 0 || strings.ToLower(entries[0].fullName) != i.repositoryFullName || !validResponseRepositoryFullName(entries[0].fullName) {
		return 0, ErrPermissionMismatch
	}
	return entries[0].id, nil
}
func (i *PermissionInspector) get(ctx context.Context, token Token, path string, query url.Values) ([]byte, error) {
	requestURL := *i.endpoint
	requestURL.Path = strings.TrimSuffix(requestURL.Path, "/") + path
	requestURL.RawPath = ""
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, ErrPermissionMismatch
	}
	request.Header.Set("Accept", permissionAccept)
	request.Header.Set("Authorization", "Bearer "+token.value)
	request.Header.Set("X-GitHub-Api-Version", i.apiVersion)
	request.Header.Set("User-Agent", permissionUserAgent)
	response, err := i.client.Do(request)
	if err != nil {
		return nil, ErrPermissionUnavailable
	}
	if response.StatusCode != http.StatusOK {
		drainAndClose(response.Body)
		if response.StatusCode == http.StatusForbidden && (response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("Retry-After") != "") {
			return nil, ErrPermissionUnavailable
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return nil, ErrPermissionDenied
		}
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return nil, ErrPermissionUnavailable
		}
		return nil, ErrPermissionMismatch
	}
	if !isPermissionJSONResponse(response) {
		drainAndClose(response.Body)
		return nil, ErrPermissionMismatch
	}
	content, ok := readBounded(response, maxPermissionResponseBytes)
	if !ok {
		return nil, ErrPermissionUnavailable
	}
	return content, nil
}
func isPermissionJSONResponse(response *http.Response) bool {
	if response == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == permissionResponseMediaType
}
func (required permissionInstallation) valid(installationID uint64, repository string) bool {
	owner, _, _ := strings.Cut(repository, "/")
	if required.id != installationID || strings.ToLower(required.accountLogin) != owner || !validResponseRepositorySlug(required.accountLogin) || required.repositorySelection != "selected" || required.suspended || !required.suspensionPresent || len(required.permissions) != 3 || len(required.events) != 1 || required.events[0] != "pull_request" {
		return false
	}
	expected := requiredGitHubPermissions()
	for name, value := range expected {
		if required.permissions[name] != value {
			return false
		}
	}
	return true
}
func requiredGitHubPermissions() map[string]string {
	return map[string]string{"contents": "read", "metadata": "read", "pull_requests": "read"}
}

type repositoryPermissionEntry struct {
	id       uint64
	fullName string
}

func parseInstallationPage(content []byte) (int, []permissionInstallation, error) {
	object, err := decodeSelectedObject(content, map[string]bool{"total_count": true, "installations": true})
	if err != nil {
		return 0, nil, err
	}
	total, ok := decodeInt(object["total_count"])
	if !ok {
		return 0, nil, ErrPermissionMismatch
	}
	var raw []json.RawMessage
	if json.Unmarshal(object["installations"], &raw) != nil || raw == nil {
		return 0, nil, ErrPermissionMismatch
	}
	entries := make([]permissionInstallation, 0, len(raw))
	for _, item := range raw {
		fields, err := decodeSelectedObject(item, map[string]bool{"id": true, "account": true, "repository_selection": true, "permissions": true, "events": true, "suspended_at": true})
		if err != nil {
			return 0, nil, err
		}
		id, ok := decodeUint(fields["id"])
		if !ok {
			return 0, nil, ErrPermissionMismatch
		}
		account, err := decodeSelectedObject(fields["account"], map[string]bool{"login": true})
		if err != nil {
			return 0, nil, err
		}
		var login, selection string
		var events []string
		permissions, permissionErr := decodeStringMap(fields["permissions"])
		if json.Unmarshal(account["login"], &login) != nil || json.Unmarshal(fields["repository_selection"], &selection) != nil || permissionErr != nil || json.Unmarshal(fields["events"], &events) != nil || events == nil {
			return 0, nil, ErrPermissionMismatch
		}
		sort.Strings(events)
		suspendedRaw, present := fields["suspended_at"]
		entries = append(entries, permissionInstallation{id, login, selection, permissions, events, !bytes.Equal(bytes.TrimSpace(suspendedRaw), []byte("null")), present})
	}
	return total, entries, nil
}
func parseRepositoryPage(content []byte) (int, []repositoryPermissionEntry, error) {
	object, err := decodeSelectedObject(content, map[string]bool{"total_count": true, "repositories": true})
	if err != nil {
		return 0, nil, err
	}
	total, ok := decodeInt(object["total_count"])
	if !ok {
		return 0, nil, ErrPermissionMismatch
	}
	var raw []json.RawMessage
	if json.Unmarshal(object["repositories"], &raw) != nil || raw == nil {
		return 0, nil, ErrPermissionMismatch
	}
	entries := make([]repositoryPermissionEntry, 0, len(raw))
	for _, item := range raw {
		fields, err := decodeSelectedObject(item, map[string]bool{"id": true, "full_name": true})
		if err != nil {
			return 0, nil, err
		}
		id, ok := decodeUint(fields["id"])
		var fullName string
		if !ok || json.Unmarshal(fields["full_name"], &fullName) != nil {
			return 0, nil, ErrPermissionMismatch
		}
		entries = append(entries, repositoryPermissionEntry{id, fullName})
	}
	return total, entries, nil
}
func decodeSelectedObject(content []byte, selected map[string]bool) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrPermissionMismatch
	}
	result := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || key == "" || !utf8.ValidString(key) || seen[key] {
			return nil, ErrPermissionMismatch
		}
		seen[key] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, ErrPermissionMismatch
		}
		if selected == nil || selected[key] {
			result[key] = append([]byte(nil), raw...)
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, ErrPermissionMismatch
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrPermissionMismatch
	}
	for name := range selected {
		if _, ok := result[name]; !ok {
			return nil, ErrPermissionMismatch
		}
	}
	return result, nil
}
func decodeStringMap(raw json.RawMessage) (map[string]string, error) {
	fields, err := decodeSelectedObject(raw, nil)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(fields))
	for name, encoded := range fields {
		var value string
		if json.Unmarshal(encoded, &value) != nil || name == "" {
			return nil, ErrPermissionMismatch
		}
		values[name] = value
	}
	return values, nil
}
func decodeUint(raw json.RawMessage) (uint64, bool) {
	var value uint64
	err := json.Unmarshal(raw, &value)
	return value, err == nil && value > 0 && value <= maxPermissionIdentifier
}
func decodeInt(raw json.RawMessage) (int, bool) {
	var value int
	err := json.Unmarshal(raw, &value)
	return value, err == nil && value >= 0
}
func validPermissionAPIVersion(value string) bool {
	return validAPIVersion(value) && value[:4] >= "2000"
}
func validRepositoryFullName(value string) bool {
	owner, name, found := strings.Cut(value, "/")
	return found && !strings.Contains(name, "/") && validRepositorySlug(owner) && validRepositorySlug(name)
}
func validResponseRepositoryFullName(value string) bool {
	owner, name, found := strings.Cut(value, "/")
	return found && !strings.Contains(name, "/") && validResponseRepositorySlug(owner) && validResponseRepositorySlug(name)
}
func validResponseRepositorySlug(value string) bool {
	return validRepositorySlug(strings.ToLower(value))
}
func derivePermissionObservationIdentity(o PermissionObservation) string {
	if o.verified {
		return brokerDigest("open-trestle/github-permission-observation/v2", struct {
			Authority, Broker, Lane, Attempt string
			InstallationID, RepositoryID     uint64
			ExpiresAt                        time.Time
		}{o.authorityIdentity, o.brokerAuthority, o.issuanceAuthority, o.attemptIdentity, o.installationID, o.repositoryID, o.expiresAt.UTC()})
	}
	encoded, _ := json.Marshal(struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Authority      string `json:"authority_identity"`
		InstallationID uint64 `json:"installation_id"`
		RepositoryID   uint64 `json:"repository_id"`
	}{"open-trestle/github-permission-observation", 1, o.authorityIdentity, o.installationID, o.repositoryID})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (o PermissionObservation) Identity() string          { return o.identity }
func (o PermissionObservation) AuthorityIdentity() string { return o.authorityIdentity }
func (o PermissionObservation) Validate() error {
	if !o.verified || !validDigest(o.brokerAuthority) || !validDigest(o.issuanceAuthority) || !validDigest(o.attemptIdentity) || o.expiresAt.IsZero() || !validDigest(o.authorityIdentity) || o.installationID == 0 || o.installationID > maxPermissionIdentifier || o.repositoryID == 0 || o.repositoryID > maxPermissionIdentifier || o.identity != derivePermissionObservationIdentity(o) {
		return ErrPermissionMismatch
	}
	return nil
}
func (o PermissionObservation) String() string   { return "GitHub permission observation" }
func (o PermissionObservation) GoString() string { return "github.PermissionObservation{<redacted>}" }
func (o PermissionObservation) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, o.String(), o.GoString())
}
func (i *PermissionInspector) String() string   { return "GitHub permission inspector" }
func (i *PermissionInspector) GoString() string { return "github.PermissionInspector{<redacted>}" }
func (i *PermissionInspector) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, i.String(), i.GoString())
}
