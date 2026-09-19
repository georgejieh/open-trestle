// Package github provides bounded immutable GitHub acquisition and authorized review publication.
package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

const (
	defaultAPIEndpoint          = "https://api.github.com"
	defaultAPIVersion           = "2026-03-10"
	defaultRequestTimeout       = 2 * time.Minute
	maximumRequestTimeout       = 5 * time.Minute
	maximumMetadataBytes        = 16 << 20
	maximumCompressedBytes      = 128 << 20
	maximumExtractedBytes       = 256 << 20
	maximumInflatedArchiveBytes = 384 << 20
	maximumFileBytes            = 10 << 20
	maximumErrorBodyBytes       = 4096
	maximumResponseHeaderBytes  = 64 << 10
	maximumTreeEntries          = 1 << 16
	maximumTokenBytes           = 4096
	maximumEndpointBytes        = 2048
	maximumArchiveAuthorities   = 16
)

var (
	// ErrInvalidConfig identifies an unsafe or incomplete adapter configuration.
	ErrInvalidConfig = errors.New("invalid GitHub source adapter configuration")
	// ErrInvalidToken identifies an empty, excessive, or header-unsafe token.
	ErrInvalidToken = errors.New("invalid GitHub API token")
)

// Token is an immutable header-safe API credential.
type Token struct{ value string }

// NewToken copies and validates one API token.
func NewToken(value []byte) (Token, error) {
	token := Token{value: string(value)}
	if err := token.Validate(); err != nil {
		return Token{}, err
	}
	return token, nil
}

// Validate verifies that the token is bounded and safe for an HTTP header.
func (t Token) Validate() error {
	if len(t.value) == 0 || len(t.value) > maximumTokenBytes || strings.TrimSpace(t.value) != t.value {
		return ErrInvalidToken
	}
	for index := 0; index < len(t.value); index++ {
		if t.value[index] < 0x21 || t.value[index] > 0x7e {
			return ErrInvalidToken
		}
	}
	return nil
}

func (t Token) String() string   { return "GitHub API token" }
func (t Token) GoString() string { return "github.Token{<redacted>}" }
func (t Token) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "GitHub API token", "github.Token{<redacted>}")
}

// TokenProvider retrieves a token at request time. A nil provider selects anonymous access.
type TokenProvider interface {
	Retrieve(context.Context) (Token, error)
}

// Config binds repository authority, API origin, and approved archive origins.
type Config struct {
	RepositoryAuthority string
	APIEndpoint         string
	APIVersion          string
	ArchiveAuthorities  []string
	Credentials         TokenProvider
	HTTPClient          *http.Client
	InstallationBroker  *InstallationTokenBroker
}

// Adapter acquires exact commit archives and checks them against Git metadata.
type Adapter struct {
	identity                evidence.SourceAdapterIdentity
	repositoryAuthority     string
	apiEndpoint             *url.URL
	apiVersion              string
	archiveAuthorities      []string
	archiveAuthorityIndex   map[string]struct{}
	credentials             TokenProvider
	httpClient              *http.Client
	installationBroker      *InstallationTokenBroker
	brokerAuthorityIdentity string
}

// New validates configuration without retrieving credentials or making a request.
func New(config Config) (*Adapter, error) {
	endpointValue := config.APIEndpoint
	if endpointValue == "" {
		endpointValue = defaultAPIEndpoint
	}
	apiVersion := config.APIVersion
	if apiVersion == "" {
		apiVersion = defaultAPIVersion
	}
	endpoint, err := url.Parse(endpointValue)
	if err != nil || !validEndpoint(endpoint) || !validAPIVersion(apiVersion) || !validRepositoryAuthority(config.RepositoryAuthority) ||
		config.Credentials != nil && nilInterface(config.Credentials) {
		return nil, ErrInvalidConfig
	}
	authorities, index, err := canonicalArchiveAuthorities(config.ArchiveAuthorities)
	if err != nil {
		return nil, err
	}
	var client *http.Client
	identity, err := adapterIdentity()
	brokerIdentity := ""
	if config.InstallationBroker != nil {
		broker := config.InstallationBroker
		if config.Credentials != nil || config.HTTPClient != nil || broker.Validate() != nil || broker.Purpose() != IssuancePurposeRuntime {
			return nil, ErrInvalidConfig
		}
		bound := broker.authority.config
		if config.RepositoryAuthority != bound.RepositoryAuthority || strings.TrimSuffix(endpoint.String(), "/") != bound.APIEndpoint || apiVersion != bound.APIVersion || !equalArchiveAuthorities(authorities, bound.ArchiveAuthorities) {
			return nil, ErrInvalidConfig
		}
		client = broker.sourceClient
		brokerIdentity = broker.AuthorityIdentity()
		identity, err = BrokeredSourceAdapterIdentity()
	} else {
		client, err = boundedClient(config.HTTPClient)
	}
	if err != nil {
		return nil, ErrInvalidConfig
	}
	endpointCopy := *endpoint
	endpointCopy.Path = strings.TrimSuffix(endpointCopy.Path, "/")
	return &Adapter{
		identity: identity, repositoryAuthority: strings.Clone(config.RepositoryAuthority),
		apiEndpoint: &endpointCopy, apiVersion: strings.Clone(apiVersion),
		archiveAuthorities: authorities, archiveAuthorityIndex: index,
		credentials: config.Credentials, httpClient: client,
		installationBroker: config.InstallationBroker, brokerAuthorityIdentity: brokerIdentity,
	}, nil
}

// SourceAdapterIdentity returns the immutable built-in GitHub source adapter contract.
func SourceAdapterIdentity() (evidence.SourceAdapterIdentity, error) { return adapterIdentity() }

// BrokeredSourceAdapterIdentity identifies installation-broker source acquisition.
func BrokeredSourceAdapterIdentity() (evidence.SourceAdapterIdentity, error) {
	return evidence.NewSourceAdapterIdentity(
		evidence.SourceAdapterKindGit, "open-trestle.github-rest-installation", "1.0.0",
		[]evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent},
	)
}

func equalArchiveAuthorities(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for n, value := range left {
		if value != right[n] {
			return false
		}
	}
	return true
}

func adapterIdentity() (evidence.SourceAdapterIdentity, error) {
	return evidence.NewSourceAdapterIdentity(
		evidence.SourceAdapterKindGit,
		"open-trestle.github-rest",
		"1.0.0",
		[]evidence.SourceAdapterCapability{
			evidence.SourceCapabilityReadManifest,
			evidence.SourceCapabilityReadContent,
		},
	)
}

func validAPIVersion(value string) bool {
	if len(value) != len("2006-01-02") {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}

func validRepositoryAuthority(value string) bool {
	repository, err := evidence.NewRepositoryIdentity(value, []string{"owner"}, "repository")
	return err == nil && repository.Authority() == value
}

func canonicalArchiveAuthorities(values []string) ([]string, map[string]struct{}, error) {
	if len(values) == 0 || len(values) > maximumArchiveAuthorities {
		return nil, nil, ErrInvalidConfig
	}
	canonical := append([]string(nil), values...)
	sort.Strings(canonical)
	index := make(map[string]struct{}, len(canonical))
	for position, value := range canonical {
		parsed, err := url.Parse("https://" + value)
		valid := err == nil && value == strings.ToLower(value) && parsed.Host == value && parsed.Hostname() != "" &&
			parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
		if !valid || position > 0 && value == canonical[position-1] {
			return nil, nil, ErrInvalidConfig
		}
		index[value] = struct{}{}
	}
	return canonical, index, nil
}

func boundedClient(configured *http.Client) (*http.Client, error) {
	if configured == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cloneTLSConfig(transport.TLSClientConfig)
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		transport.MaxResponseHeaderBytes = maximumResponseHeaderBytes
		configured = &http.Client{Transport: transport, Timeout: defaultRequestTimeout}
	}
	clone := *configured
	if clone.Timeout == 0 {
		clone.Timeout = defaultRequestTimeout
	}
	if clone.Timeout < 0 || clone.Timeout > maximumRequestTimeout {
		return nil, ErrInvalidConfig
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone, nil
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return &tls.Config{}
	}
	return config.Clone()
}

func validEndpoint(endpoint *url.URL) bool {
	if endpoint == nil || len(endpoint.String()) == 0 || len(endpoint.String()) > maximumEndpointBytes ||
		endpoint.User != nil || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.RawPath != "" || !utf8.ValidString(endpoint.Path) {
		return false
	}
	cleaned := path.Clean(endpoint.Path)
	if cleaned == "." {
		cleaned = ""
	}
	if endpoint.Path != cleaned && endpoint.Path != cleaned+"/" || strings.Contains(endpoint.Path, "//") {
		return false
	}
	if endpoint.Scheme == "https" {
		return true
	}
	address := net.ParseIP(endpoint.Hostname())
	return endpoint.Scheme == "http" && address != nil && address.IsLoopback()
}

// Identity returns the immutable adapter descriptor.
func (a *Adapter) Identity() evidence.SourceAdapterIdentity {
	if a == nil {
		return evidence.SourceAdapterIdentity{}
	}
	return a.identity
}

// Validate verifies all immutable adapter bindings.
func (a *Adapter) Validate() error {
	if a == nil || a.apiEndpoint == nil || a.httpClient == nil || !validEndpoint(a.apiEndpoint) ||
		!validRepositoryAuthority(a.repositoryAuthority) || !validAPIVersion(a.apiVersion) || len(a.archiveAuthorities) == 0 ||
		len(a.archiveAuthorities) != len(a.archiveAuthorityIndex) || a.httpClient.Timeout <= 0 ||
		a.httpClient.Timeout > maximumRequestTimeout {
		return ErrInvalidConfig
	}
	canonical, index, err := canonicalArchiveAuthorities(a.archiveAuthorities)
	if err != nil || len(index) != len(a.archiveAuthorityIndex) {
		return ErrInvalidConfig
	}
	for position, value := range canonical {
		if value != a.archiveAuthorities[position] {
			return ErrInvalidConfig
		}
		if _, exists := a.archiveAuthorityIndex[value]; !exists {
			return ErrInvalidConfig
		}
	}
	identity, err := adapterIdentity()
	if a.installationBroker != nil {
		broker := a.installationBroker
		bound := broker.authority.config
		if broker.authority.Validate() != nil || broker.Purpose() != IssuancePurposeRuntime || a.brokerAuthorityIdentity != broker.AuthorityIdentity() || a.credentials != nil || a.httpClient != broker.sourceClient || a.httpClient.Transport != broker.sourceTransport || a.httpClient.Jar != nil || !validPermissionTransport(broker.sourceTransport) || a.repositoryAuthority != bound.RepositoryAuthority || a.apiEndpoint.String() != bound.APIEndpoint || a.apiVersion != bound.APIVersion || !equalArchiveAuthorities(a.archiveAuthorities, bound.ArchiveAuthorities) {
			return ErrInvalidConfig
		}
		identity, err = BrokeredSourceAdapterIdentity()
	} else if a.brokerAuthorityIdentity != "" {
		return ErrInvalidConfig
	}
	if err != nil || identity.Identity() != a.identity.Identity() {
		return ErrInvalidConfig
	}
	return nil
}

// Acquire retrieves one exact immutable revision without writing repository state.
func (a *Adapter) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	if nilInterface(ctx) || a == nil || a.Validate() != nil || evidence.ValidateRepositoryAcquisitionRequest(request) != nil {
		return blocked(evidence.AcquisitionReasonPolicyBlocked)
	}
	if ctx.Err() != nil {
		return blocked(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if !a.requestMatches(request) {
		return blocked(evidence.AcquisitionReasonPolicyBlocked)
	}
	repository := request.Repository()
	if a.installationBroker != nil {
		op, err := a.installationBroker.beginSource(ctx, repository)
		if err != nil {
			return brokerAcquisitionFailure(err).result()
		}
		defer op.Close()
		ctx = op.Context()
	}
	owner := repository.Namespace()[0]
	name := repository.Name()
	commit := request.Revision().Digest()

	rootTree, acquisitionFailure := a.loadCommit(ctx, owner, name, commit)
	if acquisitionFailure != nil {
		return acquisitionFailure.result()
	}
	files, acquisitionFailure := a.loadTree(ctx, owner, name, rootTree, request.Revision().Algorithm())
	if acquisitionFailure != nil {
		return acquisitionFailure.result()
	}
	contents, acquisitionFailure := a.loadArchive(ctx, owner, name, commit, request.Revision().Algorithm(), files)
	if acquisitionFailure != nil {
		return acquisitionFailure.result()
	}
	manifestFiles := make([]evidence.RepositoryFile, 0, len(contents))
	for filePath, content := range contents {
		file, err := evidence.NewRepositoryFile(filePath, content)
		if err != nil {
			clearContents(contents)
			return failed(evidence.AcquisitionReasonArtifactIncomplete)
		}
		manifestFiles = append(manifestFiles, file)
	}
	manifest, err := evidence.NewRepositoryManifest(manifestFiles)
	if err != nil {
		clearContents(contents)
		return failed(evidence.AcquisitionReasonArtifactIncomplete)
	}
	if request.Artifact() == evidence.AcquisitionArtifactManifest {
		clearContents(contents)
		contents = nil
	}
	return scm.SourceAdapterResult{
		Outcome:  evidence.AcquisitionOutcomeAcquired,
		Reason:   evidence.AcquisitionReasonNone,
		Manifest: manifest,
		Contents: contents,
	}
}

func (a *Adapter) requestMatches(request evidence.RepositoryAcquisitionRequest) bool {
	repository := request.Repository()
	namespace := repository.Namespace()
	if request.SourceAdapterIdentity() != a.identity.Identity() || repository.Authority() != a.repositoryAuthority ||
		len(namespace) != 1 || !validRepositorySlug(namespace[0]) || !validRepositorySlug(repository.Name()) ||
		request.Effect() != evidence.AcquisitionEffectReadOnly {
		return false
	}
	revision := request.Revision()
	if revision.Kind() != evidence.RevisionKindGitCommit ||
		(revision.Algorithm() != evidence.RevisionAlgorithmSHA1 && revision.Algorithm() != evidence.RevisionAlgorithmSHA256) {
		return false
	}
	return request.Artifact() == evidence.AcquisitionArtifactManifest ||
		request.Artifact() == evidence.AcquisitionArtifactManifestAndContent
}

func validRepositorySlug(value string) bool {
	if value == "" || len(value) > 255 || value != strings.ToLower(value) {
		return false
	}
	for _, candidate := range value {
		if candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' ||
			candidate == '.' || candidate == '_' || candidate == '-' {
			continue
		}
		return false
	}
	return true
}

type acquisitionFailure struct {
	outcome evidence.RepositoryAcquisitionOutcome
	reason  evidence.RepositoryAcquisitionReason
}

func (f *acquisitionFailure) result() scm.SourceAdapterResult {
	if f == nil {
		return scm.SourceAdapterResult{}
	}
	return scm.SourceAdapterResult{Outcome: f.outcome, Reason: f.reason}
}

func blocked(reason evidence.RepositoryAcquisitionReason) scm.SourceAdapterResult {
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeBlocked, Reason: reason}
}
func failed(reason evidence.RepositoryAcquisitionReason) scm.SourceAdapterResult {
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: reason}
}
func blockedFailure(reason evidence.RepositoryAcquisitionReason) *acquisitionFailure {
	return &acquisitionFailure{outcome: evidence.AcquisitionOutcomeBlocked, reason: reason}
}
func failedFailure(reason evidence.RepositoryAcquisitionReason) *acquisitionFailure {
	return &acquisitionFailure{outcome: evidence.AcquisitionOutcomeFailed, reason: reason}
}

func (a *Adapter) loadCommit(ctx context.Context, owner, repository, commit string) (string, *acquisitionFailure) {
	body, status, headers, failure := a.apiGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repository)+"/git/commits/"+commit, nil, maximumMetadataBytes)
	if failure != nil {
		return "", failure
	}
	if status != http.StatusOK {
		return "", classifyStatus(status, headers)
	}
	var wire struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if decodeJSON(body, &wire) != nil || wire.SHA != commit || !validObjectID(wire.Tree.SHA, len(commit)) {
		return "", failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	return wire.Tree.SHA, nil
}

type treeFile struct {
	mode string
	sha  string
	size int64
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size *int64 `json:"size"`
}

func (a *Adapter) loadTree(ctx context.Context, owner, repository, rootTree string, algorithm evidence.RevisionAlgorithm) (map[string]treeFile, *acquisitionFailure) {
	body, status, headers, failure := a.apiGet(
		ctx,
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repository)+"/git/trees/"+rootTree,
		url.Values{"recursive": []string{"1"}},
		maximumMetadataBytes,
	)
	if failure != nil {
		return nil, failure
	}
	if status != http.StatusOK {
		return nil, classifyStatus(status, headers)
	}
	var wire struct {
		SHA       string      `json:"sha"`
		Truncated bool        `json:"truncated"`
		Tree      []treeEntry `json:"tree"`
	}
	if decodeJSON(body, &wire) != nil || wire.SHA != rootTree {
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	if wire.Truncated || len(wire.Tree) > maximumTreeEntries {
		return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
	}
	objectIDBytes := objectIDDigestBytes(algorithm)
	files := make(map[string]treeFile)
	seen := make(map[string]struct{}, len(wire.Tree))
	var totalBytes int64
	for _, entry := range wire.Tree {
		if _, err := evidence.NewRepositoryFile(entry.Path, nil); err != nil {
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		if _, exists := seen[entry.Path]; exists {
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		seen[entry.Path] = struct{}{}
		switch entry.Type {
		case "tree":
			if entry.Mode != "040000" || !validObjectID(entry.SHA, objectIDBytes*2) {
				return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
			}
		case "blob":
			validMode := entry.Mode == "100644" || entry.Mode == "100755" || entry.Mode == "120000"
			if !validMode || entry.Size == nil || *entry.Size < 0 || *entry.Size > maximumFileBytes ||
				!validObjectID(entry.SHA, objectIDBytes*2) {
				return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
			}
			if totalBytes > maximumExtractedBytes-*entry.Size {
				return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
			}
			totalBytes += *entry.Size
			files[entry.Path] = treeFile{mode: entry.Mode, sha: entry.SHA, size: *entry.Size}
		case "commit":
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		default:
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
	}
	if !verifyTreeGraph(algorithm, rootTree, wire.Tree) {
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	return files, nil
}

func verifyTreeGraph(algorithm evidence.RevisionAlgorithm, rootTree string, entries []treeEntry) bool {
	expectedTrees := map[string]string{"": rootTree}
	children := make(map[string][]treeEntry)
	for _, entry := range entries {
		parent := path.Dir(entry.Path)
		if parent == "." {
			parent = ""
		}
		children[parent] = append(children[parent], entry)
		if entry.Type == "tree" {
			expectedTrees[entry.Path] = entry.SHA
		}
	}
	for parent := range children {
		if _, exists := expectedTrees[parent]; !exists {
			return false
		}
	}
	for treePath, expected := range expectedTrees {
		members := append([]treeEntry(nil), children[treePath]...)
		sort.Slice(members, func(first, second int) bool {
			return treeSortKey(members[first]) < treeSortKey(members[second])
		})
		var raw bytes.Buffer
		for _, member := range members {
			mode := member.Mode
			if member.Type == "tree" {
				mode = "40000"
			}
			objectID, err := hex.DecodeString(member.SHA)
			if err != nil {
				return false
			}
			raw.WriteString(mode)
			raw.WriteByte(' ')
			raw.WriteString(path.Base(member.Path))
			raw.WriteByte(0)
			raw.Write(objectID)
		}
		if gitObjectID(algorithm, "tree", raw.Bytes()) != expected {
			return false
		}
	}
	return true
}

func treeSortKey(entry treeEntry) string {
	key := path.Base(entry.Path)
	if entry.Type == "tree" {
		key += "/"
	}
	return key
}

func objectIDDigestBytes(algorithm evidence.RevisionAlgorithm) int {
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		return sha1.Size
	}
	return sha256.Size
}

func validObjectID(value string, expectedLength int) bool {
	if len(value) != expectedLength || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func (a *Adapter) loadArchive(
	ctx context.Context,
	owner, repository, commit string,
	algorithm evidence.RevisionAlgorithm,
	files map[string]treeFile,
) (map[string][]byte, *acquisitionFailure) {
	archivePath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository) + "/tarball/" + commit
	status, location, headers, failure := a.apiRedirect(ctx, archivePath)
	if failure != nil {
		return nil, failure
	}
	if status != http.StatusMovedPermanently && status != http.StatusFound &&
		status != http.StatusTemporaryRedirect && status != http.StatusPermanentRedirect {
		return nil, classifyStatus(status, headers)
	}
	archiveURL, err := url.Parse(location)
	if err != nil || !a.validArchiveURL(archiveURL, owner, repository, commit) {
		return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
	}
	response, failure := a.archiveGet(ctx, archiveURL)
	if failure != nil {
		return nil, failure
	}
	if response.StatusCode != http.StatusOK {
		statusFailure := classifyStatus(response.StatusCode, response.Header)
		drainAndClose(response.Body)
		return nil, statusFailure
	}
	contents, extractionFailure := extractArchive(ctx, response, algorithm, files)
	if extractionFailure != nil {
		return nil, extractionFailure
	}
	return contents, nil
}

func (a *Adapter) apiGet(ctx context.Context, requestPath string, query url.Values, maximum int64) ([]byte, int, http.Header, *acquisitionFailure) {
	request, cleanup, failure := a.apiRequest(ctx, requestPath, query)
	if failure != nil {
		return nil, 0, nil, failure
	}
	defer cleanup()
	response, err := a.httpClient.Do(request)
	if err != nil || response == nil {
		return nil, 0, nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if response.StatusCode != http.StatusOK {
		status, headers := response.StatusCode, response.Header.Clone()
		drainAndClose(response.Body)
		return nil, status, headers, nil
	}
	body, ok := readBounded(response, maximum)
	if !ok {
		return nil, 0, nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
	}
	return body, response.StatusCode, nil, nil
}

func (a *Adapter) apiRedirect(ctx context.Context, requestPath string) (int, string, http.Header, *acquisitionFailure) {
	request, cleanup, failure := a.apiRequest(ctx, requestPath, nil)
	if failure != nil {
		return 0, "", nil, failure
	}
	defer cleanup()
	response, err := a.httpClient.Do(request)
	if err != nil || response == nil {
		return 0, "", nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	status, location, headers := response.StatusCode, response.Header.Get("Location"), response.Header.Clone()
	drainAndClose(response.Body)
	return status, location, headers, nil
}

func (a *Adapter) apiRequest(ctx context.Context, requestPath string, query url.Values) (*http.Request, func(), *acquisitionFailure) {
	if ctx.Err() != nil {
		return nil, nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	requestURL := *a.apiEndpoint
	requestURL.Path += requestPath
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", a.apiVersion)
	if a.installationBroker != nil {
		op, err := operationFromContext(ctx, a.installationBroker)
		if err != nil {
			return nil, nil, brokerAcquisitionFailure(err)
		}
		lease, err := a.installationBroker.borrow(op)
		if err != nil {
			return nil, nil, brokerAcquisitionFailure(err)
		}
		bound, cleanup, err := lease.bindSourceRequest(request)
		if err != nil {
			lease.release()
			return nil, nil, brokerAcquisitionFailure(err)
		}
		return bound, cleanup, nil
	}
	if !nilInterface(a.credentials) {
		token, err := a.credentials.Retrieve(ctx)
		if ctx.Err() != nil {
			return nil, nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
		}
		if err != nil || token.Validate() != nil {
			return nil, nil, blockedFailure(evidence.AcquisitionReasonAuthorizationRequired)
		}
		request.Header.Set("Authorization", "Bearer "+token.value)
	}
	return request, func() {}, nil
}

func brokerAcquisitionFailure(err error) *acquisitionFailure {
	if errors.Is(err, ErrBrokerUnavailable) || errors.Is(err, ErrBrokerCloseIncomplete) {
		return blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if errors.Is(err, ErrInvalidBrokerConfig) || errors.Is(err, ErrBrokerMismatch) {
		return blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
	}
	return blockedFailure(evidence.AcquisitionReasonAuthorizationRequired)
}

func (a *Adapter) validArchiveURL(candidate *url.URL, owner, repository, commit string) bool {
	if candidate == nil || candidate.User != nil || candidate.Fragment != "" || candidate.Host == "" {
		return false
	}
	if _, allowed := a.archiveAuthorityIndex[strings.ToLower(candidate.Host)]; !allowed {
		return false
	}
	if candidate.Scheme != "https" {
		address := net.ParseIP(candidate.Hostname())
		if candidate.Scheme != "http" || address == nil || !address.IsLoopback() {
			return false
		}
	}
	prefix := "/" + owner + "/" + repository + "/"
	return strings.HasPrefix(candidate.Path, prefix) && path.Base(candidate.Path) == commit
}

func (a *Adapter) archiveGet(ctx context.Context, archiveURL *url.URL) (*http.Response, *acquisitionFailure) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL.String(), nil)
	if err != nil {
		return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := a.httpClient.Do(request)
	if err != nil || response == nil {
		return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		drainAndClose(response.Body)
		return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
	}
	return response, nil
}

func classifyStatus(status int, headers http.Header) *acquisitionFailure {
	if status == http.StatusForbidden && (headers.Get("X-RateLimit-Remaining") == "0" || headers.Get("Retry-After") != "") {
		return blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return blockedFailure(evidence.AcquisitionReasonAuthorizationRequired)
	case http.StatusRequestEntityTooLarge:
		return failedFailure(evidence.AcquisitionReasonResourceLimit)
	case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if status >= 500 {
		return blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	return failedFailure(evidence.AcquisitionReasonAdapterFailure)
}

func extractArchive(
	ctx context.Context,
	response *http.Response,
	algorithm evidence.RevisionAlgorithm,
	files map[string]treeFile,
) (map[string][]byte, *acquisitionFailure) {
	return extractArchiveWithinLimits(ctx, response, algorithm, files, maximumInflatedArchiveBytes, maximumTreeEntries+1)
}

func extractArchiveWithinLimits(ctx context.Context, response *http.Response, algorithm evidence.RevisionAlgorithm, files map[string]treeFile, inflatedLimit int64, entryLimit int) (map[string][]byte, *acquisitionFailure) {
	if ctx == nil || ctx.Err() != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if inflatedLimit <= 0 || inflatedLimit > maximumInflatedArchiveBytes || entryLimit <= 0 || entryLimit > maximumTreeEntries+1 {
		return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
	}
	if response == nil || response.Body == nil {
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	defer response.Body.Close()
	if response.ContentLength > maximumCompressedBytes {
		drainAndClose(response.Body)
		return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
	}
	limited := &io.LimitedReader{R: archiveContextReader{ctx: ctx, reader: response.Body}, N: maximumCompressedBytes + 1}
	gzipReader, err := gzip.NewReader(limited)
	if err != nil {
		if ctx.Err() != nil {
			return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
		}
		if limited.N == 0 {
			return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
		}
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	defer gzipReader.Close()
	inflated := &io.LimitedReader{R: archiveContextReader{ctx: ctx, reader: gzipReader}, N: inflatedLimit + 1}
	tarReader := tar.NewReader(inflated)
	contents := make(map[string][]byte, len(files))
	root := ""
	var extracted int64
	entries := 0
	for {
		header, err := tarReader.Next()
		if ctx.Err() != nil {
			clearContents(contents)
			return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
		}
		if inflated.N == 0 || limited.N == 0 {
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil {
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		entries++
		if entries > entryLimit {
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
		}
		filePath, currentRoot, ok := archivePath(header.Name, root)
		if !ok {
			clearContents(contents)
			return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
		}
		root = currentRoot
		if filePath == "" || header.Typeflag == tar.TypeDir {
			if header.Typeflag != tar.TypeDir || header.Size != 0 {
				clearContents(contents)
				return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
			}
			continue
		}
		expected, exists := files[filePath]
		if !exists {
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		if _, duplicate := contents[filePath]; duplicate {
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		var content []byte
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if expected.mode == "120000" || header.Size != expected.size || header.Size < 0 || header.Size > maximumFileBytes {
				clearContents(contents)
				return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
			}
			content = make([]byte, int(header.Size))
			_, readErr := io.ReadFull(tarReader, content)
			if readErr != nil || inflated.N == 0 || limited.N == 0 || ctx.Err() != nil {
				clear(content)
				clearContents(contents)
				if ctx.Err() != nil {
					return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
				}
				if inflated.N == 0 || limited.N == 0 {
					return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
				}
				return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
			}
		case tar.TypeSymlink:
			if expected.mode != "120000" || int64(len(header.Linkname)) != expected.size {
				clearContents(contents)
				return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
			}
			content = []byte(header.Linkname)
		default:
			clearContents(contents)
			return nil, blockedFailure(evidence.AcquisitionReasonPolicyBlocked)
		}
		if extracted > maximumExtractedBytes-int64(len(content)) {
			clear(content)
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
		}
		extracted += int64(len(content))
		if gitBlobObjectID(algorithm, content) != expected.sha {
			clear(content)
			clearContents(contents)
			return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
		}
		contents[filePath] = content
	}
	_, inflateErr := io.Copy(io.Discard, inflated)
	if ctx.Err() != nil {
		clearContents(contents)
		return nil, blockedFailure(evidence.AcquisitionReasonAdapterUnavailable)
	}
	if inflated.N == 0 || limited.N == 0 {
		clearContents(contents)
		return nil, failedFailure(evidence.AcquisitionReasonResourceLimit)
	}
	if inflateErr != nil {
		clearContents(contents)
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	if len(contents) != len(files) {
		clearContents(contents)
		return nil, failedFailure(evidence.AcquisitionReasonArtifactIncomplete)
	}
	return contents, nil
}

type archiveContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r archiveContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(buffer) > 64<<10 {
		buffer = buffer[:64<<10]
	}
	return r.reader.Read(buffer)
}

func archivePath(name, root string) (string, string, bool) {
	if name == "" || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.ContainsRune(name, '\\') {
		return "", root, false
	}
	trimmed := strings.TrimSuffix(name, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if parts[0] == "" || parts[0] == "." || parts[0] == ".." {
		return "", root, false
	}
	if root == "" {
		root = parts[0]
	}
	if parts[0] != root {
		return "", root, false
	}
	if len(parts) == 1 {
		return "", root, true
	}
	if _, err := evidence.NewRepositoryFile(parts[1], nil); err != nil {
		return "", root, false
	}
	return parts[1], root, true
}

func gitBlobObjectID(algorithm evidence.RevisionAlgorithm, content []byte) string {
	return gitObjectID(algorithm, "blob", content)
}

func gitObjectID(algorithm evidence.RevisionAlgorithm, kind string, content []byte) string {
	header := []byte(kind + " " + strconv.Itoa(len(content)) + "\x00")
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		hash := sha1.New()
		_, _ = hash.Write(header)
		_, _ = hash.Write(content)
		return hex.EncodeToString(hash.Sum(nil))
	}
	hash := sha256.New()
	_, _ = hash.Write(header)
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func decodeJSON(content []byte, target any) error {
	if err := validateJSON(content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || key == "" || key != strings.ToLower(key) {
				return ErrInvalidConfig
			}
			if _, exists := keys[key]; exists {
				return ErrInvalidConfig
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeDelimiter(decoder, ']')
	default:
		return ErrInvalidConfig
	}
}

func consumeDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return ErrInvalidConfig
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return ErrInvalidConfig
	}
	return nil
}

func readBounded(response *http.Response, maximum int64) ([]byte, bool) {
	if response == nil || response.Body == nil || response.ContentLength > maximum {
		if response != nil {
			drainAndClose(response.Body)
		}
		return nil, false
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(content) == 0 || int64(len(content)) > maximum {
		clear(content)
		return nil, false
	}
	return content, true
}

func clearContents(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maximumErrorBodyBytes))
	_ = body.Close()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func writeRedacted(state fmt.State, verb rune, normal, detailed string) {
	value := normal
	if verb == 'q' {
		value = strconv.Quote(normal)
	} else if verb == 'v' && state.Flag('#') {
		value = detailed
	}
	_, _ = state.Write([]byte(value))
}

func (a *Adapter) String() string   { return "GitHub source adapter" }
func (a *Adapter) GoString() string { return "github.Adapter{<redacted>}" }
func (a *Adapter) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "GitHub source adapter", "github.Adapter{<redacted>}")
}

var _ scm.SourceAdapter = (*Adapter)(nil)
