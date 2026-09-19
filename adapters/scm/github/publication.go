package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

const (
	maximumPublicationBodyBytes     = 64 << 10
	maximumPublicationRequestBytes  = 512 << 10
	maximumPublicationResponseBytes = 1 << 20
)

var (
	ErrInvalidPublicationConfig          = errors.New("invalid GitHub publication adapter configuration")
	ErrPublicationCredentialsUnavailable = errors.New("GitHub publication credentials unavailable")
)

type PublicationClock interface{ Now() time.Time }
type systemPublicationClock struct{}

func (systemPublicationClock) Now() time.Time { return time.Now().UTC() }

// PublicationTokenProvider retrieves exact-scope write credentials at request time.
type PublicationTokenProvider interface {
	RetrievePublicationToken(context.Context, audit.ReviewScope, review.PublicationTarget) (Token, error)
}

type PublicationConfig struct {
	PublisherID, RepositoryAuthority, APIEndpoint, APIVersion string
	Credentials                                               PublicationTokenProvider
	CredentialIdentity                                        string
	AttemptGuard                                              review.PublicationAttemptGuard
	HTTPClient                                                *http.Client
	HTTPClientIdentity                                        string
	Clock                                                     PublicationClock
	ClockIdentity                                             string
}
type PublicationAdapter struct {
	publisherID, repositoryAuthority, apiVersion string
	endpoint                                     *url.URL
	credentials                                  PublicationTokenProvider
	credentialIdentity                           string
	guard                                        review.PublicationAttemptGuard
	client                                       *http.Client
	httpClientIdentity                           string
	clock                                        PublicationClock
	clockIdentity                                string
	configurationIdentity                        string
}

func NewPublicationAdapter(config PublicationConfig) (*PublicationAdapter, error) {
	endpointValue := config.APIEndpoint
	if endpointValue == "" {
		endpointValue = defaultAPIEndpoint
	}
	version := config.APIVersion
	if version == "" {
		version = defaultAPIVersion
	}
	endpoint, err := url.Parse(endpointValue)
	if err != nil || review.ValidatePublisherID(config.PublisherID) != nil || !validRepositoryAuthority(config.RepositoryAuthority) || !validEndpoint(endpoint) || !validAPIVersion(version) || nilInterface(config.Credentials) || !validNonzeroConfigurationIdentity(config.CredentialIdentity) || nilInterface(config.AttemptGuard) || !validDigest(config.AttemptGuard.Identity()) || config.AttemptGuard.IdempotencyGuarantee().Validate() != nil {
		return nil, ErrInvalidPublicationConfig
	}
	clock := config.Clock
	clockIdentity := config.ClockIdentity
	if clock == nil {
		if clockIdentity != "" {
			return nil, ErrInvalidPublicationConfig
		}
		clock = systemPublicationClock{}
		clockIdentity = defaultPublicationClockIdentity()
	} else if !validNonzeroConfigurationIdentity(clockIdentity) {
		return nil, ErrInvalidPublicationConfig
	}
	if nilInterface(clock) {
		return nil, ErrInvalidPublicationConfig
	}
	httpIdentity := config.HTTPClientIdentity
	if config.HTTPClient == nil {
		if httpIdentity != "" {
			return nil, ErrInvalidPublicationConfig
		}
		httpIdentity = defaultPublicationHTTPClientIdentity()
	} else if !validNonzeroConfigurationIdentity(httpIdentity) {
		return nil, ErrInvalidPublicationConfig
	}
	client, err := boundedClient(config.HTTPClient)
	if err != nil {
		return nil, ErrInvalidPublicationConfig
	}
	copy := *endpoint
	copy.Path = strings.TrimSuffix(copy.Path, "/")
	adapter := &PublicationAdapter{publisherID: strings.Clone(config.PublisherID), repositoryAuthority: strings.Clone(config.RepositoryAuthority), apiVersion: strings.Clone(version), endpoint: &copy, credentials: config.Credentials, credentialIdentity: strings.Clone(config.CredentialIdentity), guard: config.AttemptGuard, client: client, httpClientIdentity: strings.Clone(httpIdentity), clock: clock, clockIdentity: strings.Clone(clockIdentity)}
	adapter.configurationIdentity = derivePublicationAdapterConfigurationIdentity(adapter)
	if adapter.Validate() != nil {
		return nil, ErrInvalidPublicationConfig
	}
	return adapter, nil
}
func (a *PublicationAdapter) ConfigurationIdentity() string {
	if a == nil {
		return ""
	}
	return a.configurationIdentity
}
func derivePublicationAdapterConfigurationIdentity(a *PublicationAdapter) string {
	if a == nil || a.endpoint == nil || a.client == nil {
		return ""
	}
	encoded, _ := json.Marshal(struct {
		Contract     string `json:"contract"`
		Version      int    `json:"version"`
		Publisher    string `json:"publisher"`
		Authority    string `json:"authority"`
		Endpoint     string `json:"endpoint"`
		APIVersion   string `json:"api_version"`
		Credential   string `json:"credential"`
		AttemptGuard string `json:"attempt_guard"`
		HTTPClient   string `json:"http_client"`
		Timeout      int64  `json:"timeout_milliseconds"`
		Clock        string `json:"clock"`
	}{"open-trestle/github-publication-adapter", 2, a.publisherID, a.repositoryAuthority, a.endpoint.String(), a.apiVersion, a.credentialIdentity, a.guard.Identity(), a.httpClientIdentity, a.client.Timeout.Milliseconds(), a.clockIdentity})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func defaultPublicationHTTPClientIdentity() string {
	sum := sha256.Sum256([]byte("open-trestle/github-publication-default-http-client/v1"))
	return hex.EncodeToString(sum[:])
}
func defaultPublicationClockIdentity() string {
	sum := sha256.Sum256([]byte("open-trestle/github-publication-system-clock/v1"))
	return hex.EncodeToString(sum[:])
}
func validNonzeroConfigurationIdentity(value string) bool {
	if !validDigest(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, entry := range decoded {
		if entry != 0 {
			return true
		}
	}
	return false
}

func (a *PublicationAdapter) PublisherID() string {
	if a == nil {
		return ""
	}
	return a.publisherID
}
func (a *PublicationAdapter) ResolverID() string { return a.PublisherID() }
func (a *PublicationAdapter) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}
func (a *PublicationAdapter) Validate() error {
	if a == nil || review.ValidatePublisherID(a.publisherID) != nil || !validRepositoryAuthority(a.repositoryAuthority) || a.endpoint == nil || !validEndpoint(a.endpoint) || !validAPIVersion(a.apiVersion) || nilInterface(a.credentials) || !validNonzeroConfigurationIdentity(a.credentialIdentity) || nilInterface(a.guard) || !validDigest(a.guard.Identity()) || a.guard.IdempotencyGuarantee().Validate() != nil || a.client == nil || !validNonzeroConfigurationIdentity(a.httpClientIdentity) || nilInterface(a.clock) || !validNonzeroConfigurationIdentity(a.clockIdentity) || a.configurationIdentity != derivePublicationAdapterConfigurationIdentity(a) || a.client.Timeout <= 0 || a.client.Timeout > maximumRequestTimeout {
		return ErrInvalidPublicationConfig
	}
	return nil
}
func (a *PublicationAdapter) ResolveHead(ctx context.Context, request review.PublicationHeadRequest) review.PublicationHeadObservation {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || request.Validate() != nil || request.Scope().Identity() == "" {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	return a.resolveTargetHead(ctx, request.Scope(), request.Target())
}
func (a *PublicationAdapter) resolveTargetHead(ctx context.Context, scope audit.ReviewScope, target review.PublicationTarget) review.PublicationHeadObservation {
	owner, repo, number, ok := a.targetCoordinates(target)
	if ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !ok {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	token, err := a.credentials.RetrievePublicationToken(ctx, scope, target)
	if err != nil || token.Validate() != nil {
		return failedHead(review.PublicationHeadFailureAuthorization)
	}
	response, err := a.do(ctx, http.MethodGet, a.apiURL(owner, repo, "pulls", number), token, nil)
	if err != nil {
		return failedHead(classifyHeadTransport(ctx, err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		discardBounded(response.Body, maximumErrorBodyBytes)
		return failedHead(classifyHeadStatus(response.StatusCode))
	}
	if !isJSONResponse(response) {
		discardBounded(response.Body, maximumErrorBodyBytes)
		return failedHead(review.PublicationHeadFailureProvider)
	}
	body, ok := readLimited(response.Body, maximumPublicationResponseBytes)
	if !ok {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	var wire struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if decodeJSON(body, &wire) != nil {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, target.HeadRevision().Algorithm(), wire.Head.SHA)
	if err != nil {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	result, err := review.NewResolvedPublicationHeadObservation(head)
	if err != nil {
		return failedHead(review.PublicationHeadFailureProvider)
	}
	return result
}

func (a *PublicationAdapter) Publish(ctx context.Context, request review.PublicationDispatchRequest) review.PublicationResult {
	if ctx == nil || ctx.Err() != nil {
		return failedPublication(review.PublicationFailureCancelled, 0)
	}
	if a.Validate() != nil || request.Validate() != nil {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	payload, err := publicationPayload(request)
	if err != nil {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	return a.dispatchPublication(ctx, request, payload)
}
func (a *PublicationAdapter) dispatchPublication(ctx context.Context, request review.PublicationDispatchRequest, payload reviewPayloadWire) review.PublicationResult {
	scope, target := request.Scope(), request.Authorization().Plan().Target()
	operationKey, attemptIdentity := request.IdempotencyKey(), request.Attempt().Identity()
	owner, repo, number, ok := a.targetCoordinates(target)
	if ctx == nil || ctx.Err() != nil {
		return failedPublication(review.PublicationFailureCancelled, 0)
	}
	if request.Validate() != nil || !ok {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > maximumPublicationRequestBytes {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	binding, _ := json.Marshal(struct {
		Scope     string `json:"scope"`
		Target    string `json:"target"`
		Operation string `json:"operation"`
		Payload   string `json:"payload"`
	}{scope.Identity(), target.Identity(), operationKey, hashBytes(encoded)})
	requestDigest := hashBytes(binding)
	at := a.clock.Now().UTC()
	if at.UnixMilli() <= 0 {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	claimed, err := a.guard.ClaimPublicationAttempt(ctx, scope, operationKey, attemptIdentity, requestDigest, at)
	if err != nil {
		return failedPublication(review.PublicationFailureTransient, 0)
	}
	if !claimed {
		return failedPublication(review.PublicationFailureValidation, 0)
	}
	token, err := a.credentials.RetrievePublicationToken(ctx, scope, target)
	if err != nil || token.Validate() != nil {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureAuthorization, 0))
	}
	if ctx.Err() != nil {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureCancelled, 0))
	}
	remaining, err := request.RemainingDispatchTime(a.clock.Now().UTC())
	if err != nil {
		failure := review.PublicationFailureValidation
		switch {
		case errors.Is(err, review.ErrPublicationNotAuthorized):
			failure = review.PublicationFailureAuthorization
		case errors.Is(err, review.ErrPublicationHeadNotCurrent):
			failure = review.PublicationFailureStaleHead
		}
		return a.complete(ctx, scope, attemptIdentity, failedPublication(failure, 0))
	}
	dispatchContext, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	response, err := a.do(dispatchContext, http.MethodPost, a.apiURL(owner, repo, "pulls", number, "reviews"), token, encoded)
	if err != nil {
		failure := review.PublicationFailureProvider
		if ctx.Err() != nil {
			failure = review.PublicationFailureCancelled
		}
		return a.complete(ctx, scope, attemptIdentity, failedPublication(failure, 0))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result := classifyPublicationStatus(response)
		discardBounded(response.Body, maximumErrorBodyBytes)
		return a.complete(ctx, scope, attemptIdentity, result)
	}
	if !isJSONResponse(response) {
		discardBounded(response.Body, maximumErrorBodyBytes)
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureProvider, 0))
	}
	body, ok := readLimited(response.Body, maximumPublicationResponseBytes)
	if !ok {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureProvider, 0))
	}
	var wire struct {
		ID       json.Number `json:"id"`
		CommitID string      `json:"commit_id"`
	}
	if decodeJSON(body, &wire) != nil {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureProvider, 0))
	}
	id, err := strconv.ParseInt(string(wire.ID), 10, 64)
	if err != nil || id <= 0 || wire.CommitID != target.HeadRevision().Digest() {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureProvider, 0))
	}
	result, err := review.NewSuccessfulPublicationResult("github-review:" + strconv.FormatInt(id, 10))
	if err != nil {
		return a.complete(ctx, scope, attemptIdentity, failedPublication(review.PublicationFailureProvider, 0))
	}
	return a.complete(ctx, scope, attemptIdentity, result)
}

func (a *PublicationAdapter) complete(ctx context.Context, scope audit.ReviewScope, attemptIdentity string, result review.PublicationResult) review.PublicationResult {
	if ctx != nil && ctx.Err() == nil {
		at := a.clock.Now().UTC()
		if at.UnixMilli() > 0 {
			_ = a.guard.CompletePublicationAttempt(ctx, scope, attemptIdentity, result.Identity(), at)
		}
	}
	return result
}

func (a *PublicationAdapter) targetCoordinates(target review.PublicationTarget) (string, string, string, bool) {
	if target.Validate() != nil || target.PublisherID() != a.publisherID || target.RepositoryIdentity().Authority() != a.repositoryAuthority {
		return "", "", "", false
	}
	namespace := target.RepositoryIdentity().Namespace()
	if len(namespace) != 1 || !validGitHubOwner(namespace[0]) || !validGitHubRepository(target.RepositoryIdentity().Name()) {
		return "", "", "", false
	}
	number, err := strconv.ParseUint(target.ChangeID(), 10, 64)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != target.ChangeID() {
		return "", "", "", false
	}
	return namespace[0], target.RepositoryIdentity().Name(), target.ChangeID(), true
}
func validGitHubOwner(value string) bool {
	if len(value) == 0 || len(value) > 39 || value[0] == '-' || value[len(value)-1] == '-' || strings.Contains(value, "--") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}
func validGitHubRepository(value string) bool {
	if len(value) == 0 || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (a *PublicationAdapter) apiURL(parts ...string) string {
	endpoint := *a.endpoint
	path := strings.TrimSuffix(endpoint.Path, "/")
	for _, part := range append([]string{"repos"}, parts...) {
		path += "/" + part
	}
	endpoint.Path = path
	return endpoint.String()
}
func (a *PublicationAdapter) do(ctx context.Context, method, endpoint string, token Token, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token.value)
	request.Header.Set("X-GitHub-Api-Version", a.apiVersion)
	request.Header.Set("User-Agent", "open-trestle-github-publication/1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(request)
}

type reviewPayloadWire struct {
	CommitID string              `json:"commit_id"`
	Body     string              `json:"body"`
	Event    string              `json:"event"`
	Comments []reviewCommentWire `json:"comments,omitempty"`
}
type reviewCommentWire struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Side      string `json:"side"`
	StartLine int    `json:"start_line,omitempty"`
	StartSide string `json:"start_side,omitempty"`
	Body      string `json:"body"`
}

func publicationPayload(request review.PublicationDispatchRequest) (reviewPayloadWire, error) {
	plan := request.Authorization().Plan()
	target := plan.Target()
	var summary strings.Builder
	summary.WriteString("## Open Trestle verified review\n\n")
	inline := plan.InlineFindings()
	summaryOnly := plan.SummaryOnlyFindings()
	comments := make([]reviewCommentWire, 0, len(inline))
	if len(inline) > 0 {
		summary.WriteString("### Inline findings\n\n")
	}
	for _, finding := range inline {
		if finding.Validate() != nil {
			return reviewPayloadWire{}, ErrInvalidPublicationConfig
		}
		source := finding.SourceRange()
		fmt.Fprintf(&summary, "- **%s: %s** (`%s:%d-%d`)\n", strings.ToUpper(string(finding.Severity())), escapeMarkdown(finding.Title()), escapeMarkdown(source.Path()), source.StartLine(), source.EndLine())
		body := renderFinding(finding)
		if len(body) > maximumPublicationBodyBytes {
			return reviewPayloadWire{}, ErrInvalidPublicationConfig
		}
		comment := reviewCommentWire{Path: source.Path(), Line: source.EndLine(), Side: "RIGHT", Body: body}
		if source.StartLine() != source.EndLine() {
			comment.StartLine = source.StartLine()
			comment.StartSide = "RIGHT"
		}
		comments = append(comments, comment)
	}
	if len(summaryOnly) > 0 {
		summary.WriteString("\n### Summary findings\n")
	}
	for _, finding := range summaryOnly {
		if finding.Validate() != nil {
			return reviewPayloadWire{}, ErrInvalidPublicationConfig
		}
		source := finding.SourceRange()
		fmt.Fprintf(&summary, "\n#### %s: %s\n\nPath: `%s:%d-%d`\n\n%s\n", strings.ToUpper(string(finding.Severity())), escapeMarkdown(finding.Title()), escapeMarkdown(source.Path()), source.StartLine(), source.EndLine(), escapeMarkdown(finding.Claim()))
	}
	fmt.Fprintf(&summary, "\n<!-- open-trestle-operation:%s -->", request.IdempotencyKey())
	if summary.Len() > maximumPublicationBodyBytes {
		return reviewPayloadWire{}, ErrInvalidPublicationConfig
	}
	return reviewPayloadWire{CommitID: target.HeadRevision().Digest(), Body: summary.String(), Event: "COMMENT", Comments: comments}, nil
}
func renderFinding(finding review.VerifiedFinding) string {
	source := finding.SourceRange()
	return fmt.Sprintf("**%s: %s**\n\n%s\n\nLocation: `%s:%d-%d`", strings.ToUpper(string(finding.Severity())), escapeMarkdown(finding.Title()), escapeMarkdown(finding.Claim()), escapeMarkdown(source.Path()), source.StartLine(), source.EndLine())
}
func escapeMarkdown(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "@", "@\u200b", "\\", "\\\\", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "#", "\\#", "!", "\\!", "|", "\\|", "`", "\\`", "~", "\\~")
	return replacer.Replace(value)
}
func classifyHeadTransport(ctx context.Context, err error) review.PublicationHeadFailure {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return review.PublicationHeadFailureTransient
	}
	return review.PublicationHeadFailureTransient
}
func classifyHeadStatus(status int) review.PublicationHeadFailure {
	switch {
	case status == http.StatusNotFound:
		return review.PublicationHeadFailureNotFound
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return review.PublicationHeadFailureAuthorization
	case status == http.StatusTooManyRequests || status >= 500:
		return review.PublicationHeadFailureTransient
	default:
		return review.PublicationHeadFailureProvider
	}
}
func classifyPublicationStatus(response *http.Response) review.PublicationResult {
	status := response.StatusCode
	if status == http.StatusTooManyRequests || status == http.StatusForbidden && response.Header.Get("Retry-After") != "" {
		return failedPublication(review.PublicationFailureRateLimited, retryAfterMillis(response.Header.Get("Retry-After")))
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return failedPublication(review.PublicationFailureAuthorization, 0)
	case status == http.StatusConflict:
		return failedPublication(review.PublicationFailureStaleHead, 0)
	case status == http.StatusUnprocessableEntity || status == http.StatusNotFound:
		return failedPublication(review.PublicationFailureValidation, 0)
	default:
		return failedPublication(review.PublicationFailureProvider, 0)
	}
}
func retryAfterMillis(value string) uint32 {
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil || seconds == 0 || seconds > 86_400 {
		return 0
	}
	return uint32(seconds * 1000)
}
func failedHead(failure review.PublicationHeadFailure) review.PublicationHeadObservation {
	result, _ := review.NewFailedPublicationHeadObservation(failure)
	return result
}
func failedPublication(failure review.PublicationFailure, retry uint32) review.PublicationResult {
	result, err := review.NewFailedPublicationResult(failure, retry)
	if err != nil {
		result, _ = review.NewFailedPublicationResult(review.PublicationFailureProvider, 0)
	}
	return result
}
func isJSONResponse(response *http.Response) bool {
	if response == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}
func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func discardBounded(reader io.Reader, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, limit))
}
func readLimited(reader io.Reader, limit int64) ([]byte, bool) {
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	return content, err == nil && int64(len(content)) <= limit
}
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return len(value) == 64 && err == nil && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}
func (a *PublicationAdapter) String() string   { return "GitHub publication adapter" }
func (a *PublicationAdapter) GoString() string { return "github.PublicationAdapter{<redacted>}" }
func (a *PublicationAdapter) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "GitHub publication adapter", "github.PublicationAdapter{<redacted>}")
}

var _ review.Publisher = (*PublicationAdapter)(nil)
var _ review.HeadResolver = (*PublicationAdapter)(nil)
