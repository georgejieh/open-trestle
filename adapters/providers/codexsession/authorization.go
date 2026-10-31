package codexsession

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	AuthorizationEndpoint = "https://auth.openai.com/api/accounts/authorize"
	TokenEndpoint         = "https://auth.openai.com/api/accounts/oauth/token"
	Resource              = "https://api.openai.com/v1"
)

var (
	ErrInvalidAuthorization = errors.New("invalid ChatGPT-plan authorization parameters")
	ErrInvalidCallback      = errors.New("invalid ChatGPT-plan authorization callback")
	ErrAttemptFinished      = errors.New("ChatGPT-plan authorization attempt already finished")
	ErrAttemptExpired       = errors.New("ChatGPT-plan authorization attempt expired")
	ErrConsentDeclined      = errors.New("ChatGPT-plan authorization declined")
	ErrAuthorizationFailed  = errors.New("ChatGPT-plan authorization failed")
	hostPattern             = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	clientPattern           = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)
)

type AuthorizationState string

const (
	AuthorizationPending      AuthorizationState = "pending"
	AuthorizationCanceled     AuthorizationState = "canceled"
	AuthorizationExpired      AuthorizationState = "expired"
	AuthorizationDeclined     AuthorizationState = "declined"
	AuthorizationCodeReceived AuthorizationState = "code_received"
	AuthorizationFailed       AuthorizationState = "failed"
)

// Authorization is a single-use, in-memory OAuth attempt, not an authenticated session.
type Authorization struct {
	attempt *authorizationAttempt
}

type authorizationAttempt struct {
	mu                                                 sync.Mutex
	status                                             AuthorizationState
	hostID, clientID, callback, state, nonce, verifier string
	expiresAt                                          time.Time
}

// NewAuthorization prepares only local state; it opens no listener or browser.
// The caller must persist the host ID and start its approved callback listener first.
func NewAuthorization(hostID, clientID, callback string, expiresAt time.Time) (*Authorization, error) {
	u, err := url.Parse(callback)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "/auth/callback" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || expiresAt.IsZero() || !hostPattern.MatchString(hostID) || (clientID != "" && (!clientPattern.MatchString(clientID) || clientID == "dynamic_agent_client")) {
		return nil, ErrInvalidAuthorization
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != "127.0.0.1:"+strconv.Itoa(port) {
		return nil, ErrInvalidAuthorization
	}
	secrets := make([]byte, 96)
	if _, err = rand.Read(secrets); err != nil {
		return nil, ErrInvalidAuthorization
	}
	return &Authorization{attempt: &authorizationAttempt{status: AuthorizationPending, hostID: hostID, clientID: clientID, callback: callback, state: base64.RawURLEncoding.EncodeToString(secrets[:32]), nonce: base64.RawURLEncoding.EncodeToString(secrets[32:64]), verifier: base64.RawURLEncoding.EncodeToString(secrets[64:]), expiresAt: expiresAt}}, nil
}

// BrowserURL contains attempt secrets; display only after explicit user intent, never log it.
func (a *Authorization) BrowserURL() string {
	a.attempt.mu.Lock()
	defer a.attempt.mu.Unlock()
	if a.attempt.status != AuthorizationPending {
		return ""
	}
	clientID := a.attempt.clientID
	if clientID == "" {
		clientID = "dynamic_agent_client"
	}
	digest := sha256.Sum256([]byte(a.attempt.verifier))
	q := url.Values{"client_id": {clientID}, "ext_agent_host_id": {a.attempt.hostID}, "response_type": {"code"}, "redirect_uri": {a.attempt.callback}, "scope": {"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"}, "resource": {Resource}, "state": {a.attempt.state}, "nonce": {a.attempt.nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
	if a.attempt.clientID == "" {
		q.Set("agent_name_hint", "Open Trestle")
	}
	return AuthorizationEndpoint + "?" + q.Encode()
}

func (a *Authorization) State() AuthorizationState {
	a.attempt.mu.Lock()
	defer a.attempt.mu.Unlock()
	return a.attempt.status
}

// Cancel invalidates local attempt secrets, not an already-issued remote grant.
func (a *Authorization) Cancel() {
	a.attempt.mu.Lock()
	defer a.attempt.mu.Unlock()
	if a.attempt.status == AuthorizationPending {
		a.finish(AuthorizationCanceled)
	}
}

func (a *Authorization) finish(state AuthorizationState) {
	a.attempt.status = state
	a.attempt.state = ""
	a.attempt.nonce = ""
	a.attempt.verifier = ""
}

// AcceptCallback creates a code-exchange plan only. Identity and granted scopes
// must still be cryptographically verified before credentials can become active.
func (a *Authorization) AcceptCallback(q url.Values, now time.Time) (*CodeExchange, error) {
	a.attempt.mu.Lock()
	defer a.attempt.mu.Unlock()
	if a.attempt.status != AuthorizationPending {
		return nil, ErrAttemptFinished
	}
	if !now.Before(a.attempt.expiresAt) {
		a.finish(AuthorizationExpired)
		return nil, ErrAttemptExpired
	}
	if len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(a.attempt.state)) != 1 {
		return nil, ErrInvalidCallback
	}
	for _, key := range []string{"code", "client_id", "error"} {
		if len(q[key]) > 1 {
			return nil, ErrInvalidCallback
		}
	}
	if q.Get("error") != "" {
		if q.Get("code") != "" {
			return nil, ErrInvalidCallback
		}
		if q.Get("error") == "access_denied" {
			a.finish(AuthorizationDeclined)
			return nil, ErrConsentDeclined
		}
		a.finish(AuthorizationFailed)
		return nil, ErrAuthorizationFailed
	}
	code := q.Get("code")
	if len(code) == 0 || len(code) > 4096 {
		return nil, ErrInvalidCallback
	}
	for _, r := range code {
		if r < 0x21 || r > 0x7e {
			return nil, ErrInvalidCallback
		}
	}
	clientID := q.Get("client_id")
	if a.attempt.clientID != "" {
		if clientID != "" && clientID != a.attempt.clientID {
			return nil, ErrInvalidCallback
		}
		clientID = a.attempt.clientID
	}
	if !clientPattern.MatchString(clientID) || clientID == "dynamic_agent_client" {
		return nil, ErrInvalidCallback
	}
	plan := &CodeExchange{clientID: clientID, code: code, verifier: a.attempt.verifier, callback: a.attempt.callback, nonce: a.attempt.nonce}
	a.finish(AuthorizationCodeReceived)
	return plan, nil
}

func (a Authorization) String() string             { return "ChatGPT-plan authorization (<redacted>)" }
func (a Authorization) GoString() string           { return a.String() }
func (a Authorization) Format(s fmt.State, _ rune) { fmt.Fprint(s, a.String()) }

// CodeExchange is not a credential or verified account. Its explicit accessors
// contain secrets and must never feed logs, URLs, or generic diagnostics.
type CodeExchange struct{ clientID, code, verifier, callback, nonce string }

func (p *CodeExchange) Form() url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {p.clientID}, "code": {p.code}, "code_verifier": {p.verifier}, "redirect_uri": {p.callback}, "resource": {Resource}}
}
func (p *CodeExchange) VerificationNonce() string { return p.nonce }
func (p CodeExchange) String() string             { return "ChatGPT-plan code exchange (<redacted>)" }
func (p CodeExchange) GoString() string           { return p.String() }
func (p CodeExchange) Format(s fmt.State, _ rune) { fmt.Fprint(s, p.String()) }
