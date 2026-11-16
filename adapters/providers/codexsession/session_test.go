package codexsession

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRuntimeAdmissionPreservesHardBounds(t *testing.T) {
	if err := RuntimeAdmission(); !errors.Is(err, ErrHardOutputBoundUnavailable) {
		t.Fatalf("admission = %v", err)
	}
	if ProfileID == "" || PrivacyException != "non-zdr" {
		t.Fatal("missing explicit profile posture")
	}
}

func TestAuthorizationCallbackAndCancellation(t *testing.T) {
	now := time.Unix(1000, 0)
	attempt, err := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authorize, _ := url.Parse(attempt.BrowserURL())
	q := authorize.Query()
	if authorize.Host != "auth.openai.com" || q.Get("code_challenge_method") != "S256" || q.Get("agent_name_hint") != "Open Trestle" {
		t.Fatal("wrong authorization authority")
	}
	if strings.Contains(fmt.Sprintf("%+v", attempt), q.Get("state")) {
		t.Fatal("attempt leaked state")
	}
	if _, err := attempt.AcceptCallback(url.Values{"state": {"wrong"}}, now); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal(err)
	}
	plan, err := attempt.AcceptCallback(url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}, "client_id": {"oaiapp_synthetic"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", plan), "synthetic-code") {
		t.Fatal("code leaked")
	}
	form := plan.Form()
	verifier := form.Get("code_verifier")
	digest := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != q.Get("code_challenge") {
		t.Fatal("PKCE mismatch")
	}
	if form.Get("client_id") != "oaiapp_synthetic" || form.Get("redirect_uri") != "http://127.0.0.1:1455/auth/callback" {
		t.Fatal("exchange mismatch")
	}
	if _, err := attempt.AcceptCallback(url.Values{"state": {q.Get("state")}}, now); !errors.Is(err, ErrAttemptFinished) {
		t.Fatal(err)
	}
	canceled, _ := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "oaiapp_saved", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	canceled.Cancel()
	if _, err := canceled.AcceptCallback(url.Values{}, now); !errors.Is(err, ErrAttemptFinished) {
		t.Fatal(err)
	}
	if canceled.State() != AuthorizationCanceled {
		t.Fatal(canceled.State())
	}
}

func TestAuthorizationRejectsUnsafeOrExpiredAttempts(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, callback := range []string{"http://localhost:1455/auth/callback", "https://127.0.0.1:1455/auth/callback", "http://127.0.0.1:1455/callback", "http://127.0.0.1:1455/auth/callback?x=y"} {
		if _, err := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "", callback, now); !errors.Is(err, ErrInvalidAuthorization) {
			t.Fatal(callback, err)
		}
	}
	attempt, _ := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "oaiapp_saved", "http://127.0.0.1:1455/auth/callback", now)
	if _, err := attempt.AcceptCallback(url.Values{}, now); !errors.Is(err, ErrAttemptExpired) {
		t.Fatal(err)
	}
	attempt, _ = NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "oaiapp_saved", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	u, _ := url.Parse(attempt.BrowserURL())
	state := u.Query().Get("state")
	if _, err := attempt.AcceptCallback(url.Values{"state": {state}, "code": {"synthetic"}, "client_id": {"oaiapp_other"}}, now); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal(err)
	}
	if _, err := attempt.AcceptCallback(url.Values{"state": {state}, "error": {"access_denied"}}, now); !errors.Is(err, ErrConsentDeclined) {
		t.Fatal(err)
	}
	if attempt.State() != AuthorizationDeclined {
		t.Fatal(attempt.State())
	}
}

func TestProfileStatusAndErrorDisposition(t *testing.T) {
	status := Status()
	if status.Profile != ProfileID || status.RuntimeAvailable || status.Privacy != PrivacyException || status.Blocker != "hard_output_bound_unavailable" {
		t.Fatalf("%+v", status)
	}
	for _, tt := range []struct {
		code string
		want Recovery
	}{
		{"subscription_sharing_usage_limit_exceeded", RecoveryPause},
		{"subscription_sharing_usage_unavailable", RecoveryRetryLater},
		{"subscription_sharing_unsupported_capability", RecoveryFixRequest},
		{"subscription_sharing_user_not_eligible", RecoveryUnavailable},
		{"refresh_token_reused", RecoveryReauthenticate},
		{"invalid_client", RecoveryFixConfiguration},
		{"unknown", RecoveryStop},
	} {
		if got := ErrorRecovery(tt.code); got != tt.want {
			t.Fatalf("%s: %s", tt.code, got)
		}
	}
}

func TestAuthorizationErrorDoesNotPretendConsentDeclined(t *testing.T) {
	now := time.Unix(1000, 0)
	attempt, err := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "issued-client-opaque", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(attempt.BrowserURL())
	if _, err := attempt.AcceptCallback(url.Values{"state": {u.Query().Get("state")}, "error": {"server_error"}}, now); !errors.Is(err, ErrAuthorizationFailed) {
		t.Fatal(err)
	}
	if attempt.State() != AuthorizationFailed {
		t.Fatal(attempt.State())
	}
}

func TestCancelRacesCallbackWithoutReactivation(t *testing.T) {
	now := time.Unix(1000, 0)
	attempt, _ := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	u, _ := url.Parse(attempt.BrowserURL())
	start := make(chan struct{})
	done := make(chan struct{})
	go func() { <-start; attempt.Cancel(); close(done) }()
	close(start)
	plan, err := attempt.AcceptCallback(url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic"}, "client_id": {"issued-client"}}, now)
	<-done
	switch attempt.State() {
	case AuthorizationCanceled:
		if plan != nil || !errors.Is(err, ErrAttemptFinished) {
			t.Fatal("canceled attempt reactivated")
		}
	case AuthorizationCodeReceived:
		if plan == nil || err != nil {
			t.Fatal("completed callback lost")
		}
	default:
		t.Fatal(attempt.State())
	}
}

func TestSecretFormattingProtectsPointersAndValues(t *testing.T) {
	now := time.Unix(1000, 0)
	attempt, err := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "", "http://127.0.0.1:1455/auth/callback", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(attempt.BrowserURL())
	state, nonce := u.Query().Get("state"), u.Query().Get("nonce")
	check := func(value any, secrets ...string) {
		t.Helper()
		outputs := []string{fmt.Sprint(value), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
		for _, output := range outputs {
			for _, secret := range secrets {
				if secret != "" && strings.Contains(output, secret) {
					t.Error("formatted value leaked a secret")
				}
			}
		}
	}
	check(attempt, state, nonce)
	check(*attempt, state, nonce)
	check(struct{ Attempt Authorization }{*attempt}, state, nonce)
	plan, err := attempt.AcceptCallback(url.Values{"state": {state}, "code": {"synthetic-format-code"}, "client_id": {"issued-client"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	verifier := plan.Form().Get("code_verifier")
	check(plan, "synthetic-format-code", verifier, nonce)
	check(*plan, "synthetic-format-code", verifier, nonce)
	check(struct{ Plan CodeExchange }{*plan}, "synthetic-format-code", verifier, nonce)
}

func TestCopiedAuthorizationSharesCancellation(t *testing.T) {
	attempt, _ := NewAuthorization("urn:uuid:4dcfa7ac-9263-45e2-9339-01d5dcdf4927", "", "http://127.0.0.1:1455/auth/callback", time.Unix(1000, 0))
	copied := *attempt
	copied.Cancel()
	if attempt.State() != AuthorizationCanceled {
		t.Fatal("copy forked authorization state")
	}
}
