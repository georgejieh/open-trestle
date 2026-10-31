// Package codexsession defines the offline ChatGPT-plan authorization boundary.
// It cannot admit model requests while the upstream route lacks hard output bounds.
package codexsession

import "errors"

const (
	ProfileID        = "codex_chatgpt_session_v1"
	PrivacyException = "non-zdr"
)

var ErrHardOutputBoundUnavailable = errors.New("ChatGPT-plan Responses preview does not support max_output_tokens; hard output and spend admission unavailable")

// RuntimeAdmission refuses every session, independently of credentials or policy.
func RuntimeAdmission() error { return ErrHardOutputBoundUnavailable }

// ProfileStatus is observational and does not resolve credentials or start login.
type ProfileStatus struct {
	Profile          string `json:"profile"`
	RuntimeAvailable bool   `json:"runtime_available"`
	Privacy          string `json:"privacy_exception"`
	Blocker          string `json:"blocker"`
}

func Status() ProfileStatus {
	return ProfileStatus{Profile: ProfileID, Privacy: PrivacyException, Blocker: "hard_output_bound_unavailable"}
}

type Recovery string

const (
	RecoveryStop             Recovery = "stop"
	RecoveryPause            Recovery = "pause_plan_requests"
	RecoveryRetryLater       Recovery = "retry_later"
	RecoveryFixRequest       Recovery = "fix_request"
	RecoveryUnavailable      Recovery = "unavailable"
	RecoveryReauthenticate   Recovery = "reauthenticate"
	RecoveryFixConfiguration Recovery = "fix_configuration"
)

// ErrorRecovery classifies documented SIWC codes, not diagnostic text.
// Apply invalid_grant only to a refresh failure; code-exchange failures require
// a fresh authorization attempt. Unknown errors never trigger billing fallback.
func ErrorRecovery(code string) Recovery {
	switch code {
	case "subscription_sharing_usage_limit_exceeded":
		return RecoveryPause
	case "subscription_sharing_usage_unavailable", "subscription_sharing_user_unavailable":
		return RecoveryRetryLater
	case "subscription_sharing_unsupported_capability", "subscription_sharing_route_not_supported":
		return RecoveryFixRequest
	case "subscription_sharing_user_not_eligible":
		return RecoveryUnavailable
	case "invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused":
		return RecoveryReauthenticate
	case "invalid_client", "chatpass_v2_scope_not_authorized", "chatpass_v2_invalid_authorization_context":
		return RecoveryFixConfiguration
	default:
		return RecoveryStop
	}
}
