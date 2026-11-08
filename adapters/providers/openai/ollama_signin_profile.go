package openai

import (
	"encoding/json"
	"strings"

	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// RequestProfileOllamaSigninChatV1 sends Chat Completions to a local Ollama
// daemon that relays Ollama Cloud models with the operator's `ollama signin`
// account. The endpoint is loopback and no credential is sent, but content
// leaves the machine, so the adapter's zone is private_remote and every
// dispatch requires a sanitized egress proof. It is the only profile that pairs
// a loopback endpoint with a non-local zone, and only for model selectors with
// the Ollama cloud suffix.
const RequestProfileOllamaSigninChatV1 RequestProfile = "ollama_signin_chat_v1"

const ollamaSigninProviderID = "ollama-signin"

// validOllamaSigninEndpoint mirrors runtimeconfig.ValidOllamaSigninEndpoint:
// exactly http://127.0.0.1:PORT/v1 with an explicit canonical port.
func validOllamaSigninEndpoint(raw string) bool {
	endpoint, err := provider.ParseServiceEndpoint(raw)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.Path != "/v1" {
		return false
	}
	return raw == "http://127.0.0.1:"+endpoint.Port()+"/v1"
}

// ollamaCloudSelector mirrors runtimeconfig.OllamaCloudModelID.
func ollamaCloudSelector(id string) bool {
	index := strings.LastIndex(id, ":")
	if index <= 0 || len(id) > 1024 {
		return false
	}
	tag := id[index+1:]
	if strings.ContainsAny(tag, "/: \t\r\n") {
		return false
	}
	return tag == "cloud" || len(tag) > len("-cloud") && strings.HasSuffix(tag, "-cloud")
}

func (a *Adapter) validOllamaSigninProfile() bool {
	return a.requestProfile == RequestProfileOllamaSigninChatV1 && a.openRouterAuthority == nil && a.openCodeGoAuthority == nil && a.openCodeConsoleAuthority == nil && nilInterface(a.clock) && !a.localStructuredOutput && a.endpoint != nil &&
		a.protocol == ProtocolChatCompletions && a.credentialMode == CredentialModeNone && nilInterface(a.credentials) && a.credentialIdentity == "" &&
		a.zone == provider.ProviderZonePrivateRemote && a.providerID == ollamaSigninProviderID && a.contentLoggingMode == provider.ContentLoggingDisabled && validOllamaSigninEndpoint(a.endpoint.String())
}

func (a *Adapter) ollamaSigninRouteMatches(route provider.RouteReference) bool {
	return a.validOllamaSigninProfile() && a.routeMatches(route) && route.ModelVersion() == "" && ollamaCloudSelector(route.ModelID())
}

// ollamaSigninProofMatches requires the jointly validated sanitized egress
// proof for this exact request; the profile has no repository-scoped authority
// beyond it.
func (a *Adapter) ollamaSigninProofMatches(proof modelhandler.SanitizedDispatchProof, scope, request string) bool {
	return a.validOllamaSigninProfile() && proof.ValidateRequest(scope, request) == nil
}

func (a *Adapter) ollamaSigninIdentityPreimage(configuration []byte) []byte {
	encoded, _ := json.Marshal(struct {
		Contract       string          `json:"contract"`
		Version        int             `json:"version"`
		Configuration  json.RawMessage `json:"configuration"`
		Profile        RequestProfile  `json:"request_profile"`
		Protocol       Protocol        `json:"protocol"`
		CredentialMode CredentialMode  `json:"credential_mode"`
		ModelSuffix    string          `json:"model_suffix"`
	}{"open-trestle/ollama-signin-chat-adapter", 1, configuration, a.requestProfile, a.protocol, a.credentialMode, "ollama_cloud_tag"})
	return encoded
}
