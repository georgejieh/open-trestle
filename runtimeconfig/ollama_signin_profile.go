package runtimeconfig

import (
	"encoding/json"
	"strings"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// OllamaSigninChatProfile is the single closed exception to "a loopback
// endpoint serves only the local zone". It names a local Ollama daemon that
// relays Ollama Cloud models with the operator's own `ollama signin` account:
// Open Trestle talks only to the loopback daemon and sends no credential, but
// repository source leaves the machine. The route's zone is therefore
// private_remote, so the sanitizer, secret scanner and remote budget apply
// exactly as for any other remote route, and the local-only egress mode
// refuses it.
//
// The exception holds only when every condition below holds together: runtime
// policy schema version 7, which carries no other profile; Chat Completions;
// credential_mode "none"; an endpoint of exactly http://127.0.0.1:PORT/v1;
// provider ID "ollama-signin"; and only model IDs with the Ollama cloud suffix
// (":cloud" or ":...-cloud"). Whether the daemon's /api/tags entry for each
// model names https://ollama.com as its remote host is checked by the setup
// that writes this configuration, which has the daemon to ask.
const OllamaSigninChatProfile = "ollama_signin_chat_v1"

// OllamaSigninProviderID is the only provider ID the Ollama sign-in profile accepts.
const OllamaSigninProviderID = "ollama-signin"

const ollamaSigninPolicyVersion = 7

// OllamaCloudModelID reports whether a model ID carries the Ollama cloud tag
// suffix: a tag of exactly "cloud" or ending in "-cloud", such as
// gpt-oss:20b-cloud or deepseek-v4-pro:cloud.
func OllamaCloudModelID(id string) bool {
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

// ValidOllamaSigninEndpoint reports whether raw is exactly
// http://127.0.0.1:PORT/v1 with an explicit canonical port.
func ValidOllamaSigninEndpoint(raw string) bool {
	endpoint, err := provider.ParseServiceEndpoint(raw)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.Path != "/v1" {
		return false
	}
	return raw == "http://127.0.0.1:"+endpoint.Port()+"/v1"
}

func validOllamaSigninConnection(c ProviderConnection, version int) bool {
	return version == ollamaSigninPolicyVersion && c.requestProfile == OllamaSigninChatProfile && c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.openCodeConsoleAuthority == (OpenCodeConsoleRouteAuthority{}) && !c.localStructuredOutput && c.implementation == "openai_chat_completions" && c.credentialMode == "none" && c.credentialEnvironment == "" && c.credentialIdentity == "" && ValidOllamaSigninEndpoint(c.endpoint)
}

// validOllamaSigninInventoryBinding requires every route of the connection's
// adapter namespace to be an approved private_remote ollama-signin route whose
// model ID carries the Ollama cloud suffix and whose content logging is
// declared disabled.
func validOllamaSigninInventoryBinding(c ProviderConnection, inventory RouteInventory) bool {
	count := 0
	for _, observed := range inventory.candidates {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		declaration := record.RouteCandidateDeclaration()
		route := declaration.RouteCapabilityDeclaration().RouteReference()
		if route.AdapterID() != c.adapterID {
			continue
		}
		count++
		if record.Status() != provider.RouteRegistryApproved || route.Zone() != provider.ProviderZonePrivateRemote || route.ProviderID() != OllamaSigninProviderID || route.ModelVersion() != "" || !OllamaCloudModelID(route.ModelID()) || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return false
		}
	}
	return count >= 1
}

// validateV7PolicyProfileFields requires every version 7 connection to name the
// Ollama sign-in profile exactly and to carry no service authority object.
func validateV7PolicyProfileFields(encoded []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	var connections []map[string]json.RawMessage
	if json.Unmarshal(fields["connections"], &connections) != nil || len(connections) == 0 {
		return false
	}
	for _, c := range connections {
		for key := range c {
			switch strings.ToLower(key) {
			case "brokered_route_authority", "opencode_go_authority", "opencode_console_authority", "local_structured_output":
				return false
			case "request_profile":
				if key != "request_profile" {
					return false
				}
			}
		}
		var profile string
		if json.Unmarshal(c["request_profile"], &profile) != nil || profile != OllamaSigninChatProfile {
			return false
		}
	}
	return true
}
