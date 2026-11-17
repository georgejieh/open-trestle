package main

import "strings"

// initModelFamilies maps the start of a model-name token to the model family
// it marks. The table is deliberately small: a name it does not recognize has
// no family, and the wizard then makes no remark about families at all.
var initModelFamilies = []struct{ prefix, family string }{
	{"qwen", "Qwen"},
	{"qwq", "Qwen"},
	{"deepseek", "DeepSeek"},
	{"llama", "Llama"},
	{"codellama", "Llama"},
	{"mistral", "Mistral"},
	{"mixtral", "Mistral"},
	{"ministral", "Mistral"},
	{"codestral", "Mistral"},
	{"devstral", "Mistral"},
	{"magistral", "Mistral"},
	{"gemma", "Gemma"},
	{"gemini", "Gemini"},
	{"gpt", "GPT"},
	{"glm", "GLM"},
	{"kimi", "Kimi"},
	{"minimax", "MiniMax"},
	{"phi", "Phi"},
	{"granite", "Granite"},
	{"claude", "Claude"},
	{"grok", "Grok"},
	{"command", "Command"},
	{"nemotron", "Nemotron"},
}

// initVendorFamilies names the family of a vendor prefix such as "openai/" for
// a model whose own name carries no family keyword.
var initVendorFamilies = map[string]string{
	"openai":      "GPT",
	"anthropic":   "Claude",
	"meta-llama":  "Llama",
	"mistralai":   "Mistral",
	"qwen":        "Qwen",
	"deepseek":    "DeepSeek",
	"deepseek-ai": "DeepSeek",
	"z-ai":        "GLM",
	"zai-org":     "GLM",
	"thudm":       "GLM",
	"moonshotai":  "Kimi",
	"x-ai":        "Grok",
	"minimax":     "MiniMax",
	"cohere":      "Command",
	"ibm-granite": "Granite",
}

// initModelFamily returns the model family of a model selector, or "" when
// the name is not recognized. A distilled model belongs to the family it was
// distilled into ("deepseek-r1-distill-qwen-32b" is a Qwen model).
func initModelFamily(selector string) string {
	name := strings.ToLower(selector)
	vendor := ""
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		vendor, name = name[:i], name[i+1:]
		if j := strings.LastIndexByte(vendor, '/'); j >= 0 {
			vendor = vendor[j+1:]
		}
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	tokens := strings.FieldsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	start := 0
	for i, token := range tokens {
		if token == "distill" {
			start = i + 1
		}
	}
	for _, token := range tokens[start:] {
		for _, entry := range initModelFamilies {
			if strings.HasPrefix(token, entry.prefix) {
				return entry.family
			}
		}
	}
	if start == 0 {
		return initVendorFamilies[vendor]
	}
	return ""
}

// initSameFamily returns the family that two models share, or "" when either
// family is unknown or they differ.
func initSameFamily(finder, checker string) string {
	family := initModelFamily(finder)
	if family == "" || family != initModelFamily(checker) {
		return ""
	}
	return family
}
