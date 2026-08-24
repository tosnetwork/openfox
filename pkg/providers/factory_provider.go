// OpenFox - Ultra-lightweight personal AI agent
// License: MIT
//
// Copyright (c) 2026 OpenFox contributors

package providers

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	anthropicmessages "github.com/tosnetwork/openfox/pkg/providers/anthropic_messages"
	"github.com/tosnetwork/openfox/pkg/providers/azure"
	"github.com/tosnetwork/openfox/pkg/providers/bedrock"
	"github.com/tosnetwork/openfox/pkg/providers/common"
)

// ExtractProtocol extracts the effective protocol and model identifier from a
// model configuration.
//
// The explicit Provider field takes precedence. When Provider is empty, the
// protocol is inferred from Model. Plain model names default to "openai".
// Provider-prefixed models strip the first slash-separated segment from the
// returned model ID.
//
// The returned protocol is normalized to the provider's canonical spelling.
// Examples:
//   - Model "openai/gpt-4o" -> ("openai", "gpt-4o")
//   - Model "nvidia/z-ai/glm-5.1" -> ("nvidia", "z-ai/glm-5.1")
//   - Provider "nvidia", Model "z-ai/glm-5.1" -> ("nvidia", "z-ai/glm-5.1")
//   - Provider "openai", Model "openai/gpt-4o" -> ("openai", "openai/gpt-4o")
//   - Model "gpt-4o" -> ("openai", "gpt-4o")
func ExtractProtocol(cfg *config.ModelConfig) (protocol, modelID string) {
	if cfg == nil {
		return "", ""
	}

	model := strings.TrimSpace(cfg.Model)
	if provider := strings.TrimSpace(cfg.Provider); provider != "" {
		return NormalizeProvider(provider), model
	}
	return SplitModelProviderAndID(model, "openai")
}

// ResolveAPIBase returns the configured API base, or the protocol default when
// the model uses an HTTP-based provider family with a known default endpoint.
func ResolveAPIBase(cfg *config.ModelConfig) string {
	if cfg == nil {
		return ""
	}
	if apiBase := strings.TrimSpace(cfg.APIBase); apiBase != "" {
		return strings.TrimRight(apiBase, "/")
	}
	protocol, _ := ExtractProtocol(cfg)
	return strings.TrimRight(getDefaultAPIBase(protocol), "/")
}

// CreateProviderFromConfig creates a provider based on the ModelConfig.
// It uses ExtractProtocol to determine which provider to create.
// Supported protocol families include OpenAI-compatible prefixes (e.g., openai, openrouter, groq),
// Azure OpenAI, Amazon Bedrock, Anthropic (including messages), and various CLI/compatibility shims.
// See the switch on protocol in this function for the authoritative list.
// Returns the provider, the effective model ID from ExtractProtocol, and any error.
func CreateProviderFromConfig(cfg *config.ModelConfig) (LLMProvider, string, error) {
	if cfg == nil {
		return nil, "", fmt.Errorf("config is nil")
	}

	if cfg.Model == "" {
		return nil, "", fmt.Errorf("model is required")
	}

	protocol, modelID := ExtractProtocol(cfg)
	authMethod := strings.ToLower(strings.TrimSpace(cfg.AuthMethod))

	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = fmt.Sprintf("OpenFox/%s", config.Version)
	}

	switch protocol {
	case "openai":
		// Consumer ChatGPT OAuth credentials must stay inside the official Codex
		// client boundary. OpenFox no longer impersonates Codex against an
		// undocumented backend API.
		if authMethod == "oauth" || authMethod == "token" {
			return nil, "", fmt.Errorf(
				"direct OpenAI OAuth is disabled; configure provider %q with auth_method %q and agent_backend.mode %q",
				"codex-cli", "subscription", "app-server",
			)
		}
		// OpenAI with API key
		if cfg.APIKey() == "" && cfg.APIBase == "" {
			return nil, "", fmt.Errorf("api_key or api_base is required for HTTP-based protocol %q", protocol)
		}
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = getDefaultAPIBase(protocol)
		}
		provider := NewHTTPProviderWithMaxTokensFieldAndRequestTimeout(
			cfg.APIKey(),
			apiBase,
			cfg.Proxy,
			cfg.MaxTokensField,
			userAgent,
			cfg.RequestTimeout,
			cfg.ExtraBody,
			cfg.CustomHeaders,
		)
		provider.SetProviderName(protocol)
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "azure":
		// Azure OpenAI uses deployment-based URLs. Auth is Bearer token via api_key
		// when set; otherwise falls back to Entra ID (DefaultAzureCredential).
		if cfg.APIBase == "" {
			return nil, "", fmt.Errorf(
				"api_base is required for azure protocol (e.g., https://your-resource.openai.azure.com)",
			)
		}
		if cfg.APIKey() != "" {
			return finalizeProviderFromConfig(azure.NewProviderWithTimeout(
				cfg.APIKey(),
				cfg.APIBase,
				cfg.Proxy,
				userAgent,
				cfg.RequestTimeout,
			), modelID, cfg)
		}
		provider, err := azure.NewProviderWithIdentityAndTimeout(
			cfg.APIBase,
			cfg.Proxy,
			userAgent,
			cfg.RequestTimeout,
		)
		if err != nil {
			return nil, "", err
		}
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "bedrock":
		// AWS Bedrock uses AWS SDK credentials (env vars, profiles, IAM roles, etc.)
		// api_base can be:
		//   - A full endpoint URL: https://bedrock-runtime.us-east-1.amazonaws.com
		//   - A region name: us-east-1 (AWS SDK resolves endpoint automatically)
		var opts []bedrock.Option
		if cfg.APIBase != "" {
			if !strings.Contains(cfg.APIBase, "://") {
				// Treat as region: let AWS SDK resolve the correct endpoint
				// (supports all AWS partitions: aws, aws-cn, aws-us-gov, etc.)
				opts = append(opts, bedrock.WithRegion(cfg.APIBase))
			} else {
				// Full endpoint URL provided (for custom endpoints or testing)
				opts = append(opts, bedrock.WithBaseEndpoint(cfg.APIBase))
			}
		}
		// Use a separate timeout for AWS config loading (credential resolution can block)
		initTimeout := 30 * time.Second
		if cfg.RequestTimeout > 0 {
			reqTimeout := time.Duration(cfg.RequestTimeout) * time.Second
			// Set request timeout for API calls
			opts = append(opts, bedrock.WithRequestTimeout(reqTimeout))
			// Ensure init timeout is at least as large as request timeout
			if reqTimeout > initTimeout {
				initTimeout = reqTimeout
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
		defer cancel()
		// Note: AWS_PROFILE env var is automatically used by AWS SDK
		provider, err := bedrock.NewProvider(ctx, opts...)
		if err != nil {
			return nil, "", fmt.Errorf("creating bedrock provider: %w", err)
		}
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "litellm", "lmstudio", "gpt4free", "openrouter", "groq", "zhipu", "nvidia", "venice",
		"nearai", "ollama", "moonshot", "shengsuanyun", "siliconflow", "deepseek", "cerebras",
		"vivgrid", "volcengine", "vllm", "qwen-portal", "qwen-intl", "qwen-us", "mistral",
		"avian", "longcat", "modelscope", "novita", "alibaba-coding", "zai", "mimo":
		// All other OpenAI-compatible HTTP providers
		if cfg.APIKey() == "" && cfg.APIBase == "" && !isEmptyAPIKeyAllowed(protocol) {
			return nil, "", fmt.Errorf("api_key or api_base is required for HTTP-based protocol %q", protocol)
		}
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = getDefaultAPIBase(protocol)
		}
		provider := NewHTTPProviderWithMaxTokensFieldAndRequestTimeout(
			cfg.APIKey(),
			apiBase,
			cfg.Proxy,
			cfg.MaxTokensField,
			userAgent,
			cfg.RequestTimeout,
			cfg.ExtraBody,
			cfg.CustomHeaders,
		)
		provider.SetProviderName(protocol)
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "gemini":
		if cfg.APIKey() == "" && cfg.APIBase == "" {
			return nil, "", fmt.Errorf("api_key or api_base is required for gemini protocol (model: %s)", cfg.Model)
		}
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = getDefaultAPIBase(protocol)
		}
		return finalizeProviderFromConfig(NewGeminiProvider(
			cfg.APIKey(),
			apiBase,
			cfg.Proxy,
			userAgent,
			cfg.RequestTimeout,
			cfg.ExtraBody,
			cfg.CustomHeaders,
		), modelID, cfg)

	case "minimax":
		// Minimax requires reasoning_split: true in the request body
		if cfg.APIKey() == "" && cfg.APIBase == "" {
			return nil, "", fmt.Errorf("api_key or api_base is required for HTTP-based protocol %q", protocol)
		}
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = getDefaultAPIBase(protocol)
		}
		extraBody := cfg.ExtraBody
		if extraBody == nil {
			extraBody = make(map[string]any)
		}
		if _, ok := extraBody["reasoning_split"]; !ok {
			extraBody["reasoning_split"] = true
		}
		provider := NewHTTPProviderWithMaxTokensFieldAndRequestTimeout(
			cfg.APIKey(),
			apiBase,
			cfg.Proxy,
			cfg.MaxTokensField,
			userAgent,
			cfg.RequestTimeout,
			extraBody,
			cfg.CustomHeaders,
		)
		provider.SetProviderName(protocol)
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "anthropic":
		if authMethod == "oauth" || authMethod == "token" {
			return nil, "", fmt.Errorf(
				"direct Anthropic consumer OAuth is disabled; use provider %q with auth_method %q",
				"claude-cli", "subscription",
			)
		}
		// Use API key with HTTP API
		apiBase := common.NormalizeBaseURL(cfg.APIBase, "https://api.anthropic.com/v1", true)
		if cfg.APIKey() == "" {
			return nil, "", fmt.Errorf("api_key is required for anthropic protocol (model: %s)", cfg.Model)
		}
		provider := NewHTTPProviderWithMaxTokensFieldAndRequestTimeout(
			cfg.APIKey(),
			apiBase,
			cfg.Proxy,
			cfg.MaxTokensField,
			userAgent,
			cfg.RequestTimeout,
			cfg.ExtraBody,
			cfg.CustomHeaders,
		)
		provider.SetProviderName(protocol)
		return finalizeProviderFromConfig(provider, modelID, cfg)

	case "anthropic-messages":
		// Anthropic Messages API with native format (HTTP-based, no SDK)
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = "https://api.anthropic.com/v1"
		}
		if cfg.APIKey() == "" {
			return nil, "", fmt.Errorf("api_key is required for anthropic-messages protocol (model: %s)", cfg.Model)
		}
		return finalizeProviderFromConfig(anthropicmessages.NewProviderWithTimeout(
			cfg.APIKey(),
			apiBase,
			userAgent,
			cfg.RequestTimeout,
		), modelID, cfg)

	case "alibaba-coding-anthropic":
		// Alibaba Coding Plan with Anthropic-compatible API
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = getDefaultAPIBase(protocol)
		}
		if cfg.APIKey() == "" {
			return nil, "", fmt.Errorf("api_key is required for %q protocol (model: %s)", protocol, cfg.Model)
		}
		return finalizeProviderFromConfig(anthropicmessages.NewProviderWithTimeout(
			cfg.APIKey(),
			apiBase,
			userAgent,
			cfg.RequestTimeout,
		), modelID, cfg)

	case "antigravity":
		return finalizeProviderFromConfig(NewAntigravityProvider(), modelID, cfg)

	case "claude-cli":
		if err := validateSubscriptionAgentConfig(cfg, authMethod); err != nil {
			return nil, "", err
		}
		if mode := normalizedAgentBackendMode(cfg.AgentBackend.Mode); mode != "one-shot" {
			return nil, "", fmt.Errorf("claude-cli supports only agent_backend.mode %q", "one-shot")
		}
		return finalizeProviderFromConfig(NewClaudeCliProviderWithOptions(runtimeOptionsFromConfig(cfg)), modelID, cfg)

	case "codex-cli":
		if err := validateSubscriptionAgentConfig(cfg, authMethod); err != nil {
			return nil, "", err
		}
		options := runtimeOptionsFromConfig(cfg)
		switch normalizedAgentBackendMode(cfg.AgentBackend.Mode) {
		case "one-shot":
			return finalizeProviderFromConfig(NewCodexCliProviderWithOptions(options), modelID, cfg)
		case "app-server":
			return finalizeProviderFromConfig(NewCodexAppServerProvider(options), modelID, cfg)
		default:
			return nil, "", fmt.Errorf("unsupported codex-cli agent backend mode %q", cfg.AgentBackend.Mode)
		}

	case "github-copilot":
		apiBase := cfg.APIBase
		if apiBase == "" {
			apiBase = "localhost:4321"
		}
		connectMode := cfg.ConnectMode
		if connectMode == "" {
			connectMode = "grpc"
		}
		provider, err := NewGitHubCopilotProvider(apiBase, connectMode, modelID)
		if err != nil {
			return nil, "", err
		}
		return finalizeProviderFromConfig(provider, modelID, cfg)

	default:
		return nil, "", fmt.Errorf("unknown protocol %q in model %q", protocol, cfg.Model)
	}
}

func normalizedAgentBackendMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "one-shot"
	}
	return mode
}

func validateSubscriptionAgentConfig(cfg *config.ModelConfig, authMethod string) error {
	if err := cfg.AgentBackend.Validate(); err != nil {
		return err
	}
	if authMethod != "subscription" {
		return fmt.Errorf("unsupported CLI auth_method %q", cfg.AuthMethod)
	}
	if cfg.AgentBackend.SubscriptionUse != "local-personal" {
		return fmt.Errorf(
			"agent_backend.subscription_use must be %q when auth_method is %q",
			"local-personal", "subscription",
		)
	}
	if cfg.AgentBackend.OwnerPrincipal.IsZero() {
		return fmt.Errorf("agent_backend.owner_principal is required for a local-personal subscription")
	}
	if strings.TrimSpace(cfg.Workspace) == "" {
		return fmt.Errorf("workspace is required for local full-agent providers")
	}
	if !filepath.IsAbs(cfg.Workspace) {
		return fmt.Errorf("workspace must be an absolute path for local full-agent providers")
	}
	return nil
}

func runtimeOptionsFromConfig(cfg *config.ModelConfig) RuntimeOptions {
	return RuntimeOptions{
		Workspace:          cfg.Workspace,
		Sandbox:            cfg.AgentBackend.Sandbox,
		ApprovalPolicy:     cfg.AgentBackend.ApprovalPolicy,
		AllowNativeTools:   cfg.AgentBackend.AllowNativeTools,
		SubscriptionUse:    cfg.AgentBackend.SubscriptionUse,
		OwnerChannel:       strings.TrimSpace(cfg.AgentBackend.OwnerPrincipal.Channel),
		OwnerSenderID:      strings.TrimSpace(cfg.AgentBackend.OwnerPrincipal.SenderID),
		AllowInternal:      cfg.AgentBackend.AllowInternal,
		MaxConcurrentCalls: cfg.AgentBackend.MaxConcurrentCalls,
		MaxOutputBytes:     cfg.AgentBackend.MaxOutputBytes,
		Timeout:            time.Duration(cfg.AgentBackend.TimeoutSeconds) * time.Second,
	}
}

func finalizeProviderFromConfig(
	provider LLMProvider,
	modelID string,
	cfg *config.ModelConfig,
) (LLMProvider, string, error) {
	wrapped, err := wrapProviderWithToolSchemaTransform(provider, cfg.ToolSchemaTransform)
	if err != nil {
		return nil, "", err
	}
	return wrapped, modelID, nil
}

func isEmptyAPIKeyAllowed(protocol string) bool {
	option, ok := modelProviderOptionForName(protocol)
	return ok && option.EmptyAPIKeyAllowed
}

// IsEmptyAPIKeyAllowedForProtocol reports whether a protocol allows requests
// without api_key when using its default local endpoint.
func IsEmptyAPIKeyAllowedForProtocol(protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	return isEmptyAPIKeyAllowed(protocol)
}

// IsHTTPAPIProtocol reports whether a provider uses an HTTP API base in the
// model configuration path. This excludes providers such as Bedrock, CLI
// bridges, and OAuth-only managed providers even if they do not require an
// explicit api_key field.
func IsHTTPAPIProtocol(protocol string) bool {
	protocol = NormalizeProvider(protocol)
	option, ok := modelProviderOptionsByName[protocol]
	return ok && option.httpAPI
}

// DefaultAPIBaseForProtocol returns the configured default API base for a protocol.
// It returns empty string if the protocol has no default base.
func DefaultAPIBaseForProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	return getDefaultAPIBase(protocol)
}

// getDefaultAPIBase returns the default API base URL for a given protocol.
func getDefaultAPIBase(protocol string) string {
	option, ok := modelProviderOptionForName(protocol)
	if !ok {
		return ""
	}
	return option.DefaultAPIBase
}
