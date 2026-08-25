package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/tosnetwork/openfox/pkg"
	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/logger"
	providercommon "github.com/tosnetwork/openfox/pkg/providers/common"
)

// rrCounter is a global counter for round-robin load balancing across models.
var rrCounter atomic.Uint64

// CurrentVersion is the latest config schema version
const CurrentVersion = 3

func init() {
	initChannel()
}

// Config is the current config structure with version support.
type Config struct {
	// Config schema version for migration.
	Version     int                 `json:"version"             yaml:"-"`
	Isolation   IsolationConfig     `json:"isolation,omitempty" yaml:"-"`
	Agents      AgentsConfig        `json:"agents"              yaml:"-"`
	Session     SessionConfig       `json:"session,omitempty"   yaml:"-"`
	Evolution   EvolutionConfig     `json:"evolution,omitempty" yaml:"-"`
	Channels    ChannelsConfig      `json:"channel_list"        yaml:"channel_list"`
	ModelList   SecureModelList     `json:"model_list"          yaml:"model_list"` // New model-centric provider configuration
	Gateway     GatewayConfig       `json:"gateway"             yaml:"-"`
	Events      EventsConfig        `json:"events,omitempty"    yaml:"-"`
	Hooks       HooksConfig         `json:"hooks,omitempty"     yaml:"-"`
	Tools       ToolsConfig         `json:"tools"               yaml:",inline"`
	Heartbeat   HeartbeatConfig     `json:"heartbeat"           yaml:"-"`
	Opportunity OpportunitySettings `json:"opportunity"         yaml:"-"`
	Earning     EarningSettings     `json:"earning"             yaml:"-"`
	Devices     DevicesConfig       `json:"devices"             yaml:"-"`
	Voice       VoiceConfig         `json:"voice"               yaml:"-"`
	// BuildInfo contains build-time version information
	BuildInfo BuildInfo `json:"build_info,omitempty" yaml:"-"`

	// cache for sensitive values and compiled regex (computed once)
	sensitiveCache *SensitiveDataCache
}

type EvolutionConfig struct {
	Enabled         bool     `json:"enabled,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	StateDir        string   `json:"state_dir,omitempty"`
	MinTaskCount    int      `json:"min_task_count,omitempty"`
	MinSuccessRatio float64  `json:"min_success_ratio,omitempty"`
	ColdPathTrigger string   `json:"cold_path_trigger,omitempty"`
	ColdPathTimes   []string `json:"cold_path_times,omitempty"`
	// Deprecated: use MinTaskCount.
	MinCaseCount int `json:"min_case_count,omitempty"`
	// Deprecated: use MinSuccessRatio.
	MinSuccessRate float64 `json:"min_success_rate,omitempty"`
}

func (c EvolutionConfig) MarshalJSON() ([]byte, error) {
	out := struct {
		Enabled         bool     `json:"enabled,omitempty"`
		Mode            string   `json:"mode,omitempty"`
		StateDir        string   `json:"state_dir,omitempty"`
		MinTaskCount    int      `json:"min_task_count,omitempty"`
		MinSuccessRatio float64  `json:"min_success_ratio,omitempty"`
		ColdPathTrigger string   `json:"cold_path_trigger,omitempty"`
		ColdPathTimes   []string `json:"cold_path_times,omitempty"`
	}{
		Enabled:         c.Enabled,
		Mode:            c.Mode,
		StateDir:        c.StateDir,
		MinTaskCount:    c.EffectiveMinTaskCount(),
		MinSuccessRatio: c.EffectiveMinSuccessRatio(),
		ColdPathTrigger: strings.TrimSpace(c.ColdPathTrigger),
		ColdPathTimes:   c.EffectiveColdPathTimes(),
	}
	if !out.Enabled {
		out.Mode = ""
		out.ColdPathTrigger = ""
		out.ColdPathTimes = nil
	}
	return json.Marshal(out)
}

func (c EvolutionConfig) EffectiveMode() string {
	if !c.Enabled {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "draft":
		return "draft"
	case "apply":
		return "apply"
	case "", "observe":
		return "observe"
	default:
		return "observe"
	}
}

func (c EvolutionConfig) RunsColdPathAutomatically() bool {
	return c.RunsColdPathAfterTurn() || c.RunsColdPathScheduled()
}

func (c EvolutionConfig) ColdPathTriggerMode() string {
	if c.EffectiveMode() != "draft" && c.EffectiveMode() != "apply" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(c.ColdPathTrigger)) {
	case "", "after_turn":
		return "after_turn"
	case "scheduled":
		return "scheduled"
	case "manual", "none", "off":
		return "manual"
	default:
		return "after_turn"
	}
}

func (c EvolutionConfig) RunsColdPathAfterTurn() bool {
	return c.ColdPathTriggerMode() == "after_turn"
}

func (c EvolutionConfig) RunsColdPathScheduled() bool {
	return c.ColdPathTriggerMode() == "scheduled"
}

func (c EvolutionConfig) EffectiveMinTaskCount() int {
	if c.MinTaskCount > 0 {
		return c.MinTaskCount
	}
	if c.MinCaseCount > 0 {
		return c.MinCaseCount
	}
	return 2
}

func (c EvolutionConfig) EffectiveMinSuccessRatio() float64 {
	if c.MinSuccessRatio > 0 {
		return c.MinSuccessRatio
	}
	if c.MinSuccessRate > 0 {
		return c.MinSuccessRate
	}
	return 0.7
}

func (c EvolutionConfig) EffectiveColdPathTimes() []string {
	out := make([]string, 0, len(c.ColdPathTimes))
	for _, value := range c.ColdPathTimes {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func (c EvolutionConfig) AutoAppliesDrafts() bool {
	return c.EffectiveMode() == "apply"
}

// IsolationConfig controls subprocess isolation for commands started by OpenFox.
// It is applied by the isolation package rather than by sandboxing the main process.
type IsolationConfig struct {
	Enabled     bool         `json:"enabled,omitempty"`
	ExposePaths []ExposePath `json:"expose_paths,omitempty"`
}

// ExposePath describes a host path that should remain visible inside the isolated
// child-process environment. This is currently implemented on Linux only.
type ExposePath struct {
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Mode   string `json:"mode"`
}

// FilterSensitiveData filters sensitive values from content before sending to LLM.
// This prevents the LLM from seeing its own credentials.
// Uses strings.Replacer for O(n+m) performance (computed once per SecurityConfig).
// Short content (below FilterMinLength) is returned unchanged for performance.
func (c *Config) FilterSensitiveData(content string) string {
	if c == nil {
		return content
	}
	// Check if filtering is enabled (default: true)
	if !c.Tools.IsFilterSensitiveDataEnabled() {
		return content
	}
	// Fast path: skip filtering for short content
	if len(content) < c.Tools.GetFilterMinLength() {
		return content
	}
	return c.SensitiveDataReplacer().Replace(content)
}

type HooksConfig struct {
	Enabled   bool                         `json:"enabled"`
	Defaults  HookDefaultsConfig           `json:"defaults,omitempty"`
	Builtins  map[string]BuiltinHookConfig `json:"builtins,omitempty"`
	Processes map[string]ProcessHookConfig `json:"processes,omitempty"`
}

type HookDefaultsConfig struct {
	ObserverTimeoutMS    int `json:"observer_timeout_ms,omitempty"`
	InterceptorTimeoutMS int `json:"interceptor_timeout_ms,omitempty"`
	ApprovalTimeoutMS    int `json:"approval_timeout_ms,omitempty"`
}

type BuiltinHookConfig struct {
	Enabled  bool            `json:"enabled"`
	Priority int             `json:"priority,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

type ProcessHookConfig struct {
	Enabled   bool              `json:"enabled"`
	Priority  int               `json:"priority,omitempty"`
	Transport string            `json:"transport,omitempty"`
	Command   []string          `json:"command,omitempty"`
	Dir       string            `json:"dir,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Observe   []string          `json:"observe,omitempty"`
	Intercept []string          `json:"intercept,omitempty"`
}

// BuildInfo contains build-time version information
type BuildInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

// MarshalJSON implements custom JSON marshaling for Config
// to omit providers section when empty and session when empty.
func (c *Config) MarshalJSON() ([]byte, error) {
	type Alias Config
	aux := &struct {
		Session *SessionConfig `json:"session,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if len(c.Session.Dimensions) > 0 || len(c.Session.IdentityLinks) > 0 || c.Session.DmScope != "" {
		sessionCfg := c.Session
		aux.Session = &sessionCfg
	}

	return json.Marshal(aux)
}

type AgentsConfig struct {
	Defaults AgentDefaults   `json:"defaults"`
	List     []AgentConfig   `json:"list,omitempty"`
	Dispatch *DispatchConfig `json:"dispatch,omitempty"`
}

// AgentModelConfig supports both string and structured model config.
// String format: "gpt-4" (just primary, no fallbacks)
// Object format: {"primary": "gpt-4", "fallbacks": ["claude-haiku"]}
type AgentModelConfig struct {
	Primary   string   `json:"primary,omitempty"`
	Fallbacks []string `json:"fallbacks,omitempty"`
}

func (m *AgentModelConfig) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		m.Primary = s
		m.Fallbacks = nil
		return nil
	}
	type raw struct {
		Primary   string   `json:"primary"`
		Fallbacks []string `json:"fallbacks"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	m.Primary = r.Primary
	m.Fallbacks = r.Fallbacks
	return nil
}

func (m AgentModelConfig) MarshalJSON() ([]byte, error) {
	if len(m.Fallbacks) == 0 && m.Primary != "" {
		return json.Marshal(m.Primary)
	}
	type raw struct {
		Primary   string   `json:"primary,omitempty"`
		Fallbacks []string `json:"fallbacks,omitempty"`
	}
	return json.Marshal(raw{Primary: m.Primary, Fallbacks: m.Fallbacks})
}

type AgentConfig struct {
	ID        string            `json:"id"`
	Default   bool              `json:"default,omitempty"`
	Name      string            `json:"name,omitempty"`
	Workspace string            `json:"workspace,omitempty"`
	Model     *AgentModelConfig `json:"model,omitempty"`
	Skills    []string          `json:"skills,omitempty"`
	Subagents *SubagentsConfig  `json:"subagents,omitempty"`
}

type SubagentsConfig struct {
	AllowAgents []string          `json:"allow_agents,omitempty"`
	Model       *AgentModelConfig `json:"model,omitempty"`
}

type DispatchConfig struct {
	Rules []DispatchRule `json:"rules,omitempty"`
}

type DispatchRule struct {
	Name              string           `json:"name,omitempty"`
	Agent             string           `json:"agent"`
	When              DispatchSelector `json:"when"`
	SessionDimensions []string         `json:"session_dimensions,omitempty"`
}

type DispatchSelector struct {
	Channel   string `json:"channel,omitempty"`
	Account   string `json:"account,omitempty"`
	Space     string `json:"space,omitempty"`
	Chat      string `json:"chat,omitempty"`
	Topic     string `json:"topic,omitempty"`
	Sender    string `json:"sender,omitempty"`
	Mentioned *bool  `json:"mentioned,omitempty"`
}

type SessionConfig struct {
	Dimensions    []string            `json:"dimensions,omitempty"`
	IdentityLinks map[string][]string `json:"identity_links,omitempty"`
	DmScope       string              `json:"dm_scope,omitempty"`
}

// ApplyDmScope translates the user-facing dm_scope value into the internal
// dimensions array that the routing layer consumes. It is a no-op when
// DmScope is empty or when Dimensions is already set (explicit Dimensions
// take precedence over the derived value).
func (s *SessionConfig) ApplyDmScope() {
	if s.DmScope == "" || len(s.Dimensions) > 0 {
		return
	}
	switch s.DmScope {
	case "per-channel-peer":
		s.Dimensions = []string{"chat", "sender"}
	case "per-channel":
		s.Dimensions = []string{"chat"}
	case "per-peer":
		s.Dimensions = []string{"sender"}
	case "global":
		s.Dimensions = nil
	}
}

// DeriveDmScope sets DmScope based on Dimensions when DmScope is empty.
// This handles legacy/fresh configs that only have explicit Dimensions
// without a corresponding DmScope value, ensuring the API response always
// includes a dm_scope that matches the actual runtime dimensions.
func (s *SessionConfig) DeriveDmScope() {
	if s.DmScope != "" || len(s.Dimensions) == 0 {
		return
	}
	switch {
	case slices.Equal(s.Dimensions, []string{"chat", "sender"}):
		s.DmScope = "per-channel-peer"
	case slices.Equal(s.Dimensions, []string{"chat"}):
		s.DmScope = "per-channel"
	case slices.Equal(s.Dimensions, []string{"sender"}):
		s.DmScope = "per-peer"
	}
	// Dimensions not matching any known scope mapping (custom array)
	// is fine — DmScope stays empty and the UI can handle it.
}

// RoutingConfig controls the intelligent model routing feature.
// When enabled, each incoming message is scored against structural features
// (message length, code blocks, tool call history, conversation depth, attachments).
// Messages scoring below Threshold are sent to LightModel; all others use the
// agent's primary model. This reduces cost and latency for simple tasks without
// requiring any keyword matching — all scoring is language-agnostic.
type RoutingConfig struct {
	Enabled    bool    `json:"enabled"`
	LightModel string  `json:"light_model"` // model_name from model_list to use for simple tasks
	Threshold  float64 `json:"threshold"`   // complexity score in [0,1]; score >= threshold → primary model
}

// SubTurnConfig configures the SubTurn execution system.
type SubTurnConfig struct {
	MaxDepth              int `json:"max_depth"               env:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_MAX_DEPTH"`
	MaxConcurrent         int `json:"max_concurrent"          env:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_MAX_CONCURRENT"`
	DefaultTimeoutMinutes int `json:"default_timeout_minutes" env:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_DEFAULT_TIMEOUT_MINUTES"`
	DefaultTokenBudget    int `json:"default_token_budget"    env:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_DEFAULT_TOKEN_BUDGET"`
	ConcurrencyTimeoutSec int `json:"concurrency_timeout_sec" env:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_CONCURRENCY_TIMEOUT_SEC"`
}

type ToolFeedbackConfig struct {
	Enabled          bool `json:"enabled"           env:"OPENFOX_AGENTS_DEFAULTS_TOOL_FEEDBACK_ENABLED"`
	MaxArgsLength    int  `json:"max_args_length"   env:"OPENFOX_AGENTS_DEFAULTS_TOOL_FEEDBACK_MAX_ARGS_LENGTH"`
	SeparateMessages bool `json:"separate_messages" env:"OPENFOX_AGENTS_DEFAULTS_TOOL_FEEDBACK_SEPARATE_MESSAGES"`
}

type AgentDefaults struct {
	Workspace                 string             `json:"workspace"                        env:"OPENFOX_AGENTS_DEFAULTS_WORKSPACE"`
	RestrictToWorkspace       bool               `json:"restrict_to_workspace"            env:"OPENFOX_AGENTS_DEFAULTS_RESTRICT_TO_WORKSPACE"`
	AllowReadOutsideWorkspace bool               `json:"allow_read_outside_workspace"     env:"OPENFOX_AGENTS_DEFAULTS_ALLOW_READ_OUTSIDE_WORKSPACE"`
	Provider                  string             `json:"provider"                         env:"OPENFOX_AGENTS_DEFAULTS_PROVIDER"`
	ModelName                 string             `json:"model_name"                       env:"OPENFOX_AGENTS_DEFAULTS_MODEL_NAME"`
	ModelFallbacks            []string           `json:"model_fallbacks,omitempty"`
	ImageModel                string             `json:"image_model,omitempty"            env:"OPENFOX_AGENTS_DEFAULTS_IMAGE_MODEL"`
	ImageModelFallbacks       []string           `json:"image_model_fallbacks,omitempty"`
	MaxTokens                 int                `json:"max_tokens"                       env:"OPENFOX_AGENTS_DEFAULTS_MAX_TOKENS"`
	ContextWindow             int                `json:"context_window,omitempty"         env:"OPENFOX_AGENTS_DEFAULTS_CONTEXT_WINDOW"`
	Temperature               *float64           `json:"temperature,omitempty"            env:"OPENFOX_AGENTS_DEFAULTS_TEMPERATURE"`
	MaxToolIterations         int                `json:"max_tool_iterations"              env:"OPENFOX_AGENTS_DEFAULTS_MAX_TOOL_ITERATIONS"`
	SummarizeMessageThreshold int                `json:"summarize_message_threshold"      env:"OPENFOX_AGENTS_DEFAULTS_SUMMARIZE_MESSAGE_THRESHOLD"`
	SummarizeTokenPercent     int                `json:"summarize_token_percent"          env:"OPENFOX_AGENTS_DEFAULTS_SUMMARIZE_TOKEN_PERCENT"`
	MaxMediaSize              int                `json:"max_media_size,omitempty"         env:"OPENFOX_AGENTS_DEFAULTS_MAX_MEDIA_SIZE"`
	Routing                   *RoutingConfig     `json:"routing,omitempty"`
	SteeringMode              string             `json:"steering_mode,omitempty"          env:"OPENFOX_AGENTS_DEFAULTS_STEERING_MODE"`      // "one-at-a-time" (default) or "all"
	MaxParallelTurns          int                `json:"max_parallel_turns,omitempty"     env:"OPENFOX_AGENTS_DEFAULTS_MAX_PARALLEL_TURNS"` // Max concurrent turns (0 or 1 = sequential)
	SubTurn                   SubTurnConfig      `json:"subturn"                                                                                     envPrefix:"OPENFOX_AGENTS_DEFAULTS_SUBTURN_"`
	ToolFeedback              ToolFeedbackConfig `json:"tool_feedback,omitempty"`
	SplitOnMarker             bool               `json:"split_on_marker"                  env:"OPENFOX_AGENTS_DEFAULTS_SPLIT_ON_MARKER"` // split messages on <|[SPLIT]|> marker
	ContextManager            string             `json:"context_manager,omitempty"        env:"OPENFOX_AGENTS_DEFAULTS_CONTEXT_MANAGER"`
	ContextManagerConfig      json.RawMessage    `json:"context_manager_config,omitempty" env:"OPENFOX_AGENTS_DEFAULTS_CONTEXT_MANAGER_CONFIG"`
	TurnProfile               TurnProfileConfig  `json:"turn_profile,omitempty"`
	MaxLLMRetries             int                `json:"max_llm_retries,omitempty"        env:"OPENFOX_AGENTS_DEFAULTS_MAX_LLM_RETRIES"`
	LLMRetryBackoffSecs       int                `json:"llm_retry_backoff_secs,omitempty" env:"OPENFOX_AGENTS_DEFAULTS_LLM_RETRY_BACKOFF_SECS"`
}

const DefaultMaxMediaSize = 20 * 1024 * 1024 // 20 MB

func (d *AgentDefaults) GetMaxMediaSize() int {
	if d.MaxMediaSize > 0 {
		return d.MaxMediaSize
	}
	return DefaultMaxMediaSize
}

// GetToolFeedbackMaxArgsLength returns the max visible text length for tool argument previews.
func (d *AgentDefaults) GetToolFeedbackMaxArgsLength() int {
	if d.ToolFeedback.MaxArgsLength > 0 {
		return d.ToolFeedback.MaxArgsLength
	}
	return 300
}

// IsToolFeedbackEnabled returns true when tool feedback messages should be sent to the chat.
func (d *AgentDefaults) IsToolFeedbackEnabled() bool {
	return d.ToolFeedback.Enabled
}

// IsToolFeedbackSeparateMessagesEnabled returns true when each tool feedback
// update should be sent as its own chat message instead of editing a single
// in-place progress message.
func (d *AgentDefaults) IsToolFeedbackSeparateMessagesEnabled() bool {
	return d.ToolFeedback.SeparateMessages
}

// GetModelName returns the effective model name for the agent defaults.
// It prefers the new "model_name" field but falls back to "model" for backward compatibility.
func (d *AgentDefaults) GetModelName() string {
	return d.ModelName
}

// GroupTriggerConfig controls when the bot responds in group chats.
type GroupTriggerConfig struct {
	MentionOnly bool     `json:"mention_only,omitempty"`
	Prefixes    []string `json:"prefixes,omitempty"`
}

// TypingConfig controls typing indicator behavior (Phase 10).
type TypingConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

// PlaceholderConfig controls placeholder message behavior (Phase 10).
type PlaceholderConfig struct {
	Enabled bool                `json:"enabled"`
	Text    FlexibleStringSlice `json:"text,omitempty"`
}

// GetRandomText returns a random placeholder text, or default if none set.
func (p *PlaceholderConfig) GetRandomText() string {
	if len(p.Text) == 0 {
		return "Thinking..."
	}
	if len(p.Text) == 1 {
		return p.Text[0]
	}
	idx := rand.Intn(len(p.Text))
	return p.Text[idx]
}

type StreamingConfig struct {
	Enabled         bool `json:"enabled,omitempty"`
	ThrottleSeconds int  `json:"throttle_seconds,omitempty"`
	MinGrowthChars  int  `json:"min_growth_chars,omitempty"`
}

func (c StreamingConfig) IsZero() bool {
	return !c.Enabled && c.ThrottleSeconds == 0 && c.MinGrowthChars == 0
}

func (c StreamingConfig) WithDefaults(throttleSeconds, minGrowthChars int) StreamingConfig {
	if c.Enabled {
		if c.ThrottleSeconds == 0 {
			c.ThrottleSeconds = throttleSeconds
		}
		if c.MinGrowthChars == 0 {
			c.MinGrowthChars = minGrowthChars
		}
	}
	return c
}

type WhatsAppSettings struct {
	BridgeURL        string `json:"bridge_url"         yaml:"-" env:"OPENFOX_CHANNELS_WHATSAPP_BRIDGE_URL"`
	UseNative        bool   `json:"use_native"         yaml:"-" env:"OPENFOX_CHANNELS_WHATSAPP_USE_NATIVE"`
	SessionStorePath string `json:"session_store_path" yaml:"-" env:"OPENFOX_CHANNELS_WHATSAPP_SESSION_STORE_PATH"`
}

type TelegramSettings struct {
	Token             SecureString    `json:"token,omitzero"       yaml:"token,omitempty" env:"OPENFOX_CHANNELS_TELEGRAM_TOKEN"`
	BaseURL           string          `json:"base_url"             yaml:"-"               env:"OPENFOX_CHANNELS_TELEGRAM_BASE_URL"`
	Proxy             string          `json:"proxy"                yaml:"-"               env:"OPENFOX_CHANNELS_TELEGRAM_PROXY"`
	Streaming         StreamingConfig `json:"streaming,omitzero"   yaml:"-"`
	UseMarkdownV2     bool            `json:"use_markdown_v2"      yaml:"-"               env:"OPENFOX_CHANNELS_TELEGRAM_USE_MARKDOWN_V2"`
	MediaGroupDelayMS int             `json:"media_group_delay_ms" yaml:"-"               env:"OPENFOX_CHANNELS_TELEGRAM_MEDIA_GROUP_DELAY_MS"`
}

type FeishuSettings struct {
	AppID               string              `json:"app_id"                      yaml:"-"                            env:"OPENFOX_CHANNELS_FEISHU_APP_ID"`
	AppSecret           SecureString        `json:"app_secret,omitzero"         yaml:"app_secret,omitempty"         env:"OPENFOX_CHANNELS_FEISHU_APP_SECRET"`
	EncryptKey          SecureString        `json:"encrypt_key,omitzero"        yaml:"encrypt_key,omitempty"        env:"OPENFOX_CHANNELS_FEISHU_ENCRYPT_KEY"`
	VerificationToken   SecureString        `json:"verification_token,omitzero" yaml:"verification_token,omitempty" env:"OPENFOX_CHANNELS_FEISHU_VERIFICATION_TOKEN"`
	RandomReactionEmoji FlexibleStringSlice `json:"random_reaction_emoji"       yaml:"-"                            env:"OPENFOX_CHANNELS_FEISHU_RANDOM_REACTION_EMOJI"`
	IsLark              bool                `json:"is_lark"                     yaml:"-"                            env:"OPENFOX_CHANNELS_FEISHU_IS_LARK"`
}

type DiscordSettings struct {
	Token       SecureString `json:"token,omitzero" yaml:"token,omitempty" env:"OPENFOX_CHANNELS_DISCORD_TOKEN"`
	Proxy       string       `json:"proxy"          yaml:"-"               env:"OPENFOX_CHANNELS_DISCORD_PROXY"`
	MentionOnly bool         `json:"mention_only"   yaml:"-"               env:"OPENFOX_CHANNELS_DISCORD_MENTION_ONLY"`
}

type MaixCamSettings struct {
	Host string `json:"host" yaml:"-" env:"OPENFOX_CHANNELS_MAIXCAM_HOST"`
	Port int    `json:"port" yaml:"-" env:"OPENFOX_CHANNELS_MAIXCAM_PORT"`
}

type QQSettings struct {
	AppID                string       `json:"app_id"                   yaml:"-"                    env:"OPENFOX_CHANNELS_QQ_APP_ID"`
	AppSecret            SecureString `json:"app_secret,omitzero"      yaml:"app_secret,omitempty" env:"OPENFOX_CHANNELS_QQ_APP_SECRET"`
	MaxMessageLength     int          `json:"max_message_length"       yaml:"-"                    env:"OPENFOX_CHANNELS_QQ_MAX_MESSAGE_LENGTH"`
	MaxBase64FileSizeMiB int64        `json:"max_base64_file_size_mib" yaml:"-"                    env:"OPENFOX_CHANNELS_QQ_MAX_BASE64_FILE_SIZE_MIB"`
	SendMarkdown         bool         `json:"send_markdown"            yaml:"-"                    env:"OPENFOX_CHANNELS_QQ_SEND_MARKDOWN"`
}

type DingTalkSettings struct {
	ClientID     string       `json:"client_id"              yaml:"-"                       env:"OPENFOX_CHANNELS_DINGTALK_CLIENT_ID"`
	ClientSecret SecureString `json:"client_secret,omitzero" yaml:"client_secret,omitempty" env:"OPENFOX_CHANNELS_DINGTALK_CLIENT_SECRET"`
}

type SlackSettings struct {
	BotToken SecureString `json:"bot_token,omitzero" yaml:"bot_token,omitempty" env:"OPENFOX_CHANNELS_SLACK_BOT_TOKEN"`
	AppToken SecureString `json:"app_token,omitzero" yaml:"app_token,omitempty" env:"OPENFOX_CHANNELS_SLACK_APP_TOKEN"`
}

type MatrixSettings struct {
	Homeserver         string       `json:"homeserver"                     yaml:"-"                      env:"OPENFOX_CHANNELS_MATRIX_HOMESERVER"`
	UserID             string       `json:"user_id"                        yaml:"-"                      env:"OPENFOX_CHANNELS_MATRIX_USER_ID"`
	AccessToken        SecureString `json:"access_token,omitzero"          yaml:"access_token,omitempty" env:"OPENFOX_CHANNELS_MATRIX_ACCESS_TOKEN"`
	DeviceID           string       `json:"device_id,omitempty"            yaml:"-"`
	JoinOnInvite       bool         `json:"join_on_invite"                 yaml:"-"`
	MessageFormat      string       `json:"message_format,omitempty"       yaml:"-"`
	CryptoDatabasePath string       `json:"crypto_database_path,omitempty" yaml:"-"`
	CryptoPassphrase   string       `json:"crypto_passphrase,omitempty"    yaml:"-"`
}

// DeltaChatSettings configures the Delta Chat channel. Delta Chat is an
// email-based, end-to-end encrypted messenger; OpenFox talks to a local
// `deltachat-rpc-server` process over JSON-RPC (stdio).
//
// Email is the only required setting. A full address selects an already
// configured account in DataDir; a first-run marker such as "@nine.testrun.org"
// creates a chatmail account and tells the user which full email to save.
// Mailbox credentials stay in the Delta Chat account store. DisplayName and
// AvatarImage are optional profile settings applied on startup. Password remains
// only for legacy OpenFox-managed email configuration.
type DeltaChatSettings struct {
	Email          string       `json:"email"                     yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_EMAIL"`
	Password       SecureString `json:"password,omitzero"         yaml:"password,omitempty" env:"OPENFOX_CHANNELS_DELTACHAT_PASSWORD"`
	DisplayName    string       `json:"display_name,omitempty"    yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_DISPLAY_NAME"`
	AvatarImage    string       `json:"avatar_image,omitempty"    yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_AVATAR_IMAGE"`
	DataDir        string       `json:"data_dir,omitempty"        yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_DATA_DIR"`
	RPCServerPath  string       `json:"rpc_server_path,omitempty" yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_RPC_SERVER_PATH"`
	InviteLink     string       `json:"invite_link,omitempty"     yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_INVITE_LINK"`
	AllowCrosspost bool         `json:"allow_crosspost,omitempty" yaml:"-"                  env:"OPENFOX_CHANNELS_DELTACHAT_ALLOW_CROSSPOST"`
	IMAPServer     string       `json:"imap_server,omitempty"     yaml:"-"`
	IMAPPort       int          `json:"imap_port,omitempty"       yaml:"-"`
	SMTPServer     string       `json:"smtp_server,omitempty"     yaml:"-"`
	SMTPPort       int          `json:"smtp_port,omitempty"       yaml:"-"`
}

type LINESettings struct {
	ChannelSecret      SecureString `json:"channel_secret,omitzero"       yaml:"channel_secret,omitempty"       env:"OPENFOX_CHANNELS_LINE_CHANNEL_SECRET"`
	ChannelAccessToken SecureString `json:"channel_access_token,omitzero" yaml:"channel_access_token,omitempty" env:"OPENFOX_CHANNELS_LINE_CHANNEL_ACCESS_TOKEN"`
	WebhookHost        string       `json:"webhook_host"                  yaml:"-"                              env:"OPENFOX_CHANNELS_LINE_WEBHOOK_HOST"`
	WebhookPort        int          `json:"webhook_port"                  yaml:"-"                              env:"OPENFOX_CHANNELS_LINE_WEBHOOK_PORT"`
	WebhookPath        string       `json:"webhook_path"                  yaml:"-"                              env:"OPENFOX_CHANNELS_LINE_WEBHOOK_PATH"`
}

type OneBotSettings struct {
	WSUrl              string       `json:"ws_url"                yaml:"-"                      env:"OPENFOX_CHANNELS_ONEBOT_WS_URL"`
	AccessToken        SecureString `json:"access_token,omitzero" yaml:"access_token,omitempty" env:"OPENFOX_CHANNELS_ONEBOT_ACCESS_TOKEN"`
	ReconnectInterval  int          `json:"reconnect_interval"    yaml:"-"                      env:"OPENFOX_CHANNELS_ONEBOT_RECONNECT_INTERVAL"`
	GroupTriggerPrefix []string     `json:"group_trigger_prefix"  yaml:"-"                      env:"OPENFOX_CHANNELS_ONEBOT_GROUP_TRIGGER_PREFIX"`
}

type WeComGroupConfig struct {
	AllowFrom FlexibleStringSlice `json:"allow_from,omitempty"`
}

type WeComSettings struct {
	BotID               string          `json:"bot_id"                  yaml:"-"                env:"BOT_ID"`
	Secret              SecureString    `json:"secret,omitzero"         yaml:"secret,omitempty" env:"SECRET"`
	WebSocketURL        string          `json:"websocket_url,omitempty" yaml:"-"                env:"WEBSOCKET_URL"`
	SendThinkingMessage bool            `json:"send_thinking_message"   yaml:"-"                env:"SEND_THINKING_MESSAGE"`
	Streaming           StreamingConfig `json:"streaming,omitzero"      yaml:"-"`
}

func (c *WeComSettings) SetSecret(secret string) {
	c.Secret = *NewSecureString(secret)
}

type WeixinSettings struct {
	Token      SecureString `json:"token,omitzero"       yaml:"token,omitempty" env:"OPENFOX_CHANNELS_WEIXIN_TOKEN"`
	AccountID  string       `json:"account_id,omitempty" yaml:"-"               env:"OPENFOX_CHANNELS_WEIXIN_ACCOUNT_ID"`
	BaseURL    string       `json:"base_url"             yaml:"-"               env:"OPENFOX_CHANNELS_WEIXIN_BASE_URL"`
	CDNBaseURL string       `json:"cdn_base_url"         yaml:"-"               env:"OPENFOX_CHANNELS_WEIXIN_CDN_BASE_URL"`
	Proxy      string       `json:"proxy"                yaml:"-"               env:"OPENFOX_CHANNELS_WEIXIN_PROXY"`
}

// SetToken sets the Weixin token and marks it as dirty for security saving
func (c *WeixinSettings) SetToken(token string) {
	c.Token = *NewSecureString(token)
}

type PicoSettings struct {
	Token           SecureString    `json:"token,omitzero"              yaml:"token,omitempty" env:"OPENFOX_CHANNELS_PICO_TOKEN"`
	AllowTokenQuery bool            `json:"allow_token_query,omitempty" yaml:"-"`
	AllowOrigins    []string        `json:"allow_origins,omitempty"     yaml:"-"`
	Streaming       StreamingConfig `json:"streaming,omitzero"          yaml:"-"`
	PingInterval    int             `json:"ping_interval,omitempty"     yaml:"-"`
	ReadTimeout     int             `json:"read_timeout,omitempty"      yaml:"-"`
	WriteTimeout    int             `json:"write_timeout,omitempty"     yaml:"-"`
	MaxConnections  int             `json:"max_connections,omitempty"   yaml:"-"`
}

// SetToken sets the Pico token and marks it as dirty for security saving
func (c *PicoSettings) SetToken(token string) {
	c.Token = *NewSecureString(token)
}

type PicoClientSettings struct {
	URL          string       `json:"url"                     yaml:"-"               env:"OPENFOX_CHANNELS_PICO_CLIENT_URL"`
	Token        SecureString `json:"token,omitzero"          yaml:"token,omitempty" env:"OPENFOX_CHANNELS_PICO_CLIENT_TOKEN"`
	SessionID    string       `json:"session_id,omitempty"    yaml:"-"`
	PingInterval int          `json:"ping_interval,omitempty" yaml:"-"`
	ReadTimeout  int          `json:"read_timeout,omitempty"  yaml:"-"`
}

// TOSMessengerLabRoom declares a deterministic local acceptance room. Every
// member uses the canonical TOS Agent identifier form.
type TOSMessengerLabRoom struct {
	Label   string   `json:"label"   yaml:"-"`
	Members []string `json:"members" yaml:"-"`
}

// TOSMessengerLabSettings connects OpenFox to a local Messenger acceptance
// boundary. Encryption may be empty for the legacy plaintext Hub, or
// "openmls-proxy" when the socket is one Agent's private OpenMLS proxy and the
// shared Hub is only an opaque ciphertext Relay.
type TOSMessengerLabSettings struct {
	SocketPath     string                `json:"socket_path"          yaml:"-"`
	AgentID        string                `json:"agent_id"             yaml:"-"`
	Token          SecureString          `json:"token,omitzero"       yaml:"token,omitempty"`
	CursorPath     string                `json:"cursor_path"          yaml:"-"`
	PollIntervalMS int                   `json:"poll_interval_ms"     yaml:"-"`
	Rooms          []TOSMessengerLabRoom `json:"rooms,omitempty"      yaml:"-"`
	Encryption     string                `json:"encryption,omitempty" yaml:"-"`
}

// TOSMessengerRoute binds one OpenFox chat to an operator-selected Messenger
// delivery route. OpenFox never discovers or substitutes these authority
// bearing identifiers from model output.
type TOSMessengerRoute struct {
	ChatID              string `json:"chat_id"                    yaml:"-"`
	ConversationID      string `json:"conversation_id"            yaml:"-"`
	RoomID              string `json:"room_id,omitempty"          yaml:"-"`
	MembershipEpoch     uint64 `json:"membership_epoch,omitempty" yaml:"-"`
	SessionID           string `json:"session_id"                 yaml:"-"`
	RecipientEndpointID string `json:"recipient_endpoint_id"      yaml:"-"`
	// RecipientAgentID is the canonical identity for proactive direct sends.
	// It is operator-owned and is re-verified by tos-messengerd against the
	// selected Endpoint; aliases are never stored here.
	RecipientAgentID string `json:"recipient_agent_id,omitempty" yaml:"-"`
	LifetimeSeconds  uint64 `json:"lifetime_seconds,omitempty"   yaml:"-"`
}

// TOSMessengerSettings connects OpenFox to the authenticated daemon runtime
// boundary for inbound delivery and daemon-owned outbound construction.
type TOSMessengerSettings struct {
	SocketPath               string              `json:"socket_path"                  yaml:"-"`
	PollIntervalMS           int                 `json:"poll_interval_ms"             yaml:"-"`
	LeaseSeconds             int                 `json:"lease_seconds"                yaml:"-"`
	ProactiveLifetimeSeconds uint64              `json:"proactive_lifetime_seconds,omitempty" yaml:"-"`
	EnableAttachments        bool                `json:"enable_attachments,omitempty" yaml:"-"`
	Routes                   []TOSMessengerRoute `json:"routes,omitempty"             yaml:"-"`
}

type IRCSettings struct {
	Server           string              `json:"server"                     yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_SERVER"`
	TLS              bool                `json:"tls"                        yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_TLS"`
	Nick             string              `json:"nick"                       yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_NICK"`
	User             string              `json:"user,omitempty"             yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_USER"`
	RealName         string              `json:"real_name,omitempty"        yaml:"-"`
	Password         SecureString        `json:"password,omitzero"          yaml:"password,omitempty"          env:"OPENFOX_CHANNELS_IRC_PASSWORD"`
	NickServPassword SecureString        `json:"nickserv_password,omitzero" yaml:"nickserv_password,omitempty" env:"OPENFOX_CHANNELS_IRC_NICKSERV_PASSWORD"`
	SASLUser         string              `json:"sasl_user"                  yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_SASL_USER"`
	SASLPassword     SecureString        `json:"sasl_password,omitzero"     yaml:"sasl_password,omitempty"     env:"OPENFOX_CHANNELS_IRC_SASL_PASSWORD"`
	Channels         FlexibleStringSlice `json:"channels"                   yaml:"-"                           env:"OPENFOX_CHANNELS_IRC_CHANNELS"`
	RequestCaps      FlexibleStringSlice `json:"request_caps,omitempty"     yaml:"-"`
}

type VKSettings struct {
	Token   SecureString `json:"token,omitzero" yaml:"token,omitempty" env:"OPENFOX_CHANNELS_VK_TOKEN"`
	GroupID int          `json:"group_id"       yaml:"-"               env:"OPENFOX_CHANNELS_VK_GROUP_ID"`
}

func (c *VKSettings) SetToken(token string) {
	c.Token = *NewSecureString(token)
}

// TeamsWebhookSettings configures the output-only Microsoft Teams webhook channel.
// Multiple webhook targets can be configured and selected via ChatID at send time.
type TeamsWebhookSettings struct {
	Webhooks map[string]TeamsWebhookTarget `json:"webhooks" yaml:"webhooks,omitempty"`
}

// TeamsWebhookTarget represents a single Teams webhook destination.
type TeamsWebhookTarget struct {
	WebhookURL SecureString `json:"webhook_url,omitzero" yaml:"webhook_url,omitempty"`
	Title      string       `json:"title,omitempty"      yaml:"-"`
}

type MQTTSettings struct {
	Broker      string       `json:"broker"                 yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_BROKER"`
	AgentID     string       `json:"agent_id"               yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_AGENT_ID"`
	TopicPrefix string       `json:"topic_prefix,omitempty" yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_TOPIC_PREFIX"`
	Username    SecureString `json:"username,omitzero"      yaml:"username,omitempty" env:"OPENFOX_CHANNELS_MQTT_USERNAME"`
	Password    SecureString `json:"password,omitzero"      yaml:"password,omitempty" env:"OPENFOX_CHANNELS_MQTT_PASSWORD"`
	ClientID    string       `json:"client_id,omitempty"    yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_CLIENT_ID"`
	KeepAlive   int          `json:"keep_alive,omitempty"   yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_KEEP_ALIVE"`
	QoS         int          `json:"qos,omitempty"          yaml:"-"                  env:"OPENFOX_CHANNELS_MQTT_QOS"`
}

// SlackWebhookSettings configures the output-only Slack webhook channel.
type SlackWebhookSettings struct {
	Webhooks map[string]SlackWebhookTarget `json:"webhooks" yaml:"webhooks,omitempty"`
}

// SlackWebhookTarget represents a single Slack Incoming Webhook destination.
type SlackWebhookTarget struct {
	WebhookURL SecureString `json:"webhook_url,omitzero" yaml:"webhook_url,omitempty"`
	Username   string       `json:"username,omitempty"   yaml:"-"`
	IconEmoji  string       `json:"icon_emoji,omitempty" yaml:"-"`
}

type HeartbeatConfig struct {
	Enabled  bool `json:"enabled"  env:"OPENFOX_HEARTBEAT_ENABLED"`
	Interval int  `json:"interval" env:"OPENFOX_HEARTBEAT_INTERVAL"` // minutes, min 5
}

// OpportunitySettings enables bounded, read-only Capability discovery. The
// separate native coordinator owns Gateway credentials and finalized chain
// reads; this configuration carries no custody or payment material.
type OpportunitySettings struct {
	Mode                  string   `json:"mode"`
	CoordinatorSocket     string   `json:"coordinator_socket,omitempty"`
	StateDir              string   `json:"state_dir,omitempty"`
	Queries               []string `json:"queries,omitempty"`
	IntervalMinutes       uint64   `json:"interval_minutes,omitempty"`
	JitterSeconds         uint64   `json:"jitter_seconds,omitempty"`
	RequestTimeoutSeconds uint64   `json:"request_timeout_seconds,omitempty"`
	PageSize              uint32   `json:"page_size,omitempty"`
	MaxCandidates         uint32   `json:"max_candidates,omitempty"`
	AllowedOperations     []string `json:"allowed_operations,omitempty"`
	AllowedProviders      []string `json:"allowed_providers,omitempty"`
	DeniedProviders       []string `json:"denied_providers,omitempty"`
}

// EarningSettings is the explicit authority surface for autonomous commerce.
// Every side-effect gate defaults off. Enabling discovery never implicitly
// enables contact, Agreement promotion, execution, or value transfer.
type EarningSettings struct {
	Enabled                    bool                              `json:"enabled"`
	Mode                       string                            `json:"mode,omitempty"`
	ObserveOnly                bool                              `json:"observe_only"`
	StateDir                   string                            `json:"state_dir,omitempty"`
	OwnerID                    string                            `json:"owner_id,omitempty"`
	AgentID                    string                            `json:"agent_id,omitempty"`
	AuthorityID                string                            `json:"authority_id,omitempty"`
	Authority                  EarningAuthoritySettings          `json:"authority"`
	MessengerSocket            string                            `json:"messenger_socket,omitempty"`
	MandateDigest              string                            `json:"mandate_digest,omitempty"`
	MinimumIndependentCarriers uint32                            `json:"minimum_independent_carriers"`
	Carriers                   []EarningCarrierSettings          `json:"carriers,omitempty"`
	TrustedIntentIssuerKeys    map[string]string                 `json:"trusted_intent_issuer_keys,omitempty"`
	Capabilities               []EarningCapabilitySettings       `json:"capabilities,omitempty"`
	Resources                  EarningResourceSettings           `json:"resources"`
	SettlementAdapters         []string                          `json:"settlement_adapters,omitempty"`
	Gates                      EarningGateSettings               `json:"gates"`
	Policy                     EarningPolicySettings             `json:"policy"`
	Acquisition                EarningAcquisitionSettings        `json:"acquisition"`
	Retrieval                  EarningRetrievalSettings          `json:"retrieval"`
	TOSPayment                 EarningTOSPaymentSettings         `json:"tos_payment"`
	TOSEscrow                  EarningTOSEscrowSettings          `json:"tos_escrow"`
	PrivateHandoff             EarningPrivateHandoffSettings     `json:"private_handoff"`
	ExternalSettlement         EarningExternalSettlementSettings `json:"external_settlement"`
	Publication                EarningPublicationSettings        `json:"publication"`
	IntervalSeconds            uint32                            `json:"interval_seconds,omitempty"`
	JitterSeconds              uint32                            `json:"jitter_seconds,omitempty"`
	CycleTimeoutSeconds        uint32                            `json:"cycle_timeout_seconds,omitempty"`
}

type EarningExternalSettlementSettings struct {
	Enabled              bool   `json:"enabled"`
	AdapterURI           string `json:"adapter_uri,omitempty"`
	SystemID             string `json:"system_id,omitempty"`
	AdapterProfileDigest string `json:"adapter_profile_digest,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	ServerName           string `json:"server_name,omitempty"`
	CAFile               string `json:"ca_file,omitempty"`
	ClientCertFile       string `json:"client_cert_file,omitempty"`
	ClientKeyFile        string `json:"client_key_file,omitempty"`
	AttestorID           string `json:"attestor_id,omitempty"`
	AttestorPublicKey    string `json:"attestor_public_key,omitempty"`
	TimeoutMillis        uint32 `json:"timeout_millis,omitempty"`
}

type EarningPrivateHandoffSettings struct {
	Enabled               bool                             `json:"enabled"`
	IngressProfileURI     string                           `json:"ingress_profile_uri,omitempty"`
	IngressInstanceID     string                           `json:"ingress_instance_id,omitempty"`
	IngressListen         string                           `json:"ingress_listen,omitempty"`
	IngressTLSCertFile    string                           `json:"ingress_tls_cert_file,omitempty"`
	IngressTLSKeyFile     string                           `json:"ingress_tls_key_file,omitempty"`
	PurposeDigest         string                           `json:"purpose_digest,omitempty"`
	RetentionPolicyDigest string                           `json:"retention_policy_digest,omitempty"`
	MaximumPlaintextBytes uint64                           `json:"maximum_plaintext_bytes,omitempty"`
	MaximumFiles          uint32                           `json:"maximum_files,omitempty"`
	AcceptedMediaTypes    []string                         `json:"accepted_media_types,omitempty"`
	ChallengeTTLSeconds   uint32                           `json:"challenge_ttl_seconds,omitempty"`
	RetentionTTLSeconds   uint32                           `json:"retention_ttl_seconds,omitempty"`
	Inputs                []EarningPrivateInputSettings    `json:"inputs,omitempty"`
	Uploaders             []EarningPrivateUploaderSettings `json:"uploaders,omitempty"`
}

type EarningPrivateInputSettings struct {
	ObligationID         string `json:"obligation_id"`
	Path                 string `json:"path"`
	CanonicalPath        string `json:"canonical_path"`
	MediaType            string `json:"media_type"`
	MaximumBytes         uint64 `json:"maximum_bytes"`
	MaximumExpandedBytes uint64 `json:"maximum_expanded_bytes"`
	CompressionProfile   string `json:"compression_profile_uri"`
}

type EarningPrivateUploaderSettings struct {
	IngressInstanceID string `json:"ingress_instance_id"`
	Endpoint          string `json:"endpoint"`
	CAFile            string `json:"ca_file,omitempty"`
	MaximumCiphertext uint64 `json:"maximum_ciphertext_bytes"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
}

// EarningAuthoritySettings selects the owner economic-control deployment.
// personal keeps the signing key and journal in StateDir. shared uses a
// mutually-authenticated remote authority and never loads that signing key in
// the OpenFox worker process.
type EarningAuthoritySettings struct {
	Mode               string `json:"mode,omitempty"`
	Endpoint           string `json:"endpoint,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	ClientCertFile     string `json:"client_cert_file,omitempty"`
	ClientKeyFile      string `json:"client_key_file,omitempty"`
	AuthorityPublicKey string `json:"authority_public_key,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	TimeoutMillis      uint32 `json:"timeout_millis,omitempty"`
}

type EarningPublicationSettings struct {
	NetworkID                    string   `json:"network_id,omitempty"`
	AllowDemand                  bool     `json:"allow_demand"`
	AllowedAudiences             []string `json:"allowed_audiences,omitempty"`
	MinimumTTLSeconds            uint32   `json:"minimum_ttl_seconds,omitempty"`
	MaximumTTLSeconds            uint32   `json:"maximum_ttl_seconds,omitempty"`
	MinimumMarginPPM             uint32   `json:"minimum_margin_ppm,omitempty"`
	MaximumPriceChangePPM        uint32   `json:"maximum_price_change_ppm,omitempty"`
	MaximumActive                uint32   `json:"maximum_active,omitempty"`
	MaximumRevisionsPerObject    uint32   `json:"maximum_revisions_per_object,omitempty"`
	MaximumPublicationsPerPeriod uint32   `json:"maximum_publications_per_period,omitempty"`
	PeriodSeconds                uint32   `json:"period_seconds,omitempty"`
	// SettlementParameters are public, Adapter-specific offer bytes (encoded as
	// UTF-8 config strings) placed in signed supply Intents. Secrets are never
	// permitted here.
	SettlementParameters map[string]string `json:"settlement_parameters,omitempty"`
}

type EarningTOSPaymentSettings struct {
	Enabled             bool     `json:"enabled"`
	Executable          string   `json:"executable,omitempty"`
	ConfigPath          string   `json:"config_path,omitempty"`
	Wallet              string   `json:"wallet,omitempty"`
	SourceAccount       string   `json:"source_account,omitempty"`
	NetworkGlobalID     int32    `json:"network_global_id,omitempty"`
	FeeReserveNanoTOS   uint64   `json:"fee_reserve_nanotos,omitempty"`
	QuorumConfigPaths   []string `json:"quorum_config_paths,omitempty"`
	VaultURL            string   `json:"vault_url,omitempty"`
	EvidenceDirectory   string   `json:"evidence_directory,omitempty"`
	MaximumTransactions uint32   `json:"maximum_transactions,omitempty"`
	ResolveAttempts     uint32   `json:"resolve_attempts,omitempty"`
	ResolveIntervalMS   uint32   `json:"resolve_interval_ms,omitempty"`
}

// EarningTOSEscrowSettings pins every network, code, custody, budget, and
// Provider authority input needed by the optional Paid Demand Adapter. None of
// these values may be learned from an Intent or model output at execution time.
type EarningTOSEscrowSettings struct {
	Enabled                    bool                                    `json:"enabled"`
	NetworkID                  string                                  `json:"network_id,omitempty"`
	GenesisRootHash            string                                  `json:"genesis_root_hash,omitempty"`
	GenesisFileHash            string                                  `json:"genesis_file_hash,omitempty"`
	RPCEndpoints               []string                                `json:"rpc_endpoints,omitempty"`
	Quorum                     uint32                                  `json:"quorum,omitempty"`
	QueryTimeoutMillis         uint32                                  `json:"query_timeout_millis,omitempty"`
	MaximumResponseBytes       uint64                                  `json:"maximum_response_bytes,omitempty"`
	ReadinessMaximumAgeSeconds uint32                                  `json:"readiness_maximum_age_seconds,omitempty"`
	RegistryCodeBOCFile        string                                  `json:"registry_code_boc_file,omitempty"`
	RegistryCodeHash           string                                  `json:"registry_code_hash,omitempty"`
	EscrowCodeBOCFile          string                                  `json:"escrow_code_boc_file,omitempty"`
	EscrowCodeHash             string                                  `json:"escrow_code_hash,omitempty"`
	AssetWalletCodeBOCFile     string                                  `json:"asset_wallet_code_boc_file,omitempty"`
	AssetMasterAddress         string                                  `json:"asset_master_address,omitempty"`
	AssetMasterCodeHash        string                                  `json:"asset_master_code_hash,omitempty"`
	AssetWalletCodeHash        string                                  `json:"asset_wallet_code_hash,omitempty"`
	AssetDecimals              uint32                                  `json:"asset_decimals,omitempty"`
	CapabilityID               string                                  `json:"capability_id,omitempty"`
	CapabilityVersion          string                                  `json:"capability_version,omitempty"`
	TransportSecurityMode      uint8                                   `json:"transport_security_mode,omitempty"`
	TransportMaximumBytes      uint32                                  `json:"transport_maximum_bytes,omitempty"`
	TransportBaseURL           string                                  `json:"transport_base_url,omitempty"`
	FundingWindowSeconds       uint32                                  `json:"funding_window_seconds,omitempty"`
	ExecutionWindowSeconds     uint32                                  `json:"execution_window_seconds,omitempty"`
	RefundDelaySeconds         uint32                                  `json:"refund_delay_seconds,omitempty"`
	BuyerAddress               string                                  `json:"buyer_address,omitempty"`
	ProviderWallet             string                                  `json:"provider_wallet,omitempty"`
	Executable                 string                                  `json:"executable,omitempty"`
	ConfigPath                 string                                  `json:"config_path,omitempty"`
	ActionWallet               string                                  `json:"action_wallet,omitempty"`
	ProviderActionWallet       string                                  `json:"provider_action_wallet,omitempty"`
	DeploymentWallet           string                                  `json:"deployment_wallet,omitempty"`
	RelayerAddress             string                                  `json:"relayer_address,omitempty"`
	VaultURL                   string                                  `json:"vault_url,omitempty"`
	CustodyJournalDirectory    string                                  `json:"custody_journal_directory,omitempty"`
	NetworkGlobalID            int32                                   `json:"network_global_id,omitempty"`
	DeploymentNanoTOS          uint64                                  `json:"deployment_nanotos,omitempty"`
	ActionNanoTOS              uint64                                  `json:"action_nanotos,omitempty"`
	FeeReserveNanoTOS          uint64                                  `json:"fee_reserve_nanotos,omitempty"`
	MaximumPurchases           uint64                                  `json:"maximum_purchases,omitempty"`
	MaximumPerPurchaseAtomic   string                                  `json:"maximum_per_purchase_atomic,omitempty"`
	MaximumTotalAtomic         string                                  `json:"maximum_total_atomic,omitempty"`
	BudgetWindowSeconds        uint32                                  `json:"budget_window_seconds,omitempty"`
	PollIntervalMillis         uint32                                  `json:"poll_interval_millis,omitempty"`
	FinalityTimeoutSeconds     uint32                                  `json:"finality_timeout_seconds,omitempty"`
	ProviderAuthorities        []EarningProviderOfferAuthoritySettings `json:"provider_authorities,omitempty"`
}

type EarningProviderOfferAuthoritySettings struct {
	AgentID                          string `json:"agent_id"`
	PublicKey                        string `json:"public_key"`
	AgentGeneration                  uint64 `json:"agent_generation"`
	ControllerPolicyDigest           string `json:"controller_policy_digest"`
	DelegationDigest                 string `json:"delegation_digest"`
	ScopeBoundsDigest                string `json:"scope_bounds_digest"`
	OwnerMandateDigest               string `json:"owner_mandate_digest"`
	IssuanceAuthorityReferenceDigest string `json:"issuance_authority_reference_digest"`
}

type EarningAcquisitionSettings struct {
	ShortlistSize       uint32 `json:"shortlist_size,omitempty"`
	MaximumPerIssuer    uint32 `json:"max_shortlist_per_issuer,omitempty"`
	MaximumPerSource    uint32 `json:"max_shortlist_per_source,omitempty"`
	MaximumPerTaxonomy  uint32 `json:"max_shortlist_per_taxonomy,omitempty"`
	MaximumPerValueBand uint32 `json:"max_shortlist_per_value_band,omitempty"`
	ExplorationPercent  uint8  `json:"exploration_percent,omitempty"`
}

type EarningRetrievalSettings struct {
	AllowedOrigins             []string `json:"allowed_origins,omitempty"`
	MaximumRedirects           uint8    `json:"maximum_redirects,omitempty"`
	MaximumConnections         uint16   `json:"maximum_connections,omitempty"`
	MaximumResponseHeaderBytes uint32   `json:"maximum_response_header_bytes,omitempty"`
	MaximumCompressedBytes     uint64   `json:"maximum_compressed_bytes,omitempty"`
	MaximumDecodedBytes        uint64   `json:"maximum_decoded_bytes,omitempty"`
	TimeoutMillis              uint32   `json:"timeout_millis,omitempty"`
}

type EarningCarrierSettings struct {
	Kind       string        `json:"kind,omitempty"`
	ID         string        `json:"id"`
	Endpoint   string        `json:"endpoint,omitempty"`
	Directory  string        `json:"directory,omitempty"`
	ReadToken  *SecureString `json:"read_token,omitzero"`
	RelayToken *SecureString `json:"relay_token,omitzero"`
}

type EarningCapabilitySettings struct {
	Namespace      string                          `json:"namespace"`
	Identifier     string                          `json:"identifier"`
	Version        string                          `json:"version"`
	EvidenceDigest string                          `json:"evidence_digest"`
	Offer          *EarningCapabilityOfferSettings `json:"offer,omitempty"`
}

// EarningCapabilityOfferSettings is an owner-authored economic envelope for
// AI-drafted supply. The model may describe and price a READY capability only
// inside these bounds; it cannot invent an asset, settlement route, or price.
type EarningCapabilityOfferSettings struct {
	AssetNamespace        string   `json:"asset_namespace"`
	AssetIdentifier       string   `json:"asset_identifier"`
	Unit                  string   `json:"unit"`
	MinimumRevenueAtomic  string   `json:"minimum_revenue_atomic"`
	MaximumRevenueAtomic  string   `json:"maximum_revenue_atomic"`
	MaximumUnitCostAtomic string   `json:"maximum_unit_cost_atomic"`
	SettlementAdapterURI  string   `json:"settlement_adapter_uri"`
	TaxonomyPrefixes      []string `json:"taxonomy_prefixes"`
	RequiredKeywords      []string `json:"required_keywords,omitempty"`
	MinimumTTLSeconds     uint32   `json:"minimum_ttl_seconds"`
	MaximumTTLSeconds     uint32   `json:"maximum_ttl_seconds"`
}

type EarningResourceSettings struct {
	CPUUnits        uint64 `json:"cpu_units"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	StorageBytes    uint64 `json:"storage_bytes"`
	ModelTokens     uint64 `json:"model_tokens"`
	APIAtomicBudget uint64 `json:"api_atomic_budget"`
	Concurrency     uint32 `json:"concurrency"`
}

type EarningGateSettings struct {
	Publication        bool `json:"publication"`
	Contact            bool `json:"contact"`
	Agreement          bool `json:"agreement"`
	Execution          bool `json:"execution"`
	DirectPayment      bool `json:"direct_payment"`
	ExternalSettlement bool `json:"external_settlement"`
	TOSEscrow          bool `json:"tos_escrow"`
}

type EarningPolicySettings struct {
	MinimumExpectedProfitAtomic     string `json:"minimum_expected_profit_atomic"`
	MinimumROIPPM                   uint32 `json:"minimum_roi_ppm"`
	MaximumLossAtomic               string `json:"maximum_loss_atomic"`
	MaximumOutgoingPaymentAtomic    string `json:"maximum_outgoing_payment_atomic"`
	MinimumPaymentProbabilityPPM    uint32 `json:"minimum_payment_probability_ppm"`
	MinimumCompletionProbabilityPPM uint32 `json:"minimum_completion_probability_ppm"`
}

type DevicesConfig struct {
	Enabled    bool `json:"enabled"     env:"OPENFOX_DEVICES_ENABLED"`
	MonitorUSB bool `json:"monitor_usb" env:"OPENFOX_DEVICES_MONITOR_USB"`
}

type VoiceConfig struct {
	ModelName         string `json:"model_name,omitempty"         env:"OPENFOX_VOICE_MODEL_NAME"`
	TTSModelName      string `json:"tts_model_name,omitempty"     env:"OPENFOX_VOICE_TTS_MODEL_NAME"`
	EchoTranscription bool   `json:"echo_transcription"           env:"OPENFOX_VOICE_ECHO_TRANSCRIPTION"`
	ElevenLabsAPIKey  string `json:"elevenlabs_api_key,omitempty" env:"OPENFOX_VOICE_ELEVENLABS_API_KEY"`
}

type ModelStreamingConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

func (c ModelStreamingConfig) IsZero() bool {
	return !c.Enabled
}

// ModelConfig represents a model-centric provider configuration.
// It allows adding new providers (especially OpenAI-compatible ones) via configuration only.
// The Model field may be either a plain model identifier or a provider-prefixed
// identifier such as "openai/gpt-5.4" or "nvidia/z-ai/glm-5.1".
// Supported providers include openai, anthropic, antigravity, claude-cli,
// codex-cli, github-copilot, and named OpenAI-compatible protocols such as
// groq, deepseek, modelscope, and novita.
type ModelConfig struct {
	// Required fields
	ModelName string `json:"model_name"` // User-facing alias for the model
	Provider  string `json:"provider"`   // Provider name for routing and selection. When empty, provider resolution infers it from Model.
	Model     string `json:"model"`      // Model identifier, optionally provider-prefixed.

	// HTTP-based providers
	APIBase   string   `json:"api_base,omitempty"`  // API endpoint URL
	Proxy     string   `json:"proxy,omitempty"`     // HTTP proxy URL
	Fallbacks []string `json:"fallbacks,omitempty"` // Fallback model names for failover

	// Special providers (CLI-based, OAuth, etc.)
	AuthMethod   string             `json:"auth_method,omitempty"`  // Authentication method: oauth, token
	ConnectMode  string             `json:"connect_mode,omitempty"` // Connection mode: stdio, grpc
	Workspace    string             `json:"workspace,omitempty"`    // Workspace path for CLI-based providers
	AgentBackend AgentBackendConfig `json:"agent_backend,omitzero"` // Security and lifecycle policy for full-agent providers.

	// Optional optimizations
	RPM                 int                  `json:"rpm,omitempty"`              // Requests per minute limit
	MaxTokensField      string               `json:"max_tokens_field,omitempty"` // Field name for max tokens (e.g., "max_completion_tokens")
	RequestTimeout      int                  `json:"request_timeout,omitempty"`
	ThinkingLevel       string               `json:"thinking_level,omitempty"`        // Extended thinking: off|low|medium|high|xhigh|adaptive
	ToolSchemaTransform string               `json:"tool_schema_transform,omitempty"` // Optional tool schema compatibility transform (e.g. "simple")
	Streaming           ModelStreamingConfig `json:"streaming,omitzero"`              // Opt-in for provider streaming on this model entry
	ExtraBody           map[string]any       `json:"extra_body,omitempty"`            // Additional fields to inject into request body
	CustomHeaders       map[string]string    `json:"custom_headers,omitempty"`        // Additional headers to inject into every HTTP request

	APIKeys SecureStrings `json:"api_keys,omitzero" yaml:"api_keys,omitempty"` // API authentication keys (multiple keys for failover)

	// Enabled indicates whether this model entry is active. When omitted in
	// existing configs, the field is inferred during load: models with API keys
	// or the reserved "local-model" name are auto-enabled.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// UserAgent is the user agent string to use for HTTP requests.
	UserAgent string `json:"user_agent,omitempty" yaml:"-"`

	// isVirtual marks this model as a virtual model generated from multi-key expansion.
	// Virtual models should not be persisted to config files.
	isVirtual bool
}

// AgentBackendConfig controls local full-agent runtimes such as Codex CLI and
// Claude Code. These runtimes can execute tools themselves, so their policy is
// deliberately separate from ordinary HTTP inference provider settings.
type AgentBackendConfig struct {
	// Mode is "one-shot" or "app-server". app-server is currently supported by Codex.
	Mode string `json:"mode,omitempty"`
	// Sandbox is limited to "read-only" or "workspace-write". Full access is
	// intentionally unavailable through OpenFox provider configuration.
	Sandbox string `json:"sandbox,omitempty"`
	// ApprovalPolicy is currently required to be "never" for unattended calls;
	// an interactive approval broker must be specified before adding other modes.
	ApprovalPolicy string `json:"approval_policy,omitempty"`
	// AllowNativeTools opts into the backend's own tools. It defaults to false so
	// OpenFox remains the only tool loop and authorization boundary.
	AllowNativeTools bool `json:"allow_native_tools,omitempty"`
	// SubscriptionUse must be "local-personal" when a consumer subscription is
	// reused. It documents that the authenticated CLI is local to its owner and
	// must not be exposed as a multi-user proxy.
	SubscriptionUse string `json:"subscription_use,omitempty"`
	// OwnerPrincipal is the only external caller allowed to consume a personal
	// subscription. It is matched against trusted inbound runtime context.
	OwnerPrincipal AgentBackendPrincipalConfig `json:"owner_principal,omitzero"`
	// AllowInternal permits OpenFox's own scheduler and maintenance calls.
	AllowInternal bool `json:"allow_internal,omitempty"`
	// MaxConcurrentCalls bounds simultaneous turns for one backend instance.
	MaxConcurrentCalls int `json:"max_concurrent_calls,omitempty"`
	// MaxOutputBytes bounds stdout/protocol data retained for one turn.
	MaxOutputBytes int `json:"max_output_bytes,omitempty"`
	// TimeoutSeconds is a hard deadline for one local backend operation.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

type AgentBackendPrincipalConfig struct {
	Channel  string `json:"channel,omitempty"`
	SenderID string `json:"sender_id,omitempty"`
}

func (c AgentBackendPrincipalConfig) IsZero() bool {
	return strings.TrimSpace(c.Channel) == "" && strings.TrimSpace(c.SenderID) == ""
}

// APIKey returns the first API key from apiKeys
func (c *ModelConfig) APIKey() string {
	if len(c.APIKeys) > 0 {
		return c.APIKeys[0].String()
	}
	return ""
}

// IsVirtual returns true if this model was generated from multi-key expansion.
func (c *ModelConfig) IsVirtual() bool {
	return c.isVirtual
}

// Validate checks if the ModelConfig has all required fields.
func (c *ModelConfig) Validate() error {
	if c.ModelName == "" {
		return fmt.Errorf("model_name is required")
	}
	if c.Model == "" {
		return fmt.Errorf("model is required")
	}
	if _, err := providercommon.NormalizeToolSchemaTransform(c.ToolSchemaTransform); err != nil {
		return err
	}

	// Reject whitespace in model identifier
	if strings.ContainsAny(c.Model, " \t\n\r") {
		return fmt.Errorf("model identifier contains whitespace")
	}

	// Reject leading slash
	if strings.HasPrefix(c.Model, "/") {
		return fmt.Errorf("model identifier must not start with /")
	}

	// Reject consecutive slashes
	if strings.Contains(c.Model, "//") {
		return fmt.Errorf("model identifier must not contain //")
	}
	if err := c.AgentBackend.Validate(); err != nil {
		return fmt.Errorf("agent_backend: %w", err)
	}
	return nil
}

// Validate rejects unsafe or ambiguous full-agent runtime policies. Defaults
// are applied by the provider factory and therefore need no serialized fields.
func (c AgentBackendConfig) Validate() error {
	switch c.Mode {
	case "", "one-shot", "app-server":
	default:
		return fmt.Errorf("mode must be one-shot or app-server")
	}
	switch c.Sandbox {
	case "", "read-only", "workspace-write":
	default:
		return fmt.Errorf("sandbox must be read-only or workspace-write")
	}
	switch c.ApprovalPolicy {
	case "", "never":
	default:
		return fmt.Errorf("approval_policy must be never until an interactive approval broker is configured")
	}
	switch c.SubscriptionUse {
	case "", "local-personal":
	default:
		return fmt.Errorf("subscription_use must be local-personal")
	}
	if c.AllowNativeTools {
		return fmt.Errorf("allow_native_tools requires an OpenFox approval broker and is not available yet")
	}
	ownerChannelMissing := strings.TrimSpace(c.OwnerPrincipal.Channel) == ""
	ownerSenderMissing := strings.TrimSpace(c.OwnerPrincipal.SenderID) == ""
	if ownerChannelMissing != ownerSenderMissing {
		return fmt.Errorf("owner_principal requires both channel and sender_id")
	}
	if c.MaxConcurrentCalls < 0 || c.MaxConcurrentCalls > 16 {
		return fmt.Errorf("max_concurrent_calls must be between 1 and 16 when set")
	}
	if c.MaxOutputBytes < 0 || c.MaxOutputBytes > 16*1024*1024 {
		return fmt.Errorf("max_output_bytes must not exceed 16777216")
	}
	if c.MaxOutputBytes > 0 && c.MaxOutputBytes < 4096 {
		return fmt.Errorf("max_output_bytes must be at least 4096 when set")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 3600 {
		return fmt.Errorf("timeout_seconds must be between 1 and 3600 when set")
	}
	return nil
}

func (c *ModelConfig) SetAPIKey(value string) {
	if len(c.APIKeys) > 0 {
		c.APIKeys[0].Set(value)
	} else {
		c.APIKeys = append(c.APIKeys, NewSecureString(value))
	}
}

type ToolDiscoveryConfig struct {
	Enabled          bool `json:"enabled"            env:"OPENFOX_TOOLS_DISCOVERY_ENABLED"`
	TTL              int  `json:"ttl"                env:"OPENFOX_TOOLS_DISCOVERY_TTL"`
	MaxSearchResults int  `json:"max_search_results" env:"OPENFOX_MAX_SEARCH_RESULTS"`
	UseBM25          bool `json:"use_bm25"           env:"OPENFOX_TOOLS_DISCOVERY_USE_BM25"`
	UseRegex         bool `json:"use_regex"          env:"OPENFOX_TOOLS_DISCOVERY_USE_REGEX"`
}

type ToolConfig struct {
	Enabled bool `json:"enabled" yaml:"-" env:"ENABLED"`
}

type MessageToolsConfig struct {
	ToolConfig `yaml:"-" envPrefix:"OPENFOX_TOOLS_MESSAGE_"`

	MediaEnabled bool `json:"media_enabled" yaml:"-" env:"OPENFOX_TOOLS_MESSAGE_MEDIA_ENABLED"`
}

type BraveConfig struct {
	Enabled    bool          `json:"enabled"           yaml:"-"                  env:"OPENFOX_TOOLS_WEB_BRAVE_ENABLED"`
	APIKeys    SecureStrings `json:"api_keys,omitzero" yaml:"api_keys,omitempty" env:"OPENFOX_TOOLS_WEB_BRAVE_API_KEYS"`
	MaxResults int           `json:"max_results"       yaml:"-"                  env:"OPENFOX_TOOLS_WEB_BRAVE_MAX_RESULTS"`
}

// APIKey returns the Brave API key
func (c *BraveConfig) APIKey() string {
	if len(c.APIKeys) == 0 {
		return ""
	}
	return c.APIKeys[0].String()
}

// SetAPIKey sets the Brave API key
func (c *BraveConfig) SetAPIKey(key string) {
	c.APIKeys = SimpleSecureStrings(key)
}

func (c *BraveConfig) SetAPIKeys(keys []string) {
	c.APIKeys = SimpleSecureStrings(keys...)
}

type TavilyConfig struct {
	Enabled    bool          `json:"enabled"           yaml:"-"                  env:"OPENFOX_TOOLS_WEB_TAVILY_ENABLED"`
	APIKeys    SecureStrings `json:"api_keys,omitzero" yaml:"api_keys,omitempty" env:"OPENFOX_TOOLS_WEB_TAVILY_API_KEYS"`
	BaseURL    string        `json:"base_url"          yaml:"-"                  env:"OPENFOX_TOOLS_WEB_TAVILY_BASE_URL"`
	MaxResults int           `json:"max_results"       yaml:"-"                  env:"OPENFOX_TOOLS_WEB_TAVILY_MAX_RESULTS"`
}

// APIKey returns the Tavily API key
func (c *TavilyConfig) APIKey() string {
	if len(c.APIKeys) == 0 {
		return ""
	}
	return c.APIKeys[0].String()
}

// SetAPIKey sets the Tavily API key
func (c *TavilyConfig) SetAPIKey(key string) {
	c.APIKeys = SimpleSecureStrings(key)
}

// SetAPIKeys sets the Tavily API keys
func (c *TavilyConfig) SetAPIKeys(keys []string) {
	c.APIKeys = make(SecureStrings, len(keys))
	for i, k := range keys {
		c.APIKeys[i] = NewSecureString(k)
	}
}

type KagiConfig struct {
	Enabled    bool          `json:"enabled"           yaml:"-"                  env:"OPENFOX_TOOLS_WEB_KAGI_ENABLED"`
	APIKeys    SecureStrings `json:"api_keys,omitzero" yaml:"api_keys,omitempty" env:"OPENFOX_TOOLS_WEB_KAGI_API_KEYS"`
	BaseURL    string        `json:"base_url"          yaml:"-"                  env:"OPENFOX_TOOLS_WEB_KAGI_BASE_URL"`
	MaxResults int           `json:"max_results"       yaml:"-"                  env:"OPENFOX_TOOLS_WEB_KAGI_MAX_RESULTS"`
}

// APIKey returns the Kagi API key
func (c *KagiConfig) APIKey() string {
	if len(c.APIKeys) == 0 {
		return ""
	}
	return c.APIKeys[0].String()
}

// SetAPIKey sets the Kagi API key
func (c *KagiConfig) SetAPIKey(key string) {
	c.APIKeys = SimpleSecureStrings(key)
}

// SetAPIKeys sets the Kagi API keys
func (c *KagiConfig) SetAPIKeys(keys []string) {
	c.APIKeys = SimpleSecureStrings(keys...)
}

type DuckDuckGoConfig struct {
	Enabled    bool `json:"enabled"     env:"OPENFOX_TOOLS_WEB_DUCKDUCKGO_ENABLED"`
	MaxResults int  `json:"max_results" env:"OPENFOX_TOOLS_WEB_DUCKDUCKGO_MAX_RESULTS"`
}

type SogouConfig struct {
	Enabled    bool `json:"enabled"     env:"OPENFOX_TOOLS_WEB_SOGOU_ENABLED"`
	MaxResults int  `json:"max_results" env:"OPENFOX_TOOLS_WEB_SOGOU_MAX_RESULTS"`
}

type GeminiSearchConfig struct {
	Enabled    bool         `json:"enabled"          yaml:"-"                 env:"OPENFOX_TOOLS_WEB_GEMINI_ENABLED"`
	APIKey     SecureString `json:"api_key,omitzero" yaml:"api_key,omitempty" env:"OPENFOX_TOOLS_WEB_GEMINI_API_KEY"`
	Model      string       `json:"model"            yaml:"-"                 env:"OPENFOX_TOOLS_WEB_GEMINI_MODEL"`
	MaxResults int          `json:"max_results"      yaml:"-"                 env:"OPENFOX_TOOLS_WEB_GEMINI_MAX_RESULTS"`
}

type PerplexityConfig struct {
	Enabled    bool          `json:"enabled"           yaml:"-"                  env:"OPENFOX_TOOLS_WEB_PERPLEXITY_ENABLED"`
	APIKeys    SecureStrings `json:"api_keys,omitzero" yaml:"api_keys,omitempty" env:"OPENFOX_TOOLS_WEB_PERPLEXITY_API_KEYS"`
	MaxResults int           `json:"max_results"       yaml:"-"                  env:"OPENFOX_TOOLS_WEB_PERPLEXITY_MAX_RESULTS"`
}

// APIKey returns the Perplexity API key
func (c *PerplexityConfig) APIKey() string {
	if len(c.APIKeys) == 0 {
		return ""
	}
	return c.APIKeys[0].String()
}

// SetAPIKey sets the Perplexity API key
func (c *PerplexityConfig) SetAPIKey(key string) {
	c.APIKeys = SimpleSecureStrings(key)
}

type SearXNGConfig struct {
	Enabled    bool   `json:"enabled"     env:"OPENFOX_TOOLS_WEB_SEARXNG_ENABLED"`
	BaseURL    string `json:"base_url"    env:"OPENFOX_TOOLS_WEB_SEARXNG_BASE_URL"`
	MaxResults int    `json:"max_results" env:"OPENFOX_TOOLS_WEB_SEARXNG_MAX_RESULTS"`
}

type GLMSearchConfig struct {
	Enabled bool         `json:"enabled"          yaml:"-"                 env:"OPENFOX_TOOLS_WEB_GLM_ENABLED"`
	APIKey  SecureString `json:"api_key,omitzero" yaml:"api_key,omitempty" env:"OPENFOX_TOOLS_WEB_GLM_API_KEY"`
	BaseURL string       `json:"base_url"         yaml:"-"                 env:"OPENFOX_TOOLS_WEB_GLM_BASE_URL"`
	// SearchEngine specifies the search backend: "search_std" (default),
	// "search_pro", "search_pro_sogou", or "search_pro_quark".
	SearchEngine string `json:"search_engine" yaml:"-" env:"OPENFOX_TOOLS_WEB_GLM_SEARCH_ENGINE"`
	MaxResults   int    `json:"max_results"   yaml:"-" env:"OPENFOX_TOOLS_WEB_GLM_MAX_RESULTS"`
}

type BaiduSearchConfig struct {
	Enabled    bool         `json:"enabled"          yaml:"-"                 env:"OPENFOX_TOOLS_WEB_BAIDU_ENABLED"`
	APIKey     SecureString `json:"api_key,omitzero" yaml:"api_key,omitempty" env:"OPENFOX_TOOLS_WEB_BAIDU_API_KEY"`
	BaseURL    string       `json:"base_url"         yaml:"-"                 env:"OPENFOX_TOOLS_WEB_BAIDU_BASE_URL"`
	MaxResults int          `json:"max_results"      yaml:"-"                 env:"OPENFOX_TOOLS_WEB_BAIDU_MAX_RESULTS"`
}

type WebToolsConfig struct {
	ToolConfig  `                   yaml:"-"                      envPrefix:"OPENFOX_TOOLS_WEB_"`
	Brave       BraveConfig        `yaml:"brave,omitempty"                                       json:"brave"`
	Tavily      TavilyConfig       `yaml:"tavily,omitempty"                                      json:"tavily"`
	Kagi        KagiConfig         `yaml:"kagi,omitempty"                                        json:"kagi"`
	Sogou       SogouConfig        `yaml:"-"                                                     json:"sogou"`
	DuckDuckGo  DuckDuckGoConfig   `yaml:"-"                                                     json:"duckduckgo"`
	Gemini      GeminiSearchConfig `yaml:"gemini,omitempty"                                      json:"gemini"`
	Perplexity  PerplexityConfig   `yaml:"perplexity,omitempty"                                  json:"perplexity"`
	SearXNG     SearXNGConfig      `yaml:"-"                                                     json:"searxng"`
	GLMSearch   GLMSearchConfig    `yaml:"glm_search,omitempty"                                  json:"glm_search"`
	BaiduSearch BaiduSearchConfig  `yaml:"baidu_search,omitempty"                                json:"baidu_search"`
	Provider    string             `yaml:"-"                                                     json:"provider,omitempty" env:"OPENFOX_TOOLS_WEB_PROVIDER"`
	// PreferNative controls whether to use provider-native web search when
	// the active LLM supports it (e.g. OpenAI web_search_preview). When true,
	// the client-side web_search tool is hidden to avoid duplicate search surfaces,
	// and the provider's built-in search is used instead. Falls back to client-side
	// search when the provider does not support native search.
	PreferNative bool `yaml:"-" json:"prefer_native" env:"OPENFOX_TOOLS_WEB_PREFER_NATIVE"`
	// Proxy is an optional proxy URL for web tools (http/https/socks5/socks5h).
	// For authenticated proxies, prefer HTTP_PROXY/HTTPS_PROXY env vars instead of embedding credentials in config.
	Proxy                string              `yaml:"-" json:"proxy,omitempty"                  env:"OPENFOX_TOOLS_WEB_PROXY"`
	FetchLimitBytes      int64               `yaml:"-" json:"fetch_limit_bytes,omitempty"      env:"OPENFOX_TOOLS_WEB_FETCH_LIMIT_BYTES"`
	Format               string              `yaml:"-" json:"format,omitempty"                 env:"OPENFOX_TOOLS_WEB_FORMAT"`
	PrivateHostWhitelist FlexibleStringSlice `yaml:"-" json:"private_host_whitelist,omitempty" env:"OPENFOX_TOOLS_WEB_PRIVATE_HOST_WHITELIST"`
}

type CronToolsConfig struct {
	ToolConfig `envPrefix:"OPENFOX_TOOLS_CRON_"`
	// 0 means no timeout.
	ExecTimeoutMinutes    int      `json:"exec_timeout_minutes"    env:"OPENFOX_TOOLS_CRON_EXEC_TIMEOUT_MINUTES"`
	AllowCommand          bool     `json:"allow_command"           env:"OPENFOX_TOOLS_CRON_ALLOW_COMMAND"`
	CommandAllowedRemotes []string `json:"command_allowed_remotes" env:"OPENFOX_TOOLS_CRON_COMMAND_ALLOWED_REMOTES"`
}

type ExecConfig struct {
	ToolConfig          `         envPrefix:"OPENFOX_TOOLS_EXEC_"`
	EnableDenyPatterns  bool     `                                json:"enable_deny_patterns"  env:"OPENFOX_TOOLS_EXEC_ENABLE_DENY_PATTERNS"`
	AllowRemote         bool     `                                json:"allow_remote"          env:"OPENFOX_TOOLS_EXEC_ALLOW_REMOTE"`
	CustomDenyPatterns  []string `                                json:"custom_deny_patterns"  env:"OPENFOX_TOOLS_EXEC_CUSTOM_DENY_PATTERNS"`
	CustomAllowPatterns []string `                                json:"custom_allow_patterns" env:"OPENFOX_TOOLS_EXEC_CUSTOM_ALLOW_PATTERNS"`
	TimeoutSeconds      int      `                                json:"timeout_seconds"       env:"OPENFOX_TOOLS_EXEC_TIMEOUT_SECONDS"` // 0 means use default (60s)
}

type SkillsToolsConfig struct {
	ToolConfig `                       yaml:"-"                    envPrefix:"OPENFOX_TOOLS_SKILLS_"`
	Registries SkillsRegistriesConfig `yaml:"registries,omitempty"                                   json:"registries"`
	// Deprecated: use registries.github instead.
	Github                SkillsGithubConfig `yaml:"github,omitempty" json:"github"`
	MaxConcurrentSearches int                `yaml:"-"                json:"max_concurrent_searches" env:"OPENFOX_TOOLS_SKILLS_MAX_CONCURRENT_SEARCHES"`
	SearchCache           SearchCacheConfig  `yaml:"-"                json:"search_cache"`
}

type MediaCleanupConfig struct {
	ToolConfig `    envPrefix:"OPENFOX_MEDIA_CLEANUP_"`
	MaxAge     int `                                   json:"max_age_minutes"  env:"OPENFOX_MEDIA_CLEANUP_MAX_AGE"`
	Interval   int `                                   json:"interval_minutes" env:"OPENFOX_MEDIA_CLEANUP_INTERVAL"`
}

type ReadFileToolConfig struct {
	Enabled         bool   `json:"enabled"`
	Mode            string `json:"mode"`
	MaxReadFileSize int    `json:"max_read_file_size"`
}

// ActionAuthorizationConfig sends side-effect decisions to the Messenger
// runtime socket. The daemon remains the policy and one-shot grant authority.
type ActionAuthorizationConfig struct {
	Enabled        bool   `json:"enabled"         yaml:"-" env:"OPENFOX_TOOLS_ACTION_AUTHORIZATION_ENABLED"`
	SocketPath     string `json:"socket_path"     yaml:"-" env:"OPENFOX_TOOLS_ACTION_AUTHORIZATION_SOCKET_PATH"`
	TimeoutSeconds int    `json:"timeout_seconds" yaml:"-" env:"OPENFOX_TOOLS_ACTION_AUTHORIZATION_TIMEOUT_SECONDS"`
	// PhysicalCapabilities are local owner configuration, keyed by the exact
	// built-in hardware tool name. Enabling a hardware tool without a valid
	// entry leaves it registered but fail-closed at invocation time.
	PhysicalCapabilities map[string]PhysicalCapabilityConfig `json:"physical_capabilities,omitempty" yaml:"-"`
}

type PhysicalCapabilityConfig struct {
	CapabilityID string   `json:"capability_id"`
	Operations   []string `json:"operations"`
}

const (
	ReadFileModeBytes = "bytes"
	ReadFileModeLines = "lines"
)

func (c ReadFileToolConfig) EffectiveMode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case ReadFileModeLines:
		return ReadFileModeLines
	case "", ReadFileModeBytes:
		return ReadFileModeBytes
	default:
		return ReadFileModeBytes
	}
}

type ToolsConfig struct {
	ActionAuthorization ActionAuthorizationConfig `json:"action_authorization" yaml:"-" envPrefix:"OPENFOX_TOOLS_ACTION_AUTHORIZATION_"`
	AllowReadPaths      []string                  `json:"allow_read_paths"     yaml:"-"                                                 env:"OPENFOX_TOOLS_ALLOW_READ_PATHS"`
	AllowWritePaths     []string                  `json:"allow_write_paths"    yaml:"-"                                                 env:"OPENFOX_TOOLS_ALLOW_WRITE_PATHS"`
	// FilterSensitiveData controls whether to filter sensitive values (API keys,
	// tokens, secrets) from tool results before sending to the LLM.
	// Default: true (enabled)
	FilterSensitiveData bool `json:"filter_sensitive_data" yaml:"-" env:"OPENFOX_TOOLS_FILTER_SENSITIVE_DATA"`
	// FilterMinLength is the minimum content length required for filtering.
	// Content shorter than this will be returned unchanged for performance.
	// Default: 8
	FilterMinLength int                `json:"filter_min_length" yaml:"-"                env:"OPENFOX_TOOLS_FILTER_MIN_LENGTH"`
	Web             WebToolsConfig     `json:"web"               yaml:"web,omitempty"`
	Cron            CronToolsConfig    `json:"cron"              yaml:"-"`
	Exec            ExecConfig         `json:"exec"              yaml:"-"`
	Skills          SkillsToolsConfig  `json:"skills"            yaml:"skills,omitempty"`
	MediaCleanup    MediaCleanupConfig `json:"media_cleanup"     yaml:"-"`
	MCP             MCPConfig          `json:"mcp"               yaml:"-"`
	AppendFile      ToolConfig         `json:"append_file"       yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_APPEND_FILE_"`
	EditFile        ToolConfig         `json:"edit_file"         yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_EDIT_FILE_"`
	FindSkills      ToolConfig         `json:"find_skills"       yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_FIND_SKILLS_"`
	I2C             ToolConfig         `json:"i2c"               yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_I2C_"`
	InstallSkill    ToolConfig         `json:"install_skill"     yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_INSTALL_SKILL_"`
	ListDir         ToolConfig         `json:"list_dir"          yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_LIST_DIR_"`
	LoadImage       ToolConfig         `json:"load_image"        yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_LOAD_IMAGE_"`
	Message         MessageToolsConfig `json:"message"           yaml:"-"`
	ReadFile        ReadFileToolConfig `json:"read_file"         yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_READ_FILE_"`
	Serial          ToolConfig         `json:"serial"            yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SERIAL_"`
	SendFile        ToolConfig         `json:"send_file"         yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SEND_FILE_"`
	SendTTS         ToolConfig         `json:"send_tts"          yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SEND_TTS_"`
	Spawn           ToolConfig         `json:"spawn"             yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SPAWN_"`
	SpawnStatus     ToolConfig         `json:"spawn_status"      yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SPAWN_STATUS_"`
	SPI             ToolConfig         `json:"spi"               yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SPI_"`
	Subagent        ToolConfig         `json:"subagent"          yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_SUBAGENT_"`
	WebFetch        ToolConfig         `json:"web_fetch"         yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_WEB_FETCH_"`
	WriteFile       ToolConfig         `json:"write_file"        yaml:"-"                                                      envPrefix:"OPENFOX_TOOLS_WRITE_FILE_"`
}

// IsFilterSensitiveDataEnabled returns true if sensitive data filtering is enabled
func (c *ToolsConfig) IsFilterSensitiveDataEnabled() bool {
	return c.FilterSensitiveData
}

// GetFilterMinLength returns the minimum content length for filtering (default: 8)
func (c *ToolsConfig) GetFilterMinLength() int {
	if c.FilterMinLength <= 0 {
		return 8
	}
	return c.FilterMinLength
}

type SearchCacheConfig struct {
	MaxSize    int `json:"max_size"    env:"OPENFOX_SKILLS_SEARCH_CACHE_MAX_SIZE"`
	TTLSeconds int `json:"ttl_seconds" env:"OPENFOX_SKILLS_SEARCH_CACHE_TTL_SECONDS"`
}

type SkillsRegistriesConfig []*SkillRegistryConfig

func (c *SkillsRegistriesConfig) Get(name string) (SkillRegistryConfig, bool) {
	if c == nil {
		return SkillRegistryConfig{}, false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return SkillRegistryConfig{}, false
	}
	for _, registry := range *c {
		if registry == nil || registry.Name != name {
			continue
		}
		return *registry, true
	}
	return SkillRegistryConfig{}, false
}

func (c *SkillsRegistriesConfig) Set(name string, cfg SkillRegistryConfig) {
	if c == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	cfg.Name = name
	for i, registry := range *c {
		if registry == nil || registry.Name != name {
			continue
		}
		(*c)[i] = &cfg
		return
	}
	*c = append(*c, &cfg)
}

type SkillsGithubConfig struct {
	BaseURL string       `json:"base_url,omitempty" yaml:"-"               env:"OPENFOX_TOOLS_SKILLS_GITHUB_BASE_URL"`
	Token   SecureString `json:"token,omitzero"     yaml:"token,omitempty" env:"OPENFOX_TOOLS_SKILLS_GITHUB_TOKEN"`
	Proxy   string       `json:"proxy,omitempty"    yaml:"-"               env:"OPENFOX_TOOLS_SKILLS_GITHUB_PROXY"`
}

type SkillRegistryConfig struct {
	Name      string         `json:"name,omitempty"      yaml:"-"                    env:"-"`
	Enabled   bool           `json:"enabled"             yaml:"-"                    env:"-"`
	BaseURL   string         `json:"base_url"            yaml:"-"                    env:"-"`
	AuthToken SecureString   `json:"auth_token,omitzero" yaml:"auth_token,omitempty" env:"-"`
	Param     map[string]any `json:"-"                   yaml:"-"                    env:"-"`
}

const (
	envSkillsClawHubEnabled         = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_ENABLED"
	envSkillsClawHubBaseURL         = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_BASE_URL"
	envSkillsClawHubAuthToken       = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_AUTH_TOKEN"
	envSkillsClawHubSearchPath      = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_SEARCH_PATH"
	envSkillsClawHubSkillsPath      = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_SKILLS_PATH"
	envSkillsClawHubDownloadPath    = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_DOWNLOAD_PATH"
	envSkillsClawHubTimeout         = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_TIMEOUT"
	envSkillsClawHubMaxZipSize      = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_MAX_ZIP_SIZE"
	envSkillsClawHubMaxResponseSize = "OPENFOX_SKILLS_REGISTRIES_CLAWHUB_MAX_RESPONSE_SIZE"
	envSkillsGitHubEnabled          = "OPENFOX_SKILLS_REGISTRIES_GITHUB_ENABLED"
	envSkillsGitHubBaseURL          = "OPENFOX_SKILLS_REGISTRIES_GITHUB_BASE_URL"
	envSkillsGitHubAuthToken        = "OPENFOX_SKILLS_REGISTRIES_GITHUB_AUTH_TOKEN"
	envSkillsGitHubProxy            = "OPENFOX_SKILLS_REGISTRIES_GITHUB_PROXY"
)

func (c *SkillRegistryConfig) DecodeParam(target any) error {
	if c == nil {
		return nil
	}
	if len(c.Param) == 0 {
		return nil
	}
	data, err := json.Marshal(c.Param)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// MCPServerConfig defines configuration for a single MCP server
type MCPServerConfig struct {
	// Enabled indicates whether this MCP server is active
	Enabled bool `json:"enabled"`
	// Deferred controls whether this server's tools are registered as hidden (deferred/discovery mode).
	// When nil, the global Discovery.Enabled setting applies.
	// When explicitly set to true or false, it overrides the global setting for this server only.
	Deferred *bool `json:"deferred,omitempty"`
	// Command is the executable to run (e.g., "npx", "python", "/path/to/server")
	Command string `json:"command"`
	// Args are the arguments to pass to the command
	Args []string `json:"args,omitempty"`
	// Env are environment variables to set for the server process (stdio only)
	Env map[string]string `json:"env,omitempty"`
	// EnvFile is the path to a file containing environment variables (stdio only)
	EnvFile string `json:"env_file,omitempty"`
	// Type is "stdio", "sse", "http", or "streamable-http".
	// "http" and "streamable-http" both select streamable HTTP request-response
	// mode, while "sse" keeps the standalone SSE listener enabled for
	// server-initiated notifications. Defaults: stdio if command is set, sse if
	// url is set.
	Type string `json:"type,omitempty"`
	// URL is used for SSE/HTTP transport
	URL string `json:"url,omitempty"`
	// Headers are HTTP headers to send with requests (sse/http only)
	Headers map[string]string `json:"headers,omitempty"`
}

// MCPConfig defines configuration for all MCP servers
type MCPConfig struct {
	ToolConfig `                    envPrefix:"OPENFOX_TOOLS_MCP_"`
	Discovery  ToolDiscoveryConfig `                               json:"discovery"`
	// MaxInlineTextChars controls how much MCP text stays inline before it is saved as an artifact.
	MaxInlineTextChars int `json:"max_inline_text_chars,omitempty" env:"OPENFOX_TOOLS_MCP_MAX_INLINE_TEXT_CHARS"`
	// Servers is a map of server name to server configuration
	Servers map[string]MCPServerConfig `json:"servers,omitempty"`
}

const DefaultMCPMaxInlineTextChars = 16 * 1024

func (c *MCPConfig) GetMaxInlineTextChars() int {
	if c.MaxInlineTextChars > 0 {
		return c.MaxInlineTextChars
	}
	return DefaultMCPMaxInlineTextChars
}

func LoadConfig(path string) (*Config, error) {
	updateResolver(filepath.Dir(path))

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.WarnF(
				"config file not found, using default config",
				map[string]any{"path": path},
			)
			return DefaultConfig(), nil
		}
		return nil, err
	}

	// First, try to detect config version by reading the version field
	var versionInfo struct {
		Version int `json:"version"`
	}
	if e := json.Unmarshal(data, &versionInfo); e != nil {
		e = wrapJSONError(data, e, "config.json")
		logger.ErrorCF("config", formatDiagnosticLogMessage("Malformed config file", e), map[string]any{"path": path})
		return nil, e
	}
	if len(data) <= 10 {
		logger.Warn(fmt.Sprintf("content is [%s]", string(data)))
		return DefaultConfig(), nil
	}

	// Load config based on detected version
	var cfg *Config
	switch versionInfo.Version {
	case 0:
		logger.InfoF(
			"config migrate start",
			map[string]any{"from": versionInfo.Version, "to": CurrentVersion},
		)
		if err = validateLegacyConfigDiagnostics(data); err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}

		var m map[string]any
		m, err = loadConfigMap(path)
		if err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}

		migrateErr := migrateV0ToV1(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V0→V1 migration failed: %w", migrateErr)
		}
		migrateErr = migrateV1ToV2(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V1→V2 migration failed: %w", migrateErr)
		}
		migrateErr = migrateV2ToV3(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V2→V3 migration failed: %w", migrateErr)
		}

		var migrated []byte
		migrated, err = json.Marshal(m)
		if err != nil {
			return nil, err
		}

		cfg, err = loadConfig(migrated)
		if err != nil {
			return nil, err
		}

		err = MakeBackup(path)
		if err != nil {
			return nil, err
		}

		defer func(cfg *Config) {
			_ = SaveConfig(path, cfg)
		}(cfg)
	case 1:
		// V1→V3 migration: rename channels→channel_list, infer Enabled, migrate channel configs
		logger.InfoF(
			"config migrate start",
			map[string]any{"from": versionInfo.Version, "to": CurrentVersion},
		)
		if err = validateLegacyConfigDiagnostics(data); err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}

		var m map[string]any
		m, err = loadConfigMap(path)
		if err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}

		migrateErr := migrateV1ToV2(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V1→V2 migration failed: %w", migrateErr)
		}
		migrateErr = migrateV2ToV3(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V2→V3 migration failed: %w", migrateErr)
		}

		var migrated []byte
		migrated, err = json.Marshal(m)
		if err != nil {
			return nil, err
		}

		cfg, err = loadConfig(migrated)
		if err != nil {
			return nil, err
		}

		err = MakeBackup(path)
		if err != nil {
			return nil, err
		}

		defer func(cfg *Config) {
			_ = SaveConfig(path, cfg)
		}(cfg)
		logger.InfoF(
			"config migrate success",
			map[string]any{"from": versionInfo.Version, "to": CurrentVersion},
		)
	case 2:
		// V2→V3 migration: rename channels→channel_list, convert flat→nested
		logger.InfoF(
			"config migrate start",
			map[string]any{"from": versionInfo.Version, "to": CurrentVersion},
		)
		if err = validateLegacyConfigDiagnostics(data); err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}
		var m map[string]any
		m, err = loadConfigMap(path)
		if err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}
		migrateErr := migrateV2ToV3(m)
		if migrateErr != nil {
			return nil, fmt.Errorf("V2→V3 migration failed: %w", migrateErr)
		}

		var migrated []byte
		migrated, err = json.Marshal(m)
		if err != nil {
			return nil, err
		}

		cfg, err = loadConfig(migrated)
		if err != nil {
			return nil, err
		}

		err = MakeBackup(path)
		if err != nil {
			return nil, err
		}

		defer func(cfg *Config) {
			_ = SaveConfig(path, cfg)
		}(cfg)
		logger.InfoF(
			"config migrate success",
			map[string]any{"from": versionInfo.Version, "to": CurrentVersion},
		)
	case CurrentVersion:
		// Current version
		cfg, err = loadConfig(data)
		if err != nil {
			logger.ErrorCF(
				"config",
				formatDiagnosticLogMessage("Failed to load config", err),
				map[string]any{"path": path},
			)
			return nil, err
		}
		// Load security configuration
		secPath := securityPath(path)
		err = loadSecurityConfig(cfg, secPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load security config: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported config version: %d", versionInfo.Version)
	}

	applyLegacyBindingsMigration(data, cfg)

	gatewayHostBeforeEnv := cfg.Gateway.Host

	if err = env.Parse(cfg); err != nil {
		return nil, err
	}
	applySkillsRegistryEnvCompat(cfg)

	if err = InitChannelList(cfg.Channels); err != nil {
		return nil, err
	}
	if err = cfg.ValidateTurnProfile(); err != nil {
		return nil, err
	}
	cfg.Gateway.Host, err = resolveGatewayHostFromEnv(gatewayHostBeforeEnv)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway host: %w", err)
	}

	// Expand multi-key configs into separate entries for key-level failover
	cfg.ModelList = expandMultiKeyModels(cfg.ModelList)

	// Validate model_list for uniqueness and required fields
	if err = cfg.ValidateModelList(); err != nil {
		return nil, err
	}

	// Ensure Workspace has a default if not set
	if cfg.Agents.Defaults.Workspace == "" {
		homePath := GetHome()
		cfg.Agents.Defaults.Workspace = filepath.Join(homePath, pkg.WorkspaceName)
	}

	cfg.Session.ApplyDmScope()
	cfg.Session.DeriveDmScope()

	return cfg, nil
}

func applySkillsRegistryEnvCompat(cfg *Config) {
	if cfg == nil {
		return
	}

	registryCfg, foundClawHub := cfg.Tools.Skills.Registries.Get("clawhub")
	if !foundClawHub {
		registryCfg = SkillRegistryConfig{
			Name:  "clawhub",
			Param: map[string]any{},
		}
	}
	if registryCfg.Param == nil {
		registryCfg.Param = map[string]any{}
	}

	if raw, envSet := os.LookupEnv(envSkillsClawHubEnabled); envSet {
		if value, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
			registryCfg.Enabled = value
		}
	}
	if value, envSet := os.LookupEnv(envSkillsClawHubBaseURL); envSet {
		registryCfg.BaseURL = value
	}
	if value, envSet := os.LookupEnv(envSkillsClawHubAuthToken); envSet {
		registryCfg.AuthToken = *NewSecureString(value)
	}
	if value, envSet := os.LookupEnv(envSkillsClawHubSearchPath); envSet {
		registryCfg.Param["search_path"] = value
	}
	if value, envSet := os.LookupEnv(envSkillsClawHubSkillsPath); envSet {
		registryCfg.Param["skills_path"] = value
	}
	if value, envSet := os.LookupEnv(envSkillsClawHubDownloadPath); envSet {
		registryCfg.Param["download_path"] = value
	}
	if raw, envSet := os.LookupEnv(envSkillsClawHubTimeout); envSet {
		if value, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			registryCfg.Param["timeout"] = value
		}
	}
	if raw, envSet := os.LookupEnv(envSkillsClawHubMaxZipSize); envSet {
		if value, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			registryCfg.Param["max_zip_size"] = value
		}
	}
	if raw, envSet := os.LookupEnv(envSkillsClawHubMaxResponseSize); envSet {
		if value, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			registryCfg.Param["max_response_size"] = value
		}
	}

	cfg.Tools.Skills.Registries.Set("clawhub", registryCfg)

	githubCfg, foundGitHub := cfg.Tools.Skills.Registries.Get("github")
	if !foundGitHub {
		githubCfg = SkillRegistryConfig{
			Name:  "github",
			Param: map[string]any{},
		}
	}
	if githubCfg.Param == nil {
		githubCfg.Param = map[string]any{}
	}

	if raw, envSet := os.LookupEnv(envSkillsGitHubEnabled); envSet {
		if value, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
			githubCfg.Enabled = value
		}
	}
	if value, envSet := os.LookupEnv(envSkillsGitHubBaseURL); envSet {
		githubCfg.BaseURL = value
	}
	if value, envSet := os.LookupEnv(envSkillsGitHubAuthToken); envSet {
		githubCfg.AuthToken = *NewSecureString(value)
	}
	if value, envSet := os.LookupEnv(envSkillsGitHubProxy); envSet {
		githubCfg.Param["proxy"] = value
	}

	cfg.Tools.Skills.Registries.Set("github", githubCfg)
}

func MakeBackup(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	dateSuffix := time.Now().Format(".20060102.bak")
	// Backup config file
	bakPath := path + dateSuffix
	if err := fileutil.CopyFile(path, bakPath, 0o600); err != nil {
		logger.ErrorF("failed to create config backup", map[string]any{"error": err})
		return fmt.Errorf("failed to create config backup: %w", err)
	}
	// Backup security config file
	secPath := securityPath(path)
	if _, err := os.Stat(secPath); err == nil {
		secBakPath := secPath + dateSuffix
		if secErr := fileutil.CopyFile(secPath, secBakPath, 0o600); secErr != nil {
			logger.ErrorF("failed to create security backup", map[string]any{"error": secErr})
			return fmt.Errorf("failed to create security backup: %w", secErr)
		}
	}
	return nil
}

func toNameIndex(list []*ModelConfig) []string {
	nameList := make([]string, 0, len(list))
	countMap := make(map[string]int)
	for _, model := range list {
		name := model.ModelName
		index := countMap[name]
		nameList = append(nameList, fmt.Sprintf("%s:%d", name, index))
		countMap[name]++
	}
	return nameList
}

func SaveConfig(path string, cfg *Config) error {
	if cfg.Version < CurrentVersion {
		cfg.Version = CurrentVersion
	}
	// Filter out virtual models before serializing to config file
	nonVirtualModels := make([]*ModelConfig, 0, len(cfg.ModelList))
	for _, m := range cfg.ModelList {
		if !m.isVirtual {
			nonVirtualModels = append(nonVirtualModels, m)
		}
	}
	// Temporarily replace ModelList with filtered version for serialization
	originalModelList := cfg.ModelList
	defer func() {
		// Restore original ModelList after serialization
		cfg.ModelList = originalModelList
	}()
	cfg.ModelList = nonVirtualModels

	if err := saveSecurityConfig(securityPath(path), cfg); err != nil {
		logger.ErrorCF("config", "cannot save .security.yml", map[string]any{"error": err})
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(path, data, 0o600)
}

func (c *Config) WorkspacePath() string {
	return expandHome(c.Agents.Defaults.Workspace)
}

func expandHome(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '~' {
		home, _ := os.UserHomeDir()
		if len(path) > 1 && path[1] == '/' {
			return home + path[1:]
		}
		return home
	}
	return path
}

// GetModelConfig returns the ModelConfig for the given model name.
// If multiple configs exist with the same model_name, it uses round-robin
// selection for load balancing. Returns an error if the model is not found.
func (c *Config) GetModelConfig(modelName string) (*ModelConfig, error) {
	matches := c.findMatches(modelName)
	if len(matches) == 0 {
		return nil, fmt.Errorf("model %q not found in model_list or providers", modelName)
	}
	if len(matches) == 1 {
		return matches[0], nil
	}

	// Multiple configs - use round-robin for load balancing
	idx := (rrCounter.Add(1) - 1) % uint64(len(matches))
	return matches[idx], nil
}

// findMatches finds all ModelConfig entries with the given model_name.
func (c *Config) findMatches(modelName string) []*ModelConfig {
	var matches []*ModelConfig
	for i := range c.ModelList {
		if c.ModelList[i].ModelName == modelName {
			matches = append(matches, c.ModelList[i])
		}
	}
	return matches
}

// ValidateModelList validates all ModelConfig entries in the model_list.
// It checks that each model config is valid.
// Note: Multiple entries with the same model_name are allowed for load balancing.
func (c *Config) ValidateModelList() error {
	for i := range c.ModelList {
		if err := c.ModelList[i].Validate(); err != nil {
			return fmt.Errorf("model_list[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Config) SecurityCopyFrom(path string) error {
	return loadSecurityConfig(c, securityPath(path))
}

// ResetToDefaults backs up the current config, creates a default config,
// preserves security credentials from the existing config, and saves it.
func ResetToDefaults(configPath string) error {
	if err := MakeBackup(configPath); err != nil {
		return fmt.Errorf("backup before reset: %w", err)
	}
	cfg := DefaultConfig()
	cfg.Session.ApplyDmScope()
	cfg.Session.DeriveDmScope()
	if err := cfg.SecurityCopyFrom(configPath); err != nil {
		logger.WarnF("could not preserve security config", map[string]any{"error": err})
	}
	return SaveConfig(configPath, cfg)
}

func expandMultiKeyModels(models []*ModelConfig) []*ModelConfig {
	var expanded []*ModelConfig

	for _, m := range models {
		keys := m.APIKeys.Values()

		// Single key or no keys: keep as-is
		if len(keys) <= 1 {
			expanded = append(expanded, m)
			continue
		}

		// Multiple keys: expand
		originalName := m.ModelName

		// Create entries for additional keys (key_1, key_2, ...)
		var fallbackNames []string
		for i := 1; i < len(keys); i++ {
			suffix := fmt.Sprintf("__key_%d", i)
			expandedName := originalName + suffix

			// Create a copy for the additional key
			additionalEntry := &ModelConfig{
				ModelName:           expandedName,
				Provider:            m.Provider,
				Model:               m.Model,
				APIBase:             m.APIBase,
				APIKeys:             SimpleSecureStrings(keys[i]),
				Proxy:               m.Proxy,
				AuthMethod:          m.AuthMethod,
				ConnectMode:         m.ConnectMode,
				Workspace:           m.Workspace,
				AgentBackend:        m.AgentBackend,
				RPM:                 m.RPM,
				MaxTokensField:      m.MaxTokensField,
				RequestTimeout:      m.RequestTimeout,
				ThinkingLevel:       m.ThinkingLevel,
				ToolSchemaTransform: m.ToolSchemaTransform,
				Streaming:           m.Streaming,
				ExtraBody:           m.ExtraBody,
				CustomHeaders:       m.CustomHeaders,
				UserAgent:           m.UserAgent,
				isVirtual:           true,
			}
			expanded = append(expanded, additionalEntry)
			fallbackNames = append(fallbackNames, expandedName)
		}

		// Create the primary entry with first key and fallbacks
		primaryEntry := &ModelConfig{
			ModelName:           originalName,
			Provider:            m.Provider,
			Model:               m.Model,
			APIBase:             m.APIBase,
			Proxy:               m.Proxy,
			AuthMethod:          m.AuthMethod,
			ConnectMode:         m.ConnectMode,
			Workspace:           m.Workspace,
			AgentBackend:        m.AgentBackend,
			RPM:                 m.RPM,
			MaxTokensField:      m.MaxTokensField,
			RequestTimeout:      m.RequestTimeout,
			ThinkingLevel:       m.ThinkingLevel,
			ToolSchemaTransform: m.ToolSchemaTransform,
			Streaming:           m.Streaming,
			ExtraBody:           m.ExtraBody,
			CustomHeaders:       m.CustomHeaders,
			UserAgent:           m.UserAgent,
			APIKeys:             SimpleSecureStrings(keys[0]),
		}

		// Prepend new fallbacks to existing ones
		if len(fallbackNames) > 0 {
			primaryEntry.Fallbacks = append(fallbackNames, m.Fallbacks...)
		} else if len(m.Fallbacks) > 0 {
			primaryEntry.Fallbacks = m.Fallbacks
		}

		expanded = append(expanded, primaryEntry)
	}

	return expanded
}

func (t *ToolsConfig) IsToolEnabled(name string) bool {
	switch name {
	case "web":
		return t.Web.Enabled
	case "cron":
		return t.Cron.Enabled
	case "exec":
		return t.Exec.Enabled
	case "skills":
		return t.Skills.Enabled
	case "media_cleanup":
		return t.MediaCleanup.Enabled
	case "append_file":
		return t.AppendFile.Enabled
	case "edit_file":
		return t.EditFile.Enabled
	case "find_skills":
		return t.FindSkills.Enabled
	case "i2c":
		return t.I2C.Enabled
	case "install_skill":
		return t.InstallSkill.Enabled
	case "list_dir":
		return t.ListDir.Enabled
	case "load_image":
		return t.LoadImage.Enabled
	case "message":
		return t.Message.Enabled
	case "read_file":
		return t.ReadFile.Enabled
	case "serial":
		return t.Serial.Enabled
	case "spawn":
		return t.Spawn.Enabled
	case "spawn_status":
		return t.SpawnStatus.Enabled
	case "spi":
		return t.SPI.Enabled
	case "subagent":
		return t.Subagent.Enabled
	case "web_fetch":
		return t.WebFetch.Enabled
	case "send_file":
		return t.SendFile.Enabled
	case "send_tts":
		return t.SendTTS.Enabled
	case "write_file":
		return t.WriteFile.Enabled
	case "mcp":
		return t.MCP.Enabled
	default:
		return true
	}
}
