package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/logger"
	"github.com/tosnetwork/openfox/pkg/media"
	"github.com/tosnetwork/openfox/pkg/providers"
)

type ToolEntry struct {
	Tool               Tool
	IsCore             bool
	TTL                int
	Effect             actionauth.Effect
	PhysicalCapability string
	PhysicalOperations map[string]struct{}
}

// RegisterPhysicalTool binds a raw hardware tool to a separately configured
// local Capability and a closed operation set. Invalid or absent configuration
// is retained as fail-closed metadata so merely enabling a tool never grants
// physical authority.
func (r *ToolRegistry) RegisterPhysicalTool(tool Tool, capabilityID string, operations []string) {
	r.register(tool, actionauth.EffectPhysicalIO, true)
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.tools[tool.Name()]
	if !ok {
		return
	}
	entry.PhysicalCapability = capabilityID
	entry.PhysicalOperations = make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		entry.PhysicalOperations[strings.TrimSpace(operation)] = struct{}{}
	}
}

type ToolRegistry struct {
	tools      map[string]*ToolEntry
	mu         sync.RWMutex
	version    atomic.Uint64 // incremented on Register/RegisterHidden for cache invalidation
	mediaStore media.MediaStore
	allowlist  map[string]struct{}
	authorizer actionauth.Authorizer
}

type mediaStoreAware interface {
	SetMediaStore(store media.MediaStore)
}

func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]*ToolEntry),
	}
}

// SetAllowlist restricts registrations to the provided runtime tool names.
// A nil slice means "allow all". An empty-but-non-nil slice means "allow none".
func (r *ToolRegistry) SetAllowlist(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if names == nil {
		r.allowlist = nil
		return
	}

	allowlist := make(map[string]struct{}, len(names))
	for _, name := range names {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if trimmed == "" {
			continue
		}
		allowlist[trimmed] = struct{}{}
	}
	r.allowlist = allowlist
}

func (r *ToolRegistry) Register(tool Tool) {
	r.register(tool, "", true)
}

// RegisterWithEffect classifies a core tool at registration time. When an
// authorizer is configured, tools registered through the legacy unclassified
// method fail closed before their Execute method is reached.
func (r *ToolRegistry) RegisterWithEffect(tool Tool, effect actionauth.Effect) {
	r.register(tool, effect, true)
}

func (r *ToolRegistry) register(tool Tool, effect actionauth.Effect, core bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := tool.Name()
	if !r.toolAllowedLocked(name) {
		logger.DebugCF(
			"tools",
			"Skipped core tool registration by agent allowlist",
			map[string]any{"name": name},
		)
		return
	}
	if _, exists := r.tools[name]; exists {
		logger.WarnCF("tools", "Tool registration overwrites existing tool",
			map[string]any{"name": name})
	}
	r.tools[name] = &ToolEntry{
		Tool:   tool,
		IsCore: core,
		TTL:    0, // Core tools do not use TTL
		Effect: effect,
	}
	if aware, ok := tool.(mediaStoreAware); ok && r.mediaStore != nil {
		aware.SetMediaStore(r.mediaStore)
	}
	r.version.Add(1)
	logger.DebugCF("tools", "Registered core tool", map[string]any{"name": name})
}

// RegisterHidden saves hidden tools (visible only via TTL)
func (r *ToolRegistry) RegisterHidden(tool Tool) {
	r.registerHidden(tool, "")
}

// RegisterHiddenWithEffect classifies a deferred tool before it can be
// promoted and called.
func (r *ToolRegistry) RegisterHiddenWithEffect(tool Tool, effect actionauth.Effect) {
	r.registerHidden(tool, effect)
}

func (r *ToolRegistry) registerHidden(tool Tool, effect actionauth.Effect) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := tool.Name()
	if !r.toolAllowedLocked(name) {
		logger.DebugCF(
			"tools",
			"Skipped hidden tool registration by agent allowlist",
			map[string]any{"name": name},
		)
		return
	}
	if _, exists := r.tools[name]; exists {
		logger.WarnCF("tools", "Hidden tool registration overwrites existing tool",
			map[string]any{"name": name})
	}
	r.tools[name] = &ToolEntry{
		Tool:   tool,
		IsCore: false,
		TTL:    0,
		Effect: effect,
	}
	if aware, ok := tool.(mediaStoreAware); ok && r.mediaStore != nil {
		aware.SetMediaStore(r.mediaStore)
	}
	r.version.Add(1)
	logger.DebugCF("tools", "Registered hidden tool", map[string]any{"name": name})
}

// SetAuthorizer enables side-effect enforcement for this registry. Passing
// nil disables it for legacy/non-Messenger deployments.
func (r *ToolRegistry) SetAuthorizer(authorizer actionauth.Authorizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorizer = authorizer
}

// SetMediaStore injects a MediaStore into all registered tools that can
// consume it, and remembers it for future registrations.
func (r *ToolRegistry) SetMediaStore(store media.MediaStore) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.mediaStore = store
	for _, entry := range r.tools {
		if aware, ok := entry.Tool.(mediaStoreAware); ok {
			aware.SetMediaStore(store)
		}
	}
}

// PromoteTools atomically sets the TTL for multiple non-core tools.
// This prevents a concurrent TickTTL from decrementing between promotions.
func (r *ToolRegistry) PromoteTools(names []string, ttl int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	promoted := 0
	for _, name := range names {
		if entry, exists := r.tools[name]; exists {
			if !entry.IsCore {
				entry.TTL = ttl
				promoted++
			}
		}
	}
	logger.DebugCF(
		"tools",
		"PromoteTools completed",
		map[string]any{"requested": len(names), "promoted": promoted, "ttl": ttl},
	)
}

// TickTTL decreases TTL only for non-core tools
func (r *ToolRegistry) TickTTL() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.tools {
		if !entry.IsCore && entry.TTL > 0 {
			entry.TTL--
		}
	}
}

// Version returns the current registry version (atomically).
func (r *ToolRegistry) Version() uint64 {
	return r.version.Load()
}

func (r *ToolRegistry) toolAllowedLocked(name string) bool {
	if r.allowlist == nil {
		return true
	}
	if isToolDiscoveryToolName(name) {
		// Discovery tools are part of the MCP control plane: they must remain
		// available whenever configured so deferred MCP tools can still be
		// unlocked. Per-agent allowlists still apply to the hidden MCP tools
		// themselves during RegisterHidden.
		return true
	}
	_, ok := r.allowlist[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// HasRegistered reports whether a tool name is present in the registry,
// including hidden tools whose TTL is currently zero.
func (r *ToolRegistry) HasRegistered(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tools[name]
	return ok
}

// HiddenToolSnapshot holds a consistent snapshot of hidden tools and the
// registry version at which it was taken. Used by BM25SearchTool cache.
type HiddenToolSnapshot struct {
	Docs    []HiddenToolDoc
	Version uint64
}

// HiddenToolDoc is a lightweight representation of a hidden tool for search indexing.
type HiddenToolDoc struct {
	Name        string
	Description string
}

// SnapshotHiddenTools returns all non-core tools and the current registry
// version under a single read-lock, guaranteeing consistency between the
// two values.
func (r *ToolRegistry) SnapshotHiddenTools() HiddenToolSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	docs := make([]HiddenToolDoc, 0, len(r.tools))
	for name, entry := range r.tools {
		if !entry.IsCore {
			docs = append(docs, HiddenToolDoc{
				Name:        name,
				Description: entry.Tool.Description(),
			})
		}
	}
	return HiddenToolSnapshot{
		Docs:    docs,
		Version: r.version.Load(),
	}
}

func (r *ToolRegistry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.tools[name]
	if !ok {
		return nil, false
	}
	// Hidden tools with expired TTL are not callable.
	if !entry.IsCore && entry.TTL <= 0 {
		return nil, false
	}
	return entry.Tool, true
}

func (r *ToolRegistry) Execute(ctx context.Context, name string, args map[string]any) *ToolResult {
	return r.ExecuteWithContext(ctx, name, args, "", "", nil)
}

// ExecuteWithContext executes a tool with channel/chatID context and optional async callback.
// If the tool implements AsyncExecutor and a non-nil callback is provided,
// ExecuteAsync is called instead of Execute — the callback is a parameter,
// never stored as mutable state on the tool.
func (r *ToolRegistry) ExecuteWithContext(
	ctx context.Context,
	name string,
	args map[string]any,
	channel, chatID string,
	asyncCallback AsyncCallback,
) *ToolResult {
	logger.InfoCF("tool", "Tool execution started",
		map[string]any{
			"tool": name,
			"args": args,
		})

	r.mu.RLock()
	entry, ok := r.tools[name]
	if ok && !entry.IsCore && entry.TTL <= 0 {
		ok = false
	}
	var tool Tool
	var effect actionauth.Effect
	var physicalCapability string
	var physicalOperations map[string]struct{}
	if ok {
		tool = entry.Tool
		effect = entry.Effect
		physicalCapability = entry.PhysicalCapability
		physicalOperations = make(map[string]struct{}, len(entry.PhysicalOperations))
		for operation := range entry.PhysicalOperations {
			physicalOperations[operation] = struct{}{}
		}
	}
	authorizer := r.authorizer
	r.mu.RUnlock()
	if !ok {
		logger.ErrorCF("tool", "Tool not found",
			map[string]any{
				"tool": name,
			})
		return ErrorResult(
			fmt.Sprintf("tool %q not found", name),
		).WithError(fmt.Errorf("tool not found"))
	}

	// Validate arguments against the tool's declared schema.
	if err := validateToolArgs(tool.Parameters(), args); err != nil {
		logger.WarnCF("tool", "Tool argument validation failed",
			map[string]any{"tool": name, "error": err.Error()})
		return ErrorResult(fmt.Sprintf("invalid arguments for tool %q: %s", name, err)).
			WithError(fmt.Errorf("argument validation failed: %w", err))
	}

	// Inject channel/chatID into ctx so tools read them via ToolChannel(ctx)/ToolChatID(ctx).
	// Always inject — tools validate what they require.
	ctx = WithToolContext(ctx, channel, chatID)
	var physical *actionauth.PhysicalOperation
	if effect == actionauth.EffectPhysicalIO {
		// A raw hardware tool is unavailable unless both halves of the boundary
		// exist: local Capability configuration and the independent Messenger
		// owner-authorizer. Disabling generic action authorization must never
		// silently restore physical access.
		if authorizer == nil {
			return ErrorResult(fmt.Sprintf("physical tool %q requires Messenger action authorization", name)).
				WithError(fmt.Errorf("physical authorization boundary unavailable"))
		}
		operation, ok := args["action"].(string)
		if !ok || operation == "" {
			return ErrorResult(fmt.Sprintf("physical tool %q has no explicit operation", name)).
				WithError(fmt.Errorf("physical operation refused"))
		}
		if _, allowed := physicalOperations[operation]; !allowed || physicalCapability == "" {
			return ErrorResult(fmt.Sprintf("physical tool %q operation %q has no local Capability", name, operation)).
				WithError(fmt.Errorf("physical Capability refused"))
		}
		encoded, err := json.Marshal(args)
		if err != nil {
			return ErrorResult(fmt.Sprintf("physical tool %q arguments are not canonical", name)).WithError(err)
		}
		digest := sha256.Sum256(encoded)
		physical = &actionauth.PhysicalOperation{
			CapabilityID: physicalCapability, Tool: name,
			Operation: operation, ArgumentsDigest: "sha256:" + hex.EncodeToString(digest[:]),
			ArgumentsJSON: string(encoded),
		}
		if !physical.Valid() {
			return ErrorResult(fmt.Sprintf("physical tool %q has malformed local Capability configuration", name)).
				WithError(fmt.Errorf("physical Capability refused"))
		}
	}

	if authorizer != nil {
		if !effect.Known() {
			return ErrorResult(fmt.Sprintf("tool %q has no side-effect classification", name)).
				WithError(fmt.Errorf("unclassified tool refused"))
		}
		invocation, _ := actionauth.InvocationFrom(ctx)
		if !invocation.LineageComplete {
			return ErrorResult(fmt.Sprintf("tool %q has incomplete action provenance", name)).
				WithError(fmt.Errorf("incomplete action provenance refused"))
		}
		summary := strings.TrimSpace(invocation.Summary)
		if summary == "" {
			summary = "invoke OpenFox tool " + name
		}
		action := actionauth.Action{
			Effect: effect, Summary: summary, IdempotencyKey: invocation.IdempotencyKey,
			DerivedFrom: invocation.DerivedFrom, Physical: physical,
		}
		if err := authorizer.Authorize(ctx, action); err != nil {
			logger.WarnCF("tool", "Tool authorization refused",
				map[string]any{"tool": name, "effect": effect, "error": err.Error()})
			return ErrorResult(fmt.Sprintf("tool %q was not authorized: %s", name, err)).WithError(err)
		}
	}

	// If tool implements AsyncExecutor and callback is provided, use ExecuteAsync.
	// The callback is a call parameter, not mutable state on the tool instance.
	var result *ToolResult
	start := time.Now()

	// Use recover to catch any panics during tool execution
	// This prevents tool crashes from killing the entire agent
	func() {
		defer func() {
			if re := recover(); re != nil {
				logger.RecoverPanicNoExit(re)
				errMsg := fmt.Sprintf("Tool '%s' crashed with panic: %v", name, re)
				logger.ErrorCF("tool", "Tool execution panic recovered",
					map[string]any{
						"tool":  name,
						"panic": fmt.Sprintf("%v", re),
					})
				result = &ToolResult{
					ForLLM:  errMsg,
					ForUser: errMsg,
					IsError: true,
					Err:     fmt.Errorf("panic: %v", re),
				}
			}
		}()

		if asyncExec, ok := tool.(AsyncExecutor); ok && asyncCallback != nil {
			logger.DebugCF("tool", "Executing async tool via ExecuteAsync",
				map[string]any{
					"tool": name,
				})
			result = asyncExec.ExecuteAsync(ctx, args, asyncCallback)
		} else {
			result = tool.Execute(ctx, args)
		}
	}()

	// Handle nil result (should not happen, but defensive)
	if result == nil {
		result = &ToolResult{
			ForLLM:  fmt.Sprintf("Tool '%s' returned nil result unexpectedly", name),
			ForUser: fmt.Sprintf("Tool '%s' returned nil result unexpectedly", name),
			IsError: true,
			Err:     fmt.Errorf("nil result from tool"),
		}
	}

	result = normalizeToolResult(result, name, r.mediaStore, channel, chatID)

	duration := time.Since(start)

	// Log based on result type
	if result.IsError {
		logger.ErrorCF("tool", "Tool execution failed",
			map[string]any{
				"tool":     name,
				"duration": duration.Milliseconds(),
				"error":    result.ForLLM,
			})
	} else if result.Async {
		logger.InfoCF("tool", "Tool started (async)",
			map[string]any{
				"tool":     name,
				"duration": duration.Milliseconds(),
			})
	} else {
		logger.InfoCF("tool", "Tool execution completed",
			map[string]any{
				"tool":          name,
				"duration_ms":   duration.Milliseconds(),
				"result_length": len(result.ContentForLLM()),
			})
	}

	return result
}

// sortedToolNames returns tool names in sorted order for deterministic iteration.
// This is critical for KV cache stability: non-deterministic map iteration would
// produce different system prompts and tool definitions on each call, invalidating
// the LLM's prefix cache even when no tools have changed.
func (r *ToolRegistry) sortedToolNames() []string {
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *ToolRegistry) GetDefinitions() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sorted := r.sortedToolNames()
	definitions := make([]map[string]any, 0, len(sorted))
	for _, name := range sorted {
		entry := r.tools[name]

		if !entry.IsCore && entry.TTL <= 0 {
			continue
		}

		definitions = append(definitions, ToolToSchema(r.tools[name].Tool))
	}
	return definitions
}

// ToProviderDefs converts tool definitions to provider-compatible format.
// This is the format expected by LLM provider APIs.
func (r *ToolRegistry) ToProviderDefs() []providers.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sorted := r.sortedToolNames()
	definitions := make([]providers.ToolDefinition, 0, len(sorted))
	for _, name := range sorted {
		entry := r.tools[name]

		if !entry.IsCore && entry.TTL <= 0 {
			continue
		}

		schema := ToolToSchema(entry.Tool)

		// Safely extract nested values with type checks
		fn, ok := schema["function"].(map[string]any)
		if !ok {
			continue
		}

		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		params, _ := fn["parameters"].(map[string]any)
		metadata := promptMetadataForTool(entry.Tool)

		definitions = append(definitions, providers.ToolDefinition{
			Type: "function",
			Function: providers.ToolFunctionDefinition{
				Name:        name,
				Description: desc,
				Parameters:  params,
			},
			PromptLayer:  metadata.Layer,
			PromptSlot:   metadata.Slot,
			PromptSource: metadata.Source,
		})
	}
	return definitions
}

func promptMetadataForTool(tool Tool) PromptMetadata {
	metadata := PromptMetadata{
		Layer:  ToolPromptLayerCapability,
		Slot:   ToolPromptSlotTooling,
		Source: ToolPromptSourceRegistry,
	}
	if provider, ok := tool.(PromptMetadataProvider); ok {
		provided := provider.PromptMetadata()
		if provided.Layer != "" {
			metadata.Layer = provided.Layer
		}
		if provided.Slot != "" {
			metadata.Slot = provided.Slot
		}
		if provided.Source != "" {
			metadata.Source = provided.Source
		}
	}
	return metadata
}

// List returns a list of all registered tool names.
func (r *ToolRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.sortedToolNames()
}

// Clone creates an independent copy of the registry containing the same tool
// entries (shallow copy of each ToolEntry). This is used to give subagents a
// snapshot of the parent agent's tools without sharing the same registry —
// tools registered on the parent after cloning (e.g. spawn, spawn_status)
// will NOT be visible to the clone, preventing recursive subagent spawning.
// The version counter is reset to 0 in the clone as it's a new independent registry.
func (r *ToolRegistry) Clone() *ToolRegistry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clone := &ToolRegistry{
		tools:      make(map[string]*ToolEntry, len(r.tools)),
		mediaStore: r.mediaStore,
		authorizer: r.authorizer,
	}
	if r.allowlist != nil {
		clone.allowlist = make(map[string]struct{}, len(r.allowlist))
		for name := range r.allowlist {
			clone.allowlist[name] = struct{}{}
		}
	}
	for name, entry := range r.tools {
		clone.tools[name] = &ToolEntry{
			Tool:   entry.Tool,
			IsCore: entry.IsCore,
			TTL:    entry.TTL,
			Effect: entry.Effect,
		}
	}
	return clone
}

// Count returns the number of registered tools.
func (r *ToolRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// GetSummaries returns human-readable summaries of all registered tools.
// Returns a slice of "name - description" strings.
func (r *ToolRegistry) GetSummaries() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sorted := r.sortedToolNames()
	summaries := make([]string, 0, len(sorted))
	for _, name := range sorted {
		entry := r.tools[name]

		if !entry.IsCore && entry.TTL <= 0 {
			continue
		}

		summaries = append(
			summaries,
			fmt.Sprintf("- `%s` - %s", entry.Tool.Name(), entry.Tool.Description()),
		)
	}
	return summaries
}

// GetAll returns all registered tools (both core and non-core with TTL > 0).
// Used by SubTurn to inherit parent's tool set.
func (r *ToolRegistry) GetAll() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sorted := r.sortedToolNames()
	tools := make([]Tool, 0, len(sorted))
	for _, name := range sorted {
		entry := r.tools[name]

		// Include core tools and non-core tools with active TTL
		if entry.IsCore || entry.TTL > 0 {
			tools = append(tools, entry.Tool)
		}
	}
	return tools
}
