# Subscription-backed local agent security

## Scope

OpenFox can use an already authenticated Codex CLI or Claude Code installation
for a user who has a consumer subscription but no developer API key. This does
not turn a ChatGPT or Claude subscription into a general-purpose API service.
It is a local, single-owner integration with the vendor's official executable.

Direct HTTP calls to the private `chatgpt.com/backend-api/codex` endpoint are
not supported and no implementation or exported constructor for that path is
shipped. Direct OpenAI and Anthropic HTTP providers continue to require their
respective developer credentials.

## Trust boundary

The local CLI/app-server is a separate process and is not treated as trusted
OpenFox code. OpenFox retains authority over caller admission, workspace scope,
tools, side effects, credentials, spending, signatures, and settlement.

The production configuration is fail closed:

- `auth_method` must explicitly be `subscription`;
- `subscription_use` must be `local-personal`;
- `owner_principal.channel` and `owner_principal.sender_id` must both be set;
- only matching, authenticated inbound runtime metadata can invoke the backend;
- internal/background calls are denied unless `allow_internal` is explicit;
- native tools and interactive approvals are unavailable;
- workspace paths must be absolute, existing, and canonicalized;
- timeout, concurrency, and retained-output bounds are mandatory; and
- Unix process groups or Windows kill-on-close Job Objects terminate the tree.

These controls prevent a shared OpenFox deployment, another chat participant,
or an unlabelled background job from silently consuming the owner's personal
subscription. They do not attempt to defend against arbitrary malicious code
already executing inside the OpenFox process or as the same operating-system
user.

## Codex app-server

Codex app-server is launched over local stdio. Every process gets a temporary
working directory, strict configuration parsing, and a sterile `CODEX_HOME`. OpenFox copies only `auth.json`
as opaque bytes with restrictive permissions. It does not copy `config.toml`,
MCP configuration, plugins, hooks, skills, sessions, or project instructions.
OpenAI API-key and alternate API endpoint environment overrides are removed;
the opaque ChatGPT login copy is the only credential source.
The Codex one-shot backend uses the same empty working directory, strict
configuration, and sterile authentication home instead of exposing the real
workspace to Codex. Its JSONL response parser rejects malformed, incomplete,
failed, unknown, or native-execution event streams.

`account/read` is interpreted according to the official protocol:
`requiresOpenaiAuth` describes whether the selected provider requires OpenAI
credentials; it does not mean credentials are absent. The generic health check
fails when credentials are required and `account` is null. The stricter
`local-personal` policy always requires a non-null `chatgpt` account, even if a
different provider could otherwise run without OpenAI credentials.

Ephemeral threads use a temporary directory, read-only sandboxing, no approval
requests, disabled native features, no login shell, and an empty inherited
tool environment. OpenFox also rejects MCP, plugin, hook, command execution,
file change, or other native item events if the server nevertheless reports
one.

The protocol queue holds at most one decoded message. Protocol bytes are
bounded for each operation. For one-shot processes, stdout and stderr share a
single retained-byte budget; the configured value is not multiplied per
stream. Limits describe retained application data, not a claim that the Go
runtime, executable, or operating system consumes no additional memory.

## Claude Code

Claude Code currently uses non-interactive one-shot mode only. It runs from a
temporary empty directory with native tools disabled, plan-only permissions,
settings sources disabled, and session persistence disabled. Before each turn,
OpenFox requires `claude auth status` to report a first-party Claude.ai Pro or
Max subscription. All `ANTHROPIC_*` and `CLAUDE_*` environment overrides,
including alternate configuration directories, API keys, gateways, Bedrock,
Vertex, Foundry, and external OAuth tokens, are removed from the child process. This is
a local personal integration. A multi-user or hosted product must use the
Anthropic developer API or obtain the necessary vendor approval rather than
proxying a consumer login.

## Acceptance evidence

The required regression gates are:

1. authenticated ChatGPT account plus `requiresOpenaiAuth: true` succeeds;
2. null account plus `requiresOpenaiAuth: true` fails;
3. null account plus `requiresOpenaiAuth: false` still fails in personal mode;
4. Claude personal mode requires first-party Claude.ai Pro or Max status;
5. user Codex configuration is absent from the sterile home;
6. MCP/plugin/hook and native execution notifications fail closed, and the
   one-shot JSONL parser rejects native, malformed, failed, or incomplete streams;
7. omitted subscription mode or owner identity is rejected;
8. non-owner and unlabelled internal calls are rejected;
9. stdout and stderr cannot retain more than their shared budget;
10. canonical workspace assertions compare canonical paths;
11. timeout cleanup covers descendants on Unix and Windows; and
12. provider tests, race tests, vet, and platform compilation are reported
    accurately, including unrelated repository/environment failures.

## Operational limitations

Subscription quotas are finite, variable capacity rather than an API SLA.
Opportunity profitability calculations must assign subscription capacity a
shadow cost and account for quota exhaustion and paid fallback models. Paid or
autonomous execution remains subject to the separate Native Execution Gate;
this backend does not grant commercial, wallet, signing, or settlement
authority.

## References

- [Codex app-server](https://developers.openai.com/codex/app-server/)
- [Codex authentication](https://developers.openai.com/codex/auth/)
- [Claude Code setup](https://docs.anthropic.com/en/docs/claude-code/getting-started)
