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
working directory and a sterile `CODEX_HOME`. OpenFox copies only `auth.json`
as opaque bytes with restrictive permissions. It does not copy `config.toml`,
MCP configuration, plugins, hooks, skills, sessions, or project instructions.

`account/read` is interpreted according to the official protocol:
`requiresOpenaiAuth` describes whether the selected provider requires OpenAI
credentials; it does not mean credentials are absent. Authentication fails
only when credentials are required and `account` is null. In
`local-personal` mode, the returned account must be a `chatgpt` account.

Ephemeral threads use a temporary directory, read-only sandboxing, no approval
requests, and disabled native features. OpenFox also rejects MCP, plugin, hook,
command execution, file change, or other native item events if the server
nevertheless reports one.

The protocol queue holds at most one decoded message. Protocol bytes are
bounded for each operation. For one-shot processes, stdout and stderr share a
single retained-byte budget; the configured value is not multiplied per
stream. Limits describe retained application data, not a claim that the Go
runtime, executable, or operating system consumes no additional memory.

## Claude Code

Claude Code currently uses non-interactive one-shot mode only. It runs from a
temporary empty directory with native tools disabled, plan-only permissions,
settings sources disabled, and session persistence disabled. This is a local
personal integration. A multi-user or hosted product must use the Anthropic
developer API or obtain the necessary vendor approval rather than proxying a
consumer login.

## Acceptance evidence

The required regression gates are:

1. authenticated ChatGPT account plus `requiresOpenaiAuth: true` succeeds;
2. null account plus `requiresOpenaiAuth: true` fails;
3. user Codex configuration is absent from the sterile home;
4. MCP/plugin/hook and native execution notifications fail closed;
5. omitted subscription mode or owner identity is rejected;
6. non-owner and unlabelled internal calls are rejected;
7. stdout and stderr cannot retain more than their shared budget;
8. canonical workspace assertions compare canonical paths;
9. timeout cleanup covers descendants on Unix and Windows; and
10. provider tests, race tests, vet, and platform compilation are reported
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
