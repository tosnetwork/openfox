# Architecture

Internal architecture notes for major runtime mechanisms and subsystem design.

- [Steering](steering.md): injecting messages into a running agent loop between tool calls.
- [SubTurn Mechanism](subturn.md): sub-agent coordination, concurrency control, and lifecycle handling.
- [Session System](session-system.md): session scope allocation, JSONL persistence, alias compatibility, and migration. ([ZH](session-system.zh.md))
- [Routing System](routing-system.md): agent dispatch, session policy selection, and light/heavy model routing. ([ZH](routing-system.zh.md))
- [Runtime Events](runtime-events.md): runtime event envelope, centralized event logging, filters, and examples. ([ZH](runtime-events.zh.md))
- [Context Management](context-management.md): context-window regions, session history, compression paths, and token-budget boundaries.
- [Agent Self-Evolution](agent-self-evolution.md): learning records, draft generation, application modes, and state layout.
- [Agentic Internet Constitution Applicability and Compliance Record](agentic-internet-constitution-compliance.md): provisional `PARTIAL` mapping, authority boundaries, interim controls, and blocked gates for PR #16.
- [Hook System Guide](hooks/README.md): current hook architecture and protocol details.
- [Capability Boundary and Core Decomposition](capability-boundary.md): which subsystems stay in the binary, which move to Skills, MCP or separate components, and how PredictionMarket should be split across them.
- [Why an Intermediary Carries Your Traffic](../design/intermediary-incentives.md): the paid relay and sponsorship loop, the unpaid Carrier path, and why the gap is structural rather than an omission.
- [Trusted Capabilities and Mobile Owner Control Plane](../design/trusted-capabilities-and-mobile-control-plane.md): reuse-first Skills/MCP sourcing, maintained finance and market-insight Skills, and authority-aware Web/iOS/Android controls.

For proposal-style or exploratory docs, also see [`../design/`](../design/).
