# Architecture

Internal architecture notes for major runtime mechanisms and subsystem design.

- [Steering](steering.md): injecting messages into a running agent loop between tool calls.
- [SubTurn Mechanism](subturn.md): sub-agent coordination, concurrency control, and lifecycle handling.
- [Session System](session-system.md): session scope allocation, JSONL persistence, alias compatibility, and migration. ([ZH](session-system.zh.md))
- [Routing System](routing-system.md): agent dispatch, session policy selection, and light/heavy model routing. ([ZH](routing-system.zh.md))
- [Runtime Events](runtime-events.md): runtime event envelope, centralized event logging, filters, and examples. ([ZH](runtime-events.zh.md))
- [Agent Self-Evolution](agent-self-evolution.md): learning records, draft generation, application modes, and state layout.
- [Hook System Guide](hooks/README.md): current hook architecture and protocol details.
- [Agent Refactor](agent-refactor/README.md): notes and checkpoints for the agent refactor work.
- [Autonomous Earning Agent Implementation Plan](../design/autonomous-earning-agent.md): current-state gap analysis and a phased design for discovering, executing, and settling profitable work under owner policy.
- [Trusted Capabilities and Mobile Owner Control Plane](../design/trusted-capabilities-and-mobile-control-plane.md): reuse-first Skills/MCP sourcing, maintained finance and market-insight Skills, and authority-aware Web/iOS/Android controls.

For proposal-style or exploratory docs, also see [`../design/`](../design/).
