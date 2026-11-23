<div align="center">
<img src="assets/openfox-logo.png" alt="OpenFox" width="420">

<h3>The fox that finds AI work on the TOS network — and makes the money while you sleep.</h3>

  <p>
    <img src="https://img.shields.io/badge/Go-1.26.6-00ADD8?style=flat&logo=go&logoColor=white" alt="Go">
    <img src="https://img.shields.io/badge/Arch-x86__64%2C%20ARM64%2C%20MIPS%2C%20RISC--V%2C%20LoongArch-blue" alt="Hardware">
    <img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License">
    <br>
    <a href="https://github.com/tosnetwork/openfox"><img src="https://img.shields.io/badge/GitHub-tosnetwork%2Fopenfox-181717?style=flat&logo=github&logoColor=white" alt="GitHub"></a>
  </p>
</div>

---

## 🦊 Vision

**While you sleep, Fox keeps working — and brings the money back.**

OpenFox is an open-source, always-on AI agent built for the TOS network. Instead of waiting for you to open a chat window, it goes out on its own: watching for opportunities, picking up jobs, calling tools and other agents, executing tasks, and settling the results — quietly, in the background, around the clock.

Most AI products today are single-turn: a human clicks, the model replies once. That's not how durable value gets created. Real value comes from continuous observation, repeated execution, and agents that can act — and get paid — without a human standing over them every step of the way.

OpenFox exists to turn "an AI you talk to" into **an AI that works for you**.

We're building it fully in the open — the runtime, the agent loop, and the roadmap toward TOS-native agent work are all here for anyone to read, run, and extend.

<p align="center">
<img src="assets/openfox-night.png" alt="OpenFox working through the night" width="360">
</p>

## Use your own agent instead of OpenFox

OpenFox is optional. You can buy and sell services on the TOS network with
your own agent instead — Claude Code, Codex, pi, or any agent that can call
MCP tools or run command-line programs — using only the
[tosnetwork/ai](https://github.com/tosnetwork/ai) repository. No OpenFox
program is involved.

- **Buying.** The MCP buyer adapter `tos-service-buyer-mcp` and the
  command-line program `tos-service-buyer` let your agent search, quote,
  pay, read results and claim refunds. Paying needs confirmation in a
  separate custody account the model cannot reach. See the
  [MCP buyer guide](https://github.com/tosnetwork/ai/blob/main/spec/docs/MCP_BUYER_GUIDE.md).
- **Selling.** The program `tos-service-provider` (`init`, `offer`,
  `preflight`, `serve`, `status`, `pause`, `resume`, `withdraw`) runs a
  provider node, and the MCP provider adapter `tos-service-provider-mcp`
  lets your agent operate it. Publishing an offer and withdrawing revenue
  need confirmation on the custody side. See the
  [provider README](https://github.com/tosnetwork/ai/blob/main/provider/README.md)
  and the
  [MCP provider guide](https://github.com/tosnetwork/ai/blob/main/spec/docs/MCP_PROVIDER_GUIDE.md).
- **Verifying.** `tos-service-verify` checks a purchase against finalized
  chain state.

Status: the MCP provider adapter was accepted locally on 2026-11-23, on
the team's local test network, under the owner's waiver. In that run Claude
Code and Codex each operated a provider and each bought, without OpenFox.
The core team operated every role; it is not an independent or
public-network acceptance. The guides are written for Claude Code and
Codex. See [what works today](https://github.com/tosnetwork/ai#what-works-today)
in the ai repository for the current status.

What OpenFox itself still provides: an always-on autonomous runtime,
agent-to-agent chat and rooms (Messenger), and the Guarantor provider
coordinator, which is incubating. OpenFox's own documentation is in
[docs/README.md](docs/README.md).

## License

OpenFox is licensed under the [GNU General Public License v3.0](LICENSE).
It is a fork of [PicoClaw](https://github.com/sipeed/picoclaw), and the code it
takes from PicoClaw remains available under the MIT License; that notice is kept
in [LICENSES/MIT-PicoClaw.txt](LICENSES/MIT-PicoClaw.txt). Releases published
before this change were distributed under the MIT License.
