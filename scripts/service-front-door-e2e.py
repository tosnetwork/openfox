#!/usr/bin/env python3
"""A complete paid software-work sale between two OpenFox rail nodes on an
isolated local PQ network, driven by `openfox earning service` alone.

Boots three ML-DSA-44 validators serving JSON-RPC on loopback, creates and
funds one wallet per node, then uses only `openfox earning service` commands:

1. provider: `init`, `offer`, `preflight`, `serve`;
2. buyer: `init --allow-provider --direct-peer` (or, with E2E_RELAY_URL,
   `--relay-url` on both nodes), `serve`, `buy --offer`;
3. the provider executes the job in the private containerd sandbox, responds
   and delivers; the buyer accepts and acknowledges the result;
4. provider: `withdraw --all`;
5. refusals and re-runs: `init` and `offer` again change nothing on chain, a
   paused provider holds a second purchase unexecuted, and a tampered offer
   file is refused before any payment.

Every chain fact the run asserts is read by this script from the validators'
JSON-RPC, not taken from an OpenFox report.

Not OpenFox, and said so in the evidence: booting the network, creating,
funding and activating the two wallets (`tosctl wallet create`, the zerostate
faucet, `tosctl wallet activate`), staging files for the nodes' user, and the
container runtime with its imported image (with E2E_EXECUTOR_SOCKET also the
executor service in front of it).

Two executor modes:

- E2E_EXECUTOR_SOCKET set: the provider executes through the root-run executor
  service at that socket (`offer --executor-socket`). Both nodes run as the
  invoking user, their files are staged under that user, and the run uses no
  root command at all. The service itself is installed by the operator
  beforehand; this script only talks to its socket.
- otherwise (legacy single-user mode): the executor accepts only a container
  runtime socket owned by its own user in a private directory, and OpenFox
  runs the executor as its own child and reads its artifact store, so the
  provider node runs as root. The direct transport joins nodes of one user, so
  the buyer node runs as root too. Every root command goes through as_node()
  below and is listed in the evidence.

The network boot, faucet funding, RPC polling, exact transaction decoding and
secret redaction are taken from the Service Actor buyer acceptance run
(service-actor-buyer-e2e.py and its redaction helper).

Two carriers:

- default: the same-host direct transport (`--direct-peer`), each node naming
  the other's receiver socket;
- E2E_RELAY_URL set: both nodes are initialized with `--relay-url` at that
  Agent Packet Relay and no direct peer, so every packet is sealed end to end
  and travels through the relay. The provider's offer file then carries its
  encryption key card, the buyer's task carries the buyer's, and the run
  checks that the provider's outgoing envelopes were accepted by the relay.
  The relay itself is started by the operator beforehand; this script only
  names its URL.

Run it through scripts/service-front-door-e2e.sh.
"""

import asyncio
import base64
import datetime
import hashlib
import io
import json
import os
import pwd
import re
import secrets
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(os.environ["E2E_REPO"])
SOURCE = Path(os.environ["TOS_SOURCE"])
BUILD = Path(os.environ["TOS_BUILD"])
TOSCTL = Path(os.environ["TOSCTL"])
BIN = Path(os.environ["E2E_BIN"])
WORK = Path(os.environ["E2E_WORKDIR"])
REGISTRY_BOC = Path(os.environ["REGISTRY_CODE_BOC"])
ACTOR_CODE_HASH = os.environ["ACTOR_CODE_HASH"]
# The socket of the root-run executor service. Set, it selects the mode in
# which neither node runs as root.
EXECUTOR_SOCKET = os.environ.get("E2E_EXECUTOR_SOCKET", "")
SERVICE_MODE = bool(EXECUTOR_SOCKET)
EXECUTOR = None if SERVICE_MODE else Path(os.environ["E2E_EXECUTOR"])
CONTAINERD_SOCKET = os.environ.get("E2E_CONTAINERD_SOCKET", "/run/tos-service-containerd/containerd.sock")
BASE_PORT = int(os.environ["E2E_BASE_PORT"])
RPC_PORTS = [int(port) for port in os.environ["E2E_RPC_PORTS"].split(",")]
# Where both nodes' files are staged. As root: tosctl run as root refuses a
# configuration under a directory another user can modify, so the root-owned
# state needs root-owned ancestors. With the executor service the nodes run
# as the invoking user and their state is private to that user.
if SERVICE_MODE:
    ROOT = (Path(os.environ["E2E_ROOT_BASE"]) / WORK.name if os.environ.get("E2E_ROOT_BASE")
            else WORK / "private" / "nodes")
else:
    ROOT = Path(os.environ.get("E2E_ROOT_BASE", "/var/lib/openfox-front-door-e2e")) / WORK.name
HOLD = os.environ.get("E2E_HOLD") == "1"
# The Agent Packet Relay both nodes use instead of the direct transport.
RELAY_URL = os.environ.get("E2E_RELAY_URL", "")
RELAY_MODE = bool(RELAY_URL)
# The registry identity domain names the chain by its global id.
NETWORK_LABEL = os.environ.get("E2E_NETWORK_LABEL", "tos:global-id:3")
NANO = 1_000_000_000
NODES = ("provider", "buyer")
MASTER_KEYS = {node: secrets.token_hex(32) for node in NODES}
# The offer's terms. The contract's minimum response SLA and refund-claim
# window are one hour.
PRICE, STORAGE_FEE, CLEANUP_BOUNTY = "0.3", "0.25", "0.1"
PRICE_NANO, STORAGE_FEE_NANO = 300_000_000, 250_000_000

os.umask(0o077)
os.environ.setdefault("RAYON_NUM_THREADS", "2")
os.environ.setdefault("TOKIO_WORKER_THREADS", "2")
# Version 16 genesis binds wallet authorization to one network: a fresh tag.
os.environ["TOS_AUTH_NETWORK_TAG"] = secrets.token_hex(32)

PRIVATE = WORK / "private"
TRANSCRIPT = WORK / "cli-transcript.jsonl"
steps: list[dict] = []
evidence: dict = {}
root_commands: list[str] = []

# --- Secret redaction --------------------------------------------------------
#
# Every string the run logs, raises or persists passes through redact() first.

REDACTED = "<redacted>"
_SECRETS: list[str] = []
_MASTER_KEY = re.compile(r"master_key=[^&\s\"'\\]+")
_SECRET_FIELD = re.compile(
    r'((?:\\*)"(?:seed[A-Za-z0-9_]*|secret[A-Za-z0-9_]*|private_key|mnemonic)(?:\\*)"\s*:\s*(?:\\*)")'
    r'((?:[^"\\]|\\(?!"))*)')


def register_secret(value: str) -> None:
    if value and value not in _SECRETS:
        _SECRETS.append(value)


def redact(text) -> str:
    if not isinstance(text, str):
        text = str(text)
    for secret in _SECRETS:
        text = text.replace(secret, REDACTED)
    text = _MASTER_KEY.sub("master_key=" + REDACTED, text)
    return _SECRET_FIELD.sub(lambda match: match.group(1) + REDACTED, text)


def redact_value(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(key)): redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def run_logged(command: list[str], *, env: dict, check: bool = True, timeout: float = 240,
               keep: int = 40000) -> subprocess.CompletedProcess:
    """Run a command and append a redacted transcript row. A failure or a
    timeout raises RuntimeError carrying only redacted text."""
    started = time.time()
    argv = [redact(str(part)) for part in command]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as expired:
        out = redact(expired.stdout.decode() if isinstance(expired.stdout, bytes) else expired.stdout or "")
        err = redact(expired.stderr.decode() if isinstance(expired.stderr, bytes) else expired.stderr or "")
        with TRANSCRIPT.open("a") as handle:
            handle.write(json.dumps({"argv": argv, "timeout": True, "seconds": round(time.time() - started, 2),
                                     "stdout": out[-keep:], "stderr": err[-keep:]}) + "\n")
        raise RuntimeError(f"{' '.join(argv[:8])} timed out: {err[-2000:]}{out[-2000:]}") from None
    out, err = redact(result.stdout), redact(result.stderr)
    with TRANSCRIPT.open("a") as handle:
        handle.write(json.dumps({"argv": argv, "exit": result.returncode, "seconds": round(time.time() - started, 2),
                                 "stdout": out[-keep:], "stderr": err[-keep:]}) + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:8])} failed ({result.returncode}): {err[-2000:]}{out[-2000:]}")
    return result


def record(name: str, ok: bool, detail=None) -> bool:
    detail = redact_value(detail)
    steps.append({"name": name, "pass": bool(ok), "detail": detail,
                  "at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {redact(json.dumps(detail, default=str))[:3000]}"),
          flush=True)
    return bool(ok)


class Stop(Exception):
    """A step failed that every later step depends on."""


def require(name: str, ok: bool, detail=None) -> None:
    if not record(name, ok, detail):
        raise Stop(name)


def poll(predicate, timeout: float, interval: float = 2.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as error:  # noqa: BLE001 - polled reads retry
            last = error
        time.sleep(interval)
    return None


# --- Chain reads of this script ---------------------------------------------

def rpc_endpoints() -> list[str]:
    return [f"http://127.0.0.1:{port}/jsonRPC" for port in RPC_PORTS]


def rpc(method: str, /, **params):
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(rpc_endpoints()[0], data=body, headers={"Content-Type": "application/json"})
    # The thermal guard may stop the validators for a while; a read waits.
    for attempt in range(30):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
            break
        except OSError:
            if attempt == 29:
                raise
            time.sleep(5)
    with (WORK / "rpc-transcript.jsonl").open("a") as transcript:
        transcript.write(json.dumps({"method": method, "params": params, "response": redact(raw.decode())}) + "\n")
    return json.loads(raw)


def norm(address: str) -> str:
    from pytosiq_core import Address
    return Address(address).to_str(is_user_friendly=False).lower()


def account_state(address: str) -> str:
    return rpc("getAddressState", address=address).get("result")


def balance(address: str) -> int:
    return int(rpc("getAddressInformation", address=address)["result"]["balance"])


def transactions(address: str, limit: int = 50) -> list:
    """Every transaction of an account, newest first; fails rather than
    silently truncating."""
    rows = rpc("getTransactions", address=address, limit=limit)["result"]
    if len(rows) >= limit:
        raise RuntimeError("the transaction page may be truncated")
    return [transaction_summary(row) for row in rows]


def raw_address(address) -> str:
    return address.to_str(is_user_friendly=False).lower()


def transaction_summary(row: dict) -> dict:
    """One transaction decoded from its own cells: the inbound message with
    its body, and every outbound internal message."""
    from pytosiq_core import Cell, Transaction
    transaction = Transaction.deserialize(Cell.one_from_boc(base64.b64decode(row["data"])).begin_parse())
    inbound = transaction.in_msg.info if transaction.in_msg is not None and transaction.in_msg.is_internal else None
    summary = {"lt": int(row["transaction_id"]["lt"]), "hash": row["transaction_id"]["hash"],
               "in_source": raw_address(inbound.src) if inbound else None,
               "in_value": inbound.value_coins if inbound else 0, "op": None, "query_id": None,
               "outs": [{"destination": raw_address(m.info.dest), "value": m.info.value_coins}
                        for m in transaction.out_msgs if m.is_internal],
               "aborted": bool(row.get("aborted")), "compute_success": (row.get("compute") or {}).get("success")}
    if inbound is not None:
        body = transaction.in_msg.body.begin_parse()
        if body.remaining_bits >= 96:
            summary["op"], summary["query_id"] = body.load_uint(32), body.load_uint(64)
            if summary["op"] == OP_RESPOND and body.remaining_bits >= 320:
                summary["request_id"] = body.load_uint(64)
                summary["response_hash"] = body.load_uint(256).to_bytes(32, "big").hex()
            if summary["op"] == OP_WITHDRAW:
                summary["withdraw_amount"] = body.load_coins()
    return summary


# Service Actor operations, as the contract source names them.
OP_CALL, OP_RESPOND, OP_UPDATE_POLICY, OP_WITHDRAW = 0x53564301, 0x53564302, 0x53564306, 0x53564309


def actor_facts(actor: str) -> dict:
    """What the actor's own finalized transactions say: successful calls,
    responds and withdrawals."""
    rows = [row for row in transactions(actor) if not row["aborted"] and row["compute_success"]]
    return {"calls": [row for row in rows if row["op"] == OP_CALL],
            "responds": [row for row in rows if row["op"] == OP_RESPOND],
            "withdrawals": [row for row in rows if row["op"] == OP_WITHDRAW],
            "all": len(rows)}


def service_data(actor: str) -> dict:
    """The actor's get_service_data getter, run by the validator."""
    answer = rpc("runGetMethod", address=actor, method="get_service_data", stack=[])["result"]
    if answer.get("exit_code") != 0:
        raise RuntimeError(f"get_service_data exit {answer.get('exit_code')}")
    # The endpoint lists the stack from its top: the getter's last value
    # first. Numbers are decimal.
    stack = list(reversed(answer["stack"]))
    if len(stack) != 25:
        raise RuntimeError(f"get_service_data returned {len(stack)} values")

    def number(index: int) -> int:
        kind, value = stack[index][0], stack[index][1]
        if kind != "num":
            raise RuntimeError(f"stack[{index}] is {kind}")
        return int(value, 10)
    return {"active": number(1), "policy_version": number(2), "price": number(3), "storage_fee": number(4),
            "metadata_hash": f"{number(12):064x}", "next_request_id": number(16), "pending_count": number(17),
            "live_count": number(18), "withdrawable_revenue": number(19), "locked_storage_fees": number(20),
            "pending_liability": number(21), "refundable_liability": number(22)}


def chain_snapshot(accounts: dict) -> dict:
    """The transaction count and last transaction of each account: any chain
    effect on one of them changes this."""
    result = {}
    for name, address in accounts.items():
        info = rpc("getAddressInformation", address=address)["result"]
        result[name] = {"address": address, "state": info.get("state"),
                        "last_lt": info["last_transaction_id"]["lt"], "last_hash": info["last_transaction_id"]["hash"]}
    return result


# --- Commands ----------------------------------------------------------------

def user_env(node: str | None = None) -> dict:
    env = dict(os.environ)
    if node:
        env["VAULT_URL"] = f"file://{PRIVATE / node}/vault.json?master_key={MASTER_KEYS[node]}"
    return env


def tosctl_user(node: str, *args: str) -> subprocess.CompletedProcess:
    """tosctl run directly, as the invoking user. Used only to create, fund
    and activate the wallets, before either node exists."""
    return run_logged([str(TOSCTL), *args, "-c", str(PRIVATE / node / "tosctl-config.json")], env=user_env(node))


def as_node(*args, env: dict | None = None, check: bool = True, timeout: float = 240) -> subprocess.CompletedProcess:
    """A command run as the user the nodes run as. With the executor service
    that is the invoking user and the command runs directly. Otherwise it is
    root: the command goes through `sudo -n`, and each distinct program run as
    root is listed in the evidence."""
    if SERVICE_MODE:
        return run_logged([str(part) for part in args], env=env or dict(os.environ), check=check, timeout=timeout)
    program = next(str(part) for part in args if not str(part).startswith("-"))
    label = Path(program).name
    if label == "openfox":
        label = "openfox " + " ".join(str(part) for part in args[args.index(program) + 1:][:3])
    if label not in root_commands:
        root_commands.append(label)
    return run_logged(["sudo", "-n", *map(str, args)], env=env or dict(os.environ), check=check, timeout=timeout)


def node_env(node: str) -> dict:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{ROOT / node}/vault.json?master_key={MASTER_KEYS[node]}"
    return env


OPENFOX = ROOT / "bin" / "openfox"


def fox_argv(*args: str) -> list[str]:
    # The vault URL reaches the node in its environment, never on a command
    # line; under sudo it has to be let through explicitly.
    through_sudo = [] if SERVICE_MODE else ["--preserve-env=VAULT_URL"]
    return [*through_sudo, str(OPENFOX), "earning", "service", *args]


def fox(node: str, *args: str, check: bool = True, timeout: float = 900) -> subprocess.CompletedProcess:
    """One `openfox earning service` command of a node."""
    return as_node(*fox_argv(*args), env=node_env(node), check=check, timeout=timeout)


# What OpenFox prints when its finalized reads did not reach a quorum in
# time. The thermal guard stops the validators' process group while the host
# is hot, so a command can meet this through no fault of its own.
TRANSIENT = re.compile(r"finalized state is unavailable|quorum not reached|no finalized checkpoint|"
                       r"deadline exceeded|connection refused|not yet established")


def fox_again(node: str, *args: str, timeout: float = 900) -> subprocess.CompletedProcess:
    """A command that reads only, or that is built to be run again (`init`,
    `offer`, `withdraw`): after an unavailable chain read it is run again, as
    its own message tells an operator to. Every repeat is in the evidence."""
    for attempt in range(8):
        result = fox(node, *args, check=False, timeout=timeout)
        if result.returncode == 0 or not TRANSIENT.search(result.stderr):
            return result
        evidence.setdefault("repeated_after_unavailable_chain_read", []).append(
            {"node": node, "command": args[0], "attempt": attempt + 1, "stderr": result.stderr[-400:]})
        time.sleep(15)
    return result


def fox_json(node: str, *args: str, **kwargs):
    result = fox_again(node, *args, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"openfox earning service {args[0]} failed ({result.returncode}): {result.stderr[-2500:]}")
    return json.loads(result.stdout)


def rail(node: str) -> str:
    return str(ROOT / node / "rail.json")


def root_json(path) -> dict:
    return json.loads(as_node("cat", path).stdout)


def root_sha256(path) -> str | None:
    result = as_node("sha256sum", path, check=False)
    return result.stdout.split()[0] if result.returncode == 0 else None


SERVING: dict = {}


def start_serve(node: str) -> None:
    log = (WORK / f"{node}-serve.log").open("ab")
    launcher = [] if SERVICE_MODE else ["sudo", "-n"]
    SERVING[node] = subprocess.Popen([*launcher, *fox_argv("serve", "--rail-config", rail(node))],
                                     env=node_env(node), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    if not SERVICE_MODE and "openfox serve --rail-config" not in root_commands:
        root_commands.append("openfox serve --rail-config")


def stop_serve(node: str) -> int | None:
    process = SERVING.pop(node, None)
    if process is None:
        return None
    # The node itself is signalled, by its exact command line: sudo does not
    # reliably relay a signal sent to it from outside its terminal.
    pattern = f"^{OPENFOX} earning service serve --rail-config {rail(node)}$"
    if process.poll() is None:
        as_node("pkill", "-TERM", "-f", pattern, check=False)
    try:
        return process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        # A node that does not stop leaves its goroutine dump in its log.
        as_node("pkill", "-QUIT", "-f", pattern, check=False)
        time.sleep(3)
        as_node("kill", "-KILL", process.pid, check=False)
        return process.wait(timeout=30)


def serve_log(node: str) -> str:
    path = WORK / f"{node}-serve.log"
    return redact(path.read_text(errors="replace"))[-4000:] if path.exists() else ""


def init_flags(node: str) -> list[str]:
    flags = ["--rail-config", rail(node), "--state-dir", str(ROOT / node / "state")]
    for endpoint in rpc_endpoints():
        flags += ["--rpc", endpoint]
    return flags + ["--global-config", str(ROOT / "etc" / "global.json"), "--network-label", NETWORK_LABEL,
                    "--tosctl", str(ROOT / "bin" / "tosctl"), "--tosctl-config", str(ROOT / node / "tosctl-config.json"),
                    "--wallet", node, "--registry-code-boc", str(ROOT / "etc" / "registry-code.boc"),
                    "--actor-code-hash", ACTOR_CODE_HASH] + (["--relay-url", RELAY_URL] if RELAY_MODE else [])


def offer_flags() -> list[str]:
    if SERVICE_MODE:
        executor = ["--executor-socket", EXECUTOR_SOCKET]
    else:
        executor = ["--executor", str(ROOT / "bin" / "software-work-execute"), "--containerd-socket", CONTAINERD_SOCKET,
                    "--fifo-dir", str(FIFO_DIR)]
    return ["--rail-config", rail("provider"), "--price", PRICE, "--storage-fee", STORAGE_FEE,
            "--cleanup-bounty", CLEANUP_BOUNTY, "--response-sla", "3600", "--refund-claim-window", "3600", *executor]


# The executor refuses a FIFO directory with residue; a directory of this
# run next to the private socket, as the runtime's own layout has it.
FIFO_DIR = Path(CONTAINERD_SOCKET).parent / f"front-door-{WORK.name}-fifos"


def source_archive() -> bytes:
    """A deterministic USTAR archive of a Go module with one passing test."""
    files = [("go.mod", "module example.test/paidwork\n\ngo 1.26.5\n"),
             ("work_test.go", "package paidwork\n\nimport \"testing\"\n\nfunc TestWork(t *testing.T) {\n"
                              "\tif 2+2 != 4 {\n\t\tt.Fatal(\"arithmetic\")\n\t}\n}\n")]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0o444, 0, 0, 0, "", ""
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# `install` options that give a staged file to root; the invoking user's own
# files need none.
OWNER = [] if SERVICE_MODE else ["-o", "root", "-g", "root"]


def install_node(source: Path, target: Path, mode: str = "0600") -> None:
    as_node("install", *OWNER, "-m", mode, source, target)


# --- Not OpenFox: wallets and staging -----------------------------------------

async def provision(faucet) -> dict:
    """Create, fund and activate one wallet per node with tosctl and the
    zerostate faucet. This is the only use of tosctl outside OpenFox."""
    from contract import tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

    wallets = {}
    for node in NODES:
        directory = PRIVATE / node
        directory.mkdir(mode=0o700)
        config_path = directory / "tosctl-config.json"
        run_logged([str(TOSCTL), "config", "generate", "-o", str(config_path), "--force"], env=user_env())
        config = json.loads(config_path.read_text())
        config["chain_rpc"] = {"urls": [f"http://127.0.0.1:{port}" for port in RPC_PORTS], "api_key": None}
        config["elections"] = None
        config_path.write_text(json.dumps(config, indent=2))
        tosctl_user(node, "wallet", "create", "-n", node, "-v", "V3R2", "-w", "0")
        listed = json.loads(tosctl_user(node, "wallet", "ls", "--format", "json").stdout)
        address = next(norm(entry["address"]) for entry in listed if entry["name"] == node and entry.get("address"))
        wallets[node] = address
        await faucet.send(WalletMessage(send_mode=3, message=MessageAny(
            info=InternalMsgInfo(ihr_disabled=True, bounce=False, bounced=False, src=faucet.address, dest=Address(address),
                                 value=tos(60), ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
            init=None, body=Cell.empty())))
        funded = poll(lambda a=address: balance(a) >= 59 * NANO, 120)
        tosctl_user(node, "wallet", "activate", "-n", node)
        active = poll(lambda a=address: account_state(a) == "active", 120)
        require(f"not OpenFox: the {node} wallet is created, funded from the faucet and activated with tosctl",
                bool(funded) and bool(active), address)
    return wallets


def stage_nodes() -> None:
    """Private files of the nodes' user, outside what the run leaves as
    evidence: the binaries, the chain files and each node's tosctl
    configuration and vault. tosctl and the executor refuse files their user
    does not own."""
    base = ROOT.parent
    as_node("install", "-d", *OWNER, "-m", "0700", base)
    if as_node("test", "-e", ROOT, check=False).returncode == 0:
        raise RuntimeError(f"{ROOT} already exists; every run stages a fresh directory")
    if not SERVICE_MODE and as_node("test", "-e", FIFO_DIR, check=False).returncode == 0:
        raise RuntimeError(f"{FIFO_DIR} already exists")
    as_node("install", "-d", *OWNER, "-m", "0700", ROOT, ROOT / "bin", ROOT / "etc", *(ROOT / node for node in NODES))
    install_node(BIN / "openfox", OPENFOX, "0755")
    install_node(TOSCTL, ROOT / "bin" / "tosctl", "0700")
    binaries = {"openfox": BIN / "openfox", "tosctl": TOSCTL}
    if not SERVICE_MODE:
        install_node(EXECUTOR, ROOT / "bin" / "software-work-execute", "0755")
        binaries["software-work-execute"] = EXECUTOR
    install_node(WORK / "global.json", ROOT / "etc" / "global.json")
    install_node(REGISTRY_BOC, ROOT / "etc" / "registry-code.boc")
    (PRIVATE / "source.tar").write_bytes(source_archive())
    install_node(PRIVATE / "source.tar", ROOT / "buyer" / "source.tar")
    for node in NODES:
        install_node(PRIVATE / node / "tosctl-config.json", ROOT / node / "tosctl-config.json")
        install_node(PRIVATE / node / "vault.json", ROOT / node / "vault.json")
    staged = {name: root_sha256(ROOT / "bin" / name) for name in binaries}
    built = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    ownership = as_node("stat", "-c", "%u:%g %a %n", ROOT, ROOT / "bin", OPENFOX, ROOT / "provider", ROOT / "buyer",
                        ROOT / "provider" / "vault.json").stdout.split("\n")
    evidence["binaries"] = {name: {"sha256": digest} for name, digest in built.items()}
    if SERVICE_MODE:
        socket = as_node("stat", "-c", "%u:%g %a %n", Path(EXECUTOR_SOCKET).parent, EXECUTOR_SOCKET,
                         check=False).stdout.split("\n")
        evidence["node_user"] = {"staged_under": str(ROOT), "uid": os.geteuid(),
                                 "ownership": [line for line in ownership if line],
                                 "executor_service_socket": [line for line in socket if line],
                                 "why": "the provider node executes through the root-run executor service and reads "
                                        "none of its files, so neither node needs root. The service, its unit and "
                                        "its allow-list were installed by the operator before this run; the run "
                                        "itself uses no root command."}
        require("neither node runs as root: the run itself is unprivileged and stages the nodes' files as its own user",
                os.geteuid() != 0 and staged == built and not root_commands,
                {"uid": os.geteuid(), "staged": staged, "built": built, "ownership": ownership})
        return
    socket = as_node("stat", "-c", "%u:%g %a %n", Path(CONTAINERD_SOCKET).parent, CONTAINERD_SOCKET).stdout.split("\n")
    evidence["root"] = {"staged_under": str(ROOT), "ownership": [line for line in ownership if line],
                        "container_runtime_socket": [line for line in socket if line],
                        "why": "the executor accepts only a runtime socket its own user owns, in a private directory; "
                               "OpenFox runs the executor as its own child and reads its artifact store, so the "
                               "provider node runs as the socket's owner, root. The direct transport joins nodes of "
                               "one user, so the buyer node runs as root too. No permission of the socket, the "
                               "executor, tosctl or OpenFox was changed."}
    require("not OpenFox: binaries, chain files and each node's tosctl configuration and vault are staged root-owned",
            staged == built, {"staged": staged, "built": built, "ownership": ownership})


# --- The sale, by `openfox earning service` alone ----------------------------

RUN: dict = {}


def strict_json(result: subprocess.CompletedProcess):
    """A command's standard output is exactly one JSON document."""
    return json.loads(result.stdout)


def setup_nodes() -> None:
    provider_wallet, buyer_wallet = RUN["wallets"]["provider"], RUN["wallets"]["buyer"]
    provider_socket = str(ROOT / "provider" / "state" / "rail-receiver.sock")
    buyer_socket = str(ROOT / "buyer" / "state" / "rail-receiver.sock")

    # Provider: init. Neither node knows the other's Agent id yet, so the
    # first init names no transport.
    before = chain_snapshot({"wallet": provider_wallet})
    planned = fox_again("provider", "init", *init_flags("provider"))
    record("provider init without --yes creates, signs and sends nothing",
           planned.returncode != 0 and strict_json(planned).get("confirmed") is False and
           as_node("test", "-e", rail("provider"), check=False).returncode != 0 and
           chain_snapshot({"wallet": provider_wallet}) == before, planned.stderr[-1500:])
    init = fox_json("provider", "init", *init_flags("provider"), "--yes")
    provider_agent, agent_address = init.get("agent_id", ""), init.get("agent_address", "")
    require("provider init registered the node's Agent and wrote the rail configuration",
            init.get("confirmed") is True and provider_agent.startswith("agent_") and
            account_state(agent_address) == "active" and init.get("wallet_address") == provider_wallet, init)

    # Provider: offer.
    before = chain_snapshot({"wallet": provider_wallet})
    preview = fox_again("provider", "offer", *offer_flags())
    early = strict_json(preview).get("preview") or {}
    record("provider offer without --yes shows the terms, every attached value and what will be created, and sends "
           "nothing", preview.returncode != 0 and strict_json(preview).get("confirmed") is False and
           early.get("total_attached_nanotos") == "3210000000" and
           early.get("buyer_attaches_per_call_nanotos") == str(PRICE_NANO + STORAGE_FEE_NANO + 200_000_000) and
           (early.get("terms") or {}).get("price_nanotos") == str(PRICE_NANO) and bool(early.get("to_be_created")) and
           chain_snapshot({"wallet": provider_wallet}) == before, preview.stderr[-3000:])
    offer = fox_json("provider", "offer", *offer_flags(), "--yes")
    plan = offer.get("preview") or {}
    actor, capability_address = plan.get("actor", ""), plan.get("capability_address", "")
    offer_path = offer.get("offer_file", "")
    data = service_data(actor) if actor else {}
    require("provider offer deployed the actor, registered the Capability and set the policy (read from the chain)",
            offer.get("confirmed") is True and account_state(actor) == "active" and
            account_state(capability_address) == "active" and data.get("active") == 1 and
            data.get("price") == PRICE_NANO and data.get("storage_fee") == STORAGE_FEE_NANO and
            data.get("metadata_hash") == plan.get("metadata_hash") and data.get("next_request_id") == 0,
            {"offer": offer, "service_data": data})
    offer_file = root_json(offer_path)
    require("the offer file names the provider's Agent and Capability and holds nothing but public data",
            offer_file.get("provider_agent_id") == provider_agent and
            offer_file.get("capability_id") == plan.get("capability_id") and
            offer_file.get("manifest_digest") == plan.get("manifest_digest"),
            {key: value for key, value in offer_file.items() if key != "manifest_cbor_base64"})
    if RELAY_MODE:
        card = offer_file.get("relay_key_card_base64", "")
        try:
            card_packet = json.loads(base64.b64decode(card, validate=True)) if card else {}
        except ValueError:
            card_packet = {}
        require("the offer file carries the provider's encryption key card for the relay, signed as the provider "
                "Agent and addressed to the key card audience",
                offer_file.get("schema") == "tos.openfox.rail-offer.v2" and
                card_packet.get("sender_agent_id") == provider_agent and
                card_packet.get("recipient_agent_id") == "agent_" + "0" * 64 and
                card_packet.get("capability_id") == "cap_" + "0" * 64,
                {key: card_packet.get(key) for key in ("sender_agent_id", "recipient_agent_id", "capability_id")})
    RUN.update(provider_agent=provider_agent, provider_agent_address=agent_address, actor=actor,
               capability_address=capability_address, offer_path=offer_path, offer_file=offer_file, offer=offer)
    evidence["objects"] = {"provider_agent_id": provider_agent, "provider_agent_address": agent_address, "actor": actor,
                           "capability_id": plan.get("capability_id"), "capability_address": capability_address,
                           "manifest_digest": plan.get("manifest_digest"), "attestor": plan.get("attestor_key_id"),
                           "metadata_hash": plan.get("metadata_hash")}

    # Buyer: init, allowing the provider the offer file names and reaching
    # it directly, or through the relay its key card names.
    reach = [] if RELAY_MODE else ["--direct-peer", f"{offer_file['provider_agent_id']}={provider_socket}"]
    buyer_init = fox_json("buyer", "init", *init_flags("buyer"), "--allow-provider", offer_file["provider_agent_id"],
                          *reach, "--yes")
    buyer_agent = buyer_init.get("agent_id", "")
    require("buyer init registered the buyer's Agent with a spending policy that allows the provider",
            buyer_init.get("confirmed") is True and buyer_agent.startswith("agent_") and
            account_state(buyer_init.get("agent_address", "")) == "active" and buyer_agent != provider_agent, buyer_init)
    RUN.update(buyer_agent=buyer_agent, buyer_agent_address=buyer_init["agent_address"])
    evidence["objects"].update(buyer_agent_id=buyer_agent, buyer_agent_address=buyer_init["agent_address"])

    if RELAY_MODE:
        # The provider reaches the buyer through the card the buyer's task
        # carries; neither node names a direct peer.
        configs = {node: root_json(rail(node)) for node in NODES}
        require("both nodes are configured for the relay and name no direct peer",
                all(config.get("relay_urls") == [RELAY_URL] and not config.get("direct_peers") and
                    not config.get("messenger_socket") for config in configs.values()),
                {node: {key: config.get(key) for key in ("relay_urls", "direct_peers", "messenger_socket")}
                 for node, config in configs.items()})
    else:
        # Provider: the buyer's Agent id exists now; add it as a direct peer.
        before = chain_snapshot(watched_accounts())
        peered = fox_json("provider", "init", *init_flags("provider"), "--direct-peer",
                          f"{buyer_agent}={buyer_socket}", "--yes")
        config = root_json(rail("provider"))
        require("provider init run again adds the buyer as a direct peer, keeps its Agent and sends nothing",
                peered.get("confirmed") is True and peered.get("agent_id") == provider_agent and
                config.get("direct_peers") == {buyer_agent: buyer_socket} and config.get("provider") is not None and
                chain_snapshot(watched_accounts()) == before, peered.get("steps"))

    # Buyer serves first so the provider's preflight sees its socket.
    start_serve("buyer")
    require("buyer serve is running", bool(poll(lambda: as_node("test", "-S", buyer_socket, check=False).returncode == 0, 60, 1))
            and SERVING["buyer"].poll() is None, serve_log("buyer"))
    preflight = fox_again("provider", "preflight", "--rail-config", rail("provider"))
    report = strict_json(preflight)
    not_passing = [check for check in report.get("checks", []) if check.get("status") != "pass"]
    evidence["preflight_not_passing"] = not_passing
    require("provider preflight is ok", preflight.returncode == 0 and report.get("ok") is True and
            not any(check["status"] == "fail" for check in not_passing), not_passing)
    start_serve("provider")
    require("provider serve is running", bool(poll(lambda: as_node("test", "-S", provider_socket, check=False).returncode == 0,
                                                    60, 1)) and SERVING["provider"].poll() is None, serve_log("provider"))


def watched_accounts() -> dict:
    """Every account a setup command could touch."""
    accounts = {"provider_wallet": RUN["wallets"]["provider"], "buyer_wallet": RUN["wallets"]["buyer"]}
    for name in ("provider_agent_address", "buyer_agent_address", "actor", "capability_address"):
        if RUN.get(name):
            accounts[name] = RUN[name]
    return accounts


def purchases() -> list:
    listed = fox_json("buyer", "purchases", "--rail-config", rail("buyer"))
    if not isinstance(listed, list):
        raise RuntimeError(f"purchases printed {listed!r}, not a list")
    return listed


def provider_status() -> dict:
    return fox_json("provider", "status", "--rail-config", rail("provider"))


def executions() -> list[str]:
    """One entry per job that ran. As root that is the executor's own
    at-most-once journal. With the executor service the journal belongs to
    root and the node cannot read it; what the node holds is one retention
    record per execution whose verified objects it keeps."""
    state = ROOT / "provider" / "state"
    directory = (state / "executor-service" / "artifacts" / "retention" if SERVICE_MODE
                 else state / "executor" / "journal")
    listing = as_node("find", directory, "-name", "*.json", "-printf", "%f\n", check=False).stdout.split()
    return sorted(listing)


def buy(label: str) -> dict:
    """One `buy --offer`. A purchase that failed on an unavailable chain read
    is repeated only when the chain shows no call was made."""
    actor = RUN["actor"]
    for attempt in range(6):
        before = service_data(actor)["next_request_id"]
        known = len(purchases())
        bought = fox("buyer", "buy", "--rail-config", rail("buyer"), "--offer", RUN["offer_path"],
                     "--source", str(ROOT / "buyer" / "source.tar"), "--yes", check=False)
        if bought.returncode == 0 or not TRANSIENT.search(bought.stderr):
            break
        time.sleep(20)
        if service_data(actor)["next_request_id"] != before or len(purchases()) != known:
            break
        evidence.setdefault("repeated_after_unavailable_chain_read", []).append(
            {"node": "buyer", "command": "buy", "attempt": attempt + 1, "stderr": bought.stderr[-400:]})
    purchase = strict_json(bought) if bought.returncode == 0 else {}
    require(f"{label}: buyer buy --offer built the Quote locally and called the actor", bought.returncode == 0 and
            purchase.get("phase") == "called" and purchase.get("actor") == actor and
            purchase.get("provider_agent_id") == RUN["provider_agent"] and
            purchase.get("price_nanotos") == str(PRICE_NANO), bought.stderr[-2000:] or purchase)
    return purchase


def purchase_of(request_hash: str) -> dict:
    return next((row for row in purchases() if row.get("request_hash") == request_hash), {})


def request_of(request_hash: str) -> dict:
    return next((row for row in provider_status().get("requests", []) if row.get("request_hash") == request_hash), {})


def cell_bytes(cell, out: list) -> list:
    data = cell.begin_parse()
    out.append(data.load_bytes(data.remaining_bits // 8) if data.remaining_bits % 8 == 0 else b"")
    for reference in cell.refs:
        cell_bytes(reference, out)
    return out


def verify_sale(purchase: dict) -> None:
    """The first sale, end to end: OpenFox's reports, then the chain and the
    delivered bytes as this script reads them."""
    from pytosiq_core import Cell
    actor, request_hash = RUN["actor"], purchase["request_hash"]
    done = poll(lambda: (lambda row: row if row.get("phase") in ("completed", "receipt-mismatch", "refused", "not-called")
                         else None)(purchase_of(request_hash)), 900, 5) or purchase_of(request_hash)
    require("buyer purchases shows the result accepted: the purchase is completed", done.get("phase") == "completed" and
            done.get("status") == "responded", {"purchase": {k: v for k, v in done.items() if k != "cost_disclosure"},
                                                "buyer_serve": serve_log("buyer"), "provider_serve": serve_log("provider")})
    request = poll(lambda: (lambda row: row if row.get("state") == "acked" else None)(request_of(request_hash)), 300, 5) \
        or request_of(request_hash)
    require("provider status shows the request responded and the buyer's acknowledgement received",
            request.get("operator_state") == "responded" and request.get("chain_fact") == "responded" and
            request.get("state") == "acked" and request.get("request_id") == done.get("request_id"),
            {k: v for k, v in request.items() if k not in ("package_base64",)})

    # The chain, read by this script.
    facts, data = actor_facts(actor), service_data(actor)
    calls, responds = facts["calls"], facts["responds"]
    one = len(calls) == 1 and len(responds) == 1
    chain_hash = responds[0].get("response_hash") if one else None
    require("chain: exactly one request exists, called by the buyer wallet with price, storage fee and allowance",
            one and data["next_request_id"] == 1 and calls[0]["in_source"] == RUN["wallets"]["buyer"] and
            calls[0]["in_value"] == PRICE_NANO + STORAGE_FEE_NANO + 200_000_000, {"calls": calls, "service_data": data})
    require("chain: the request is responded by the provider wallet and nothing is pending",
            one and responds[0]["in_source"] == RUN["wallets"]["provider"] and responds[0].get("request_id") == 0 and
            data["pending_count"] == 0 and data["pending_liability"] == 0 and
            data["withdrawable_revenue"] == PRICE_NANO + STORAGE_FEE_NANO, {"responds": responds, "service_data": data})
    receipt = Cell.one_from_boc(base64.b64decode(request.get("receipt_boc_base64", "")))
    require("chain: the response hash equals the Receipt hash OpenFox reports on both nodes, and is the hash of the "
            "Receipt the provider holds", chain_hash is not None and chain_hash == request.get("response_hash") and
            chain_hash == done.get("response_hash") and receipt.hash.hex() == chain_hash,
            {"chain": chain_hash, "provider": request.get("response_hash"), "buyer": done.get("response_hash"),
             "receipt_cell_hash": receipt.hash.hex()})

    # The artifact the buyer received.
    received = root_sha256(ROOT / "buyer" / "state" / "purchases" / request_hash / "artifact.tar")
    stated = request.get("artifact_digest", "")
    in_receipt = received is not None and any(bytes.fromhex(received) in part for part in cell_bytes(receipt, []))
    journal = executions()
    require("the artifact the buyer received hashes to the artifact digest inside the Receipt",
            received is not None and stated == "sha256:" + received and in_receipt,
            {"received_sha256": received, "provider_artifact_digest": stated, "digest_in_receipt_cells": in_receipt})
    record("the provider holds the verified objects of exactly one execution, the purchase's execution id"
           if SERVICE_MODE else
           "the executor ran exactly one job, the purchase's execution id, in the private sandbox",
           journal == [done.get("execution_id", "") + ".json"], journal)
    RUN["first"] = {"request_hash": request_hash, "response_hash": chain_hash}
    evidence["sale"] = {"request_hash": request_hash, "request_id": done.get("request_id"), "response_hash": chain_hash,
                        "artifact_sha256": received, "call": calls[0], "respond": responds[0],
                        "execution_id": done.get("execution_id")}


def withdraw() -> None:
    actor, wallet = RUN["actor"], RUN["wallets"]["provider"]
    credited = service_data(actor)["withdrawable_revenue"]
    before = chain_snapshot(watched_accounts())
    preview = fox_again("provider", "withdraw", "--rail-config", rail("provider"), "--all")
    record("provider withdraw without --yes previews the whole credit and sends nothing", preview.returncode != 0 and
           (strict_json(preview).get("preview") or {}).get("amount_nanotos") == str(credited) and
           strict_json(preview).get("confirmed") is False and chain_snapshot(watched_accounts()) == before,
           preview.stderr[-1500:])
    result = fox_again("provider", "withdraw", "--rail-config", rail("provider"), "--all", "--yes")
    report = strict_json(result) if result.stdout.strip() else {}
    withdrawal = report.get("withdrawal") or {}
    if withdrawal.get("state") not in ("finalized", "failed", "not_included"):
        # The command says to run it again while the outcome is not final.
        def resolved():
            again = fox_again("provider", "withdraw", "--rail-config", rail("provider"), "--all", "--yes")
            rows = provider_status().get("withdrawals", [])
            return rows if rows and rows[0].get("state") in ("finalized", "failed", "not_included") else None
        rows = poll(resolved, 420, 20) or []
        withdrawal = rows[0] if rows else withdrawal
    require("provider withdraw --all --yes reports the withdrawal finalized for the whole credit",
            withdrawal.get("state") == "finalized" and withdrawal.get("amount_nanotos") == str(credited) and
            credited == PRICE_NANO + STORAGE_FEE_NANO, {"report": report, "stderr": result.stderr[-1500:]})
    facts, data = actor_facts(actor), service_data(actor)
    sent = facts["withdrawals"]
    payout = sent[0]["outs"][0] if len(sent) == 1 and sent[0]["outs"] else {}
    require("chain: one withdraw_revenue from the owner wallet with this query id, whose first payout message "
            "carries exactly the amount to the owner wallet; the credit is zero afterwards",
            len(sent) == 1 and sent[0]["in_source"] == wallet and str(sent[0]["query_id"]) == withdrawal.get("query_id") and
            sent[0].get("withdraw_amount") == credited and payout.get("destination") == wallet and
            payout.get("value") == credited and data["withdrawable_revenue"] == 0, {"withdrawals": sent, "service_data": data})
    listed = provider_status()
    first = (listed.get("withdrawals") or [{}])[0]
    require("provider status lists the withdrawal as finalized and no credited revenue",
            first.get("state") == "finalized" and first.get("amount_nanotos") == str(credited) and
            first.get("query_id") == withdrawal.get("query_id") and
            (listed.get("actor") or {}).get("credited_revenue_nanotos") == "0", listed.get("withdrawals"))
    evidence["withdrawal"] = {"amount_nanotos": credited, "query_id": withdrawal.get("query_id"), "transaction": sent[0]}


def relay_delivery() -> None:
    """With the relay carrier, the provider's results went out as sealed
    envelopes that the relay durably accepted, and its keys are reported
    without their private parts."""
    relay = provider_status().get("relay") or {}
    outbox = relay.get("outbox") or []
    keys = ((relay.get("poller") or {}).get("keys")) or []
    require("the provider's outgoing packets were sealed and accepted by the relay",
            bool(outbox) and all(RELAY_URL in entry.get("accepted_by", []) for entry in outbox) and
            relay.get("configured_relays") == [RELAY_URL],
            {"envelopes": len(outbox), "accepted_by": sorted({url for entry in outbox
                                                             for url in entry.get("accepted_by", [])})})
    record("the relay status names the provider's keys by id and validity only",
           bool(keys) and all(set(key) == {"key_id", "not_before_unix", "not_after_unix", "destroy_at_unix", "relays"}
                              for key in keys), [key.get("key_id") for key in keys])


def run_again() -> None:
    """`init` and `offer` after success: no message, no new object."""
    before = chain_snapshot(watched_accounts())
    configs = {node: root_json(rail(node)) for node in NODES}
    init = fox_json("provider", "init", *init_flags("provider"), "--yes")
    offer = fox_json("provider", "offer", *offer_flags(), "--yes")
    buyer = fox_json("buyer", "init", *init_flags("buyer"), "--yes")
    plan = offer.get("preview") or {}
    same = (init.get("agent_id") == RUN["provider_agent"] and buyer.get("agent_id") == RUN["buyer_agent"] and
            plan.get("actor") == RUN["actor"] and plan.get("capability_address") == RUN["capability_address"] and
            plan.get("capability_id") == evidence["objects"]["capability_id"])
    sends = [step for report in (init, offer, buyer) for step in report.get("steps", [])
             if step.get("id") in ("agent.register", "actor.deploy", "capability.register", "actor.policy") and
             step.get("status") != "already_done"]
    after = chain_snapshot(watched_accounts())
    require("init and offer run again after success change nothing on chain: no transaction on either wallet, the "
            "Agents, the actor or the Capability, and the same ids", same and after == before and not sends and
            all(report.get("confirmed") is True for report in (init, offer, buyer)) and
            {node: root_json(rail(node)) for node in NODES} == configs and
            root_json(RUN["offer_path"]).get("manifest_digest") == RUN["offer_file"]["manifest_digest"],
            {"before": before, "after": after, "not_already_done": sends})


def tampered_offer() -> None:
    """An offer file whose manifest was changed is refused before payment:
    once as it is, and once with its stated digest recomputed to match."""
    offer = dict(RUN["offer_file"])
    manifest = bytearray(base64.b64decode(offer["manifest_cbor_base64"]))
    record("the offer's manifest digest is the SHA-256 of its manifest bytes",
           "sha256:" + hashlib.sha256(manifest).hexdigest() == offer["manifest_digest"], offer["manifest_digest"])
    position = bytes(manifest).index(b"Deterministic")
    manifest[position] ^= 0x01  # one bit of one letter of the name: still canonical CBOR
    flipped = dict(offer, manifest_cbor_base64=base64.b64encode(bytes(manifest)).decode())
    consistent = dict(flipped, manifest_digest="sha256:" + hashlib.sha256(manifest).hexdigest())
    before = chain_snapshot(watched_accounts())
    known = len(purchases())
    outcomes = {}
    for name, value in (("flipped", flipped), ("flipped-and-rehashed", consistent)):
        local = PRIVATE / f"offer-{name}.json"
        local.write_text(json.dumps(value))
        staged = ROOT / "buyer" / f"offer-{name}.json"
        install_node(local, staged)
        for _ in range(6):
            refused = fox("buyer", "buy", "--rail-config", rail("buyer"), "--offer", str(staged),
                          "--source", str(ROOT / "buyer" / "source.tar"), "--yes", check=False)
            if refused.returncode == 0 or not TRANSIENT.search(refused.stderr):
                break
            time.sleep(15)
        outcomes[name] = {"exit": refused.returncode, "stderr": refused.stderr.strip()[-600:]}
    after = chain_snapshot(watched_accounts())
    require("a tampered offer file is refused by buy before any payment, also when its digest is recomputed",
            all(outcome["exit"] != 0 for outcome in outcomes.values()) and
            "does not hash to the digest" in outcomes["flipped"]["stderr"] and
            "finalized" in outcomes["flipped-and-rehashed"]["stderr"] and after == before and len(purchases()) == known,
            outcomes)


def paused_purchase() -> None:
    """While admission is paused a second purchase is called and delivered
    but held: not admitted, not executed, not responded. After resume it is
    served."""
    actor = RUN["actor"]
    paused = fox_json("provider", "pause", "--rail-config", rail("provider"), "--reason", "front-door acceptance run")
    record("provider pause is in effect", paused.get("paused") is True and
           (provider_status().get("admission") or {}).get("paused") is True, paused)
    second = buy("while paused")
    request_hash = second["request_hash"]
    held = poll(lambda: purchase_of(request_hash).get("phase") == "task-sent" and
                "task(s) held" in serve_log("provider"), 300, 5)
    # Long enough for several rounds of the provider's five-second loop.
    time.sleep(45)
    facts, data = actor_facts(actor), service_data(actor)
    listed = request_of(request_hash)
    require("while paused the second purchase is held: called and delivered, but not admitted, executed or responded",
            bool(held) and len(facts["calls"]) == 2 and len(facts["responds"]) == 1 and data["pending_count"] == 1 and
            data["next_request_id"] == 2 and len(executions()) == 1 and
            listed.get("operator_state") in (None, "outcome_unknown") and not listed.get("response_hash") and
            purchase_of(request_hash).get("status") == "pending",
            {"service_data": data, "provider_request": listed, "executions": executions(),
             "provider_serve": serve_log("provider")[-600:]})
    resumed = fox_json("provider", "resume", "--rail-config", rail("provider"))
    done = poll(lambda: (lambda row: row if row.get("phase") in ("completed", "receipt-mismatch", "refused") else None)(
        purchase_of(request_hash)), 900, 5) or purchase_of(request_hash)
    facts, data = actor_facts(actor), service_data(actor)
    require("after resume the held purchase is admitted, executed, responded and accepted",
            resumed.get("paused") is False and done.get("phase") == "completed" and len(facts["responds"]) == 2 and
            data["pending_count"] == 0 and len(executions()) == 2 and
            facts["responds"][0].get("response_hash") == done.get("response_hash"),
            {"purchase": {k: v for k, v in done.items() if k != "cost_disclosure"}, "service_data": data})


def stop_nodes() -> None:
    running = {node: SERVING[node].poll() is None for node in list(SERVING)}
    codes = {node: stop_serve(node) for node in list(SERVING)}
    logs = {node: serve_log(node) for node in NODES}
    unexpected = {node: [line for line in logs[node].splitlines() if line and "admission paused" not in line][-10:]
                  for node in NODES}
    evidence["serve_log_lines_other_than_pause_notices"] = unexpected
    record("both serve processes ran until the end of the run and stopped cleanly on SIGTERM",
           running == {"provider": True, "buyer": True} and codes == {"provider": 0, "buyer": 0},
           {"running": running, "exit": codes, "log_tail": unexpected})


def personal_data(text: str) -> list[str]:
    """Which kinds of personal data of the invoking user text holds: the home
    directory path, or the login name as a word of its own. Ownership is
    recorded as numeric ids, so neither has a reason to appear."""
    kinds = []
    if os.path.expanduser("~") in text:
        kinds.append("home directory path")
    login = pwd.getpwuid(os.getuid()).pw_name
    # "root" is a word of the evidence itself and never the unprivileged
    # invoking user's name.
    if login != "root" and re.search(r"(?<![A-Za-z0-9_-])" + re.escape(login) + r"(?![A-Za-z0-9_-])", text):
        kinds.append("login name")
    return kinds


def scan_artifacts() -> None:
    """No home directory path and no login name in what the run leaves as
    evidence. evidence.json is checked when it is written."""
    found = {path.name: kinds for path in WORK.glob("*") if path.is_file() and path.name != "run.log"
             and (kinds := personal_data(path.read_text(errors="replace")))}
    record("no home directory path or login name in the transcripts or logs", not found, found)


async def main() -> int:
    from tostester.install import Install
    from tostester.n6_cluster import _wait_all_heights
    from tostester.network import Network, StartOptions, _write_model

    PRIVATE.mkdir(mode=0o700)
    for key in MASTER_KEYS.values():
        register_secret(key)
    # The launcher scans every artifact for these values after the run exits.
    secret_file = PRIVATE / "scan-secrets"
    secret_file.write_text("".join(key + "\n" for key in MASTER_KEYS.values()))
    secret_file.chmod(0o600)
    tree = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain"], capture_output=True, text=True).stdout
    tree_status = tree.strip().splitlines()
    evidence.update({"schema": "tos.openfox.service-front-door.local-acceptance.v1",
                     "qualifies_as_public_acceptance": False,
                     "reason": "one host runs every validator, every endpoint and both nodes" +
                               ("" if SERVICE_MODE else ", and both nodes run as root"),
                     "executor_mode": "executor service socket" if SERVICE_MODE else "executor as the node's child",
                     "carrier": f"Agent Packet Relay at {RELAY_URL}" if RELAY_MODE else "same-host direct transport",
                     "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "openfox_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                                                      text=True).stdout.strip(),
                     "openfox_tree_status": tree_status, "openfox_tree_dirty": bool(tree_status),
                     "tos_commit": subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True,
                                                  text=True).stdout.strip(),
                     "actor_code_hash": ACTOR_CODE_HASH, "network_label": NETWORK_LABEL,
                     "terms": {"price": PRICE, "storage_fee": STORAGE_FEE, "cleanup_bounty": CLEANUP_BOUNTY},
                     "not_openfox": [
                         "booting the three-validator network (tostester)",
                         "creating each wallet (`tosctl wallet create`), funding it from the zerostate faucet and "
                         "activating it (`tosctl wallet activate`)",
                         "staging the binaries, chain files, tosctl configurations and vaults for the nodes' user "
                         "(`install`; as root in the legacy mode)",
                         "the private container runtime and its imported toolchain image" +
                         (", and the root-run executor service in front of it" if SERVICE_MODE else ""),
                         "this script's own JSON-RPC reads, used only to verify"]})
    record("the OpenFox tree is clean at the commit the evidence names", not tree_status, tree_status or "clean")
    try:
        async with Network(Install(BUILD, SOURCE), WORK / "network", base_port=BASE_PORT) as network:
            dht = network.create_dht_node()
            nodes = []
            for _ in range(len(RPC_PORTS)):
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                nodes.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(nodes, RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(nodes, 5, 300)
            client = await nodes[0].toslib_client()
            global_config = json.loads((nodes[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", nodes[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            (WORK / "global.json").write_text(json.dumps(global_config, indent=2))
            zerostate = network.zerostate.as_block()
            evidence["network"] = {"network_id": NETWORK_LABEL, "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                                   "genesis_file_hash": "sha256:" + zerostate.file_hash.hex(), "validators": len(nodes),
                                   "json_rpc": rpc_endpoints(), "base_port": BASE_PORT}
            ready = poll(lambda: "result" in rpc("getMasterchainInfo"), 180)
            record("every validator serves finalized JSON-RPC", bool(ready))
            try:
                RUN["wallets"] = await provision(network.zerostate.main_wallet(client))
                evidence["wallets"] = RUN["wallets"]
                await asyncio.to_thread(sale)
            except Stop:
                pass
            except Exception as error:  # noqa: BLE001 - the evidence records the failure
                import traceback
                trace = traceback.format_exc().replace(str(REPO), "<repo>").replace(os.path.expanduser("~"), "~")
                record("the sale ran without an exception", False, redact(trace)[-3000:])
            finally:
                await asyncio.to_thread(finish)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        record("run completed without an exception", False, repr(error))
    evidence["ran_as_root"] = root_commands
    evidence["steps"] = steps
    evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # The evidence file itself must hold no personal data either. The check
    # is recorded in it, so the kinds found are named and never the values.
    leaked = personal_data(json.dumps(redact_value(evidence), default=str))
    record("no home directory path or login name in evidence.json", not leaked, leaked)
    passed = bool(steps) and all(step["pass"] for step in steps)
    evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(redact_value(evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


def sale() -> None:
    stage_nodes()
    RUN["wallet_lt"] = {node: chain_snapshot({"w": RUN["wallets"][node]})["w"]["last_lt"] for node in NODES}
    setup_nodes()
    verify_sale(buy("first purchase"))
    if RELAY_MODE:
        relay_delivery()
    withdraw()
    run_again()
    tampered_offer()
    paused_purchase()


def finish() -> None:
    if HOLD:
        print(f"holding the network until {WORK / 'release'} exists", flush=True)
        while not (WORK / "release").exists():
            time.sleep(2)
    if set(SERVING) == set(NODES):
        stop_nodes()
    for node in list(SERVING):
        stop_serve(node)
    scan_artifacts()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
