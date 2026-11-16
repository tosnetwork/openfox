#!/usr/bin/env python3
"""Messenger relay carriage milestone M-R1 (spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md
section 8): one-to-one private chat between two OpenFox nodes A and B, each
with its own finalized Agent, its own tos-messengerd and its own chat key and
card, carried only by two Agent Packet Relay daemons.

Local mode, one host, seven network locations
(scripts/messenger-relay-two-host-net.sh):

- the host namespace runs the three-validator chain on 127.0.0.1 and a
  forwarder from the host end of a private bridge (10.231.78.1) to it;
- tosmr-a and tosmr-b run node A and node B, tosmr-c runs a stranger node C;
  each node runs, as the invoking user, a chain RPC forwarder on its own
  127.0.0.1, a test Endpoint signer, tos-messengerd (transport
  agent-packet-relay, discovery contact-files) and `openfox earning service
  serve`. Each node's processes run with the other nodes' directories, the
  run's private files and the relays' state covered by an empty read-only
  tmpfs, so no two nodes share a file or a Unix socket;
- tosmr-relay1 and tosmr-relay2 each run one tos-service-packet-relay daemon
  serving TLS with a certificate of a certificate authority generated for this
  run; both nodes' chat cards name both relays and pin that authority
  (`init --relay-ca-file`).

The firewall lets each node connect only to the relays' TLS port and the
forwarder ports, and nothing reaches a node; a host bridge table drops every
frame between two node addresses. The cut is probed before and after the
rules.

Setup, besides OpenFox: the chain boot, the wallets (tosctl and the faucet),
each node's Messaging Endpoint identity (keys, delegation and descriptor
policy, by scripts/messenger-relay-e2e-tool) and the delegation commitment on
chain (`tosctl agent native-registry action --kind delegate` sent from the
node's wallet). A and B exchange contact files out of band once (`openfox
earning chat contact export` / `import`).

The run then proves, live, each M-R1 gate item it can (the evidence's
`gate_items` maps every item to its steps, and `not_verified` lists what is
covered by named unit tests only): the conversation over the relays with
`carried -> delivered` times, the in-band card, relay 1 down for the whole
conversation, an offline recipient across a re-deposit with generation 1
withdrawn, older duplicates answered `duplicate`, both crash windows, the
refusals, the public-id race, the plaintext and size search of relay state, the
evidence pull and descriptor-expired retry with short-lived descriptors, the
Agent revocation, and the signing cost.

Run it through scripts/messenger-relay-two-host-e2e.sh.
"""

import asyncio
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("front_door", HERE / "service-front-door-e2e.py")
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)

WORK, PRIVATE, ROOT, BIN = fd.WORK, fd.PRIVATE, fd.ROOT, fd.BIN
UID, GID = os.getuid(), os.getgid()
NETSH = HERE / "messenger-relay-two-host-net.sh"
FORWARD = HERE / "service-relay-two-host-forward.py"
SYSTEM_PYTHON = "/usr/bin/python3"
TOOL = BIN / "messenger-relay-e2e-tool"
MESSENGERD = BIN / "tos-messengerd"
RELAY_BIN = BIN / "tos-service-packet-relay"
HOST_IP, RELAY_PORT = "10.231.78.1", 8443
NODES = ("a", "b", "c")
ADDRESS = {"a": "10.231.78.10", "b": "10.231.78.11", "c": "10.231.78.12",
           "relay1": "10.231.78.20", "relay2": "10.231.78.21"}
NAMESPACE = {name: f"tosmr-{name}" for name in ADDRESS}
RELAYS = ("relay1", "relay2")
RELAY_URL = {relay: f"https://{ADDRESS[relay]}:{RELAY_PORT}" for relay in RELAYS}
RELAY_URLS = sorted(RELAY_URL.values())
TLS = WORK / "tls"
CA, WRONG_CA = TLS / "ca.pem", TLS / "unrelated-ca.pem"
SNAPSHOTS = WORK / "relay-snapshots"
REDEPOSIT = int(os.environ.get("MR1_REDEPOSIT_SECONDS", "600"))
DESCRIPTOR_LIFETIME = int(os.environ.get("MR1_DESCRIPTOR_LIFETIME", "1800"))
PUBLISH_INTERVAL = min(300, DESCRIPTOR_LIFETIME // 2)
CHAT_TIMEOUT = 60
ZERO_CAPABILITY = "cap_" + "0" * 64
HOLD_AT = os.environ.get("MR1_HOLD_AT", "")
DEV_SCRIPTS_RUN: list[dict] = []

# The front-door module provisions one wallet per name in its NODES.
fd.NODES = NODES
fd.MASTER_KEYS = {node: secrets.token_hex(32) for node in NODES}
HIDE = {node: [PRIVATE, *(ROOT / other for other in NODES if other != node), *(WORK / r for r in RELAYS)]
        for node in NODES}
HIDE.update({relay: [PRIVATE, ROOT.parent, *(WORK / r for r in RELAYS if r != relay)] for relay in RELAYS})
ENTER = ('set -e; uid=$1; gid=$2; shift 2; while [ "$1" != -- ]; do '
         'mount -t tmpfs -o ro,size=16k,mode=0555 tosmr-hidden "$1"; shift; done; shift; '
         'exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"')
LAUNCHED: list[str] = []
PROCESSES: dict = {}
TLS_CONTEXT = ssl.create_default_context(cafile=str(CA)) if CA.exists() else None
record, require, poll, Stop = fd.record, fd.require, fd.poll, fd.Stop
RUN: dict = {}
GATE: dict[str, list[str]] = {}


def gate(item: str, name: str, ok: bool, detail=None, required: bool = True) -> bool:
    """A step that proves (part of) one M-R1 gate item."""
    GATE.setdefault(item, []).append(name)
    if required:
        require(f"[M-R1 {item}] {name}", ok, detail)
        return True
    return record(f"[M-R1 {item}] {name}", ok, detail)


def hold(point: str) -> None:
    """With MR1_HOLD_AT naming this point, wait for <workdir>/release."""
    if HOLD_AT != point and not (point == "failure" and HOLD_AT):
        return
    (WORK / "held").write_text(point + "\n")
    print(f"held at {point}; touch {WORK / 'release'} to continue", flush=True)
    # While held, a development aid: <workdir>/dev/<n>.py is run in this
    # process (with the run's state) and its output written to <n>.out.
    dev = WORK / "dev"
    dev.mkdir(mode=0o700, exist_ok=True)
    while not (WORK / "release").exists():
        for script in sorted(dev.glob("*.py")):
            output = script.with_suffix(".out")
            if output.exists():
                continue
            import contextlib
            import io
            import traceback
            source = script.read_bytes()
            # Any dev script that runs voids the acceptance: it is recorded by
            # name and digest, and the result is forced to non-qualifying.
            DEV_SCRIPTS_RUN.append({"name": script.name, "sha256": hashlib.sha256(source).hexdigest()})
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                try:
                    exec(source.decode(), globals())
                except BaseException:  # noqa: BLE001 - a development aid reports everything
                    traceback.print_exc(file=buffer)
            output.write_text(fd.redact(buffer.getvalue()))
        time.sleep(2)


def now() -> int:
    return int(time.time())


# --- Namespaces and processes -------------------------------------------------

def ns_argv(name: str, argv: list, label: str) -> list[str]:
    entry = f"ip netns exec {NAMESPACE[name]} (tmpfs over the other parties' directories, then setpriv " \
            f"--reuid={UID} --regid={GID} --init-groups): {label}"
    if entry not in LAUNCHED:
        LAUNCHED.append(entry)
    hidden = [str(path) for path in HIDE[name] if path.is_dir()]
    return ["sudo", "-n", "--preserve-env=VAULT_URL", "ip", "netns", "exec", NAMESPACE[name], "/bin/sh", "-c",
            ENTER, "tosmr-enter", str(UID), str(GID), *hidden, "--", *map(str, argv)]


def node_env(node: str) -> dict:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{ROOT / node}/vault.json?master_key={fd.MASTER_KEYS[node]}"
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        env.pop(name, None)
    return env


def in_ns(name: str, argv: list, label: str, *, check: bool = True, timeout: float = 240, env: dict | None = None,
          data: str | None = None):
    command = ns_argv(name, argv, label)
    if data is None:
        return fd.run_logged(command, env=env or dict(os.environ), check=check, timeout=timeout)
    started = time.time()
    result = subprocess.run(command, input=data, capture_output=True, text=True, timeout=timeout,
                            env=env or dict(os.environ))
    with fd.TRANSCRIPT.open("a") as handle:
        handle.write(json.dumps({"argv": [fd.redact(str(part)) for part in command], "stdin": fd.redact(data)[-4000:],
                                 "exit": result.returncode, "seconds": round(time.time() - started, 2),
                                 "stdout": fd.redact(result.stdout)[-20000:],
                                 "stderr": fd.redact(result.stderr)[-4000:]}) + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{label} failed ({result.returncode}): {fd.redact(result.stderr)[-2000:]}")
    return result


def spawn(name: str, key: str, argv: list, label: str, env: dict | None = None) -> subprocess.Popen:
    log = (WORK / f"{key}.log").open("ab")
    # Its own session: the thermal guard pauses and resumes the run's process
    # group, and its SIGCONT must not resume a node process this run paused
    # on purpose (the crash windows). Every namespace process is still ended
    # by the namespace teardown, also after an interrupt.
    process = subprocess.Popen(ns_argv(name, argv, label), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                               env=env or dict(os.environ), start_new_session=True)
    PROCESSES[key] = process
    return process


def log_text(key: str) -> str:
    path = WORK / f"{key}.log"
    return fd.redact(path.read_text(errors="replace")) if path.exists() else ""


def wait_line(key: str, text: str, timeout: float = 30) -> bool:
    return bool(poll(lambda: text in log_text(key), timeout, 0.5))


def pids(pattern: str) -> list[int]:
    out = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False).stdout.split()
    return [int(pid) for pid in out]


def proc_state(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return "?"


def signal_pattern(pattern: str, sig: str) -> list[int]:
    found = pids(pattern)
    if found:
        subprocess.run(["kill", f"-{sig}", *map(str, found)], capture_output=True, check=False)
    return found


def netsh(action: str, *args: str) -> None:
    fd.run_logged(["bash", str(NETSH), action, str(WORK), *args], env=dict(os.environ), timeout=120)


# --- Node files ------------------------------------------------------------------

def nd(node: str) -> Path:
    return ROOT / node


def sock(node: str, name: str) -> Path:
    return nd(node) / "s" / name


def rail(node: str) -> Path:
    return nd(node) / "rail.json"


def mdir(node: str) -> Path:
    return nd(node) / "m"


def card_path(node: str) -> Path:
    return nd(node) / "state" / "relay" / "chat-card.json"


def read_json(path: Path):
    return json.loads(path.read_text())


# --- Relays ----------------------------------------------------------------------

def relay_argv(relay: str) -> list[str]:
    return [str(RELAY_BIN), "-listen", f"{ADDRESS[relay]}:{RELAY_PORT}", "-tls-cert", str(TLS / f"{relay}-cert.pem"),
            "-tls-key", str(WORK / relay / "tls-key.pem"), "-state-dir", str(WORK / relay / "state"),
            "-global-max-entries", "10000", "-global-max-bytes", "268435456", "-sweep-interval", "10s"]


def relay_request(relay: str, path: str, *, method: str = "GET", body: bytes | None = None, timeout: float = 10):
    request = urllib.request.Request(RELAY_URL[relay] + path, data=body, method=method,
                                     headers={"Content-Type": "application/octet-stream"} if body else {})
    try:
        with urllib.request.urlopen(request, context=TLS_CONTEXT, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def relay_up(relay: str) -> bool:
    try:
        status, body = relay_request(relay, "/v1/relay", timeout=3)
        return status == 200 and json.loads(body).get("schema") == "tos.service.agent-packet-relay.relay.v1"
    except (OSError, ValueError):
        return False


def start_relay(relay: str, label: str) -> None:
    spawn(relay, relay, relay_argv(relay), "tos-service-packet-relay")
    up = poll(lambda: relay_up(relay), 30, 0.5)
    require(f"{label}: {relay} serves TLS on {ADDRESS[relay]}:{RELAY_PORT} (verified against the run's certificate "
            "authority)", bool(up) and PROCESSES[relay].poll() is None, log_text(relay)[-600:])


def relay_pattern(relay: str) -> str:
    return f"^{RELAY_BIN} -listen {ADDRESS[relay]}:{RELAY_PORT}"


def stop_relay(relay: str, label: str) -> None:
    process = PROCESSES.pop(relay, None)
    signal_pattern(relay_pattern(relay), "TERM")
    code = process.wait(timeout=30) if process else None
    down = not relay_up(relay)
    require(f"{label}: {relay} stopped on SIGTERM and no longer answers", code == 0 and down,
            {"exit": code, "answers": not down})


def listing(relay: str, agent: str) -> list[dict]:
    status, body = relay_request(relay, f"/v1/mailboxes/{agent}/envelopes")
    if status != 200:
        raise RuntimeError(f"{relay} listing answered {status}")
    return json.loads(body)["envelopes"]


def listed_ids(relay: str, agent: str) -> list[str]:
    return [entry["envelope_id"] for entry in listing(relay, agent)]


def envelope_status(relay: str, agent: str, envelope_id: str) -> int:
    return relay_request(relay, f"/v1/mailboxes/{agent}/envelopes/{envelope_id}")[0]


def deposit(relay: str, agent: str, envelope_id: str, envelope: bytes) -> int:
    return relay_request(relay, f"/v1/mailboxes/{agent}/envelopes/{envelope_id}", method="PUT", body=envelope)[0]


def snapshot(name: str) -> dict:
    """Copies of both relays' state directories, for the plaintext search."""
    result = {}
    for relay in RELAYS:
        target = SNAPSHOTS / name / relay
        shutil.copytree(WORK / relay / "state", target, ignore=shutil.ignore_patterns("LOCK", "tmp"))
        files = [path for path in target.rglob("*") if path.is_file()]
        envelopes = [path for path in files if "envelopes" in path.parts]
        result[relay] = {"files": len(files), "envelope_files": len(envelopes),
                         "envelope_bytes": sorted(path.stat().st_size for path in envelopes)}
    return result


# --- Forwarders, isolation -------------------------------------------------------

LISTEN = ("import socket,sys\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
          "s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(); print('listening', flush=True)\n"
          "while True:\n    c, _ = s.accept(); c.close()\n")
CONNECT = ("import socket,sys\ntry:\n    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()\n"
           "    print('connected')\nexcept OSError as e:\n    print('refused or unreachable: ' + type(e).__name__)\n")
LIST_HIDDEN = ("import os,sys\nfor p in sys.argv[1:]:\n    print(p + ': ' + (repr(sorted(os.listdir(p))) "
               "if os.path.isdir(p) else 'absent'))\n")


def start_forwarders() -> None:
    ports = [str(port) for port in fd.RPC_PORTS]
    log = (WORK / "forward-host.log").open("ab")
    PROCESSES["forward-host"] = subprocess.Popen([SYSTEM_PYTHON, "-I", str(FORWARD), HOST_IP, "127.0.0.1", *ports],
                                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    ok = wait_line("forward-host", "ready")
    for node in NODES:
        spawn(node, f"forward-{node}", [SYSTEM_PYTHON, "-I", FORWARD, "127.0.0.1", HOST_IP, *ports],
              "the chain RPC forwarder")
        ok = wait_line(f"forward-{node}", "ready") and ok
    require("the chain RPC is forwarded: host 10.231.78.1 to the validators on 127.0.0.1, and in each node namespace "
            "127.0.0.1 to 10.231.78.1, for the JSON-RPC ports only", ok,
            {key: log_text(key)[-200:] for key in ("forward-host", *(f"forward-{n}" for n in NODES))})


def probe(name: str, host: str, port: int) -> str:
    return in_ns(name, [SYSTEM_PYTHON, "-I", "-c", CONNECT, host, port], "connection probe", timeout=30).stdout.strip()


def isolation() -> None:
    for node in NODES:
        spawn(node, f"probe-listener-{node}", [SYSTEM_PYTHON, "-I", "-c", LISTEN, ADDRESS[node], 47000],
              "probe listener")
    listening = all(wait_line(f"probe-listener-{node}", "listening") for node in NODES)
    pairs = [("a", "b"), ("b", "a"), ("c", "b"), ("a", "c")]
    before = {f"{x} to {y}": probe(x, ADDRESS[y], 47000) for x, y in pairs}
    netsh("firewall")
    after = {f"{x} to {y}": probe(x, ADDRESS[y], 47000) for x, y in pairs}
    after["b to its own listener"] = probe("b", ADDRESS["b"], 47000)
    others = {"a to host ssh 10.231.78.1:22": probe("a", HOST_IP, 22),
              "b to host ssh 10.231.78.1:22": probe("b", HOST_IP, 22),
              "relay1 to the chain forwarder": probe("relay1", HOST_IP, fd.RPC_PORTS[0]),
              "relay2 to node a's listener": probe("relay2", ADDRESS["a"], 47000),
              "a to an internet address 1.1.1.1:443": probe("a", "1.1.1.1", 443)}
    for node in NODES:
        PROCESSES.pop(f"probe-listener-{node}").terminate()
    signal_pattern("^" + SYSTEM_PYTHON + " -I -c import socket,sys", "TERM")
    evidence = {"before_rules": before, "after_rules": after, "other_paths": others, "listeners_started": listening}
    fd.evidence["isolation_probe"] = evidence
    gate("1", "no direct path: before the rules each node reaches a listener in another node's namespace; after them "
         "every node-to-node connection is dropped both ways, while B still reaches its own listener",
         listening and all(v == "connected" for v in before.values()) and
         all(after[f"{x} to {y}"].startswith("refused") for x, y in pairs) and
         after["b to its own listener"] == "connected", evidence)
    gate("1", "a node reaches neither other host services nor the internet, and a relay reaches neither the chain "
         "nor a node", all(value.startswith("refused") for value in others.values()), others)


def relay_reachability() -> None:
    reached = {f"{node} to {relay}": probe(node, ADDRESS[relay], RELAY_PORT) for node in NODES for relay in RELAYS}
    fd.evidence["isolation_probe"]["relay_reachability"] = reached
    require("each node reaches both relays' TLS port", all(v == "connected" for v in reached.values()), reached)


def hidden_files() -> None:
    seen = {}
    for name in (*NODES, *RELAYS):
        paths = [str(path) for path in HIDE[name]]
        seen[name] = in_ns(name, [SYSTEM_PYTHON, "-I", "-c", LIST_HIDDEN, *paths], "file visibility probe",
                           timeout=30).stdout.strip().splitlines()
    fd.evidence["file_isolation"] = seen
    gate("1", "no shared file or socket: each node sees the other nodes' directories, the run's private files and the "
         "relays' state as empty, and each relay sees neither the nodes nor the other relay",
         all(line.endswith(": []") for lines in seen.values() for line in lines) and
         all(len(seen[name]) == len(HIDE[name]) for name in seen), seen)


def trust_negative_control() -> None:
    """The relays verify only under the run's authority: neither the system
    trust store nor an unrelated authority accepts them."""
    results = {}
    for label, context in (("system trust store", ssl.create_default_context()),
                           ("unrelated CA", ssl.create_default_context(cafile=str(WRONG_CA)))):
        try:
            urllib.request.urlopen(RELAY_URL["relay1"] + "/v1/relay", context=context, timeout=5)
            results[label] = "verified"
        except (urllib.error.URLError, ssl.SSLError, OSError) as error:
            results[label] = "refused: " + type(getattr(error, "reason", error)).__name__
    results["run CA"] = "verified" if relay_up("relay1") else "refused"
    fd.evidence["tls_negative_control"] = results
    gate("1", "TLS is verified: the relays verify only under the run's CA, which both nodes pin with "
         "--relay-ca-file; the system trust store and an unrelated CA refuse them",
         results["run CA"] == "verified" and all(v.startswith("refused") for k, v in results.items() if k != "run CA"),
         results)


# --- Staging and the OpenFox nodes -----------------------------------------------

def stage() -> None:
    """Each node's private files, as the invoking user, outside the run's
    private directory (which every namespace process sees empty)."""
    if ROOT.exists():
        raise RuntimeError(f"{ROOT} already exists")
    for directory in (ROOT.parent, ROOT, ROOT / "bin", ROOT / "etc"):
        directory.mkdir(mode=0o700)
    for node in NODES:
        for sub in ("", "s", "m", "m/state", "m/contacts", "m/export", "keys", "handed"):
            (nd(node) / sub).mkdir(mode=0o700, exist_ok=sub == "")
    fd.install_node(BIN / "openfox", fd.OPENFOX, "0755")
    fd.install_node(fd.TOSCTL, ROOT / "bin" / "tosctl", "0700")
    for name in ("tos-messengerd", "tos-messenger-owner", "messenger-relay-e2e-tool"):
        fd.install_node(BIN / name, ROOT / "bin" / name, "0755")
    fd.install_node(WORK / "global.json", ROOT / "etc" / "global.json")
    fd.install_node(fd.REGISTRY_BOC, ROOT / "etc" / "registry-code.boc")
    for node in NODES:
        fd.install_node(PRIVATE / node / "tosctl-config.json", nd(node) / "tosctl-config.json")
        fd.install_node(PRIVATE / node / "vault.json", nd(node) / "vault.json")
    binaries = {"openfox": BIN / "openfox", "tosctl": fd.TOSCTL, "tos-messengerd": MESSENGERD,
                "tos-messenger-owner": BIN / "tos-messenger-owner", "tos-service-packet-relay": RELAY_BIN,
                "messenger-relay-e2e-tool": TOOL}
    fd.evidence["binaries"] = {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                               for name, path in binaries.items()}
    require("every node's files are staged as the invoking user (uid %d), one private directory per node" % UID,
            os.geteuid() != 0 and fd.root_sha256(fd.OPENFOX) == fd.evidence["binaries"]["openfox"]["sha256"],
            fd.as_node("stat", "-c", "%u:%g %a %n", ROOT, *(nd(n) for n in NODES)).stdout.split("\n"))


def fox_argv(*args: str) -> list[str]:
    return [str(fd.OPENFOX), "earning", *args]


def fox(node: str, *args: str, check: bool = True, timeout: float = 900):
    """One `openfox earning` command of a node, inside its namespace. A
    command that met an unavailable chain read is run again, as its own
    message says; every repeat is in the evidence."""
    for attempt in range(8):
        result = in_ns(node, fox_argv(*args), "openfox earning " + " ".join(args[:2]), check=False,
                       timeout=timeout, env=node_env(node))
        if result.returncode == 0 or not fd.TRANSIENT.search(result.stderr):
            break
        fd.evidence.setdefault("repeated_after_unavailable_chain_read", []).append(
            {"node": node, "command": " ".join(args[:2]), "attempt": attempt + 1, "stderr": result.stderr[-400:]})
        time.sleep(15)
    if check and result.returncode != 0:
        raise RuntimeError(f"openfox earning {' '.join(args[:2])} on {node} failed ({result.returncode}): "
                           f"{fd.redact(result.stderr)[-2500:]}")
    return result


def fox_json(node: str, *args: str, **kwargs):
    return json.loads(fox(node, *args, **kwargs).stdout)


def init_flags(node: str) -> list[str]:
    flags = ["--rail-config", str(rail(node)), "--state-dir", str(nd(node) / "state")]
    for endpoint in fd.rpc_endpoints():
        flags += ["--rpc", endpoint]
    flags += ["--global-config", str(ROOT / "etc" / "global.json"), "--network-label", fd.NETWORK_LABEL,
              "--tosctl", str(ROOT / "bin" / "tosctl"), "--tosctl-config", str(nd(node) / "tosctl-config.json"),
              "--wallet", node, "--registry-code-boc", str(ROOT / "etc" / "registry-code.boc"),
              "--actor-code-hash", fd.ACTOR_CODE_HASH, "--relay-ca-file", str(CA)]
    for url in RELAY_URLS:
        flags += ["--relay-url", url]
    return flags + ["--messenger-carrier-socket", str(sock(node, "carrier.sock")),
                    "--chat-carrier-socket", str(sock(node, "chat-carrier.sock")),
                    "--chat-card-path", str(card_path(node)),
                    "--messenger-evidence-dir", str(mdir(node) / "export"),
                    "--messenger-contact-dir", str(mdir(node) / "contacts"),
                    "--chat-timeout-seconds", str(CHAT_TIMEOUT)]


def init_nodes() -> None:
    for node in NODES:
        init = fox_json(node, "service", "init", *init_flags(node), "--yes")
        agent, address = init.get("agent_id", ""), init.get("agent_address", "")
        require(f"{node}: `openfox earning service init` registered the node's Agent and wrote a chat section",
                init.get("confirmed") is True and agent.startswith("agent_") and
                fd.account_state(address) == "active", init)
        config = read_json(rail(node))
        RUN[node] = {"agent": agent, "agent_address": address, "controller": config["packet_controller"],
                     "key_id": config["packet_key_id"], "wallet": config["wallet_address"]}
        chat = fox_json(node, "chat", "init", "--rail-config", str(rail(node)))
        RUN[node]["chat_key"] = chat.get("key_id")
        require(f"{node}: `openfox earning chat init` issued the chat key and published a card naming both relays",
                chat.get("agent_id") == agent and chat.get("relays") == RELAY_URLS and card_path(node).is_file(), chat)
    agents = {node: RUN[node]["agent"] for node in NODES}
    fd.evidence["objects"] = {node: {"agent_id": RUN[node]["agent"], "agent_address": RUN[node]["agent_address"]}
                              for node in NODES}
    require("three distinct Agents", len(set(agents.values())) == 3, agents)
    configs = {node: read_json(rail(node)) for node in NODES}
    gate("1", "relay only: every node names both relays for rail and chat, pins the run's CA and names no direct peer "
         "and no Messenger packet socket",
         all(c.get("relay_urls") == RELAY_URLS and not c.get("direct_peers") and not c.get("messenger_socket") and
             c.get("relay_ca_sha256") == hashlib.sha256(CA.read_bytes()).hexdigest() and
             Path(c.get("relay_ca_file", "")).read_bytes() == CA.read_bytes() and (c.get("chat") or {}).get("messenger_carrier_socket") ==
             str(sock(n, "carrier.sock")) for n, c in configs.items()),
         {n: {k: c.get(k) for k in ("relay_urls", "direct_peers", "messenger_socket", "relay_ca_sha256")}
          for n, c in configs.items()})


# --- Messenger identities (not OpenFox) --------------------------------------------

def tosctl(node: str, *args: str) -> dict:
    """tosctl on the host as the invoking user, with the node's staged
    configuration and vault (the controllers OpenFox's init created)."""
    result = fd.run_logged([str(ROOT / "bin" / "tosctl"), *args, "-c", str(nd(node) / "tosctl-config.json")],
                           env=node_env(node), timeout=300)
    return json.loads(result.stdout) if result.stdout.strip().startswith(("{", "[")) else {"stdout": result.stdout}


def domain() -> None:
    answer = tosctl("a", "agent", "native-registry", "domain", "--global-config", str(ROOT / "etc" / "global.json"),
                    "--network-label", fd.NETWORK_LABEL, "--format", "json")
    RUN["domain"] = {"network_id": fd.NETWORK_LABEL, "genesis_root": answer["genesis_root"],
                     "genesis_file": answer["genesis_file"], "code_hash": "tvm-cell-sha256:" + answer["code_hash"]}
    require("not OpenFox: the registry domain (genesis anchors and registry code hash) is read with tosctl",
            all(re.fullmatch(r"[0-9a-f]{64}", answer[key]) for key in ("genesis_root", "genesis_file", "code_hash")),
            RUN["domain"])


def registry_action(node: str, kind: str, *extra: str) -> dict:
    nonce = secrets.token_hex(32)
    message = tosctl(node, "agent", "native-registry", "action", "--global-config", str(ROOT / "etc" / "global.json"),
                     "--network-label", fd.NETWORK_LABEL, "--kind", kind, "--agent", RUN[node]["agent_address"],
                     "--nonce", nonce, *extra, "--signer", RUN[node]["controller"], "--format", "json")
    before = fd.transactions(RUN[node]["agent_address"])
    fd.run_logged([str(ROOT / "bin" / "tosctl"), "wallet", "send", "--from", node, "--to", message["destination"],
                   "--amount-nanotos", str(2 * fd.NANO), "--body-boc", message["body_boc"], "--yes",
                   "-c", str(nd(node) / "tosctl-config.json")], env=node_env(node), timeout=300)
    landed = poll(lambda: [row for row in fd.transactions(RUN[node]["agent_address"])
                           if row["hash"] not in {b["hash"] for b in before}], 180, 3)
    return {"kind": kind, "action_hash": message.get("action_hash"), "landed": landed or []}


def identities() -> None:
    for node in NODES:
        out = in_ns(node, [ROOT / "bin" / "messenger-relay-e2e-tool", "identity", "--agent", RUN[node]["agent"],
                           "--network-id", RUN["domain"]["network_id"], "--genesis-root", RUN["domain"]["genesis_root"],
                           "--genesis-file", RUN["domain"]["genesis_file"], "--rule", "allow-list",
                           "--unknown", "require-admission", "--descriptor-lifetime", str(DESCRIPTOR_LIFETIME),
                           "--delegation-lifetime", str(2 * 86400), "--session-lifetime", str(86400),
                           "--private-dir", nd(node) / "keys", "--public-dir", mdir(node)],
                    "messenger-relay-e2e-tool identity", timeout=60)
        RUN[node]["identity"] = json.loads(out.stdout)
        action = registry_action(node, "delegate", "--delegation", RUN[node]["identity"]["delegation_digest_hex"])
        ok = bool(action["landed"]) and all(row["compute_success"] and not row["aborted"] for row in action["landed"])
        require(f"not OpenFox: {node}'s Messaging Endpoint delegation (relay-only, an ADNL route, allow-list inbox) is "
                "committed by its Agent on chain (tosctl agent native-registry action --kind delegate, sent from its "
                "wallet)", ok, {"identity": RUN[node]["identity"], "action": action})
    fd.evidence["messenger_identities"] = {node: {key: RUN[node]["identity"][key] for key in (
        "endpoint_id", "device_id", "delegation_digest", "descriptor_policy_digest", "inbox_policy_digest")}
        for node in NODES}


def daemon_config(node: str) -> dict:
    peers = {"a": ["b"], "b": ["a"], "c": ["b"]}[node]
    identity = RUN[node]["identity"]
    return {
        "schema": "tos.messaging.daemon-config.v10",
        "state_dir": str(mdir(node) / "state"),
        "socket_path": str(sock(node, "runtime.sock")),
        "owner_socket_path": str(sock(node, "owner.sock")),
        "network_id": RUN["domain"]["network_id"],
        "genesis_root_hash": RUN["domain"]["genesis_root"],
        "genesis_file_hash": RUN["domain"]["genesis_file"],
        "registries": [{"code_hash": RUN["domain"]["code_hash"],
                        "code_boc": (ROOT / "etc" / "registry-code.boc").read_text().strip(), "workchain": 0}],
        "chain_endpoints": fd.rpc_endpoints(),
        "chain_quorum": 2,
        "native_registry_code_hash": RUN["domain"]["code_hash"],
        "chain_checkpoint_path": str(mdir(node) / "state" / "chain.checkpoint"),
        "delegation_path": str(mdir(node) / "delegation.json"),
        "discovery": {"mode": "contact-files", "contact_dir": str(mdir(node) / "contacts"),
                      "refresh_interval_seconds": 60},
        "publication": {"mode": "prekeys", "device_socket_path": str(sock(node, "device.sock")),
                        "device_ids": [identity["device_id"]], "algorithm_id": "tos.messaging.e2ee.x3dh-aes256gcm-dr.v2",
                        "generation_lifetime_seconds": 3600, "replenish_before_seconds": 600,
                        "check_interval_seconds": 60},
        "agent_id": RUN[node]["agent"], "endpoint_id": identity["endpoint_id"], "device_id": identity["device_id"],
        "owner_public_key": identity["owner_public_key"],
        "admission": {"rule": "allow-list", "unknown": "require-admission",
                      "known_agent_ids": sorted(RUN[p]["agent"] for p in peers),
                      "max_content_bytes": 128 << 10, "max_clock_skew_seconds": 300},
        "firewall": {"unattended_ceiling": "message", "own_initiative_ceiling": "message"},
        "transport": "agent-packet-relay",
        "relay_carriage": {"carry_socket_path": str(sock(node, "chat-carrier.sock")),
                           "listen_socket_path": str(sock(node, "carrier.sock")),
                           "card_path": str(card_path(node)), "evidence_export_dir": str(mdir(node) / "export"),
                           "timeout_seconds": CHAT_TIMEOUT, "redeposit_interval_seconds": REDEPOSIT},
        "sweep_interval_seconds": 2,
        "maintenance_interval_seconds": 3600,
    }


def publication_config(node: str) -> dict:
    return {"schema": "tos.messaging.publication-operator.v1", "mode": "relay",
            "descriptor_policy_path": str(mdir(node) / "descriptor-policy.json"),
            "endpoint_signer_socket": str(sock(node, "signer.sock")), "signer_timeout_seconds": 10,
            "publish_interval_seconds": PUBLISH_INTERVAL, "messaging_versions": [1],
            "maximum_envelope_bytes": 196608}


def write_configs() -> None:
    for node in NODES:
        (mdir(node) / "config.json").write_text(json.dumps(daemon_config(node), indent=2) + "\n")
        (mdir(node) / "publication.json").write_text(json.dumps(publication_config(node), indent=2) + "\n")
        for name in ("config.json", "publication.json"):
            (mdir(node) / name).chmod(0o600)
        check = in_ns(node, [ROOT / "bin" / "tos-messengerd", "-config", mdir(node) / "config.json",
                             "-publication-operator-config", mdir(node) / "publication.json", "-check"],
                      "tos-messengerd -check", check=False, timeout=60)
        require(f"{node}: tos-messengerd accepts its configuration (-check)", check.returncode == 0,
                (check.stderr + check.stdout)[-1500:])
    fd.evidence["daemon_configuration"] = {
        "transport": "agent-packet-relay", "discovery": "contact-files", "publication": "prekeys, relay-only descriptor",
        "admission": {"a": "allow-list: B", "b": "allow-list: A (C unknown, require-admission)",
                      "c": "allow-list: B"},
        "redeposit_interval_seconds": REDEPOSIT, "descriptor_max_lifetime_seconds": DESCRIPTOR_LIFETIME,
        "publish_interval_seconds": PUBLISH_INTERVAL, "carrier_timeout_seconds": CHAT_TIMEOUT,
        "note": "the re-deposit interval is the shortest the daemon accepts (a test MAY set 10 min to 20 h, spec 4); "
                "the descriptor lifetime is short so the evidence pull and the descriptor-expired retry run live"}


# --- Processes of a node -------------------------------------------------------------

def signer_argv(node: str) -> list:
    return [ROOT / "bin" / "messenger-relay-e2e-tool", "signer", "--key", nd(node) / "keys" / "endpoint.key",
            "--socket", sock(node, "signer.sock"), "--count-file", nd(node) / "s" / "signatures"]


def daemon_argv(node: str) -> list:
    return [ROOT / "bin" / "tos-messengerd", "-config", mdir(node) / "config.json",
            "-publication-operator-config", mdir(node) / "publication.json"]


def daemon_pattern(node: str) -> str:
    return f"^{ROOT / 'bin' / 'tos-messengerd'} -config {mdir(node) / 'config.json'}"


def serve_pattern(node: str) -> str:
    return f"^{fd.OPENFOX} earning service serve --rail-config {rail(node)}$"


def start_signer(node: str) -> None:
    spawn(node, f"signer-{node}", signer_argv(node), "test Endpoint signer")
    require(f"{node}: the test Endpoint signer serves its socket", wait_line(f"signer-{node}", "ready"),
            log_text(f"signer-{node}")[-300:])


def start_daemon(node: str, label: str = "start") -> None:
    spawn(node, f"messengerd-{node}", daemon_argv(node), "tos-messengerd")
    up = poll(lambda: sock(node, "carrier.sock").exists() and sock(node, "runtime.sock").exists() and
              (mdir(node) / "export" / "relay-contact.json").is_file(), 120, 1)
    require(f"{node} ({label}): tos-messengerd verified its finalized delegation, serves its sockets and exported its "
            "relay evidence", bool(up) and PROCESSES[f"messengerd-{node}"].poll() is None,
            log_text(f"messengerd-{node}")[-1500:])


def stop_daemon(node: str, sig: str = "TERM") -> int | None:
    process = PROCESSES.pop(f"messengerd-{node}", None)
    signal_pattern(daemon_pattern(node), sig)
    return process.wait(timeout=60) if process else None


def start_serve(node: str, label: str = "start") -> None:
    spawn(node, f"serve-{node}", fox_argv("service", "serve", "--rail-config", rail(node)), "openfox earning service serve",
          env=node_env(node))
    up = poll(lambda: sock(node, "chat-carrier.sock").exists() and PROCESSES[f"serve-{node}"].poll() is None, 120, 1)
    require(f"{node} ({label}): `openfox earning service serve` runs and serves carrier.carry",
            bool(up) and PROCESSES[f"serve-{node}"].poll() is None, log_text(f"serve-{node}")[-1500:])


def stop_serve(node: str, sig: str = "TERM") -> int | None:
    process = PROCESSES.pop(f"serve-{node}", None)
    signal_pattern(serve_pattern(node), sig)
    try:
        return process.wait(timeout=60) if process else None
    except subprocess.TimeoutExpired:
        signal_pattern(serve_pattern(node), "QUIT")
        time.sleep(3)
        signal_pattern(serve_pattern(node), "KILL")
        return process.wait(timeout=30)


def start_node(node: str, label: str = "start") -> None:
    start_daemon(node, label)
    start_serve(node, label)


def stop_node(node: str) -> dict:
    return {"serve": stop_serve(node), "messengerd": stop_daemon(node)}


# --- Contacts --------------------------------------------------------------------------

def chat_status(node: str) -> dict:
    return fox_json(node, "chat", "status", "--rail-config", str(rail(node)))


def export_contact(node: str) -> Path:
    out = nd(node) / "contact.json"
    fox_json(node, "chat", "contact", "export", "--rail-config", str(rail(node)), "--out", str(out))
    return out


def hand_contact(source: str, target: str) -> Path:
    """The owners exchange the contact file out of band: the target node
    cannot see the source's directory, so the run copies it across."""
    handed = nd(target) / "handed" / f"contact-{source}.json"
    shutil.copyfile(nd(source) / "contact.json", handed)
    handed.chmod(0o600)
    return handed


def import_contact(node: str, source: str) -> dict:
    return fox_json(node, "chat", "contact", "import", "--rail-config", str(rail(node)),
                    "--file", str(hand_contact(source, node)))


def peer_cards(node: str) -> dict:
    return {card.get("agent_id"): card for card in chat_status(node).get("peer_cards", [])}


def contacts() -> None:
    """One out-of-band exchange: B's owner hands B's contact file to A's
    owner (and, as a public file, to the stranger C). A's contact file is
    exported but not handed to B, so B can only learn A's card and evidence
    in band, from A's first frame (M-R1 item 3)."""
    for node in NODES:
        export_contact(node)
    contact_b = read_json(nd("b") / "contact.json")
    require("the contact file is the daemon's relay contact (evidence, no locator) wrapped with the current chat card",
            contact_b.get("schema") == "tos.openfox.chat-contact.v1" and "relay_contact" in contact_b,
            sorted(contact_b))
    imported = {"a<-b": import_contact("a", "b"), "c<-b": import_contact("c", "b")}
    require("A imports B's contact file (its owner's admission decision) and the stranger C imports the same public "
            "file; B imports nothing", all(v.get("agent_id") == RUN["b"]["agent"] for v in imported.values()) and
            not list((mdir("b") / "contacts").iterdir()), imported)
    committed = poll(lambda: all((mdir(n) / "state" / "relay-evidence" / (RUN["b"]["agent"][6:] + ".json")).is_file()
                                 for n in ("a", "c")), 180, 2)
    require("A's and C's daemons verified and committed B's relay evidence from the imported contact file",
            bool(committed), {n: sorted(p.name for p in (mdir(n) / "state" / "relay-evidence").iterdir())
                              for n in ("a", "c")})
    fd.evidence["contact_exchange"] = {"imports": imported, "handed": ["b -> a", "b -> c (public)"],
                                       "not_handed": "a -> b: B learns A in band",
                                       "out_of_band_exchanges": 1}


# --- Run ---------------------------------------------------------------------------------

def git(path, *args) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True).stdout.strip()


def setup() -> None:
    stage()
    start_forwarders()
    isolation()
    hidden_files()
    for relay in RELAYS:
        start_relay(relay, "start")
    relay_reachability()
    trust_negative_control()
    init_nodes()
    domain()
    identities()
    write_configs()
    for node in NODES:
        start_signer(node)
        start_node(node)
    contacts()
    hold("setup")


def finish() -> None:
    for node in NODES:
        for key, stop in ((f"serve-{node}", stop_serve), (f"messengerd-{node}", stop_daemon)):
            if key in PROCESSES:
                continue_wrapper(key)
                try:
                    stop(node)
                except (subprocess.TimeoutExpired, OSError) as error:
                    record(f"teardown: {key} stopped", False, fd.redact(str(error))[-300:])
    for key in list(PROCESSES):
        continue_wrapper(key)
    for name, process in list(PROCESSES.items()):
        if process.poll() is None:
            process.terminate()
    # The host forwarder runs outside every namespace, so the namespace
    # teardown does not reach it; a process that ignores SIGTERM is killed.
    for name, process in list(PROCESSES.items()):
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # The launcher is root's; its child is the invoking user's.
            subprocess.run(["sudo", "-n", "kill", "-KILL", str(process.pid)], capture_output=True, check=False)
    try:
        netsh("down")
    except RuntimeError as error:
        record("teardown ran", False, fd.redact(str(error))[-1500:])
    left = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    bridge = subprocess.run(["ip", "link", "show", "tosmr-br0"], capture_output=True, text=True).returncode
    record("teardown: the namespaces, the bridge and the host table are removed",
           "tosmr-" not in left and bridge != 0, left)
    fd.scan_artifacts()


def acceptance() -> None:
    setup()
    scenario()


async def main() -> int:
    from tostester.install import Install
    from tostester.n6_cluster import _wait_all_heights
    from tostester.network import Network, StartOptions, _write_model

    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    for key in fd.MASTER_KEYS.values():
        fd.register_secret(key)
    secret_file = PRIVATE / "scan-secrets"
    secret_file.write_text("".join(key + "\n" for key in fd.MASTER_KEYS.values()))
    secret_file.chmod(0o600)
    ai_source = Path(os.environ["E2E_AI_SOURCE"])
    tree = git(fd.REPO, "status", "--porcelain").splitlines()
    ai_tree = git(ai_source, "status", "--porcelain").splitlines()
    fd.evidence.update({
        "schema": "tos.messaging.relay-carriage.acceptance.v1",
        "milestone": "M-R1",
        "mode": "local: one host, network namespaces",
        "qualifies_as_public_acceptance": False,
        "reason": "one physical host: the nodes, the relays and the chain are separated by Linux network namespaces "
                  "and firewall rules, not by machines; the relays and the chain are operated by the run itself; no "
                  "internet path exists",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "openfox_commit": git(fd.REPO, "rev-parse", "HEAD"), "openfox_tree_status": tree,
        "openfox_tree_dirty": bool(tree), "tos_commit": git(fd.SOURCE, "rev-parse", "HEAD"),
        "ai_commit": git(ai_source, "rev-parse", "HEAD"), "ai_tree_status": ai_tree,
        "builds": {"openfox": "GOWORK=off CGO_ENABLED=0 go build -trimpath -tags goolm,stdjson ./cmd/openfox",
                   "ai": "GOWORK=off CGO_ENABLED=0 go build -trimpath ./messenger/cmd/tos-messengerd "
                         "./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay",
                   "tool": "GOWORK=off CGO_ENABLED=0 go build -trimpath ./scripts/messenger-relay-e2e-tool"},
        "relays": {relay: {"url": RELAY_URL[relay],
                           "argv": [p.replace(str(WORK), "<workdir>") for p in relay_argv(relay)]} for relay in RELAYS},
        "topology": {
            "bridge": "tosmr-br0 10.231.78.0/24, host end 10.231.78.1, no default route in any namespace",
            "namespaces": {NAMESPACE[name]: ADDRESS[name] for name in ADDRESS},
            "chain": f"three validators in the host namespace on 127.0.0.1, JSON-RPC ports {fd.RPC_PORTS}",
            "firewall": "node namespaces: outgoing only to the relays' port %d and 10.231.78.1 JSON-RPC ports, no "
                        "incoming connection; relay namespaces: incoming only to port %d, no outgoing connection; "
                        "host bridge table: every node-to-node frame dropped" % (RELAY_PORT, RELAY_PORT),
            "files": "each namespace process runs with empty read-only tmpfs mounts over the other parties' "
                     "directories and the run's private files",
            "thermal_guard": "pauses and resumes the run and the validators (their process group); the node, relay "
                             "and forwarder processes run in their own sessions, so a guard resume never continues a "
                             "process the run paused for a crash window"},
        "network_label": fd.NETWORK_LABEL,
        "not_openfox": [
            "booting the three-validator network (tostester)",
            "creating, funding and activating the three wallets with tosctl and the zerostate faucet",
            "each node's Messaging Endpoint identity: Endpoint and owner keys, the delegation and descriptor policy "
            "(scripts/messenger-relay-e2e-tool identity), and its commitment on chain (tosctl agent native-registry "
            "action --kind delegate, then tosctl wallet send)",
            "the test Endpoint signer (scripts/messenger-relay-e2e-tool signer): the Messenger ships only the signer "
            "client",
            "the Agent revocation at the end (tosctl agent native-registry action --kind revoke-agent)",
            "the network namespaces, firewall rules, forwarders and the relay daemons",
            "the Messenger runtime calls (scripts/messenger-relay-e2e-tool call): this script is the Agent runtime "
            "of both nodes",
            "the adversarial envelopes (scripts/messenger-relay-e2e-tool craft) and this script's relay reads, "
            "deposits and chain reads"]})
    record("the OpenFox tree is clean at the commit the evidence names", not tree, tree or "clean")
    record("the Messenger and relay binaries are built from a clean ai tree at the commit the evidence names",
           not ai_tree, ai_tree or "clean")
    try:
        async with Network(Install(fd.BUILD, fd.SOURCE), WORK / "network", base_port=fd.BASE_PORT) as network:
            dht = network.create_dht_node()
            validators = []
            for _ in range(len(fd.RPC_PORTS)):
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                validators.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(validators, fd.RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(validators, 5, 300)
            client = await validators[0].toslib_client()
            global_config = json.loads((validators[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", validators[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            (WORK / "global.json").write_text(json.dumps(global_config, indent=2))
            zerostate = network.zerostate.as_block()
            fd.evidence["network"] = {"network_id": fd.NETWORK_LABEL,
                                      "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                                      "genesis_file_hash": "sha256:" + zerostate.file_hash.hex(),
                                      "validators": len(validators), "json_rpc": fd.rpc_endpoints()}
            record("every validator serves finalized JSON-RPC", bool(poll(
                lambda: "result" in fd.rpc("getMasterchainInfo"), 180)))
            try:
                fd.RUN["wallets"] = await fd.provision(network.zerostate.main_wallet(client))
                fd.evidence["wallets"] = fd.RUN["wallets"]
                await asyncio.to_thread(acceptance)
            except fd.Stop:
                hold("failure")
            except Exception:  # noqa: BLE001 - the evidence records the failure
                import traceback
                trace = traceback.format_exc().replace(str(fd.REPO), "<repo>").replace(os.path.expanduser("~"), "~")
                fd.record("the run ran without an exception", False, fd.redact(trace)[-3000:])
                hold("failure")
            finally:
                await asyncio.to_thread(finish)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("run completed without an exception", False, repr(error))
    log = WORK / "net" / "root-commands.log"
    commands = log.read_text().splitlines() if log.exists() else []
    fd.evidence["ran_as_root"] = {
        "network_setup_and_teardown": sorted({line.replace(str(WORK), "<workdir>") for line in commands}),
        "namespace_entry": LAUNCHED, "launcher_signals": ROOT_SIGNALS,
        "note": "Only the namespace, firewall and teardown commands, the namespace entry and a SIGCONT/SIGKILL to "
                "a paused process's sudo launcher run as root; every node, "
                "relay, forwarder and probe process runs as uid %d (setpriv) and the run itself runs as uid %d."
                % (UID, UID)}
    fd.evidence["gate_items"] = GATE
    fd.evidence["not_verified"] = NOT_VERIFIED
    # A development hold, and any dev script it ran, voids the acceptance: a
    # run that stepped through dev code is not an unattended acceptance.
    fd.evidence["hold_at"] = HOLD_AT or None
    fd.evidence["dev_scripts_executed"] = DEV_SCRIPTS_RUN
    fd.evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    text = json.dumps(fd.redact_value(fd.evidence), default=str)
    leaked = fd.personal_data(text)
    fd.record("no home directory path or login name in evidence.json", not leaked, leaked)
    passed = bool(fd.steps) and all(step["pass"] for step in fd.steps) and not DEV_SCRIPTS_RUN
    fd.evidence["steps"] = fd.steps
    fd.evidence["pass_count"] = sum(1 for step in fd.steps if step["pass"])
    if DEV_SCRIPTS_RUN:
        fd.evidence["result"] = "NOT A VALID ACCEPTANCE: dev scripts were executed during the run"
    else:
        fd.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


# --- The Agent runtime of each node (this script), and the journals it reads ----------

TEXT = "text/plain; charset=utf-8"
SENT: dict[str, dict] = {}


def mcall(node: str, request: dict, socket: str = "runtime.sock") -> dict:
    result = in_ns(node, [ROOT / "bin" / "messenger-relay-e2e-tool", "call", "--socket", sock(node, socket)],
                   "Messenger runtime call " + request.get("op", ""), check=False, timeout=90,
                   data=json.dumps(request))
    if result.returncode != 0:
        return {"ok": False, "call_error": fd.redact(result.stderr)[-600:]}
    return json.loads(result.stdout)


def idem() -> str:
    return "idem_" + secrets.token_hex(32)


def marker(label: str) -> str:
    """A message text that is unique, so the relay search can look for it."""
    return f"M-R1 {label} " + secrets.token_hex(12)


def send(node: str, peer: str, label: str, body: str | None = None) -> dict:
    text = body if body is not None else marker(label)
    answer = mcall(node, {"op": "messages.send-direct", "recipient": RUN[peer]["agent"], "media_type": TEXT,
                          "body": text, "idempotency_key": idem(), "expires_at_unix": now() + 7 * 86400})
    SENT[label] = {"from": node, "to": peer, "text": text, "event_id": answer.get("event_id", ""), "answer": answer,
                   "sent_at": now()}
    return SENT[label]


def pending(node: str) -> list[dict]:
    answer = mcall(node, {"op": "inbox.pending", "limit": 64})
    return answer.get("events") or []


def inbound_texts(node: str) -> dict[str, str]:
    """Event id -> text of every event the runtime of node can list."""
    out = {}
    for item in pending(node):
        try:
            event = json.loads(item["event"]) if isinstance(item["event"], str) else item["event"]
        except (TypeError, ValueError):
            event = {}
        out[item["event_id"]] = json.dumps(event)
    return out


def take(node: str, event_id: str) -> dict:
    """Claim one event and complete it: the runtime applies it once."""
    lease = "lease_" + secrets.token_hex(32)
    claimed = mcall(node, {"op": "inbox.claim", "event_id": event_id, "lease_id": lease, "lease_seconds": 120})
    done = mcall(node, {"op": "inbox.complete", "event_id": event_id, "lease_id": lease}) if claimed.get("ok") else {}
    APPLIED.setdefault(node, []).append(event_id)
    return {"claimed": claimed.get("ok"), "completed": done.get("ok"), "detail": claimed.get("detail") or
            done.get("detail")}


APPLIED: dict[str, list[str]] = {}


def reply(node: str, event_id: str, label: str) -> dict:
    text = marker(label)
    answer = mcall(node, {"op": "messages.reply-direct", "reply_to_event_id": event_id, "media_type": TEXT,
                          "body": text, "idempotency_key": idem(), "expires_at_unix": now() + 7 * 86400})
    SENT[label] = {"from": node, "reply_to": event_id, "text": text, "event_id": answer.get("event_id", ""),
                   "answer": answer, "sent_at": now()}
    return SENT[label]


def deliveries(node: str) -> list[dict]:
    """The sender Messenger journal's outbound copies, read as files."""
    out = []
    for path in sorted((mdir(node) / "state" / "outbound").glob("*.json")):
        try:
            out.append(read_json(path))
        except (OSError, ValueError):
            continue
    return out


def delivery_of(node: str, event_id: str) -> dict:
    return next((row for row in deliveries(node) if row.get("event_id") == event_id), {})


def delivered(node: str, event_id: str) -> dict | None:
    row = delivery_of(node, event_id)
    return row if row.get("state") == "delivered" else None


def chat_outbox(node: str) -> list[dict]:
    directory = nd(node) / "state" / "relay" / "chat-outbox"
    out = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            out.append(read_json(path))
        except (OSError, ValueError):
            continue
    return out


INSPECTED: dict[str, dict] = {}


def inspect_packet(packet_base64: str) -> dict:
    """Decode one signed packet and the frame it carries (tool inspect)."""
    key = hashlib.sha256(packet_base64.encode()).hexdigest()
    if key not in INSPECTED:
        scratch = PRIVATE / "inspect"
        scratch.mkdir(mode=0o700, exist_ok=True)
        path = scratch / f"{key}.b64"
        path.write_text(packet_base64)
        result = fd.run_logged([str(TOOL), "inspect", "--packet-base64-file", str(path)], env=dict(os.environ),
                               timeout=60, keep=4000)
        INSPECTED[key] = json.loads(result.stdout)
    return INSPECTED[key]


def frames_of(node: str) -> list[dict]:
    """Every envelope of node's chat outbox, with its decoded packet."""
    rows = []
    for record_ in chat_outbox(node):
        if not record_.get("packet_base64"):
            continue
        view = inspect_packet(record_["packet_base64"])
        rows.append({"record": record_, "packet": view, "frame": view.get("frame") or {}})
    return rows


# --- Scenario helpers -------------------------------------------------------------------

def cut_off(node: str) -> None:
    """The node's connections to both relays are refused (firewall), so what
    the relays hold for it stays there; its processes keep running."""
    for relay in RELAYS:
        netsh("block", node, relay)


def reconnect(node: str) -> None:
    for relay in RELAYS:
        netsh("unblock", node, relay)


ROOT_SIGNALS: list[str] = []


def continue_wrapper(key: str) -> None:
    """A process paused with SIGSTOP stops its root `sudo` launcher too, and
    a SIGCONT to the process does not resume the launcher, which then never
    reaps it. The launcher is continued as root (and continues the process)."""
    process = PROCESSES.get(key)
    if process is not None and process.poll() is None:
        entry = f"kill -CONT <the {key} launcher>"
        if entry not in ROOT_SIGNALS:
            ROOT_SIGNALS.append(entry)
        subprocess.run(["sudo", "-n", "kill", "-CONT", str(process.pid)], capture_output=True, check=False)


def require_sent(label: str) -> str:
    row = SENT[label]
    require(f"the runtime of {row['from']} queued '{label}'",
            bool(row["answer"].get("ok")) and row["event_id"].startswith("evt_"), row["answer"])
    return row["event_id"]


def wait_delivered(node: str, event_id: str, timeout: float = 420) -> dict:
    return poll(lambda: delivered(node, event_id), timeout, 2) or delivery_of(node, event_id)


def copy_frames(node: str, event_id: str, kind: int = 1) -> list[dict]:
    return [row for row in frames_of(node)
            if row["frame"].get("kind") == kind and row["frame"].get("event_id") == event_id]


def apply_once(node: str, label: str) -> dict:
    """The runtime lists the event and applies it exactly once."""
    event_id = SENT[label]["event_id"]
    listed = poll(lambda: event_id in inbound_texts(node), 420, 2)
    taken = take(node, event_id) if listed else {}
    return {"listed": bool(listed), "applied": bool(taken.get("completed")),
            "listed_again_after": event_id in inbound_texts(node)}


SIGN_SECONDS: list[float] = []


def craft(sender: str, recipient: str, card: Path, name: str, payload: Path | None = None,
          ofr1: bool = False, packet_out: Path | None = None) -> dict:
    """An envelope signed as sender (its own controller, through tosctl) and
    sealed to the given card, written to the sender's directory."""
    out = nd(sender) / "handed" / f"{name}.envelope"
    argv = [ROOT / "bin" / "messenger-relay-e2e-tool", "craft", "--tosctl", ROOT / "bin" / "tosctl",
            "--tosctl-sha256", fd.evidence["binaries"]["tosctl"]["sha256"],
            "--tosctl-config", nd(sender) / "tosctl-config.json", "--controller", RUN[sender]["controller"],
            "--key-id", RUN[sender]["key_id"], "--sender", RUN[sender]["agent"],
            "--recipient", RUN[recipient]["agent"], "--card", card, "--out", out]
    if ofr1:
        argv.append("--ofr1-payload")
    if payload:
        argv += ["--payload", payload]
    if packet_out:
        argv += ["--packet-out", packet_out]
    result = json.loads(in_ns(sender, argv, "messenger-relay-e2e-tool craft", env=node_env(sender),
                              timeout=180).stdout)
    SIGN_SECONDS.append(result["sign_seconds"])
    result["path"] = out
    return result


def hand_file(source: Path, node: str, name: str) -> Path:
    target = nd(node) / "handed" / name
    shutil.copyfile(source, target)
    target.chmod(0o600)
    return target


# --- Items 2, 3, 4 and 9 (snapshots): the conversation with relay 1 down ------------------

def relay2_only(rows: list[dict]) -> bool:
    return bool(rows) and all(row["record"].get("accepted") == [RELAY_URL["relay2"]] for row in rows)


def conversation() -> None:
    stop_relay("relay1", "item 4: relay 1 is stopped before the conversation")
    RUN["relay1_down_at"] = now()
    # A copy held at the relay: B cannot reach the relays while A sends.
    cut_off("b")
    m1 = (send("a", "b", "m1"), require_sent("m1"))[1]
    carried = poll(lambda: delivery_of("a", m1).get("state") == "carried" and delivery_of("a", m1), 120, 1)
    gate("2", "A's copy of m1 is `carried` once relay 2 accepted it, and not yet delivered while B cannot answer",
         bool(carried) and carried.get("relay_generation") == 1, delivery_of("a", m1))
    RUN["snapshots"] = {"copy-held": snapshot("copy-held")}
    # B's delivery ack held at the relay: A cannot reach the relays while B
    # answers.
    cut_off("a")
    reconnect("b")
    acked = poll(lambda: listed_ids("relay2", RUN["a"]["agent"]), 120, 1)
    RUN["snapshots"]["ack-held"] = snapshot("ack-held")
    reconnect("a")
    gate("9", "relay state is copied while relay 2 held A's copy for B and B's delivery ack for A",
         bool(acked) and RUN["snapshots"]["copy-held"]["relay2"]["envelope_files"] > 0 and
         RUN["snapshots"]["ack-held"]["relay2"]["envelope_files"] > 0, RUN["snapshots"])
    done = wait_delivered("a", m1)
    gate("2", "m1 becomes `delivered` only on B's verified kind-2 ack: carried, then delivered later",
         done.get("state") == "delivered" and done.get("settled_at_unix", 0) >= done.get("last_deposit_at_unix", 0) > 0,
         {k: done.get(k) for k in ("state", "created_at_unix", "last_deposit_at_unix", "settled_at_unix")})
    applied = apply_once("b", "m1")
    gate("2", "B's runtime lists m1 and applies it once", applied["applied"] and not applied["listed_again_after"],
         applied)
    cards = peer_cards("b")
    held_a = cards.get(RUN["a"]["agent"], {})
    evidence_file = mdir("b") / "state" / "relay-evidence" / (RUN["a"]["agent"][6:] + ".json")
    m1_frame = (copy_frames("a", m1) or [{}])[0].get("frame", {})
    gate("3", "first contact over the relay: B had no contact file of A, admitted A's first frame and learned A's "
         "chat card and relay evidence in band from it",
         not list((mdir("b") / "contacts").iterdir()) and held_a.get("key_id") == RUN["a"]["chat_key"] and
         evidence_file.is_file() and m1_frame.get("card_bytes", 0) > 0 and m1_frame.get("bootstrap_bytes", 0) > 0,
         {"b_contact_dir": [p.name for p in (mdir("b") / "contacts").iterdir()], "held_card": held_a,
          "a_chat_key": RUN["a"]["chat_key"], "frame": {k: m1_frame.get(k) for k in ("card_bytes", "evidence_bytes",
                                                                                     "bootstrap_bytes")}})
    r1 = (reply("b", m1, "r1"), require_sent("r1"))[1]
    done_r1 = wait_delivered("b", r1)
    gate("2", "B's runtime answers with messages.reply-direct; the reply is sealed to the card B learned in band "
         "and becomes `delivered` on A's ack", done_r1.get("state") == "delivered" and
         all(row["record"].get("recipient_key_id") == RUN["a"]["chat_key"] for row in copy_frames("b", r1)),
         {k: done_r1.get(k) for k in ("state", "created_at_unix", "last_deposit_at_unix", "settled_at_unix")})
    gate("2", "A's runtime receives the reply once", apply_once("a", "r1")["applied"], SENT["r1"]["event_id"])
    m2 = (send("a", "b", "m2"), require_sent("m2"))[1]
    done_m2 = wait_delivered("a", m2)
    applied_m2 = apply_once("b", "m2")
    gate("2", "A's second message m2 is delivered and applied once", done_m2.get("state") == "delivered" and
         applied_m2["applied"], applied_m2)
    rows = [row for node in ("a", "b") for row in frames_of(node) if row["frame"].get("kind") in (1, 2)]
    times = {label: {k: delivery_of(SENT[label]["from"], SENT[label]["event_id"]).get(k)
                     for k in ("created_at_unix", "last_deposit_at_unix", "settled_at_unix")}
             for label in ("m1", "r1", "m2")}
    fd.evidence["conversation"] = {"carried_to_delivered": times,
                                   "envelopes": [{"from": row["packet"]["sender_agent_id"][:14],
                                                  "kind": row["frame"].get("kind"),
                                                  "accepted_by": row["record"].get("accepted")} for row in rows]}
    gate("4", "relay 1 was down for the whole conversation: every copy and ack of it was accepted by relay 2 only",
         relay2_only(rows) and "relay1" not in PROCESSES, fd.evidence["conversation"]["envelopes"])
    start_relay("relay1", "item 4: relay 1 restarts after the conversation")


def older_duplicate() -> None:
    """Another generation of A's older copy m1 -- a fresh envelope carrying
    the same copy frame, signed by A and sealed to B's card -- deposited after
    B applied the newer m2 of the same session, reaches B's daemon (a new
    envelope id the carrier's replay guard does not catch), is answered
    `duplicate` with a signed ack and never reaches the ratchet or the runtime.
    A same-id replay is instead caught at the relay (a tombstone, 410) or by
    the carrier; this exercises the daemon's committed-Event-ID check."""
    m1 = SENT["m1"]["event_id"]
    record_ = copy_frames("a", m1)[0]["record"]
    payload = base64.b64decode(json.loads(base64.b64decode(record_["packet_base64"]))["payload_base64"])
    frame_file = nd("a") / "handed" / "m1-frame.bin"
    frame_file.write_bytes(payload)
    b_card = hand_file(card_path("b"), "a", "card-b-dup.json")
    replay = craft("a", "b", b_card, "m1-replay", payload=frame_file)
    status = deposit("relay1", RUN["b"]["agent"], replay["envelope_id"], replay["path"].read_bytes())
    dup = poll(lambda: [row for row in copy_frames("b", m1, kind=2) if row["frame"].get("ack_outcome") == "duplicate"],
               180, 2)
    acked = refused_and_acknowledged("relay1", "b", replay["envelope_id"])
    inbound = mdir("b") / "state" / "inbound"
    gate("5", "an older duplicate (a fresh generation of A's m1 copy, deposited after B applied m2) reaches B's "
         "daemon, is answered `duplicate` with a signed ack, relay-acknowledged, and not listed to B's runtime again",
         status in (200, 201) and bool(dup) and bool(acked) and m1 not in inbound_texts("b") and
         APPLIED["b"].count(m1) == 1,
         {"deposit": status, "duplicate_acks": len(dup or []), "inbound_records": len(list(inbound.glob("*")))})


# --- Sizes at the bound, and item 7: refusals --------------------------------------------

def largest_text() -> None:
    """The largest text the inbox bound admits crosses in the largest frame
    bucket; a larger one is refused at composition, before any seal."""
    body = "x" * (96 << 10)
    big = (send("a", "b", "largest", body=body), require_sent("largest"))[1]
    done = wait_delivered("a", big)
    frames = copy_frames("a", big)
    applied = apply_once("b", "largest")
    gate("9", "a large text (98,304 bytes) is carried in one padded frame bucket and delivered, and applied once",
         done.get("state") == "delivered" and applied["applied"] and bool(frames) and
         all(row["frame"].get("frame_bytes") in relayframe_buckets() for row in frames),
         [row["frame"].get("frame_bytes") for row in frames])
    before = len(deliveries("a"))
    over = send("a", "b", "oversize", body="x" * (104 << 10))
    gate("7", "an oversize payload is refused with `content-too-large` before sealing (the daemon computes the "
         "worst-case frame size, 190,464 bytes, before any key is spent): no delivery is journaled",
         not over["answer"].get("ok") and "content-too-large" in json.dumps(over["answer"]) and
         len(deliveries("a")) == before, over["answer"])


def refused_and_acknowledged(relay: str, recipient: str, envelope_id: str) -> bool:
    return bool(poll(lambda: envelope_id not in listed_ids(relay, RUN[recipient]["agent"]), 90, 2))


def refusals() -> None:
    b_card = hand_file(card_path("b"), "a", "card-b.json")
    a_card = hand_file(card_path("a"), "c", "card-a.json")
    b_card_for_c = hand_file(card_path("b"), "c", "card-b.json")
    inbound_b = sorted(p.name for p in (mdir("b") / "state" / "inbound").glob("*"))
    # A rail (OFR1) packet sealed to B's chat key.
    rail_packet = craft("a", "b", b_card, "rail-to-chat-key", ofr1=True, packet_out=nd("a") / "handed" / "rail.json")
    status = deposit("relay2", RUN["b"]["agent"], rail_packet["envelope_id"], rail_packet["path"].read_bytes())
    gate("7", "a rail (OFR1) packet sealed to B's chat key is refused and relay-acknowledged, with no daemon call",
         status == 201 and refused_and_acknowledged("relay2", "b", rail_packet["envelope_id"]) and
         sorted(p.name for p in (mdir("b") / "state" / "inbound").glob("*")) == inbound_b and
         "does not carry a relay frame" in log_text("serve-b"), {"deposit": status})
    # agent.packet over the relay route, refused at the sender's daemon.
    packet = (nd("a") / "handed" / "rail.json").read_bytes()
    answer = mcall("a", {"op": "messages.send-direct-application", "recipient": RUN["b"]["agent"],
                         "application_kind": "agent.packet", "application_body_base64": base64.b64encode(packet).decode(),
                         "idempotency_key": idem(), "expires_at_unix": now() + 3600})
    gate("7", "an agent.packet Event is refused on the relay route (a valid signed packet; the delegation grants "
         "agent.packet)", not answer.get("ok") and "not carried on the relay route" in json.dumps(answer), answer)
    # C wraps A's genuine copy frame (m2) in a packet of its own to B.
    frame = copy_frames("a", SENT["m2"]["event_id"])[0]["packet"]
    payload = nd("c") / "handed" / "a-copy-frame.bin"
    payload.write_bytes(base64.b64decode(json.loads(base64.b64decode(
        copy_frames("a", SENT["m2"]["event_id"])[0]["record"]["packet_base64"]))["payload_base64"]))
    mismatch = craft("c", "b", b_card_for_c, "sender-mismatch", payload=payload)
    status = deposit("relay2", RUN["b"]["agent"], mismatch["envelope_id"], mismatch["path"].read_bytes())
    gate("7", "a packet whose sender (C) is not the Event sender of the copy it carries (A) is refused and "
         "relay-acknowledged; nothing reaches B's runtime and B sends no ack to C",
         status == 201 and refused_and_acknowledged("relay2", "b", mismatch["envelope_id"]) and
         not [row for row in frames_of("b") if row["packet"]["recipient_agent_id"] == RUN["c"]["agent"]] and
         sorted(p.name for p in (mdir("b") / "state" / "inbound").glob("*")) == inbound_b,
         {"deposit": status, "frame_sender_in_packet": frame["sender_agent_id"][:14]})
    # C wraps B's genuine delivery ack (m2) in a packet of its own to A.
    ack = copy_frames("b", SENT["m2"]["event_id"], kind=2)[0]["record"]
    ack_payload = nd("c") / "handed" / "b-ack-frame.bin"
    ack_payload.write_bytes(base64.b64decode(json.loads(base64.b64decode(ack["packet_base64"]))["payload_base64"]))
    journal_a = hashlib.sha256(b"".join(p.read_bytes() for p in sorted((mdir("a") / "state" / "outbound").glob("*"))))
    forged = craft("c", "a", a_card, "ack-sender-mismatch", payload=ack_payload)
    status = deposit("relay2", RUN["a"]["agent"], forged["envelope_id"], forged["path"].read_bytes())
    gate("7", "a kind-2 ack whose packet sender (C) is not the Agent of the signing Endpoint (B) is refused and "
         "relay-acknowledged; A's journal is unchanged",
         status == 201 and refused_and_acknowledged("relay2", "a", forged["envelope_id"]) and
         hashlib.sha256(b"".join(p.read_bytes() for p in sorted((mdir("a") / "state" / "outbound").glob("*"))))
         .hexdigest() == journal_a.hexdigest(), {"deposit": status})


# --- Item 6: crash windows -----------------------------------------------------------------

def crash_windows() -> None:
    # B: killed between the Messenger commit and the relay ack.
    signal_pattern(daemon_pattern("b"), "STOP")
    m = (send("a", "b", "crash-b"), require_sent("crash-b"))[1]
    sent = poll(lambda: [row for row in copy_frames("a", m) if row["record"].get("accepted")], 90, 1)
    envelope_id = sent[0]["record"]["envelope_id"] if sent else ""
    # B's poller may be in its failure backoff (up to 5 min) after the earlier
    # cut-offs. Wait until it handed the frame to the paused daemon: the call
    # times out and is logged, and its request stays queued at the daemon,
    # which processes it once continued, after B's serve is gone.
    unanswered = "the Messenger carrier socket did not answer"
    before = log_text("serve-b").count(unanswered)
    waiting = poll(lambda: log_text("serve-b").count(unanswered) > before, 480, 2)
    require("B's serve downloaded the copy and called its paused daemon (the call is queued, unanswered)",
            bool(waiting), log_text("serve-b")[-400:])
    stop_serve("b", "KILL")
    signal_pattern(daemon_pattern("b"), "CONT")
    continue_wrapper("messengerd-b")
    committed = poll(lambda: m in inbound_texts("b"), 60, 1)
    held = {relay: envelope_id in listed_ids(relay, RUN["b"]["agent"]) for relay in RELAYS}
    gate("6", "B's serve is killed while its daemon commits the copy: the Event is committed and the envelope is "
         "still listed at the relays (no relay ack)", bool(committed) and all(held.values()) and
         delivery_of("a", m).get("state") == "carried", {"listed": held})
    start_serve("b", "after the kill")
    done = wait_delivered("a", m)
    acks = [row["frame"].get("ack_outcome") for row in copy_frames("b", m, kind=2)]
    applied = apply_once("b", "crash-b")
    gate("6", "after the restart B finds the same envelope again, answers it `duplicate` and the runtime applies "
         "it once", done.get("state") == "delivered" and acks == ["duplicate"] and applied["applied"] and
         not applied["listed_again_after"], {"acks": acks, "applied": applied})
    # A: killed between `carried` and its journal write.
    for relay in RELAYS:
        signal_pattern(relay_pattern(relay), "STOP")
    try:
        m = (send("a", "b", "crash-a"), require_sent("crash-a"))[1]
        journaled = poll(lambda: copy_frames("a", m), 60, 1)
        unaccepted = bool(journaled) and not journaled[0]["record"].get("accepted")
        stop_daemon("a", "KILL")
    finally:
        for relay in RELAYS:
            signal_pattern(relay_pattern(relay), "CONT")
            continue_wrapper(relay)
    accepted = poll(lambda: [row for row in copy_frames("a", m) if row["record"].get("accepted")], 120, 1)
    state_before = delivery_of("a", m).get("state")
    gate("6", "A's daemon is killed while its carrier deposits: the relays accept the envelope after the kill and "
         "A's journal never recorded `carried`", unaccepted and bool(accepted) and state_before == "pending",
         {"journal_state": state_before})
    start_daemon("a", "after the kill")
    done = wait_delivered("a", m)
    records = copy_frames("a", m)
    gate("6", "after the restart A retries the same generation key and gets `carried` with no new deposit: one "
         "envelope, delivered, applied once", done.get("state") == "delivered" and len(records) == 1 and
         records[0]["record"]["envelope_id"] == accepted[0]["record"]["envelope_id"] and
         apply_once("b", "crash-a")["applied"], {"records": len(records), "generation": done.get("relay_generation")})


# --- Item 8: the public-id race -------------------------------------------------------------

def public_id_race() -> None:
    stop_serve("b")  # nothing acknowledges the junk while A retries
    netsh("block", "a", "relay1")
    try:
        m = (send("a", "b", "race"), require_sent("race"))[1]
        row = poll(lambda: [r["record"] for r in copy_frames("a", m) if r["record"].get("accepted")], 120, 1)
        record_ = row[0] if row else {}
        junk = bytearray(base64.b64decode(record_.get("envelope_base64", "")))
        junk[-1] ^= 0xFF
        status = deposit("relay1", RUN["b"]["agent"], record_.get("envelope_id", ""), bytes(junk))
    finally:
        netsh("unblock", "a", "relay1")
    conflict = poll(lambda: [r["record"] for r in copy_frames("a", m) if r["record"].get("conflicts")], 420, 3)
    gate("8", "an observer deposits junk under the public id of A's envelope at relay 1 first; A's deposit there "
         "gets 409 and is abandoned at relay 1", record_.get("accepted") == [RELAY_URL["relay2"]] and status == 201 and
         bool(conflict) and conflict[0]["conflicts"] == [RELAY_URL["relay1"]], {"junk_deposit": status,
                                                                                "record": conflict and conflict[0].get("conflicts")})
    start_serve("b", "after the race")
    done = wait_delivered("a", m)
    gate("8", "the copy is delivered through relay 2", done.get("state") == "delivered" and
         apply_once("b", "race")["applied"], done.get("state"))


# --- Item 5: offline recipient across a re-deposit; item 7: the refused stranger ---------------

def files_naming(root: Path, values: list[str]) -> list[str]:
    hits = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if any(value.encode() in data or value.encode() in path.name.encode() for value in values):
            hits.append(str(path.relative_to(ROOT)))
    return hits


def stranger_values() -> list[str]:
    identity = RUN["c"]["identity"]
    return [RUN["c"]["agent"], RUN["c"]["agent"][6:], identity["endpoint_id"], identity["device_id"],
            identity["endpoint_public_key"]]


def offline_recipient() -> None:
    stop_node("b")
    RUN["b_offline_at"] = now()
    # The stranger C writes to B: it holds B's public contact file, but B's
    # inbox admits only A and refuses unknown senders. C's envelope ids are
    # kept, so the refusal is proven by B relay-acknowledging those exact ids
    # (only B holds its mailbox's ack secret), not by time passing.
    c1 = (send("c", "b", "stranger"), require_sent("stranger"))[1]
    c_envelopes = poll(lambda: [r["record"]["envelope_id"] for r in copy_frames("c", c1)
                                if r["record"].get("accepted")], 120, 1) or []
    c_listed = poll(lambda: all(any(e in listed_ids(relay, RUN["b"]["agent"]) for relay in RELAYS)
                                for e in c_envelopes) if c_envelopes else None, 120, 2)
    require("the stranger C deposited its copy to B, and both its envelope ids are listed in B's mailbox at a relay "
            "while B is offline", bool(c_envelopes) and bool(c_listed), {"c_envelopes": c_envelopes})
    m = (send("a", "b", "offline"), require_sent("offline"))[1]
    first = poll(lambda: [r["record"] for r in copy_frames("a", m)
                          if sorted(r["record"].get("accepted") or []) == RELAY_URLS], 120, 1)
    gen1 = first[0]["envelope_id"] if first else ""
    gate("5", "B is stopped; A's copy is carried as generation 1 and both relays hold it",
         bool(gen1) and all(gen1 in listed_ids(relay, RUN["b"]["agent"]) for relay in RELAYS), gen1)
    second = poll(lambda: delivery_of("a", m).get("relay_generation", 0) >= 2 and delivery_of("a", m),
                  REDEPOSIT + 600, 10)
    gone = poll(lambda: (lambda codes: codes if all(code in (404, 410) for code in codes.values()) else None)(
        {relay: envelope_status(relay, RUN["b"]["agent"], gen1) for relay in RELAYS}), 300, 5)
    generations = (second or {}).get("relay_generations") or []
    gate("5", f"after the re-deposit interval ({REDEPOSIT} s, the test setting the spec allows) A deposits "
         "generation 2 with the same ciphertext and fresh evidence, and generation 1 is withdrawn at every relay "
         "that held it (404 or 410 afterwards)",
         bool(second) and len(generations) >= 2 and bool(gone) and
         len({row["frame"].get("ciphertext_sha_prefix_hex") for row in copy_frames("a", m)}) == 1,
         {"generations": generations, "generation_1_status": gone,
          "offline_seconds_at_generation_2": (second or {}).get("last_deposit_at_unix", 0) - RUN["b_offline_at"]})
    boundary_before = sorted(files_naming(mdir("b") / "state", stranger_values()))
    start_node("b", "after the offline period")
    done = wait_delivered("a", m)
    applied = apply_once("b", "offline")
    gate("5", "B, restarted, receives the retained message once (generation 2 only) and A's copy is delivered",
         done.get("state") == "delivered" and applied["applied"] and not applied["listed_again_after"],
         {"applied": applied, "generation": done.get("relay_generation")})
    # The stranger's copy is refused: B downloads it (both ids leave B's
    # mailbox at every relay, relay-acknowledged by B), but nothing of C is
    # stored and B sends C no ack. Bounded on the relay-ack, not a fixed wait.
    acked = poll(lambda: all(all(e not in listed_ids(relay, RUN["b"]["agent"]) for relay in RELAYS)
                             for e in c_envelopes), 180, 3)
    stored = {"c_envelopes_relay_acknowledged_by_b": bool(acked),
              "b_chat_cards_naming_c": [a for a in peer_cards("b") if a == RUN["c"]["agent"]],
              "b_messenger_files_naming_c": sorted(files_naming(mdir("b") / "state", stranger_values())),
              "b_openfox_files_naming_c": files_naming(nd("b") / "state" / "relay" / "chat-peers", stranger_values()),
              "b_messenger_files_naming_c_before": boundary_before,
              "c_kind2_from_b": [row["frame"].get("ack_outcome") for row in frames_of("b")
                                 if row["packet"]["recipient_agent_id"] == RUN["c"]["agent"]]}
    gate("7", "a refused stranger: B downloaded C's copy (both ids relay-acknowledged by B) and refused it; C's "
         "in-band card and evidence are not stored (so it was refused, not held), no Messenger file of B names C "
         "(its rollback boundary is unchanged), B sent C no ack, and C's delivery stays carried",
         bool(acked) and not stored["b_chat_cards_naming_c"] and not stored["b_messenger_files_naming_c"] and
         not stored["b_openfox_files_naming_c"] and c1 not in inbound_texts("b") and
         delivery_of("c", c1).get("state") == "carried" and not stored["c_kind2_from_b"], stored)


# --- Item 5: descriptor expiry, mutual staleness and the evidence pull -------------------------

def latest_expiry(node: str, peer: str) -> int:
    """The latest descriptor expiry in the evidence node sent to peer."""
    return max([row["frame"].get("descriptor_expires_at_unix", 0) for row in frames_of(node)
                if row["packet"]["recipient_agent_id"] == RUN[peer]["agent"]] or [0])


def evidence_pull() -> None:
    stop_node("b")
    m = (send("a", "b", "stale"), require_sent("stale"))[1]
    carried = poll(lambda: delivery_of("a", m).get("state") == "carried", 120, 1)
    stop_node("a")
    deadline = max(latest_expiry("a", "b"), latest_expiry("b", "a")) + 30
    RUN["stale_window"] = {"start": now(), "both_stale_after": deadline}
    gate("5", "B and then A are stopped with A's copy carried; the run waits until every descriptor either holds "
         f"of the other has expired (descriptor lifetime {DESCRIPTOR_LIFETIME} s)", bool(carried),
         {"wait_seconds": deadline - now()})
    while now() < deadline:
        time.sleep(min(60, max(1, deadline - now())))
    # A returns first, while B is still offline: its copy is due for a
    # re-deposit, B's stored evidence fails CheckPeer, so the copy is held
    # pending and one kind-4 request carrying A's fresh evidence and card is
    # deposited for B.
    start_node("a", "with B's evidence expired")
    requested = poll(lambda: [f for f in frames_of("a") if f["frame"].get("kind") == 4 and
                              f["frame"].get("evidence_object") == "request" and
                              f["packet"]["created_at_unix"] >= RUN["stale_window"]["start"]], REDEPOSIT + 300, 5)
    held = delivery_of("a", m)
    gate("5", "with B's evidence expired, A seals and deposits no new generation of its copy: it holds it pending "
         "and deposits one kind-4 evidence request for B instead",
         bool(requested) and len(held.get("relay_generations") or []) == 1,
         {"state": held.get("state"), "generations": len(held.get("relay_generations") or [])})
    start_node("b", "with A's evidence expired")
    expired = poll(lambda: [row for row in copy_frames("b", m, kind=2)
                            if row["frame"].get("ack_code") == "descriptor-expired"], 420, 2)
    gate("5", "descriptor expiry: B receives the retained copy whose frame evidence expired and answers a signed "
         "`rejected` ack with descriptor-expired (A is admitted); the copy does not reach B's runtime",
         bool(expired) and m not in inbound_texts("b"), [row["frame"].get("ack_outcome") for row in expired or []])
    done = wait_delivered("a", m, timeout=600)
    row = delivery_of("a", m)
    window = (RUN["stale_window"]["start"], now())
    requests = [f for f in frames_of("a") if f["frame"].get("kind") == 4 and
                f["frame"].get("evidence_object") == "request" and window[0] <= f["packet"]["created_at_unix"] <= window[1]]
    responses = [f for f in frames_of("b") if f["frame"].get("kind") == 4 and
                 f["frame"].get("evidence_object") == "response" and window[0] <= f["packet"]["created_at_unix"] <= window[1]]
    applied = apply_once("b", "stale")
    gate("5", "mutual staleness: one kind-4 request (A) and one response (B), each carrying its sender's card and "
         "fresh evidence, make both views fresh; A retries the copy only with newer evidence and it is delivered "
         "and applied once", done.get("state") == "delivered" and len(requests) == 1 and len(responses) == 1 and
         all(f["frame"].get("card_bytes", 0) > 0 for f in requests + responses) and applied["applied"] and
         bool(row.get("rejected_descriptor_digest")) and len(row.get("relay_generations") or []) >= 2,
         {"requests": len(requests), "responses": len(responses), "generations": row.get("relay_generations"),
          "rejected_descriptor_digest": row.get("rejected_descriptor_digest")})
    # The stranger's evidence request.
    c_requests = [f for f in frames_of("c") if f["frame"].get("kind") == 4 and f["frame"].get("evidence_object") ==
                  "request"]
    acked = poll(lambda: not [f for f in c_requests if f["record"]["envelope_id"] in
                              listed_ids("relay2", RUN["b"]["agent"])], 120, 2)
    gate("5", "a stranger's evidence request (C held a pending copy for B and B's evidence expired) gets the relay "
         "ack only: no response and no write at B", bool(c_requests) and bool(acked) and
         not [f for f in frames_of("b") if f["packet"]["recipient_agent_id"] == RUN["c"]["agent"]] and
         not files_naming(mdir("b") / "state", stranger_values()), {"c_requests": len(c_requests)})
    kind4_rules()


def kind4_rules() -> None:
    """No kind-4 request without a pending copy, at most one outstanding per
    peer, and publishing a descriptor sends none (from the chat outboxes)."""
    problems = []
    published = {}
    for node in ("a", "b"):
        peer = "b" if node == "a" else "a"
        published[node] = sorted({f["frame"].get("descriptor_digest") for f in frames_of(node)} - {None})
        requests = sorted(f["packet"]["created_at_unix"] for f in frames_of(node)
                          if f["frame"].get("kind") == 4 and f["frame"].get("evidence_object") == "request")
        copies = [row for row in deliveries(node) if row.get("event_id") and
                  RUN[peer]["identity"]["endpoint_id"] == row.get("recipient_messaging_endpoint_id")]
        for at in requests:
            open_copies = [row for row in copies if row.get("created_at_unix", 0) <= at and
                           (not row.get("settled_at_unix") or row["settled_at_unix"] >= at)]
            if not open_copies:
                problems.append({"node": node, "request_at": at, "reason": "no pending copy"})
        for first, second in zip(requests, requests[1:]):
            if second - first < REDEPOSIT - 60:
                problems.append({"node": node, "requests": [first, second], "reason": "two outstanding"})
    gate("5", "no kind-4 request is sent to a peer without a pending copy, none is repeated before the re-deposit "
         "schedule, and the descriptors each node published during the run sent none",
         not problems and all(len(v) >= 2 for v in published.values()),
         {"problems": problems, "own_descriptors_seen": {k: len(v) for k, v in published.items()}})


# --- Item 5: Agent revocation ----------------------------------------------------------------------

# The codes a send to a revoked peer reaches: the Agent is tombstoned, so
# its delegation is no longer committed by the live Agent.
REVOCATION_CODES = {"agent-tombstoned", "delegation-uncommitted"}


def revocation_refusal(answer: dict, delivery: dict) -> bool:
    """The send was a real runtime exchange (the socket answered, so no
    transport error) and it was refused with a revocation code, either in the
    synchronous answer or as the copy's last code once it fails to seal."""
    if "call_error" in answer:
        return False
    return answer.get("code") in REVOCATION_CODES or delivery.get("last_code") in REVOCATION_CODES


def revocation() -> None:
    # The queued-copy case: a copy A carried while B was reachable, whose
    # re-deposit falls due after B's Agent is revoked.
    cut_off("b")
    queued = (send("a", "b", "before-revocation"), require_sent("before-revocation"))[1]
    carried = poll(lambda: delivery_of("a", queued).get("state") == "carried" and delivery_of("a", queued), 180, 2)
    gate("5", "a copy A carried to B (generation 1 at the relays) before B's Agent is revoked",
         bool(carried) and len((carried or {}).get("relay_generations") or []) == 1, carried)

    action = registry_action("b", "revoke-agent")
    ok = bool(action["landed"]) and all(row["compute_success"] and not row["aborted"] for row in action["landed"])
    require("not OpenFox: B's Agent is revoked on chain (tosctl agent native-registry action --kind revoke-agent), "
            "which withdraws its Endpoint delegation", ok, action)

    # A new send after the revocation: the runtime answers, and the copy is
    # refused with a revocation code (not a transport failure).
    frames_before = {f["record"]["idempotency_key"] for f in frames_of("a")}
    new = send("a", "b", "after-revocation")
    refused = poll(lambda: revocation_refusal(new["answer"], delivery_of("a", new["event_id"]))
                   if new["event_id"] else revocation_refusal(new["answer"], {}), 180, 3)
    new_row = delivery_of("a", new["event_id"]) if new["event_id"] else {}
    added_copy = [f for f in frames_of("a") if f["record"]["idempotency_key"] not in frames_before and
                  f["frame"].get("kind") == 1]
    gate("5", "after B's Endpoint delegation is withdrawn on chain, A's runtime answers a new send and refuses it "
         "with a revocation code (CheckPeer reads finalized state); no copy is sealed or carried",
         bool(refused) and (not new_row or (new_row.get("state") == "pending" and not new_row.get("ciphertext_base64")))
         and not added_copy,
         {"answer": new["answer"], "state": new_row.get("state"), "last_code": new_row.get("last_code"),
          "added_kind1_frames": len(added_copy)})

    # The queued copy's re-deposit is now due; CheckPeer fails, so A deposits
    # no new generation and the copy stays at generation 1.
    queued_before = {f["record"]["idempotency_key"] for f in frames_of("a") if f["frame"].get("event_id") == queued}
    due = carried["last_deposit_at_unix"] + REDEPOSIT + 90
    while now() < due:
        time.sleep(min(60, max(1, due - now())))
    row = delivery_of("a", queued)
    new_generation = [f for f in frames_of("a") if f["frame"].get("event_id") == queued and
                      f["record"]["idempotency_key"] not in queued_before and f["frame"].get("kind") == 1]
    gate("5", "the copy carried before the revocation is not re-deposited after it: past its re-deposit time A "
         "seals no new generation (CheckPeer fails), and the copy stays at generation 1, undelivered",
         row.get("relay_generation") == 1 and len(row.get("relay_generations") or []) == 1 and
         not new_generation and row.get("state") in ("carried", "pending"),
         {"state": row.get("state"), "generation": row.get("relay_generation"),
          "new_generations_after_revocation": len(new_generation)})
    reconnect("b")


# --- Item 9: nothing readable at the relays, and the size formula; item 10: cost -----------

RELAY_META_BYTES = 73  # APRSENV1 magic, received/expires, client address, sha-256 over them


def relay_envelope_sizes(snapshot_dir: Path) -> list[int]:
    return [path.stat().st_size - RELAY_META_BYTES for path in sorted(snapshot_dir.rglob("*"))
            if path.is_file() and "envelopes" in path.parts]


RELAY_FILE = re.compile(r"^([0-9a-f]{64})-[0-9a-f]{64}")


def search(roots: list[Path], needles: dict[str, list[bytes]]) -> dict[str, list[str]]:
    """Which needles each file holds. A relay envelope or tombstone file is
    named <recipient agent hex>-<envelope id> and holds its recipient's Agent
    id by design (the mailbox key, and the envelope header); that one Agent's
    id forms are not searched in it, every other Agent's are."""
    found: dict[str, list[str]] = {}
    for root in roots:
        for path in ([root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            owner = RELAY_FILE.match(path.name)
            public = set(hexforms({"agent_" + owner.group(1)})) if owner else set()
            for kind, items in needles.items():
                if any(item in data for item in items if item not in public):
                    found.setdefault(kind, []).append(str(path))
    return found


def hexforms(values) -> list[bytes]:
    out = []
    for value in values:
        if not value:
            continue
        out.append(value.encode())
        tail = value.split("_", 1)[-1]
        out.append(tail.encode())
        try:
            out.append(bytes.fromhex(tail))
        except ValueError:
            pass
    return out


def relay_search_and_sizes() -> None:
    texts = [SENT[label]["text"].encode() for label in SENT if SENT[label].get("text")]
    conversations, events, endpoints, devices = set(), set(), set(), set()
    for node in NODES:
        for row in deliveries(node):
            conversations.add(row.get("conversation_id", ""))
            events.add(row.get("event_id", ""))
            endpoints.add(row.get("recipient_messaging_endpoint_id", ""))
            devices.add(row.get("recipient_device_id", ""))
    # The sender Agent is never in an envelope; it is searched for in the
    # recipient's mailbox state in both directions.
    senders = hexforms({RUN[n]["agent"] for n in NODES} | {RUN[n]["identity"]["endpoint_id"] for n in NODES} |
                       {RUN[n]["identity"]["device_id"] for n in NODES})
    needles = {"message text": texts, "conversation id": hexforms(conversations), "event id": hexforms(events),
               "endpoint id": hexforms(endpoints), "device id": hexforms(devices), "sender agent id": senders}
    needles = {kind: [item for item in items if item and len(item) >= 8] for kind, items in needles.items()}
    control = PRIVATE / "plaintext-control.bin"
    control.write_bytes(b"".join(secrets.token_bytes(32) + items[0] for items in needles.values() if items))
    control_found = search([control], needles)
    require("the relay plaintext search finds every searched value in a control file holding one of each",
            set(control_found) == set(needles), sorted(control_found))
    roots = [WORK / relay / "state" for relay in RELAYS] + [SNAPSHOTS] + [WORK / f"{relay}.log" for relay in RELAYS]
    found = search([root for root in roots if root.exists()], needles)
    snapshots = RUN.get("snapshots", {})
    gate("9", "nothing readable at the relays: no live relay state, no snapshot taken while a relay held a copy and "
         "an ack, and no relay log contains any message text, conversation, Event, Endpoint or device id or the "
         "sender Agent id (the control proves the search works)",
         not found and all(any(snapshots[name][relay]["envelope_files"] > 0 for relay in RELAYS)
                           for name in ("copy-held", "ack-held")),
         {"found": found, "snapshots": {name: {r: snapshots[name][r]["envelope_files"] for r in RELAYS}
                                        for name in snapshots}})
    frame_sizes: dict[str, list[int]] = {}
    envelope_ok = []
    for node in ("a", "b"):
        for row in frames_of(node):
            frame = row["frame"]
            frame_sizes.setdefault(node, []).append(frame.get("frame_bytes"))
            # A withdrawn generation keeps its packet but no envelope bytes.
            if not row["record"].get("envelope_base64"):
                continue
            if frame.get("is_bucket") and frame.get("frame_bytes") == frame.get("smallest_bucket") and \
               row["packet"].get("expected_envelope_bytes"):
                stored = len(base64.b64decode(row["record"]["envelope_base64"]))
                fixed = row["packet"]["fixed_field_bytes"]
                envelope_ok.append(stored == row["packet"]["expected_envelope_bytes"] and 5394 <= fixed <= 5432)
            else:
                envelope_ok.append(False)
    buckets = relayframe_buckets()
    all_buckets = all(size in buckets for sizes in frame_sizes.values() for size in sizes)
    stored_sizes = {name: {relay: relay_envelope_sizes(SNAPSHOTS / name / relay) for relay in RELAYS}
                    for name in snapshots}
    stored_match = all(relayframe_envelope_size(size) for sizes in stored_sizes.values()
                       for relay_sizes in sizes.values() for size in relay_sizes)
    gate("9", "every decoded frame is exactly its smallest padded bucket, every stored envelope equals "
         "1,373 + F + 4·⌈B/3⌉ with F in 5,394..5,432, and the snapshots' stored envelope sizes match the formula",
         all_buckets and all(envelope_ok) and bool(envelope_ok) and stored_match,
         {"frame_buckets": {k: sorted(set(v)) for k, v in frame_sizes.items()},
          "envelope_formula_checks": len(envelope_ok), "stored_sizes": stored_sizes})
    fd.evidence["sizes"] = {"frame_buckets_seen": sorted({s for v in frame_sizes.values() for s in v}),
                            "stored_envelope_sizes": sorted({s for v in stored_sizes.values()
                                                             for rs in v.values() for s in rs})}


def relayframe_buckets() -> list[int]:
    return [1 << 10, 2 << 10, 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 190464]


def relayframe_envelope_size(size: int) -> bool:
    return any(size == 1373 + fixed + 4 * ((bucket + 2) // 3)
               for bucket in relayframe_buckets() for fixed in range(5394, 5433))


def signing_cost() -> None:
    gate("10", "`tosctl` sign-to-deposit cost: the per-frame signing time is recorded", bool(SIGN_SECONDS), None)
    fd.evidence["signing_cost"] = {
        "note": "sign_seconds is the tosctl sign time of one chat packet, measured by the harness's craft helper "
                "signing as a node's own controller through its tosctl custody (the controller and context OpenFox's "
                "carrier uses). It is sign only; the deposit is a separate TLS round trip.",
        "samples": len(SIGN_SECONDS), "sign_seconds_min": min(SIGN_SECONDS), "sign_seconds_max": max(SIGN_SECONDS),
        "sign_seconds_mean": sum(SIGN_SECONDS) / len(SIGN_SECONDS)}
    NOT_VERIFIED.extend([
        {"item": "5 (offline beyond 24 h across a re-deposit, past every locator lifetime)",
         "reason": "the relay route reads no locator at all, so there is no locator lifetime to outlast; the "
                   "offline-across-a-re-deposit case is proven live with the test-shortened re-deposit interval "
                   "(spec section 4 permits 10 min..20 h), and the run never reads a locator on RouteRelay. The "
                   ">24 h wall-clock duration itself is not reproduced.",
         "unit_tests": ["ai messenger/pkg/daemon TestRelayCopyIsCarriedAndDeliveredOnlyOnAVerifiedAck",
                        "ai messenger/pkg/directory TestCheckPeerAcceptsCurrentLocatorFreeEvidence",
                        "openfox pkg/servicebridge TestGenerationNIsWithdrawnOnceGenerationNPlusOneIsAccepted"]},
        {"item": "5 (descriptor expiry, >7-day default)",
         "reason": "proven live with a test-shortened descriptor (MR1_DESCRIPTOR_LIFETIME); the >7-day default "
                   "lifetime is not waited out.",
         "unit_tests": ["ai messenger/pkg/daemon TestDescriptorExpiredRetriesAtOnceOnlyWithNewerEvidence",
                        "ai messenger/pkg/daemon TestRelayEvidencePullRepairsStaleEvidenceInOneRoundTrip",
                        "ai messenger/pkg/directory TestCheckPeerRefusesExpiredEvidence"]},
        {"item": "quota isolation between chat and task traffic (D2)",
         "reason": "M-R1 shares the relays between chat and rail; separate chat relays are a production requirement "
                   "(spec section 7), not shown here.", "unit_tests": []},
        {"item": "3 (first contact with an admission invite)",
         "reason": "product gap: an invite can be created (invites.create) and is checked on receipt, but no runtime "
                   "operation attaches the bearer to an outbound copy (dispatch never sets Message.AdmissionToken), "
                   "so no route can present one. First contact here is admitted by B's allow-list roster instead; "
                   "B still learns A's card and evidence in band.",
         "unit_tests": []},
        {"item": "7 (a relay frame sealed to the rail key)",
         "reason": "needs B's rail key card, which OpenFox keeps only inside its private key files; the run reads no "
                   "key file. The rail packet sealed to the chat key is proven live.",
         "unit_tests": ["openfox pkg/servicebridge TestPurposeIsEnforcedAtTheKeyBeforeAnySideEffect"]},
        {"item": "7 (an agent.packet Event arriving over the relay)",
         "reason": "the sender's daemon refuses to compose it on this route (proven live), so a receive-side case "
                   "needs a hand-built E2EE copy.",
         "unit_tests": ["ai messenger/pkg/daemon TestRelayRefusesAgentPacketEventsAndSenderSubstitution"]},
        {"item": "5 (device removed through a newer descriptor)",
         "reason": "V1 has one device per Agent and the publication roster must include it; the Agent revocation "
                   "case is proven live.",
         "unit_tests": ["ai messenger/pkg/daemon TestRelayRevocationHoldsTheCopyUnsealed",
                        "ai messenger/pkg/directory TestCheckPeerFailsOnceTheDeviceIsRevoked"]},
        {"item": "5 (evidence pull with the responder offline > 24 h)",
         "reason": "the request re-deposit is proven only within the run's duration; the 24 h relay TTL is not "
                   "waited out.",
         "unit_tests": ["ai messenger/pkg/daemon TestRelayEvidencePullRepairsStaleEvidenceInOneRoundTrip"]},
        {"item": "multi-device over the relay (D3), and M0 freeze evidence",
         "reason": "V1 is one Messenger device per Agent; M0 freeze (independent review and a second E2EE "
                   "implementation) is out of scope.", "unit_tests": []},
    ])


def scenario() -> None:
    conversation()
    older_duplicate()
    largest_text()
    refusals()
    crash_windows()
    public_id_race()
    offline_recipient()
    evidence_pull()
    revocation()
    relay_search_and_sizes()
    signing_cost()


NOT_VERIFIED: list = []


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
