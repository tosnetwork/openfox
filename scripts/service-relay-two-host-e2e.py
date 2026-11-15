#!/usr/bin/env python3
"""A paid software-work sale between two OpenFox nodes that have no network
path to each other, carried only by a real Agent Packet Relay daemon.

One host, four network locations (scripts/service-relay-two-host-net.sh):

- the host namespace runs the three-validator chain on 127.0.0.1 and a
  forwarder from the host end of a private bridge (10.231.77.1) to it;
- tosrly-buyer (10.231.77.10) and tosrly-provider (10.231.77.11) each run
  one node as the invoking user, with a forwarder on their own 127.0.0.1
  to the host end of the bridge, because a node takes plain-HTTP RPC
  endpoints only on loopback;
- tosrly-relay (10.231.77.20) runs the tos-service-packet-relay daemon as
  the invoking user, serving TLS on 10.231.77.20:8443 with a certificate of
  a certificate authority generated for this run only.

The firewall lets each node connect only to the relay's TLS port and the
forwarder ports, and nothing reaches a node. A host bridge table drops every
frame between the buyer's and the provider's addresses. The run proves the
cut with a listener in each node namespace that the other node reaches
before the rules and cannot reach after them. Each node process also runs
with the other node's directories, every private file of the run and the
relay's state covered by an empty read-only tmpfs, so the nodes share no
file and no Unix socket.

The nodes trust the relay's certificate through SSL_CERT_FILE (the run's
certificate authority only) and an empty SSL_CERT_DIR: verification stays
on, and a preflight with an unrelated authority is shown to fail.

The sale itself is the front-door run's (service-front-door-e2e.py, loaded as
a module: the same commands, checks and chain reads), with both nodes on the
relay and no other transport. Two live relay outages are added around it:

1. the provider is stopped, the buyer pays and its task is accepted by the
   relay; the relay daemon is stopped (SIGTERM) while it holds the task, the
   provider starts and its polls fail, and the relay restarts on the same
   state directory and still holds the task;
2. as soon as the provider has acknowledged the task the relay is stopped
   again, so the result cannot be deposited; the provider responds on chain
   and its result deposits fail; after the relay restarts the result is
   accepted and the buyer, restarted, receives it. Execution happens
   exactly once.

After the run every file the relay wrote, including copies of its state
taken while it held the task and the result, is searched for the source
archive, the artifact, the buyer wallet address and the Quote package: none
is found. The search is shown to find every one of them in a control file.

No live adversarial case runs here; the in-repository tests the evidence
lists cover them. Run it through scripts/service-relay-two-host-e2e.sh.
"""

import asyncio
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("front_door", HERE / "service-front-door-e2e.py")
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)

WORK, PRIVATE, ROOT, BIN = fd.WORK, fd.PRIVATE, fd.ROOT, fd.BIN
RELAY_URL = fd.RELAY_URL
UID, GID = os.getuid(), os.getgid()
NETSH = HERE / "service-relay-two-host-net.sh"
FORWARD = HERE / "service-relay-two-host-forward.py"
SYSTEM_PYTHON = "/usr/bin/python3"
HOST_IP, RELAY_IP, RELAY_PORT = "10.231.77.1", "10.231.77.20", 8443
ADDRESS = {"buyer": "10.231.77.10", "provider": "10.231.77.11", "relay": RELAY_IP}
NAMESPACE = {name: f"tosrly-{name}" for name in ADDRESS}
TLS = WORK / "tls"
CA, WRONG_CA, EMPTY_CERTS = TLS / "ca.pem", TLS / "unrelated-ca.pem", TLS / "empty-certs"
RELAY_DIR = WORK / "relay"
RELAY_STATE = RELAY_DIR / "state"
RELAY_BIN = BIN / "tos-service-packet-relay"
SNAPSHOTS = WORK / "relay-snapshots"
RELAY_ARGV = [str(RELAY_BIN), "-listen", f"{RELAY_IP}:{RELAY_PORT}", "-tls-cert", str(TLS / "relay-cert.pem"),
              "-tls-key", str(RELAY_DIR / "tls-key.pem"), "-state-dir", str(RELAY_STATE),
              "-global-max-entries", "10000", "-global-max-bytes", "268435456", "-sweep-interval", "10s"]
# What each process launched in a namespace must not see.
HIDE = {"buyer": [PRIVATE, ROOT / "provider", RELAY_DIR],
        "provider": [PRIVATE, ROOT / "buyer", RELAY_DIR],
        "relay": [PRIVATE, ROOT.parent]}
# Mount an empty read-only tmpfs over each named directory (inside the
# namespace's own mount namespace, which `ip netns exec` creates), then run
# the command as the invoking user with its own supplementary groups.
ENTER = ('set -e; uid=$1; gid=$2; shift 2; while [ "$1" != -- ]; do '
         'mount -t tmpfs -o ro,size=16k,mode=0555 tosrly-hidden "$1"; shift; done; shift; '
         'exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"')
LAUNCHED: list[str] = []
PROCESSES: dict = {}
TLS_CONTEXT = ssl.create_default_context(cafile=str(CA)) if CA.exists() else None


def ns_argv(name: str, argv: list, label: str) -> list[str]:
    """The command run as the invoking user inside a namespace. The vault URL
    and the trust settings reach it in its environment, never on a command
    line."""
    entry = f"ip netns exec {NAMESPACE[name]} (tmpfs over the other parties' directories, then setpriv " \
            f"--reuid={UID} --regid={GID} --init-groups): {label}"
    if entry not in LAUNCHED:
        LAUNCHED.append(entry)
    hidden = [str(path) for path in HIDE[name] if path.is_dir()]
    return ["sudo", "-n", "--preserve-env=VAULT_URL,SSL_CERT_FILE,SSL_CERT_DIR", "ip", "netns", "exec",
            NAMESPACE[name], "/bin/sh", "-c", ENTER, "tosrly-enter", str(UID), str(GID), *hidden, "--",
            *map(str, argv)]


# --- The front-door run's node commands, moved into the namespaces ---------

_node_env = fd.node_env


def node_env(node: str) -> dict:
    env = _node_env(node)
    env.update(SSL_CERT_FILE=str(CA), SSL_CERT_DIR=str(EMPTY_CERTS))
    return env


def fox(node: str, *args: str, check: bool = True, timeout: float = 900, env: dict | None = None):
    return fd.run_logged(ns_argv(node, fd.fox_argv(*args), "openfox earning service " + args[0]),
                         env=env or fd.node_env(node), check=check, timeout=timeout)


def start_serve(node: str) -> None:
    log = (WORK / f"{node}-serve.log").open("ab")
    argv = ns_argv(node, fd.fox_argv("serve", "--rail-config", fd.rail(node)), "openfox earning service serve")
    fd.SERVING[node] = subprocess.Popen(argv, env=fd.node_env(node), stdin=subprocess.DEVNULL, stdout=log, stderr=log)


fd.node_env, fd.fox, fd.start_serve = node_env, fox, start_serve


# --- Network, forwarders and relay -------------------------------------------

def netsh(action: str) -> None:
    fd.run_logged(["bash", str(NETSH), action, str(WORK)], env=dict(os.environ), timeout=120)


def spawn(name: str, argv: list, log_name: str) -> subprocess.Popen:
    log = (WORK / log_name).open("ab")
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=dict(os.environ))


def wait_line(log_name: str, text: str, timeout: float = 30) -> bool:
    return bool(fd.poll(lambda: text in (WORK / log_name).read_text(errors="replace"), timeout, 0.5))


def start_forwarders() -> None:
    ports = [str(port) for port in fd.RPC_PORTS]
    PROCESSES["forward-host"] = spawn("host", [SYSTEM_PYTHON, "-I", str(FORWARD), HOST_IP, "127.0.0.1", *ports],
                                      "forward-host.log")
    ok = wait_line("forward-host.log", "ready")
    for node in fd.NODES:
        PROCESSES[f"forward-{node}"] = spawn(node, ns_argv(node, [SYSTEM_PYTHON, "-I", FORWARD, "127.0.0.1", HOST_IP,
                                                                   *ports], "the chain RPC forwarder"),
                                             f"forward-{node}.log")
        ok = wait_line(f"forward-{node}.log", "ready") and ok
    fd.require("the chain RPC is forwarded: host 10.231.77.1 to the validators on 127.0.0.1, and in each node "
               "namespace 127.0.0.1 to 10.231.77.1, for the JSON-RPC ports only", ok,
               {name: (WORK / f"{name}.log").read_text()[-200:] for name in
                ("forward-host", "forward-buyer", "forward-provider")})


def relay_request(path: str, timeout: float = 10):
    with urllib.request.urlopen(RELAY_URL + path, context=TLS_CONTEXT, timeout=timeout) as response:
        return response.status, response.read()


def relay_up() -> bool:
    try:
        status, body = relay_request("/v1/relay", timeout=3)
        return status == 200 and json.loads(body).get("schema") == "tos.service.agent-packet-relay.relay.v1"
    except (OSError, ValueError):
        return False


def listing(agent: str) -> list[str]:
    status, body = relay_request(f"/v1/mailboxes/{agent}/envelopes")
    if status != 200:
        raise RuntimeError(f"listing answered {status}")
    return [entry["envelope_id"] for entry in json.loads(body)["envelopes"]]


def start_relay(label: str) -> None:
    log = (RELAY_DIR / "relay.log").open("ab")
    PROCESSES["relay"] = subprocess.Popen(ns_argv("relay", RELAY_ARGV, "tos-service-packet-relay"),
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    up = fd.poll(relay_up, 30, 0.5)
    fd.require(f"{label}: the relay daemon serves TLS on {RELAY_IP}:{RELAY_PORT} (verified against the run's "
               "certificate authority)", bool(up) and PROCESSES["relay"].poll() is None,
               (RELAY_DIR / "relay.log").read_text()[-600:])


def stop_relay(label: str) -> None:
    process = PROCESSES.pop("relay", None)
    fd.as_node("pkill", "-TERM", "-f", f"^{RELAY_BIN} -listen {RELAY_IP}:{RELAY_PORT}", check=False)
    code = process.wait(timeout=30) if process else None
    down = not relay_up()
    fd.require(f"{label}: the relay daemon stopped on SIGTERM and no longer answers", code == 0 and down,
               {"exit": code, "answers": not down})


def snapshot(name: str) -> dict:
    """A copy of the relay's state directory, taken while it holds envelopes,
    for the plaintext search."""
    target = SNAPSHOTS / name
    shutil.copytree(RELAY_STATE, target, ignore=shutil.ignore_patterns("LOCK", "tmp"))
    files = [path for path in target.rglob("*") if path.is_file()]
    envelopes = [path for path in files if "envelopes" in path.parts]
    return {"files": len(files), "envelope_files": len(envelopes), "envelope_bytes": sum(p.stat().st_size for p in envelopes)}


# --- Isolation probes ----------------------------------------------------------

LISTEN = ("import socket,sys\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
          "s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(); print('listening', flush=True)\n"
          "while True:\n    c, _ = s.accept(); c.close()\n")
CONNECT = ("import socket,sys\ntry:\n    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()\n"
           "    print('connected')\nexcept OSError as e:\n    print('refused or unreachable: ' + type(e).__name__)\n")
LIST_HIDDEN = ("import os,sys\nfor p in sys.argv[1:]:\n    print(p + ': ' + (repr(sorted(os.listdir(p))) "
               "if os.path.isdir(p) else 'absent'))\n")


def probe(name: str, host: str, port: int) -> str:
    result = fd.run_logged(ns_argv(name, [SYSTEM_PYTHON, "-I", "-c", CONNECT, host, port], "connection probe"),
                           env=dict(os.environ), timeout=30)
    return result.stdout.strip()


def isolation() -> None:
    listeners = {node: spawn(node, ns_argv(node, [SYSTEM_PYTHON, "-I", "-c", LISTEN, ADDRESS[node], 47000],
                                           "probe listener"), f"probe-listener-{node}.log") for node in fd.NODES}
    listening = all(wait_line(f"probe-listener-{node}.log", "listening") for node in fd.NODES)
    before = {"buyer to provider": probe("buyer", ADDRESS["provider"], 47000),
              "provider to buyer": probe("provider", ADDRESS["buyer"], 47000)}
    netsh("firewall")
    after = {"buyer to provider": probe("buyer", ADDRESS["provider"], 47000),
             "provider to buyer": probe("provider", ADDRESS["buyer"], 47000),
             "provider to its own listener": probe("provider", ADDRESS["provider"], 47000),
             "buyer to the relay": None, "provider to the relay": None,
             "buyer to host ssh 10.231.77.1:22": probe("buyer", HOST_IP, 22),
             "relay to the chain forwarder 10.231.77.1:%d" % fd.RPC_PORTS[0]: probe("relay", HOST_IP, fd.RPC_PORTS[0]),
             "buyer to an internet address 1.1.1.1:443": probe("buyer", "1.1.1.1", 443)}
    for process in listeners.values():
        process.terminate()
    fd.as_node("pkill", "-TERM", "-f", "^" + SYSTEM_PYTHON + " -I -c import socket,sys", check=False)
    evidence = {"before_rules": before, "after_rules": after, "listeners_started": listening}
    fd.evidence["isolation_probe"] = evidence
    fd.require("isolation: before the rules each node reaches a listener in the other node's namespace; after them "
               "buyer to provider and provider to buyer are dropped in both directions, while the provider still "
               "reaches its own listener", listening and all(v == "connected" for v in before.values()) and
               after["buyer to provider"].startswith("refused") and after["provider to buyer"].startswith("refused") and
               after["provider to its own listener"] == "connected", evidence)
    fd.require("isolation: a node reaches neither other host services nor the internet, and the relay cannot reach "
               "the chain", all(value.startswith("refused") for key, value in after.items()
                                if value is not None and key.startswith(("buyer to host", "relay to", "buyer to an"))),
               after)


def relay_reachability() -> None:
    reached = {f"{node} to the relay": probe(node, RELAY_IP, RELAY_PORT) for node in fd.NODES}
    fd.evidence["isolation_probe"]["after_rules"].update(reached)
    fd.require("each node reaches the relay's TLS port", all(value == "connected" for value in reached.values()), reached)


def hidden_files() -> None:
    seen = {}
    for node in fd.NODES:
        paths = [str(path) for path in HIDE[node]]
        result = fd.run_logged(ns_argv(node, [SYSTEM_PYTHON, "-I", "-c", LIST_HIDDEN, *paths], "file visibility probe"),
                               env=dict(os.environ), timeout=30)
        seen[node] = result.stdout.strip().splitlines()
    fd.evidence["file_isolation"] = seen
    fd.require("each node sees the other node's directory, the run's private files and the relay's state as empty",
               all(line.endswith(": []") for lines in seen.values() for line in lines) and
               all(len(seen[node]) == len(HIDE[node]) for node in fd.NODES), seen)


def tls_negative_control() -> None:
    env = fd.node_env("provider")
    env["SSL_CERT_FILE"] = str(WRONG_CA)
    result = fox("provider", "preflight", "--rail-config", fd.rail("provider"), check=False, env=env)
    checks = {check["id"]: check for check in json.loads(result.stdout).get("checks", [])} if result.stdout else {}
    reach = checks.get("relay.reachable", {})
    fd.evidence["tls_negative_control"] = reach
    fd.require("TLS is verified: with an unrelated certificate authority as its only trust root, the provider's "
               "preflight cannot reach the relay", result.returncode != 0 and reach.get("status") == "fail", reach)


# --- The sale with two relay outages ----------------------------------------

def outbox(node: str) -> list[dict]:
    directory = ROOT / node / "state" / "relay" / "outbox"
    if not directory.is_dir():
        return []
    return [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]


def to(node: str, other: str) -> list[dict]:
    agent = fd.RUN["provider_agent"] if other == "provider" else fd.RUN["buyer_agent"]
    return [record for record in outbox(node) if record.get("recipient") == agent]


def relay_outages() -> dict:
    provider, buyer = fd.RUN["provider_agent"], fd.RUN["buyer_agent"]
    fd.stop_serve("provider")
    fd.record("the provider node is stopped before the purchase, so only the relay can hold the task", True)
    purchase = fd.buy("first purchase")
    tasks = fd.poll(lambda: (lambda rows: rows if rows and all(RELAY_URL in row.get("accepted", []) for row in rows)
                             else None)(to("buyer", "provider")), 300, 2) or []
    task_ids = sorted(row["envelope_id"] for row in tasks)
    held = listing(provider) if tasks else []
    fd.require("the buyer's task was sealed to the provider's card and durably accepted by the relay, which lists it "
               "in the provider's mailbox", bool(task_ids) and set(task_ids) <= set(held),
               {"journaled": task_ids, "listed": held})

    stop_relay("outage 1, task held")
    held_snapshot = snapshot("task-held")
    start_serve("provider")
    failing = fd.poll(lambda: (lambda relays: relays if relays and relays[0].get("consecutive_failures", 0) >= 1
                               else None)(((fd.provider_status().get("relay") or {}).get("poller") or {})
                                          .get("relays") or []), 180, 5)
    calls_down = fd.actor_facts(fd.RUN["actor"])
    fd.require("outage 1: the provider runs and its relay polls fail; nothing is admitted, executed or responded",
               bool(failing) and len(calls_down["responds"]) == 0 and fd.executions() == [],
               {"poller": failing, "responds": len(calls_down["responds"]), "executions": fd.executions()})
    start_relay("outage 1, restart on the same state directory")
    after_restart = listing(provider)
    fd.require("outage 1: after the restart the relay still lists the task, from its durable store",
               set(task_ids) <= set(after_restart), {"task": task_ids, "listed": after_restart})

    # The provider acknowledges the task only after its durable inbox
    # write; the relay goes down right then, before any result exists.
    acked = fd.poll(lambda: not (set(task_ids) & set(listing(provider))), 600, 0.5)
    stop_relay("outage 2, result pending")
    early = {row["envelope_id"] for row in to("provider", "buyer") if row.get("accepted")}
    state = fd.purchase_of(purchase["request_hash"])
    fd.require("outage 2: the relay is stopped as soon as the provider acknowledged the task, before the purchase "
               "completed", bool(acked) and state.get("phase") != "completed",
               {"provider_envelopes_already_accepted": len(early), "phase": state.get("phase")})
    fd.stop_serve("buyer")
    fd.record("the buyer node is stopped during outage 2, so the result waits at the relay once it is accepted", True)
    responded = fd.poll(lambda: len(fd.actor_facts(fd.RUN["actor"])["responds"]) == 1, 900, 5)
    pending = fd.poll(lambda: [row["envelope_id"] for row in to("provider", "buyer")
                               if not row.get("accepted") and RELAY_URL in row.get("relays", [])], 600, 5) or []
    fd.require("outage 2: the provider executed and responded on chain while its result deposits fail and stay "
               "journaled", bool(responded) and bool(pending) and len(fd.executions()) == 1,
               {"responded": bool(responded), "pending_envelopes": pending, "executions": fd.executions()})
    start_relay("outage 2, restart on the same state directory")
    # The courier redelivers the result as a new packet generation (a new
    # envelope); any envelope to the buyer accepted after the restart is it.
    accepted = fd.poll(lambda: [row["envelope_id"] for row in to("provider", "buyer")
                                if RELAY_URL in row.get("accepted", []) and row["envelope_id"] not in early], 1500, 5) or []
    in_mailbox = listing(buyer)
    result_snapshot = snapshot("result-held")
    fd.require("outage 2: once the relay is back the provider's courier deposits the result again and the relay "
               "holds it for the buyer", bool(accepted) and set(accepted) <= set(in_mailbox),
               {"failed_while_down": pending, "accepted_after_restart": accepted, "listed_for_buyer": in_mailbox})
    start_serve("buyer")
    fd.require("buyer serve is running again", bool(fd.poll(lambda: fd.SERVING["buyer"].poll() is None, 10, 1)),
               fd.serve_log("buyer"))
    fd.evidence["relay_outages"] = {"task_envelopes": task_ids, "failed_while_down": pending,
                                    "accepted_after_restart": accepted,
                                    "snapshots": {"task-held": held_snapshot, "result-held": result_snapshot}}
    return purchase


# --- No plaintext at the relay --------------------------------------------------

def public_values() -> list[bytes]:
    """What the relay holds in clear by design: the recipients' Agent ids
    (mailbox keys and envelope headers)."""
    out = []
    for agent in (fd.RUN["provider_agent"], fd.RUN["buyer_agent"]):
        out += [agent.encode(), agent[len("agent_"):].encode(), bytes.fromhex(agent[len("agent_"):])]
    return out


def windows(data: bytes, size: int = 48, step: int = 1024) -> list[bytes]:
    """Distinctive slices of data, so a copy split across envelopes or
    framed is still found; slices of padding and slices that lie inside a
    value the relay holds in clear by design are skipped."""
    public = public_values()
    return [window for window in (data[offset:offset + size] for offset in range(0, max(len(data) - size, 1), step))
            if len(set(window)) > 8 and not any(window in value for value in public)]


def needles() -> dict[str, list[bytes]]:
    from pytosiq_core import Address
    source = (PRIVATE / "source.tar").read_bytes()
    artifact = (ROOT / "buyer" / "state" / "purchases" / fd.RUN["first"]["request_hash"] / "artifact.tar").read_bytes()
    wallet = fd.RUN["wallets"]["buyer"]
    forms = {wallet, wallet.split(":", 1)[1], wallet.split(":", 1)[1].upper()}
    for bounceable in (True, False):
        for url_safe in (True, False):
            try:
                forms.add(Address(wallet).to_str(is_user_friendly=True, is_bounceable=bounceable, is_url_safe=url_safe))
            except TypeError:
                pass
    request = fd.request_of(fd.RUN["first"]["request_hash"])
    package = base64.b64decode(request.get("package_base64", ""))
    if not source or not artifact or not package:
        raise RuntimeError("a searched value is empty")

    def of(data: bytes) -> list[bytes]:
        return [data, base64.b64encode(data), *windows(data)]
    return {"source archive": of(source) + [b"example.test/paidwork", b"func TestWork"],
            "artifact": of(artifact), "buyer wallet address": [form.encode() for form in forms] +
            [bytes.fromhex(wallet.split(":", 1)[1])], "Quote package": of(package)}


def search(paths: list[Path], wanted: dict[str, list[bytes]]) -> tuple[dict, dict]:
    found: dict[str, list[str]] = {}
    scanned = {"files": 0, "bytes": 0}
    for root in paths:
        for path in ([root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())):
            data = path.read_bytes()
            scanned["files"] += 1
            scanned["bytes"] += len(data)
            for kind, items in wanted.items():
                if any(item in data for item in items):
                    found.setdefault(kind, []).append(str(path.relative_to(WORK)))
    return found, scanned


def no_plaintext() -> None:
    wanted = needles()
    control = PRIVATE / "plaintext-control.bin"
    control.write_bytes(b"".join(secrets.token_bytes(64) + items[-1] for items in wanted.values()))
    control_found, _ = search([control], wanted)
    fd.require("the plaintext search finds every searched value in a control file holding one slice of each",
               set(control_found) == set(wanted), sorted(control_found))
    targets = [RELAY_STATE, SNAPSHOTS, RELAY_DIR / "relay.log"]
    found, scanned = search(targets, wanted)
    fd.evidence["plaintext_search"] = {"searched": [str(p.relative_to(WORK)) for p in targets], "scanned": scanned,
                                       "values": {kind: len(items) for kind, items in wanted.items()}, "found": found}
    snapshots = fd.evidence["relay_outages"]["snapshots"]
    fd.require("nothing in clear at the relay: no file it wrote, nor its state while it held the task and while it "
               "held the result, contains the source archive, the artifact, the buyer wallet address or the Quote "
               "package", not found and all(item["envelope_files"] > 0 for item in snapshots.values()),
               {"found": found, "scanned": scanned, "snapshots": snapshots})
    log = (RELAY_DIR / "relay.log").read_text(errors="replace")
    named = [value for value in (fd.RUN["provider_agent"], fd.RUN["buyer_agent"], ADDRESS["buyer"],
                                 ADDRESS["provider"], HOST_IP) if value in log]
    fd.require("the relay log names no Agent and no client address", not named and bool(log), named)


# --- Evidence ---------------------------------------------------------------------

ADVERSARIAL_COVERAGE = {
    "statement": "No live adversarial case was run against the relay in this run. The adversarial cases are covered by "
                 "merged in-repository tests, listed here by name.",
    "ai protocol/pkg/agentpacketrelay": [
        "TestCrossMailboxSquat", "TestPublicIDRace", "TestQuotas", "TestPerClientDepositBound", "TestPer48DepositBound",
        "TestLimitListenerPerClient", "TestLimitListenerPer48", "TestRateLimit", "TestRateLimiterPer48",
        "TestCorpusEnvelopes", "TestDepositStatusCodes", "TestAcknowledge", "TestPathsMethodsAndQueries",
        "TestClientRefusesRedirects", "TestClientStrictList", "TestClientStrictDownloadAndAck", "TestNoBodyEchoed",
        "TestDiskRefusesCorruptOrForeignState", "TestTTLExpiryAndSweep"],
    "ai protocol/pkg/agentpacketseal": [
        "TestParseEnvelopeRefusesEveryFieldOutOfShape", "TestHeaderRewriteForAnotherRecipient",
        "TestAuthenticatedButInvalidContentsAreRefused", "TestRelayVectors"],
    "openfox pkg/servicebridge": [
        "TestAJunkCopyUnderThePublicIDAtAnotherRelayDoesNotSuppressTheGenuineEnvelope",
        "TestTheReferenceRelayRaceOfAJunkCopyDoesNotSuppressTheGenuineEnvelope",
        "TestTamperedForeignAndUnauthorizedEnvelopesAreRefusedAsSpecified",
        "TestAConflictAtEveryRelayResealsUnderAFreshIDAndTheRetrySucceeds",
        "TestAnInboxRefusalOfAnOpenedPacketIsAcknowledged",
        "TestAnEnvelopeForAKeyNotHeldIsLeftToExpireWithoutADownload",
        "TestPeerCardsNamingLoopbackRelaysAreRefusedUnlessThisNodeIsOnLoopback"],
}
KEY_LIFECYCLE_COVERAGE = {
    "statement": "Key expiry and rotation are covered by unit tests only, not by this run.",
    "openfox pkg/servicebridge": [
        "TestKeysRotateAheadOfExpiryAndAreDestroyedAfterTheirRetention",
        "TestMaintenanceDestroysKeysAnotherProcessWroteOnTime",
        "TestJournaledBytesSealedToAnExpiredCardAreResealedToTheCurrentOne",
        "TestJournaledBytesAreNeverResentToARevokedCard", "TestRedundantDepositsStopWhenTheCardIsRevoked",
        "TestAnExpiringBuyerCardIsRefreshedByTheAckAndResultsStillArriveAfterItExpired"],
    "ai protocol/pkg/agentpacketseal": ["TestKeyCardTimeWindow", "TestVerifyKeyCard"],
}


def git(path, *args) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True).stdout.strip()


def stage() -> None:
    """The nodes' private files, as the invoking user, outside the run's
    private directory (which every namespace process sees empty)."""
    if ROOT.exists():
        raise RuntimeError(f"{ROOT} already exists")
    for directory in (ROOT.parent, ROOT, ROOT / "bin", ROOT / "etc", *(ROOT / node for node in fd.NODES)):
        directory.mkdir(mode=0o700)
    fd.install_node(BIN / "openfox", fd.OPENFOX, "0755")
    fd.install_node(fd.TOSCTL, ROOT / "bin" / "tosctl", "0700")
    fd.install_node(WORK / "global.json", ROOT / "etc" / "global.json")
    fd.install_node(fd.REGISTRY_BOC, ROOT / "etc" / "registry-code.boc")
    (PRIVATE / "source.tar").write_bytes(fd.source_archive())
    fd.install_node(PRIVATE / "source.tar", ROOT / "buyer" / "source.tar")
    for node in fd.NODES:
        fd.install_node(PRIVATE / node / "tosctl-config.json", ROOT / node / "tosctl-config.json")
        fd.install_node(PRIVATE / node / "vault.json", ROOT / node / "vault.json")
    binaries = {"openfox": BIN / "openfox", "tosctl": fd.TOSCTL, "tos-service-packet-relay": RELAY_BIN}
    fd.evidence["binaries"] = {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                               for name, path in binaries.items()}
    fd.require("both nodes' files are staged as the invoking user (uid %d), one private directory per node" % UID,
               os.geteuid() != 0 and fd.root_sha256(fd.OPENFOX) == fd.evidence["binaries"]["openfox"]["sha256"],
               fd.as_node("stat", "-c", "%u:%g %a %n", ROOT, ROOT / "provider", ROOT / "buyer").stdout.split("\n"))


def sale() -> None:
    stage()
    start_forwarders()
    isolation()
    hidden_files()
    start_relay("start")
    relay_reachability()
    fd.setup_nodes()
    tls_negative_control()
    # The owner hands the offer file to the buyer, which cannot see the
    # provider's directory.
    handed = ROOT / "buyer" / "offer.json"
    fd.install_node(Path(fd.RUN["offer_path"]), handed)
    fd.RUN["offer_path"] = str(handed)
    configs = {node: fd.root_json(fd.rail(node)) for node in fd.NODES}
    fd.require("relay only: both nodes name the TLS relay and no direct peer or Messenger socket",
               all(c.get("relay_urls") == [RELAY_URL] and not c.get("direct_peers") and not c.get("messenger_socket")
                   for c in configs.values()), {n: c.get("relay_urls") for n, c in configs.items()})
    purchase = relay_outages()
    fd.verify_sale(purchase)
    fd.relay_delivery()


def finish() -> None:
    if set(fd.SERVING) == set(fd.NODES):
        fd.stop_nodes()
    for node in list(fd.SERVING):
        fd.stop_serve(node)
    try:
        if "relay" in PROCESSES:
            stop_relay("end of run")
        if fd.RUN.get("first"):
            no_plaintext()
    except fd.Stop:
        pass
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("the plaintext search ran", False, fd.redact(repr(error)))
    for name, process in list(PROCESSES.items()):
        if process.poll() is None:
            process.terminate()
    try:
        netsh("down")
    except RuntimeError as error:
        fd.record("teardown ran", False, fd.redact(str(error))[-1500:])
    left = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    bridge = subprocess.run(["ip", "link", "show", "tosrly-br0"], capture_output=True, text=True).returncode
    fd.record("teardown: the namespaces, the bridge and the host table are removed",
              "tosrly-" not in left and bridge != 0, left)
    fd.scan_artifacts()


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
    relay_source = Path(os.environ["E2E_RELAY_SOURCE"])
    tree = git(fd.REPO, "status", "--porcelain").splitlines()
    relay_tree = git(relay_source, "status", "--porcelain").splitlines()
    fd.evidence.update({
        "schema": "tos.openfox.service-relay-two-host.local-acceptance.v1",
        "qualifies_as_public_acceptance": False,
        "reason": "one physical host: the two nodes, the relay and the chain are separated by Linux network "
                  "namespaces and firewall rules, not by machines; the relay is operated by the run itself; no "
                  "internet path exists",
        "executor_mode": "executor service socket",
        "carrier": f"Agent Packet Relay daemon at {RELAY_URL}, the only transport of both nodes",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "openfox_commit": git(fd.REPO, "rev-parse", "HEAD"), "openfox_tree_status": tree, "openfox_tree_dirty": bool(tree),
        "relay_daemon": {"ai_commit": git(relay_source, "rev-parse", "HEAD"), "ai_tree_status": relay_tree,
                         "build": "GOWORK=off go build -trimpath ./protocol/cmd/tos-service-packet-relay",
                         "argv": [part.replace(str(WORK), "<workdir>") for part in RELAY_ARGV],
                         "runs_as_uid": UID, "chain_rpc_configured": False, "key_material": "its TLS key only"},
        "tls": {"mode": "direct TLS on the relay's namespace address, with a certificate of a certificate authority "
                        "generated for this run (P-256, SAN IP:%s)" % RELAY_IP,
                "node_trust": "SSL_CERT_FILE names the run's certificate authority only and SSL_CERT_DIR an empty "
                              "directory, so it is the nodes' only trust root; certificate verification stays on. "
                              "OpenFox has no per-relay CA option yet.",
                "plain_http": False},
        "topology": {
            "bridge": "tosrly-br0 10.231.77.0/24, host end 10.231.77.1, no default route in any namespace",
            "namespaces": {NAMESPACE[name]: ADDRESS[name] for name in ADDRESS},
            "chain": f"three validators in the host namespace on 127.0.0.1, JSON-RPC ports {fd.RPC_PORTS}",
            "chain_forwarders": "host namespace 10.231.77.1:<port> to 127.0.0.1:<port>, and in each node namespace "
                                "127.0.0.1:<port> to 10.231.77.1:<port> (service-relay-two-host-forward.py, as uid %d)"
                                % UID,
            "firewall": "node namespaces: outgoing only to %s:%d and 10.231.77.1 JSON-RPC ports, no incoming "
                        "connection; relay namespace: incoming only to port %d, no outgoing connection; host bridge "
                        "table: buyer<->provider dropped both ways" % (RELAY_IP, RELAY_PORT, RELAY_PORT),
            "files": "each namespace process runs with empty read-only tmpfs mounts over the other parties' "
                     "directories and the run's private files; binaries and the chain files are shared read-only"},
        "actor_code_hash": fd.ACTOR_CODE_HASH, "network_label": fd.NETWORK_LABEL,
        "terms": {"price": fd.PRICE, "storage_fee": fd.STORAGE_FEE, "cleanup_bounty": fd.CLEANUP_BOUNTY},
        "adversarial_coverage": ADVERSARIAL_COVERAGE, "key_expiry_and_rotation": KEY_LIFECYCLE_COVERAGE,
        "not_verified": ["two physical machines or an internet path", "a relay operated by a third party",
                         "a second relay in the card",
                         ("live adversarial envelopes, quota pressure and the public-id race (unit tests "
                          "only)"), "key expiry and rotation (unit tests only)",
                         "crash windows of the nodes (kill between inbox write and acknowledgement)"],
        "not_openfox": ["booting the three-validator network (tostester)",
                        "creating, funding and activating the two wallets with tosctl and the zerostate faucet",
                        "the network namespaces, firewall rules, forwarders and the relay daemon",
                        "the container runtime and the root-run executor service in front of it",
                        "this script's own JSON-RPC reads and relay listings, used only to verify"]})
    fd.record("the OpenFox tree is clean at the commit the evidence names", not tree, tree or "clean")
    fd.record("the relay daemon is built from a clean ai tree at the commit the evidence names", not relay_tree,
              relay_tree or "clean")
    try:
        async with Network(Install(fd.BUILD, fd.SOURCE), WORK / "network", base_port=fd.BASE_PORT) as network:
            dht = network.create_dht_node()
            nodes = []
            for _ in range(len(fd.RPC_PORTS)):
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                nodes.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(nodes, fd.RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(nodes, 5, 300)
            client = await nodes[0].toslib_client()
            global_config = json.loads((nodes[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", nodes[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            (WORK / "global.json").write_text(json.dumps(global_config, indent=2))
            zerostate = network.zerostate.as_block()
            fd.evidence["network"] = {"network_id": fd.NETWORK_LABEL,
                                      "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                                      "genesis_file_hash": "sha256:" + zerostate.file_hash.hex(),
                                      "validators": len(nodes), "json_rpc": fd.rpc_endpoints(),
                                      "base_port": fd.BASE_PORT}
            fd.record("every validator serves finalized JSON-RPC", bool(fd.poll(
                lambda: "result" in fd.rpc("getMasterchainInfo"), 180)))
            try:
                fd.RUN["wallets"] = await fd.provision(network.zerostate.main_wallet(client))
                fd.evidence["wallets"] = fd.RUN["wallets"]
                await asyncio.to_thread(sale)
            except fd.Stop:
                pass
            except Exception:  # noqa: BLE001 - the evidence records the failure
                import traceback
                trace = traceback.format_exc().replace(str(fd.REPO), "<repo>").replace(os.path.expanduser("~"), "~")
                fd.record("the sale ran without an exception", False, fd.redact(trace)[-3000:])
            finally:
                await asyncio.to_thread(finish)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("run completed without an exception", False, repr(error))
    log = WORK / "net" / "root-commands.log"
    commands = log.read_text().splitlines() if log.exists() else []
    fd.evidence["ran_as_root"] = {
        "network_setup_and_teardown": sorted({line.replace(str(WORK), "<workdir>") for line in commands}),
        "namespace_entry": LAUNCHED,
        "note": "Only the namespace, firewall and teardown commands and the namespace entry run as root; every node, "
                "relay, forwarder and probe process runs as uid %d (setpriv) and the run itself runs as uid %d."
                % (UID, UID)}
    fd.evidence["steps"] = fd.steps
    fd.evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    leaked = fd.personal_data(json.dumps(fd.redact_value(fd.evidence), default=str))
    fd.record("no home directory path or login name in evidence.json", not leaked, leaked)
    passed = bool(fd.steps) and all(step["pass"] for step in fd.steps)
    fd.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
