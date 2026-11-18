#!/usr/bin/env python3
"""Messenger relay carriage milestone M-R2 across machines (remote mode of
scripts/messenger-relay-three-host-rooms-e2e.py): the private-room run with
the room members B and C on two separate remote hosts over SSH, the room's
authority A and the filler joiners D and E in network namespaces on this
host (A behind its NAT, no inbound port), the two installed test relay units
on their own hosts, and the chain here, reaching B and C only through SSH
reverse tunnels to their hosts' loopback.

The run is the M-R2 harness unchanged, with the remote mode of the M-R1 run
(scripts/messenger-relay-two-host-e2e-remote.py) configured for two remote
nodes, B and C, and patched into the SAME M-R1 harness instance the M-R2
harness uses: B's and C's commands run on their own hosts (a vault URL only
on standard input), their long-running processes under a supervisor that
records each pid, and their node files sit at the same absolute path on
every host, staged once (sha256-checked) and mirrored back read-only, so the
M-R2 reads of their journals, chat outboxes, cards and logs read their
state. Owner decisions run on the node's own host (`tos-messenger-owner
sign`, `openfox earning chat ...`), so an owner key is only ever read there;
the run never reads key material. C's crash window pauses C's daemon with
SIGSTOP/SIGCONT through the supervisor's recorded pid, sent only while that
pid still runs a command of the run.

Nothing changes a VPS firewall: the M-R2 steps stop processes rather than
cut connections, so no nft table is created on B's or C's host (the M-R1
cut-off probe is off); their `ufw status verbose` and `nft list ruleset` are
recorded before and verified identical after. Every host change is logged
with its reversal (<workdir>/host-changes.log, in the evidence): the scratch
directory <base>/<run> (0700) on each remote host, each supervised process,
each reverse tunnel. Nothing under /opt/tos-testnet* and no testnet unit is
touched; the relay units are only read (state by a read-only tar, logs,
metrics).

A remote node MAY share a host with a test relay only if it reaches that
relay through the relay's public TLS URL (spec section 8, M-R2). With
C_SHARES_RELAY=relay2, C runs on relay 2's host; the record states it, the
run checks that C's host has relay 2's machine id, that C names only the
relays' public TLS URLs, and that C's host reaches both relays at their
public addresses.

Test-shortened values are recorded (`test_shortened_values`): the relays'
-ttl 1h (MR2_RELAY_TTL must be 3600, and every daemon's
own_relay_max_ttl_seconds is 3600), the re-deposit interval, the descriptor
lifetime, the room part size, handshake retention and authorization
lifetime of a roomtest build, and the room_settings lines the daemons print.

Addresses, SSH targets and key paths appear only as labels (<b-host>,
<c-host> or the relay host label of a shared host, <relay1-host>, ...) in
the transcript and the evidence. The record is <workdir>/evidence.json; it
becomes messenger-relay-rooms-<date>.json when it is copied into the ai
repository.

Run it through scripts/messenger-relay-three-host-rooms-e2e.sh with
MR2_REMOTE=1.
"""

import asyncio
import functools
import hashlib
import importlib.util
import json
import os
import re
import shlex
import time
import threading
import subprocess
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The remote mode's node sets; the M-R1 remote module reads them when it is
# loaded.
os.environ["MR_REMOTE_NODES"] = "b c"
os.environ["MR_LOCAL_NODES"] = "a d e"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mr2 = _load("mr2", HERE / "messenger-relay-three-host-rooms-e2e.py")
mr1 = mr2.mr1
# The M-R1 remote module patches this instance, the one the M-R2 harness uses.
sys.modules["mr1"] = mr1
remote = _load("mr1_remote", HERE / "messenger-relay-two-host-e2e-remote.py")
fd = mr1.fd

WORK, ROOT = mr1.WORK, mr1.ROOT
REMOTE_NODES, LOCAL_NODES = ("b", "c"), ("a", "d", "e")
RELAY_TTL = 3600
SCRATCH_ROOT = "/opt/tos-relay-test"
record, require, poll = fd.record, fd.require, fd.poll
rail, read_json = mr1.rail, mr1.read_json


# --- Host changes of the M-R2 run ------------------------------------------------

class LoggedProcess(remote.RemoteProcess):
    """A supervised process on a remote host, logged as a host change."""

    def __init__(self, node: str, key: str, argv: list, vault: str | None) -> None:
        super().__init__(node, key, argv, vault)
        remote.change(f"{node.upper()} host: started {key} under the run's supervisor inside "
                      f"{remote.REMOTES[node].base}; reversal: stopped by the run, any leftover killed at the end")


def start_tunnel(node: str) -> None:
    _start_tunnel(node)
    remote.change(f"{node.upper()} host: an SSH reverse tunnel listens on its 127.0.0.1 on the chain RPC ports "
                  f"{fd.RPC_PORTS}; reversal: the tunnel ends with the run")


_start_tunnel = remote.start_tunnel


def install_mls_driver() -> None:
    """The OpenMLS driver joins the staged binaries before they are copied
    to the remote hosts."""
    fd.install_node(mr2.MLS_DRIVER, ROOT / "bin" / "tos-openmls-driver", "0755")
    fd.evidence["binaries"]["tos-openmls-driver"] = {
        "sha256": hashlib.sha256(mr2.MLS_DRIVER.read_bytes()).hexdigest()}


# --- M-R2 adaptations: files handed to remote nodes, decisions on their host ------

DECISION_DIRS: set[str] = set()


def decision_path(node: str, name: str) -> Path:
    """A remote node's owner decisions are prepared, signed and submitted on
    its own host: its decisions directory is made there."""
    path = _decision_path(node, name)
    if node in remote.REMOTES and node not in DECISION_DIRS:
        remote.on_node(node, f"install -d -m 0700 {shlex.quote(str(path.parent))}")
        DECISION_DIRS.add(node)
    return path


def issue_invite(issuer: str, holder: str, expires_at: int, name: str) -> Path:
    """An invite token handed to a remote holder reaches its host too."""
    handed = _issue_invite(issuer, holder, expires_at, name)
    if holder in remote.REMOTES:
        remote.write_on(holder, handed, (mr2.SECRETS_HANDED[-1] + "\n").encode())
    return handed


def chat_owner_socket() -> None:
    """As M-R2; a remote node's rail configuration is edited from a fresh
    copy and written back to its host, with its mirror held."""
    for node in mr2.NODES:
        if node not in remote.REMOTES:
            config = read_json(rail(node))
            config["chat"]["owner_socket"] = str(mr1.sock(node, "owner.sock"))
            rail(node).write_text(json.dumps(config, indent=2) + "\n")
            rail(node).chmod(0o600)
            continue
        with remote.REMOTES[node].lock:
            remote.sync_node(node)
            config = read_json(rail(node))
            config["chat"]["owner_socket"] = str(mr1.sock(node, "owner.sock"))
            remote.write_on(node, rail(node), (json.dumps(config, indent=2) + "\n").encode())
    fd.evidence["chat_owner_socket"] = "each node's rail configuration names chat.owner_socket, the daemon's " \
                                       "owner_socket_path"


def state_view(node: str) -> dict:
    if node in remote.REMOTES:
        remote.sync_node(node)
    return _state_view(node)


def room_settings_check() -> None:
    _room_settings_check()
    fd.evidence["room_settings"]["note"] = "the relays are the installed test relays (-ttl 1h); the room test " \
                                           "settings are accepted only by a roomtest build"


def states_counters_sizes_search_step(step):
    """The M-R2 search step, after a last copy of both relays' state and
    their logs since the run started (read on the relay hosts)."""
    @functools.wraps(step)
    def wrapped():
        remote.final_relay_reads()
        return step()
    return wrapped


# The longest the teardown of B and C takes, kept clear of a blackout.
TEARDOWN_SECONDS = 900


def finish() -> None:
    # The teardown stops B's and C's processes: like every stop on those
    # hosts it waits out a blackout window (a validator set switch), with
    # the guard still sampling.
    if mr2.BLACKOUTS:
        mr2.wait_outside_blackout("teardown", TEARDOWN_SECONDS)
    GUARD["stop"] = True
    fd.evidence["validator_guard"] = {
        "nodes": list(GUARD_NODES), "unit": GUARD_UNIT, "samples": GUARD["samples"], "tripped": GUARD["tripped"],
        "baseline": GUARD["baseline"], "limits": {"mem_available_min_kb": GUARD_MEM_KB, "head_stall_seconds": GUARD_STALL},
        "rule": "read-only every 30 s: validator unit state, its head (loopback JSON-RPC) and MemAvailable; a trip "
                "stops that member's slice and fails the run"}
    _finish()
    settings = fd.evidence.get("room_settings", {})
    fd.evidence.setdefault("test_shortened_values", {})["room_settings_lines"] = {
        "daemon_check": settings.get("daemon_check_lines"), "daemon_startup": settings.get("daemon_startup_lines")}


# --- Setup ------------------------------------------------------------------------

def go_seconds(text: str) -> float | None:
    """A Go duration ("1h", "60m", "3600s", "1h0m0s") in seconds."""
    if not re.fullmatch(r"(?:\d+(?:\.\d+)?(?:h|ms|m|s))+", text or ""):
        return None
    scale = {"h": 3600, "m": 60, "s": 1, "ms": 0.001}
    return sum(float(value) * scale[unit] for value, unit in re.findall(r"(\d+(?:\.\d+)?)(h|ms|m|s)", text))


def relay_ttl_check() -> None:
    ttls = {name: unit.get("ttl") for name, unit in fd.evidence.get("relay_units", {}).items()}
    seconds = {name: go_seconds(value) for name, value in ttls.items()}
    values = fd.evidence.setdefault("test_shortened_values", {})
    values["relay_unit_ttl"] = ttls
    require(f"the test relays run with -ttl 1h ({ttls}); MR2_RELAY_TTL and every daemon's "
            f"own_relay_max_ttl_seconds are {mr2.RELAY_TTL} s",
            len(seconds) == 2 and all(value == RELAY_TTL for value in seconds.values()) and
            mr2.RELAY_TTL == RELAY_TTL, {"unit_ttl": ttls, "daemon_ttl": mr2.RELAY_TTL})


def shared_host_check() -> None:
    """A remote node on a relay's host names only the relays' public TLS
    URLs and reaches the relays there."""
    for node, item in remote.REMOTES.items():
        if not item.shares_relay:
            continue
        config = read_json(rail(node))
        urls = config.get("relay_urls") or []
        hosts = [urllib.parse.urlsplit(url).hostname or "" for url in urls]
        loopback = [host for host in hosts if host in ("localhost", "::1") or host.startswith("127.")]
        reached = fd.evidence["isolation_probe"]["relay_reachability"]
        facts = fd.evidence["machines"]
        detail = {"shares_host_with": item.shares_relay, "relay_urls": urls,
                  "same_machine_id": facts[f"{node}_host"].get("machine_id_sha256_prefix") ==
                  facts[f"{item.shares_relay}_host"].get("machine_id_sha256_prefix"),
                  "reaches": {relay: reached.get(f"{node} to {relay}") for relay in mr1.RELAYS}}
        fd.evidence.setdefault("shared_hosts", {})[node] = detail
        require(f"{node.upper()} shares {item.shares_relay}'s host and reaches both relays only through their public "
                f"TLS URLs: it names exactly the two public https URLs, none a loopback address, and from its host a "
                f"connection to each relay's public address and TLS port opens",
                urls == mr1.RELAY_URLS and all(url.startswith("https://") for url in urls) and not loopback and
                detail["same_machine_id"] and all(v == "connected" for v in detail["reaches"].values()), detail)


# Non-test files that may differ between the deployed relay's commit and the
# run's ai commit inside the packages the relay binary links, each with why
# the relay server's behaviour is unchanged by it.
RELAY_SERVER_EXPLAINED = {
    "protocol/pkg/agentpacketrelay/client.go": "client-side code paths only (the relay client the nodes use); "
                                               "the server handlers in the same package are unchanged",
}
RELAY_MODULE = "github.com/tosnetwork/ai/"


def relay_packages(tree: Path) -> list[str]:
    """The module-internal packages the relay binary links, as directories."""
    out = subprocess.run(["go", "list", "-deps", "./protocol/cmd/tos-service-packet-relay"], cwd=tree,
                         capture_output=True, text=True, check=True,
                         env={**os.environ, "GOWORK": "off", "GOFLAGS": "-mod=readonly"}).stdout.split()
    return sorted(pkg[len(RELAY_MODULE):] for pkg in out if pkg.startswith(RELAY_MODULE))


def relay_server_proof() -> None:
    """The deployed relays run a build of an older ai commit. Their binary is
    checked byte-identical to one built here from that commit (the relay
    source), and the packages that binary links are shown unchanged in the
    run's ai commit except explained client-only files."""
    relay_tree = Path(os.environ["E2E_RELAY_SOURCE"])
    ai_tree = Path(os.environ["E2E_AI_SOURCE"])
    relay_commit = mr1.git(relay_tree, "rev-parse", "HEAD")
    ai_commit = mr1.git(ai_tree, "rev-parse", "HEAD")
    packages = sorted(set(relay_packages(relay_tree)) | set(relay_packages(ai_tree)))
    stat = mr1.git(ai_tree, "diff", "--stat", relay_commit, ai_commit, "--", *packages)
    changed = mr1.git(ai_tree, "diff", "--name-only", relay_commit, ai_commit, "--", *packages).splitlines()
    cmd_stat = mr1.git(ai_tree, "diff", "--stat", relay_commit, ai_commit, "--", "protocol/cmd/tos-service-packet-relay")
    unexplained = [f for f in changed if not f.endswith("_test.go") and f not in RELAY_SERVER_EXPLAINED]
    fd.evidence["relay_build"] = {
        "relay_build_commit": relay_commit, "run_ai_commit": ai_commit,
        "relay_binary": "built from the relay build commit and checked byte-identical to both deployed relays",
        "nodes_built_from": "the run's ai commit (daemon, owner tool, MLS driver)",
        "linked_module_packages": packages,
        "diff_stat_cmd_dir": cmd_stat or "(empty)",
        "diff_stat_linked_packages": stat or "(empty)", "changed_files": changed,
        "explained_changes": {f: RELAY_SERVER_EXPLAINED[f] for f in changed if f in RELAY_SERVER_EXPLAINED}}
    fd.require("the relay server is unchanged between the deployed relays' commit and the run's ai commit: the "
               "relay command directory has no diff, and every other change in the packages it links is a test "
               "file or an explained client-only file", not cmd_stat and not unexplained,
               {"unexplained": unexplained, "changed": changed})


# --- The validator guard on hosts shared with a testnet validator -----------------
#
# MR2_GUARD_NODES names the members whose host also runs a testnet validator.
# Read-only, before the run and every 30 s: the validator unit's state, its
# masterchain head (its own JSON-RPC on the host's loopback) and the host's
# MemAvailable. If the validator restarts or stops, its head does not advance
# for more than 2 minutes, or MemAvailable drops below 1.5 GB, that member's
# slice is stopped at once and the run fails.

GUARD_NODES = tuple(os.environ.get("MR2_GUARD_NODES", "").split())
GUARD_UNIT = os.environ.get("MR2_GUARD_UNIT", "tos-testnet-validator")
GUARD_RPC = os.environ.get("MR2_GUARD_RPC", "http://127.0.0.1:8081/")
GUARD_MEM_KB = 1536 * 1024
GUARD_STALL = 120
GUARD = {"stop": False, "tripped": None, "samples": 0, "baseline": {}, "last": {}, "thread": None}
GUARD_READ = ("systemctl show -p ActiveState,NRestarts,ExecMainStartTimestampMonotonic {unit}; "
              "grep MemAvailable /proc/meminfo; "
              "curl -s -m 5 -H 'Content-Type: application/json' "
              "-d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMasterchainInfo\",\"params\":{{}}}}' {rpc}")


def guard_read(node: str) -> dict:
    out = remote.on_node(node, GUARD_READ.format(unit=shlex.quote(GUARD_UNIT), rpc=shlex.quote(GUARD_RPC)),
                         check=False, timeout=30).stdout
    state = dict(line.split("=", 1) for line in out.splitlines() if "=" in line and not line.startswith("{"))
    memory = re.search(r"MemAvailable:\s+(\d+)", out)
    head = re.search(r'"seqno":(\d+)', out)
    return {"active": state.get("ActiveState"), "restarts": state.get("NRestarts"),
            "started": state.get("ExecMainStartTimestampMonotonic"),
            "mem_available_kb": int(memory.group(1)) if memory else 0, "head": int(head.group(1)) if head else None,
            "at": mr2.now()}


def guard_problem(node: str, sample: dict) -> str:
    base = GUARD["baseline"][node]
    if sample["active"] != "active" or sample["restarts"] != base["restarts"] or sample["started"] != base["started"]:
        return f"the validator unit changed: {sample['active']}, restarts {sample['restarts']}"
    if sample["mem_available_kb"] < GUARD_MEM_KB:
        return f"MemAvailable fell to {sample['mem_available_kb']} kB"
    last = GUARD["last"].setdefault(node, {"head": sample["head"], "since": sample["at"]})
    if sample["head"] is not None and (last["head"] is None or sample["head"] > last["head"]):
        last.update(head=sample["head"], since=sample["at"])
    elif sample["at"] - last["since"] > GUARD_STALL:
        return f"the validator head stayed at {last['head']} for {sample['at'] - last['since']} s"
    return ""


def guard_trip(node: str, problem: str) -> None:
    GUARD["tripped"] = {"node": node, "problem": problem, "at": mr2.now()}
    unit = remote.contain_slice(node)
    remote.on_node(node, f"systemctl stop {shlex.quote(unit)}", check=False, timeout=60)
    remote.change(f"{node.upper()} host: stopped {unit} (the validator guard tripped: {problem})")
    fd.record(f"the validator guard on {node.upper()}'s host never tripped", False, GUARD["tripped"])


def guard_loop() -> None:
    while not GUARD["stop"] and not GUARD["tripped"]:
        for node in GUARD_NODES:
            try:
                problem = guard_problem(node, guard_read(node))
            except Exception as error:  # noqa: BLE001 - a failed read is retried; three in a row trip
                GUARD.setdefault("read_failures", {}).setdefault(node, []).append(repr(error)[-200:])
                problem = "three guard reads in a row failed" if len(GUARD["read_failures"][node]) >= 3 else ""
            else:
                GUARD.setdefault("read_failures", {})[node] = []
            GUARD["samples"] += 1
            if problem:
                guard_trip(node, problem)
                return
        for _ in range(30):
            if GUARD["stop"]:
                return
            time.sleep(1)


def guard_start() -> None:
    for node in GUARD_NODES:
        sample = guard_read(node)
        GUARD["baseline"][node] = sample
        fd.require(f"{node.upper()}'s host before the run: its validator unit is active, its head readable and "
                   "MemAvailable at least 1.5 GB", sample["active"] == "active" and sample["head"] is not None and
                   sample["mem_available_kb"] >= GUARD_MEM_KB, sample)
    GUARD["thread"] = threading.Thread(target=guard_loop, daemon=True)
    GUARD["thread"].start()


def guarded_poll(predicate, timeout: float, interval: float = 2.0):
    """fd.poll that gives up at once once the validator guard tripped."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if GUARD["tripped"]:
            raise fd.Stop(f"the validator guard tripped: {GUARD['tripped']}")
        try:
            last = predicate()
            if last:
                return last
        except Exception:  # noqa: BLE001 - polled reads retry
            pass
        time.sleep(interval)
    return None


def setup() -> None:
    guard_start()
    relay_server_proof()
    remote.prepare_hosts()
    relay_ttl_check()
    mr1.stage()
    mr2.install_driver_hold()
    mr1.start_forwarders()
    mr1.isolation()
    mr1.hidden_files()
    mr1.relay_reachability()
    mr1.trust_negative_control()
    mr2.init_nodes()
    shared_host_check()
    mr2.chat_owner_socket()
    mr1.domain()
    mr2.identities()
    mr1.write_configs()
    mr2.room_settings_check()
    for node in mr2.NODES:
        mr1.start_signer(node)
        mr1.start_node(node)
    mr2.contacts()
    mr2.start_sampler()
    mr1.hold("setup")


def host_labels() -> dict:
    labels = {"a_d_e_and_chain_host": "this host (no label needed: its address never appears)"}
    for node, item in remote.REMOTES.items():
        labels[f"{node}_host"] = remote.LABELS.get(item.host, "")
    for relay in remote.RELAYS:
        labels[f"{relay.name}_host"] = remote.LABELS.get(relay.host, "")
    return labels


def acceptance() -> None:
    shares = {node: item.shares_relay for node, item in remote.REMOTES.items() if item.shares_relay}
    fd.evidence.update({
        "mode": "remote: three hosts plus the relay hosts",
        "qualifies_as_public_acceptance": False,
        "reason": "the two relays are the core team's test deployment (installed units on two VPS, -ttl 1h) and the "
                  "chain is a three-validator test network the run boots on A's host; B and C run on separate VPSs "
                  "and A is behind its host's NAT, but no third party operates any relay, host or chain",
        "relays": {relay.name: {"url": relay.url, "unit": relay.unit} for relay in remote.RELAYS},
        "host_labels": host_labels(),
        "c_shares_relay": shares.get("c") or None,
        "shared_host_statement": {node: f"{node.upper()} runs on {relay}'s host and reaches both relays only through "
                                        "their public TLS URLs (no loopback address or local socket), so its traffic "
                                        f"counts as cross-host: node and relay share no state ({node.upper()}'s files "
                                        "sit in the run's 0700 scratch directory, the relay's in its unit's state "
                                        "directory)"
                                  for node, relay in shares.items()},
        "topology": {
            "a_d_e_and_chain_host": "node A, the room's authority (tosmr-a, 10.231.78.10), and the filler joiners D "
                                    "(tosmr-d, 10.231.78.13) and E (tosmr-e, 10.231.78.14) in network namespaces on "
                                    "bridge tosmr-br0 (host end 10.231.78.1); each routes through the host, which "
                                    "forwards and masquerades only TCP to the two relays' TLS port (tagged iptables "
                                    "rules, removed at the end); the three validators listen on 127.0.0.1, JSON-RPC "
                                    f"ports {fd.RPC_PORTS}",
            "b_host": "node B, a member, on a separate VPS over SSH",
            "c_host": "node C, a member, on another VPS over SSH" +
                      (f" ({shares['c']}'s host; see shared_host_statement)" if shares.get("c") else ""),
            "remote_nodes": "B's and C's files sit inside one scratch directory per host (<base>/<run>, 0700), "
                            "removed at the end; their processes run as root there under the run's supervisor; the "
                            "chain's JSON-RPC reaches each only through an SSH reverse tunnel bound to its 127.0.0.1",
            "relays": "two installed tos-service-packet-relay units on two VPS, TLS under the pinned test CA; the run "
                      "neither starts nor stops them",
            "firewall": "A, D and E: outgoing only to the relays' TLS port and the forwarder ports, no incoming "
                        "connection, and a host bridge table drops every frame between them; B's and C's host "
                        "firewalls are untouched (the run stops processes rather than cutting connections)",
            "files": "B's and C's node files are at the same absolute path on every host: staged once and mirrored "
                     "back to this host read-only (rsync over SSH), so the harness reads their journals, chat "
                     "outboxes, cards and logs; owner keys and Endpoint keys are never copied back",
            "thermal_guard": "pauses and resumes this host's run and validators; B, C and the relays are not paused"},
        "test_shortened_values": {
            **fd.evidence.get("test_shortened_values", {}),
            "relay_ttl_seconds": mr2.RELAY_TTL, "own_relay_max_ttl_seconds": mr2.RELAY_TTL,
            "redeposit_interval_seconds": mr1.REDEPOSIT, "descriptor_lifetime_seconds": mr1.DESCRIPTOR_LIFETIME,
            "room_part_bytes": mr2.PART_BYTES or "production cut",
            "room_handshake_retention_seconds": mr2.RETENTION or "production (7 days)",
            "room_authorization_seconds": mr2.AUTHORIZATION or "production (24 h)",
            "daemon_build_tags": "roomtest" if mr2.ROOMTEST else "none (production build)"},
        "vps_firewalls": "no rule is added on any VPS: the cut-off probe is off and no step cuts a connection; "
                         "remote_reversal.*_firewall holds the before and after fingerprints"})
    fd.evidence["not_openfox"] = fd.evidence.get("not_openfox", []) + [
        "staging B's and C's node files to their hosts and mirroring them back (rsync over SSH), the supervisor "
        "that runs their processes there, and the SSH reverse tunnels for their chain RPC",
        "the harness's tosctl actions for B and C (the delegations) run on A's host with a copy of each vault: the "
        "wallets were created there before they were staged",
        "the relay units' state, logs and metrics, read on the relay hosts (read-only tar, journalctl, curl to "
        "127.0.0.1)"]
    setup()
    mr2.scenario()


# --- Install -------------------------------------------------------------------------

# The M-R2 module's names bound to M-R1 functions at its import; after the
# remote overrides they must name the overriding functions.
MR2_ALIASES = ("in_ns", "node_env", "now", "mcall", "idem", "frames_of", "inbound_texts", "take", "deliveries",
               "stop_node", "start_node", "stop_daemon", "start_daemon", "stop_serve", "start_serve", "listed_ids",
               "deposit", "craft", "hand_file", "snapshot", "log_text")
_decision_path, _issue_invite, _state_view = mr2.decision_path, mr2.issue_invite, mr2.state_view
_room_settings_check, _finish = mr2.room_settings_check, mr2.finish


def install() -> None:
    remote.CUT_PROBE = False
    remote.STAGE_HOOKS.append(install_mls_driver)
    remote.RemoteProcess = LoggedProcess
    remote.start_tunnel = start_tunnel
    remote.install_overrides()
    for name in MR2_ALIASES:
        setattr(mr2, name, getattr(mr1, name))
    mr2.decision_path, mr2.issue_invite, mr2.state_view = decision_path, issue_invite, state_view
    mr2.chat_owner_socket, mr2.room_settings_check = chat_owner_socket, room_settings_check
    mr2.setup, mr2.acceptance, mr2.finish = setup, acceptance, finish
    if GUARD_NODES:
        fd.poll = mr1.poll = mr2.poll = guarded_poll
    mr2.STEPS[:] = [states_counters_sizes_search_step(step) if step.__name__ == "states_counters_sizes_search" else step
                    for step in mr2.STEPS]


def configuration_problems() -> list[str]:
    problems = []
    if tuple(remote.REMOTES) != REMOTE_NODES or remote.LOCAL_NODES != LOCAL_NODES:
        problems.append("the remote nodes must be B and C, the local ones A, D and E")
    if mr2.RELAY_TTL != RELAY_TTL:
        problems.append(f"MR2_RELAY_TTL must be {RELAY_TTL} (the test relays' -ttl 1h)")
    bases = {str(item.scratch_base) for item in remote.REMOTES.values()}
    if len(bases) != 1:
        problems.append("B_REMOTE_BASE and C_REMOTE_BASE must be the same path: the node files sit at the same "
                        "absolute path on every host")
    for item in remote.REMOTES.values():
        base = str(item.scratch_base)
        if not (base == SCRATCH_ROOT or base.startswith(SCRATCH_ROOT + "/")) or ".." in base:
            problems.append(f"{item.upper}_REMOTE_BASE must be {SCRATCH_ROOT} or below it")
        if item.base.parent != item.scratch_base:
            problems.append(f"the node files must sit at <{item.upper}_REMOTE_BASE>/<run>/<run> (E2E_ROOT_BASE)")
    if remote.REMOTES["b"].shares_relay:
        problems.append("B shares no relay host in this run (only C_SHARES_RELAY is supported)")
    return problems


def main() -> int:
    problems = configuration_problems()
    if problems:
        raise SystemExit("; ".join(problems))
    install()
    return asyncio.run(mr2.main())


if __name__ == "__main__":
    raise SystemExit(main())
