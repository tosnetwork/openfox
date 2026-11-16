#!/usr/bin/env python3
"""Phase 2 of the Messenger relay carriage M-R1 acceptance: the phase-1 run
across machines. Node A and the stranger node C run in network namespaces on
this host and reach the relays through its uplink (NAT, no inbound port);
node B runs on another host over SSH; the two relays are installed systemd
units on their own hosts; the chain runs here and reaches B only through an
SSH reverse tunnel to B's loopback.

This module reuses the phase-1 harness (messenger-relay-two-host-e2e.py) and
redirects node B's operations to its host and the relays to their units. Every
phase-1 check runs unchanged; only where it reads or acts runs differently:

- B's files live at the same absolute path on both hosts (under the scratch
  base), staged to B once (sha256-checked) and mirrored back read-only by
  rsync, so the phase-1 reads of B's journals, cards and logs read B's state;
- B's commands run over SSH (a vault URL only on standard input), and B's
  long-running processes under a small supervisor that records their pid and
  exit code;
- cutting B off from the relays is a reject rule in an nft table of the run's
  own on B's host, removed on every exit path, with B's `ufw status verbose`
  and `nft list ruleset` recorded before and verified identical after;
- relay 1's outage is `systemctl stop`/`start` of its installed unit (a
  marker makes the wrapper restart only a unit this run stopped);
- the crash window that phase 1 opened by pausing the relay daemons is opened
  by silently dropping A's packets to the relays (A's namespace), so A's
  deposit is in flight while its daemon is killed and completes afterwards;
- relay state is copied by a read-only tar on the relay hosts. Envelopes that
  were already stored before the run (other runs' mailboxes) are searched for
  plaintext like everything else but are not counted as this run's.

Addresses, SSH targets and key paths are replaced by labels in the transcript
and in the evidence; no key file is read for its contents.
"""

import asyncio
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mr1", HERE / "messenger-relay-two-host-e2e.py")
mr1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr1)
fd = mr1.fd

WORK, ROOT = mr1.WORK, mr1.ROOT
B_SSH, B_KEY = os.environ["B_SSH"], os.environ["B_SSH_KEY"]
CA = Path(os.environ["E2E_RELAY_CA_FILE"])
SCRATCH_BASE = Path(os.environ.get("B_REMOTE_BASE", "/opt/tos-relay-test"))
# The node files of the run sit at the same absolute path on this host and
# on B: <base>/<run>/<run>. B_BASE holds B's logs, pid files and supervisor.
B_BASE, B_ROOT = ROOT.parent, ROOT
DRYRUN = os.environ.get("MR1_DRYRUN") == "1"
B_TABLE = os.environ.get("MR1_B_TABLE") or "tosmr_" + re.sub(r"[^A-Za-z0-9_]", "_", WORK.name)
if os.environ.get("MR1_NETSH"):
    mr1.NETSH = Path(os.environ["MR1_NETSH"])
SYSTEM_PYTHON = "/usr/bin/python3"
CONTROL = Path(tempfile.mkdtemp(prefix="mr1r-"))
TLS_CONTEXT = mr1.ssl.create_default_context(cafile=str(CA))
LOCAL_NODES = ("a", "c")
CHANGES = WORK / "host-changes.log"


def change(text: str) -> None:
    """One host change (or its reversal), appended to the run's change log."""
    with CHANGES.open("a") as handle:
        handle.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + redact(text) + "\n")


# --- Labels and redaction (addresses, SSH targets, key paths never in clear) ----

LABELS: dict[str, str] = {}


def label(raw: str, name: str) -> None:
    if raw:
        LABELS[raw] = name


class Relay:
    """One external relay unit: its URL, host, SSH target, unit and paths."""

    def __init__(self, name: str, url: str, ssh: str, key: str, unit: str) -> None:
        self.name, self.url, self.ssh, self.key, self.unit = name, url, ssh, key, unit
        parts = urllib.parse.urlsplit(url)
        self.host, self.port = parts.hostname, parts.port or 443
        self.state = Path(os.environ.get("RELAY_STATE_DIR", "/var/lib/private/tos-service-packet-relay"))
        self.binary = Path(os.environ.get("RELAY_BIN", "/usr/local/bin/tos-service-packet-relay"))
        self.metrics = os.environ.get("RELAY_METRICS", "127.0.0.1:9095")
        self.since = ""
        self.preexisting: set[str] = set()


_urls = os.environ["RELAY_URLS"].split()
_sshs = os.environ["RELAY_SSHS"].split()
_keys = os.environ["RELAY_SSH_KEYS"].split()
_units = os.environ.get("RELAY_UNITS", "").split() or ["tos-service-packet-relay"] * len(_urls)
if not len(_urls) == len(_sshs) == len(_keys) == len(_units) == 2:
    raise SystemExit("RELAY_URLS, RELAY_SSHS, RELAY_SSH_KEYS and RELAY_UNITS must each name two relays")
RELAYS = [Relay(f"relay{index + 1}", *spec) for index, spec in enumerate(zip(_urls, _sshs, _keys, _units))]
# The run's relay names map to the real URLs, so the phase-1 code's relay keys
# ("relay1", "relay2") address the external units.
RELAY_BY_NAME = {relay.name: relay for relay in RELAYS}

label(B_SSH, "<b-ssh>")
label(B_KEY, "<ssh-key>")
label(B_SSH.rsplit("@", 1)[-1], "<b-host>")
for _relay in RELAYS:
    label(_relay.ssh, f"<{_relay.name}-ssh>")
    label(_relay.key, "<ssh-key>")
    label(_relay.ssh.rsplit("@", 1)[-1], f"<{_relay.name}-host>")
    label(_relay.host, f"<{_relay.name}-host>")

_redact = fd.redact


def redact(text) -> str:
    text = _redact(text)
    for raw in sorted(LABELS, key=len, reverse=True):
        if raw:
            text = text.replace(raw, LABELS[raw])
    return text


fd.redact = redact
_personal = fd.personal_data
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
# A public anycast resolver address the isolation probe names as "the
# internet"; it identifies nobody.
NOT_PERSONAL_ADDRESSES = {"1.1.1.1"}


def personal_data(text: str) -> list[str]:
    kinds = _personal(text)
    if EMAIL.search(text):
        kinds.append("e-mail address")
    if ".ssh/" in text or any(Path(key).name in text for key in (B_KEY, *(relay.key for relay in RELAYS))):
        kinds.append("SSH key path")
    if any(raw in text for raw in LABELS):
        kinds.append("host address or SSH target")
    for match in IPV4.findall(text):
        try:
            address = ipaddress.ip_address(match)
        except ValueError:
            continue
        if address.is_global and match not in NOT_PERSONAL_ADDRESSES:
            kinds.append("public IP address")
            break
    return kinds


fd.personal_data = personal_data


def scrub(text: str) -> str:
    """A log for the work directory: labels for the run's hosts, and any other
    public address (a relay's other clients) replaced too."""
    def other(match):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return "<address>" if address.is_global and match.group(0) not in NOT_PERSONAL_ADDRESSES else match.group(0)
    return IPV4.sub(other, redact(text))


KEEP_AS_WRITTEN = {"run.log", "run.pgid", "evidence.json", "stopped-units", "iptables-before.txt",
                   "iptables-after.txt"}


def scrub_work_files() -> None:
    for path in sorted([*WORK.glob("*"), *(WORK / "net").glob("*")]):
        if path.is_file() and path.name not in KEEP_AS_WRITTEN:
            text = path.read_text(errors="replace")
            cleaned = scrub(text)
            if cleaned != text:
                path.write_text(cleaned)


_scan_artifacts = fd.scan_artifacts


def scan_artifacts() -> None:
    scrub_work_files()
    _scan_artifacts()


fd.scan_artifacts = scan_artifacts


# --- SSH --------------------------------------------------------------------------

SSH_CONNECT_FAILURE = re.compile(r"^(ssh: connect to host|kex_exchange_identification|Connection timed out during "
                                 r"banner|mux_client_request_session|Control socket connect)", re.MULTILINE)


def ssh_argv(target: str, key: str) -> list[str]:
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=8", "-o", "ControlMaster=auto",
            "-o", f"ControlPath={CONTROL}/%C", "-o", "ControlPersist=120", "-i", key, target, "--"]


def logged(argv: list[str], *, data: bytes | None = None, check: bool = True, timeout: float = 240,
           keep_stdout: bool = True) -> subprocess.CompletedProcess:
    """A remote command whose redacted argv, exit and output go to the
    transcript; standard input is never recorded. A failure to open the SSH
    connection is retried: the command never ran."""
    shown = [redact(str(part)) for part in argv]
    result = None
    err = ""
    for attempt in range(6):
        started = time.time()
        try:
            result = subprocess.run(argv, input=data if data is not None else b"", capture_output=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired:
            with fd.TRANSCRIPT.open("a") as handle:
                handle.write(json.dumps({"argv": shown, "timeout": True}) + "\n")
            raise RuntimeError(f"{' '.join(shown[-6:])} timed out") from None
        err = redact(result.stderr.decode(errors="replace"))
        out = redact(result.stdout.decode(errors="replace")) if keep_stdout else f"<{len(result.stdout)} bytes>"
        with fd.TRANSCRIPT.open("a") as handle:
            handle.write(json.dumps({"argv": shown, "exit": result.returncode,
                                     "seconds": round(time.time() - started, 2),
                                     "stdout": out[-40000:], "stderr": err[-40000:]}) + "\n")
        if result.returncode == 255 and SSH_CONNECT_FAILURE.search(result.stderr.decode(errors="replace")):
            fd.evidence.setdefault("ssh_connection_retries", []).append({"attempt": attempt + 1, "stderr": err[-300:]})
            time.sleep(10)
            continue
        break
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(shown[-8:])[:600]} failed ({result.returncode}): {err[-2000:]}")
    text = subprocess.CompletedProcess(argv, result.returncode,
                                       result.stdout.decode(errors="replace") if keep_stdout else "",
                                       result.stderr.decode(errors="replace"))
    text.raw = result.stdout
    return text


def on_b(script: str, *, data: bytes | None = None, check: bool = True, timeout: float = 240,
         keep_stdout: bool = True) -> subprocess.CompletedProcess:
    return logged(ssh_argv(B_SSH, B_KEY) + [script], data=data, check=check, timeout=timeout, keep_stdout=keep_stdout)


def on_relay(relay: Relay, script: str, *, check: bool = True, timeout: float = 120, keep_stdout: bool = True):
    return logged(ssh_argv(relay.ssh, relay.key) + [script], check=check, timeout=timeout, keep_stdout=keep_stdout)


def rsync_ssh() -> str:
    """The SSH command rsync uses for B (the same connection options)."""
    return shlex.join(ssh_argv(B_SSH, B_KEY)[:-2])


# --- External relay control, with a marker so only stopped units restart ----------

STOPPED_MARKER = WORK / "stopped-units"


def unit_state(relay: Relay) -> dict:
    out = on_relay(relay, "systemctl show -p ActiveState,UnitFileState,User,DynamicUser,"
                          f"ExecMainStartTimestampMonotonic,InactiveEnterTimestampMonotonic,NRestarts "
                          f"{shlex.quote(relay.unit)}", check=False).stdout
    return dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)


def relay_up(relay: Relay) -> bool:
    try:
        with urllib.request.urlopen(relay.url + "/v1/relay", context=TLS_CONTEXT, timeout=5) as response:
            return response.status == 200 and \
                json.loads(response.read()).get("schema") == "tos.service.agent-packet-relay.relay.v1"
    except (OSError, ValueError):
        return False


def relay_uid(relay: Relay) -> str:
    return on_relay(relay, f'ps -o uid= -p "$(systemctl show -p MainPID --value {shlex.quote(relay.unit)})"',
                    check=False).stdout.strip()


def metrics(relay: Relay) -> dict:
    """The relay's request counters, scraped on its host (127.0.0.1 only)."""
    out = on_relay(relay, f"curl -s --max-time 5 http://{relay.metrics}/metrics", check=False).stdout
    counters = {}
    for line in out.splitlines():
        match = re.match(r"packet_relay_requests_total\{route=\"(\w+)\",code=\"(\d+)\"\}\s+(\d+)", line)
        if match:
            counters[f"{match.group(1)}:{match.group(2)}"] = int(match.group(3))
    return counters


def relay_arguments(relay: Relay) -> list[str]:
    """The unit's effective relay command line (systemd's ExecStart)."""
    out = on_relay(relay, f"systemctl show -p ExecStart --value {shlex.quote(relay.unit)}", check=False).stdout
    match = re.search(r"argv\[\]=([^;]*)", out)
    return match.group(1).split() if match else []


def stored_envelopes(relay: Relay) -> set[str]:
    out = on_relay(relay, f"cd {shlex.quote(str(relay.state))} && find envelopes -type f 2> /dev/null; true").stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def prepare_relay(relay: Relay) -> None:
    state = unit_state(relay)
    uid, up = relay_uid(relay), relay_up(relay)
    remote = on_relay(relay, f"sha256sum {shlex.quote(str(relay.binary))}").stdout.split()[0]
    local = hashlib.sha256((mr1.BIN / "tos-service-packet-relay").read_bytes()).hexdigest()
    relay.since = on_relay(relay, "date +%s").stdout.strip()
    relay.preexisting = stored_envelopes(relay)
    arguments = relay_arguments(relay)
    ttl = arguments[arguments.index("-ttl") + 1] if "-ttl" in arguments[:-1] else "default"
    fd.evidence.setdefault("relay_units", {})[relay.name] = {
        "url": relay.url, "unit": relay.unit, "before_run": state, "uid": uid, "binary_on_host": remote,
        "binary_built_here": local, "arguments": arguments, "ttl": ttl,
        "envelopes_stored_before_the_run": len(relay.preexisting), "metrics_before": metrics(relay)}
    fd.require(f"{relay.name}: the installed relay unit is active and enabled, runs as an unprivileged user "
               f"(uid {uid}) and serves TLS at its public URL, verified against the pinned CA; its binary is "
               "byte-identical to the one built here from the named ai commit",
               state.get("ActiveState") == "active" and state.get("UnitFileState") == "enabled" and up and
               uid.isdigit() and int(uid) != 0 and remote == local,
               {"unit": state, "uid": uid, "answers": up, "binary_on_host": remote, "binary_built_here": local,
                "ttl": ttl})


def mark_stopped(index: int) -> None:
    with STOPPED_MARKER.open("a") as handle:
        handle.write(f"{index}\n")


def unmark_stopped(index: int) -> None:
    if STOPPED_MARKER.exists():
        kept = [line for line in STOPPED_MARKER.read_text().splitlines() if line.strip() != str(index)]
        STOPPED_MARKER.write_text("".join(line + "\n" for line in kept))


def stop_relay_unit(relay: str, label_: str) -> None:
    unit = RELAY_BY_NAME[relay]
    index = RELAYS.index(unit)
    mark_stopped(index)  # the wrapper's trap restarts only marked units
    change(f"{relay} host: systemctl stop {unit.unit} (the outage); reversal: systemctl start")
    on_relay(unit, f"systemctl stop {shlex.quote(unit.unit)}", check=False)
    state = on_relay(unit, f"systemctl show -p ActiveState --value {shlex.quote(unit.unit)}", check=False).stdout.strip()
    down = not relay_up(unit)
    fd.require(f"{label_}: {relay}'s installed unit stopped on SIGTERM and no longer answers",
               state == "inactive" and down, {"active_state": state, "answers": not down})


def start_relay_unit(relay: str, label_: str) -> None:
    unit = RELAY_BY_NAME[relay]
    index = RELAYS.index(unit)
    on_relay(unit, f"systemctl start {shlex.quote(unit.unit)}")
    up = fd.poll(lambda: relay_up(unit), 60, 1)
    state = on_relay(unit, f"systemctl show -p ActiveState --value {shlex.quote(unit.unit)}", check=False).stdout.strip()
    if up and state == "active":
        unmark_stopped(index)
        change(f"{relay} host: systemctl start {unit.unit} (reversed the outage)")
    fd.require(f"{label_}: {relay}'s unit runs again and serves TLS", bool(up) and state == "active",
               {"answers": bool(up), "active_state": state})


# --- Host facts, the direct-path probe, the tunnel --------------------------------

def host_facts(run) -> dict:
    script = ("printf '%s\\n' \"$(sha256sum /etc/machine-id | cut -c1-16)\" \"$(nproc)\" \"$(uname -r)\" "
              "\"$(. /etc/os-release; echo $PRETTY_NAME)\"")
    lines = run(script).stdout.strip().splitlines()
    return dict(zip(("machine_id_sha256_prefix", "vcpus", "kernel", "os"), lines))


def machines() -> None:
    facts = {"a_c_and_chain_host": host_facts(lambda s: subprocess.run(["sh", "-c", s], capture_output=True,
                                                                       text=True)),
             "b_host": host_facts(lambda s: logged(ssh_argv(B_SSH, B_KEY) + [s]))}
    for relay in RELAYS:
        facts[f"{relay.name}_host"] = host_facts(lambda s, relay=relay: on_relay(relay, s))
    fd.evidence["machines"] = facts
    ids = {item.get("machine_id_sha256_prefix") for item in facts.values()}
    fd.require("four different machines: the A/C and chain host, B's host and the two relay hosts have distinct "
               "machine ids", len(ids) == len(facts) == 4 and all(ids), facts)


def _parse_connect(text):
    return {line.split(" ", 1)[0]: line.split(" ", 1)[1] for line in text.strip().splitlines() if " " in line}


CONNECT = ("import socket,sys\nhost=sys.argv[1]\nfor port in sys.argv[2:]:\n    try:\n"
           "        socket.create_connection((host, int(port)), timeout=5).close(); print(port, 'connected')\n"
           "    except OSError as e:\n        print(port, 'refused or unreachable: ' + type(e).__name__)\n")


def b_connect(host: str, ports: list) -> dict:
    return _parse_connect(on_b(f"{SYSTEM_PYTHON} -I -c {shlex.quote(CONNECT)} {shlex.quote(host)} "
                               f"{' '.join(map(str, ports))}").stdout)


def seen_address() -> str:
    """This host's public address as B sees it (SSH_CLIENT)."""
    seen = logged(ssh_argv(B_SSH, B_KEY) + ['printf "%s\\n" "${SSH_CLIENT%% *}"'],
                  keep_stdout=False).raw.decode().strip()
    ipaddress.ip_address(seen)
    label(seen, "<a-c-host-public-address>")
    return seen


def direct_path() -> None:
    """No direct path between the nodes: A and C sit in private namespaces on
    this host (no inbound, nothing forwarded to them), and B is a separate
    host. The probe is between the nodes, not between the hosts -- this host's
    own sshd is not part of it. From B, a connection to A's namespace address
    and to this host's public address on the ports a node would use (the relay
    TLS port, the chain RPC ports and the probe port) must all fail; and A, in
    its namespace, cannot reach B's public address on those ports, nor B's
    open SSH port. Both this host and B still reach both relays' TLS port."""
    seen = seen_address()
    local_addresses = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True).stdout
    behind_nat = re.search(rf"inet {re.escape(seen)}/", local_addresses) is None
    b_host = B_SSH.rsplit("@", 1)[-1]
    node_ports = ["8443", *map(str, fd.RPC_PORTS), "47000"]
    b_to_a = b_connect(mr1.ADDRESS["a"], node_ports)
    b_to_host = b_connect(seen, node_ports)
    a_to_b = _parse_connect(mr1.in_ns("a", [SYSTEM_PYTHON, "-I", "-c", CONNECT, b_host, *node_ports, "22"],
                                      "connection probe", timeout=90).stdout)
    b_ssh_open = b_connect("127.0.0.1", ["22"])
    to_relay, from_here = {}, {}
    for relay in RELAYS:
        to_relay[relay.name] = b_connect(relay.host, [relay.port])
        from_here[relay.name] = _parse_connect(subprocess.run([SYSTEM_PYTHON, "-I", "-c", CONNECT, relay.host,
                                                               str(relay.port)], capture_output=True, text=True).stdout)
    fd.evidence["direct_path_probe"] = {"b_to_a_namespace": b_to_a, "b_to_a_c_host_node_ports": b_to_host,
                                        "a_to_b_host_node_ports_and_ssh": a_to_b,
                                        "b_ssh_port_open_on_b_itself": b_ssh_open,
                                        "a_c_host_behind_nat": behind_nat,
                                        "b_to_relay": to_relay, "a_c_host_to_relay": from_here}
    refused = all(v.startswith("refused") for v in (*b_to_a.values(), *b_to_host.values(), *a_to_b.values()))
    mr1.gate("1", "no direct path between the nodes: from B no connection opens to A's namespace address or to this "
             "host's public address on any node port, and from A's namespace no connection opens to B's public "
             "address on any node port, nor to B's SSH port, which is open on B",
             refused and len(b_to_a) == len(b_to_host) == len(node_ports) and len(a_to_b) == len(node_ports) + 1 and
             b_ssh_open.get("22") == "connected", fd.evidence["direct_path_probe"])
    mr1.gate("1", "A is on a host behind NAT with no inbound port: the address B sees for it is none of its own "
             "addresses", behind_nat, {"behind_nat": behind_nat})
    fd.require("both nodes' hosts reach both relays' TLS port over the internet",
               all(to_relay[relay.name].get(str(relay.port)) == "connected" and
                   from_here[relay.name].get(str(relay.port)) == "connected" for relay in RELAYS),
               {"b": to_relay, "a_c": from_here})


def start_tunnel() -> None:
    """The chain's JSON-RPC reaches B only through an SSH reverse tunnel to
    B's 127.0.0.1."""
    listening = on_b("ss -ltnH").stdout
    taken = [port for port in fd.RPC_PORTS if re.search(rf":{port}\s", listening)]
    fd.require("the RPC ports are free on B's host", not taken, taken)
    forwards = [arg for port in fd.RPC_PORTS for arg in ("-R", f"127.0.0.1:{port}:127.0.0.1:{port}")]
    argv = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
            "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=20", "-o",
            "ControlMaster=no", "-o", "ControlPath=none", "-i", B_KEY, *forwards, B_SSH]
    log = (WORK / "tunnel.log").open("ab")
    mr1.PROCESSES["tunnel"] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    fd.evidence["chain_tunnel"] = {"argv": [redact(part) for part in argv]}
    probe = ("import json,sys,urllib.request\nfor port in sys.argv[1:]:\n    body=json.dumps({'jsonrpc':'2.0','id':1,"
             "'method':'getMasterchainInfo','params':{}}).encode()\n    r=urllib.request.Request("
             "f'http://127.0.0.1:{port}/jsonRPC',data=body,headers={'Content-Type':'application/json'})\n"
             "    print(port, 'result' in json.loads(urllib.request.urlopen(r,timeout=10).read()))\n")

    def answered():
        result = on_b(f"{SYSTEM_PYTHON} -I -c {shlex.quote(probe)} {' '.join(map(str, fd.RPC_PORTS))}", check=False)
        return result.returncode == 0 and result.stdout.count("True") == len(fd.RPC_PORTS)
    ok = fd.poll(answered, 60, 3)
    bound = [line.split()[3] for line in on_b("ss -ltnH").stdout.splitlines()
             if any(line.split()[3].endswith(f":{port}") for port in fd.RPC_PORTS)]
    fd.evidence["chain_tunnel"]["listening_on_b_host"] = bound
    fd.require("the chain's JSON-RPC reaches B's host only through the SSH reverse tunnel, bound to its 127.0.0.1",
               bool(ok) and mr1.PROCESSES["tunnel"].poll() is None and bool(bound) and
               all(address.startswith("127.0.0.1:") for address in bound), fd.evidence["chain_tunnel"])


# --- B's firewall: an nft table of the run's own, removed on every exit path -------

def b_firewall_state() -> dict:
    """B's firewall as text: `ufw status verbose` and `nft list ruleset`."""
    return {"ufw": on_b("ufw status verbose", check=False).stdout,
            "nft": on_b("nft list ruleset", check=False).stdout}


def b_block(relay: str) -> None:
    unit = RELAY_BY_NAME[relay]
    table = shlex.quote(B_TABLE)
    script = (f"nft list table inet {table} > /dev/null 2>&1 || {{ nft add table inet {table} && "
              f"nft add chain inet {table} output '{{ type filter hook output priority 0; policy accept; }}'; }} && "
              f"nft insert rule inet {table} output ip daddr {shlex.quote(unit.host)} tcp dport {unit.port} "
              f"reject with tcp reset comment '\"block-{relay}\"'")
    on_b(script)
    change(f"B host: nft table inet {B_TABLE}: reject B's TCP to {relay}'s TLS port; reversal: delete the rule, "
           "and the table at the end")


def b_unblock(relay: str) -> None:
    table = shlex.quote(B_TABLE)
    script = (f"for h in $(nft -a list chain inet {table} output | grep -F 'comment \"block-{relay}\"' | "
              f"grep -o 'handle [0-9]*' | cut -d' ' -f2); do nft delete rule inet {table} output handle $h; done")
    on_b(script)
    change(f"B host: nft table inet {B_TABLE}: removed the rule rejecting B's TCP to {relay}")


def b_remove_table() -> bool:
    out = on_b(f"if nft list table inet {shlex.quote(B_TABLE)} > /dev/null 2>&1; then "
               f"nft delete table inet {shlex.quote(B_TABLE)} && echo removed; fi", check=False).stdout
    if "removed" in out:
        change(f"B host: deleted nft table inet {B_TABLE}")
    return "removed" in out


def b_cut_probe() -> None:
    """Cutting B off from the relays (its own nft table on B's host) refuses
    its connections to both relays, and reconnecting restores them."""
    for relay in mr1.RELAYS:
        b_block(relay)
    cut = {relay.name: b_connect(relay.host, [relay.port]) for relay in RELAYS}
    for relay in mr1.RELAYS:
        b_unblock(relay)
    back = {relay.name: b_connect(relay.host, [relay.port]) for relay in RELAYS}
    detail = {"cut": cut, "reconnected": back}
    fd.evidence["b_cut_probe"] = detail
    fd.require("cutting B off (a reject rule in the run's own nft table on B's host) refuses B's connections to both "
               "relays, and reconnecting restores them",
               all(v.startswith("refused") for item in cut.values() for v in item.values()) and
               all(v == "connected" for item in back.values() for v in item.values()), detail)


# --- Node B over SSH: exec, supervised processes, a read-only state mirror --------

def b_env() -> list[str]:
    """B's commands keep every file they write inside the scratch directory."""
    return ["env", f"HOME={B_BASE}/home", f"TMPDIR={B_BASE}/tmp", f"XDG_CONFIG_HOME={B_BASE}/home/.config",
            f"XDG_CACHE_HOME={B_BASE}/home/.cache", f"XDG_DATA_HOME={B_BASE}/home/.local/share",
            f"XDG_STATE_HOME={B_BASE}/home/.local/state"]


def b_exec(argv: list, *, data: str | None = None, vault: str | None = None, check: bool = True,
           timeout: float = 240):
    """Run one B command on its host. A vault URL, when needed, is read from
    standard input and never put on a command line; a command that also needs
    standard input (the tool's `call`) never needs a vault."""
    remote = shlex.join(b_env() + [str(part) for part in argv])
    if vault:
        script = "IFS= read -r VAULT_URL && export VAULT_URL && exec " + remote + " < /dev/null"
        result = on_b(script, data=(vault + "\n").encode(), check=check, timeout=timeout)
    elif data is not None:
        result = on_b(f"exec {remote}", data=data.encode(), check=check, timeout=timeout)
    else:
        result = on_b(f"exec {remote} < /dev/null", check=check, timeout=timeout)
    sync_b()
    return result


def b_vault() -> str:
    return f"file://{B_ROOT}/b/vault.json?master_key={fd.MASTER_KEYS['b']}"


class RemoteProcess:
    """A supervised long-running process on B, with the Popen methods the
    phase-1 harness uses."""

    def __init__(self, key: str, argv: list, vault: str | None) -> None:
        self.key, self.returncode = key, None
        self.pid_file = f"{B_BASE}/{key}.pid"
        self.exit_file = f"{B_BASE}/{key}.exit"
        command = shlex.join(b_env() + [SYSTEM_PYTHON, "-I", f"{B_BASE}/supervisor.py", f"{B_BASE}/{key}.log",
                                        self.pid_file, self.exit_file, *map(str, argv)])
        clear = f"rm -f {shlex.quote(self.pid_file)} {shlex.quote(self.exit_file)}"
        if vault:
            on_b(f"{clear} && IFS= read -r VAULT_URL && export VAULT_URL && exec {command} < /dev/null",
                 data=(vault + "\n").encode(), timeout=60)
        else:
            on_b(f"{clear} && exec {command} < /dev/null", timeout=60)
        self.pid = fd.poll(lambda: on_b(f"cat {self.pid_file} 2>/dev/null", check=False).stdout.strip() or None, 30, 0.5)
        if not self.pid:
            raise RuntimeError(f"{key} did not start on B's host")

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        answer = on_b(f'if [ -e {self.exit_file} ]; then cat {self.exit_file}; elif kill -0 {self.pid} 2>/dev/null; '
                      'then echo running; else echo gone; fi', check=False).stdout.strip()
        if re.fullmatch(r"-?\d+", answer):
            self.returncode = int(answer)
            return self.returncode
        return None if answer == "running" else -1000

    def wait(self, timeout: float):
        if fd.poll(lambda: self.poll() is not None, timeout, 1) is None:
            raise subprocess.TimeoutExpired(self.key, timeout)
        return self.returncode

    def terminate(self):
        self.signal("TERM")

    def signal(self, name: str):
        if self.pid and re.fullmatch(r"[A-Z]+", name):
            on_b(f"kill -{name} {self.pid} 2>/dev/null; true", check=False)


SUPERVISOR = '''import os, subprocess, sys
log, pid_file, exit_file, *argv = sys.argv[1:]
if os.fork():
    sys.exit(0)
os.setsid()
null = os.open(os.devnull, os.O_RDWR)
for n in (0, 1, 2):
    os.dup2(null, n)
with open(log, "ab") as out:
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=out, cwd="/")
with open(pid_file + ".part", "w") as f:
    f.write(str(child.pid))
os.rename(pid_file + ".part", pid_file)
code = child.wait()
with open(exit_file + ".part", "w") as f:
    f.write(str(code))
os.rename(exit_file + ".part", exit_file)
'''

MIRROR = {"stop": False, "thread": None, "syncs": 0, "failures": 0}
MIRROR_LOCK = threading.Lock()


def sync_b() -> None:
    """Copy B's node directory and B's process logs to the same paths here
    (read-only use): the phase-1 reads of B's journals, cards and logs read
    B's state. Sockets and the Endpoint key are not copied."""
    if not MIRROR["thread"]:
        return
    with MIRROR_LOCK:
        state = subprocess.run(["rsync", "-a", "--delete", "--exclude=/s/", "--exclude=/keys/", "-e", rsync_ssh(),
                                f"{B_SSH}:{B_ROOT}/b/", str(ROOT / "b") + "/"], capture_output=True)
        logs = subprocess.run(["rsync", "-a", "-e", rsync_ssh(), f"{B_SSH}:{B_BASE}/*.log", str(WORK) + "/"],
                              capture_output=True)
        MIRROR["syncs"] += 1
        if state.returncode != 0 or logs.returncode not in (0, 23):
            MIRROR["failures"] += 1


def mirror_loop() -> None:
    while not MIRROR["stop"]:
        sync_b()
        time.sleep(2)


def b_socket(name: str) -> str:
    return str(mr1.sock("b", name))


def push_to_b(*paths: Path) -> None:
    """Copy files or directories of this host to the same path on B."""
    for path in paths:
        subprocess.run(["rsync", "-a", "--no-owner", "--no-group", "-e", rsync_ssh(), str(path),
                        f"{B_SSH}:{path.parent}/"], check=True, capture_output=True, timeout=600)


def tree_digests(lines: str) -> dict:
    return {line.split(None, 1)[1].strip(): line.split(None, 1)[0] for line in lines.splitlines() if line.strip()}


B_STATE: dict = {}


def stage_on_b() -> None:
    """Node B's binaries and files at the same paths on B's host, owner-only
    (root, 0700 directories), every file byte-identical to this host's copy."""
    base = shlex.quote(str(SCRATCH_BASE))
    out = on_b(f"test ! -e {shlex.quote(str(B_BASE))} || {{ echo exists; exit 3; }}; "
               f"if [ -d {base} ]; then echo base-existed; else mkdir -m 0700 {base} && echo base-created; fi; "
               f"install -d -m 0700 {shlex.quote(str(B_BASE))} {shlex.quote(str(B_ROOT))} "
               f"{shlex.quote(str(B_BASE))}/home {shlex.quote(str(B_BASE))}/tmp && "
               f"touch {shlex.quote(str(B_BASE))}/started").stdout
    B_STATE["base_created"] = "base-created" in out
    if B_STATE["base_created"]:
        change(f"B host: created {SCRATCH_BASE} (0700); reversal: rmdir at the end")
    change(f"B host: created {B_BASE} (0700, the run's scratch directory); reversal: remove at the end")
    (B_BASE / "supervisor.py").write_text(SUPERVISOR)
    (B_BASE / "supervisor.py").chmod(0o600)
    push_to_b(B_BASE / "supervisor.py", ROOT / "bin", ROOT / "etc", ROOT / "b")
    find = "find bin etc b -type f -exec sha256sum {} + | sort -k2"
    local = tree_digests(subprocess.run(["sh", "-c", find], cwd=ROOT, capture_output=True, text=True).stdout)
    remote = tree_digests(on_b(f"cd {shlex.quote(str(B_ROOT))} && {find}").stdout)
    modes = on_b(f"stat -c '%u %a %n' {shlex.quote(str(B_BASE))} {shlex.quote(str(B_ROOT))} "
                 f"{shlex.quote(str(B_ROOT / 'b'))} {shlex.quote(str(B_ROOT / 'b' / 'vault.json'))}").stdout.split("\n")
    version = on_b(f"{shlex.quote(str(B_ROOT / 'bin' / 'tosctl'))} --version | head -n 2", check=False)
    tosctl_ok = version.returncode == 0 and fd.evidence["binaries"]["tosctl"]["sha256"] == remote.get("bin/tosctl")
    detail = {"files": len(remote), "identical": local == remote, "modes": [redact(m) for m in modes if m],
              "tosctl_runs_on_b": tosctl_ok, "binaries": {k: v for k, v in remote.items() if k.startswith("bin/")}}
    fd.evidence["b_staging"] = detail
    fd.require("b: node B's binaries and files are staged on B's host at the same paths, owner-only (root, 0700 "
               "directories) inside the run's scratch directory, every file byte-identical (sha256) to this host's "
               "copy, and the pinned tosctl runs there",
               local == remote and bool(remote) and tosctl_ok and
               all(m.split()[0] == "0" and m.split()[1] in ("700", "600") for m in modes if m), detail)
    MIRROR["thread"] = threading.Thread(target=mirror_loop, daemon=True)
    MIRROR["thread"].start()


# --- The phase-1 overrides for node B, the relays and the remote topology ---------

def install_overrides() -> None:
    _in_ns, _fox = mr1.in_ns, mr1.fox
    _start_signer, _start_daemon, _stop_daemon = mr1.start_signer, mr1.start_daemon, mr1.stop_daemon
    _start_serve, _stop_serve, _mcall = mr1.start_serve, mr1.stop_serve, mr1.mcall
    _signal_pattern, _cut_off, _reconnect = mr1.signal_pattern, mr1.cut_off, mr1.reconnect
    _stage, _finish, _relay_search, _relay_sizes = mr1.stage, mr1.finish, mr1.relay_search_and_sizes, \
        mr1.relay_envelope_sizes

    def in_ns(name, argv, label, *, check=True, timeout=240, env=None, data=None):
        if name != "b":
            return _in_ns(name, argv, label, check=check, timeout=timeout, env=env, data=data)
        vault = (env or {}).get("VAULT_URL") if env else None
        result = b_exec(argv, data=data, vault=vault, check=check, timeout=timeout)
        return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)

    def fox(node, *args, check=True, timeout=900):
        if node != "b":
            return _fox(node, *args, check=check, timeout=timeout)
        argv = mr1.fox_argv(*args)
        for attempt in range(8):
            result = b_exec(argv, vault=b_vault(), check=False, timeout=timeout)
            if result.returncode == 0 or not fd.TRANSIENT.search(result.stderr):
                break
            fd.evidence.setdefault("repeated_after_unavailable_chain_read", []).append(
                {"node": node, "command": " ".join(args[:2]), "attempt": attempt + 1,
                 "stderr": redact(result.stderr)[-400:]})
            time.sleep(15)
        if check and result.returncode != 0:
            raise RuntimeError(f"openfox earning {' '.join(args[:2])} on b failed ({result.returncode}): "
                               f"{redact(result.stderr)[-2500:]}")
        return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)

    def fox_json(node, *a, **k):
        return json.loads(fox(node, *a, **k).stdout)

    def start_signer(node):
        if node != "b":
            return _start_signer(node)
        mr1.PROCESSES["signer-b"] = RemoteProcess("signer-b", mr1.signer_argv("b"), None)
        fd.require("b: the test Endpoint signer serves its socket on B's host",
                   fd.poll(lambda: on_b(f"test -S {shlex.quote(b_socket('signer.sock'))} && echo yes",
                                        check=False).stdout.strip() == "yes", 30, 1) is not None,
                   mr1.log_text("signer-b")[-300:])

    def start_daemon(node, label="start"):
        if node != "b":
            return _start_daemon(node, label)
        mr1.PROCESSES["messengerd-b"] = RemoteProcess("messengerd-b", mr1.daemon_argv("b"), None)
        up = fd.poll(lambda: on_b(f"test -S {shlex.quote(b_socket('carrier.sock'))} && test -S "
                                  f"{shlex.quote(b_socket('runtime.sock'))} && test -f "
                                  f"{shlex.quote(str(mr1.mdir('b') / 'export' / 'relay-contact.json'))} && echo y",
                                  check=False).stdout.strip() == "y", 120, 1)
        sync_b()
        mr1.require(f"b ({label}): tos-messengerd on B's host verified its finalized delegation, serves its sockets "
                    "and exported its relay evidence", bool(up) and mr1.PROCESSES["messengerd-b"].poll() is None,
                    mr1.log_text("messengerd-b")[-1500:])

    def stop_daemon(node, sig="TERM"):
        if node != "b":
            return _stop_daemon(node, sig)
        process = mr1.PROCESSES.pop("messengerd-b", None)
        if process is None:
            return None
        process.signal("KILL" if sig == "KILL" else "TERM")
        code = process.wait(60)
        sync_b()
        return code

    def start_serve(node, label="start"):
        if node != "b":
            return _start_serve(node, label)
        mr1.PROCESSES["serve-b"] = RemoteProcess("serve-b", mr1.fox_argv("service", "serve", "--rail-config",
                                                                        mr1.rail("b")), b_vault())
        up = fd.poll(lambda: on_b(f"test -S {shlex.quote(b_socket('chat-carrier.sock'))} && echo y",
                                  check=False).stdout.strip() == "y" and mr1.PROCESSES["serve-b"].poll() is None, 120, 1)
        sync_b()
        mr1.require(f"b ({label}): `openfox earning service serve` runs on B's host and serves carrier.carry",
                    bool(up) and mr1.PROCESSES["serve-b"].poll() is None, mr1.log_text("serve-b")[-1500:])

    def stop_serve(node, sig="TERM"):
        if node != "b":
            return _stop_serve(node, sig)
        process = mr1.PROCESSES.pop("serve-b", None)
        if process is None:
            return None
        process.signal("KILL" if sig == "KILL" else "TERM")
        try:
            code = process.wait(60)
        except subprocess.TimeoutExpired:
            process.signal("QUIT")
            time.sleep(3)
            process.signal("KILL")
            code = process.wait(30)
        sync_b()
        return code

    def mcall(node, request, socket="runtime.sock"):
        if node != "b":
            return _mcall(node, request, socket)
        argv = [ROOT / "bin" / "messenger-relay-e2e-tool", "call", "--socket", mr1.sock("b", socket)]
        result = b_exec(argv, data=json.dumps(request), check=False, timeout=90)
        if result.returncode != 0:
            return {"ok": False, "call_error": redact(result.stderr)[-600:]}
        return json.loads(result.stdout)

    def signal_pattern(pattern, sig):
        """B's processes are signalled on B's host through their handles. The
        relay daemons are not paused: phase 1's relay pause (STOP/CONT) is a
        silent drop (hold/release) of A's packets to that relay."""
        for key, own in (("messengerd-b", mr1.daemon_pattern("b")), ("serve-b", mr1.serve_pattern("b"))):
            if pattern == own:
                process = mr1.PROCESSES.get(key)
                if process is None:
                    return []
                process.signal(sig)
                return [int(process.pid)]
        for relay in mr1.RELAYS:
            if pattern == mr1.relay_pattern(relay):
                if sig == "STOP":
                    mr1.netsh("hold", "a", relay)
                    HELD.append({"relay": relay, "held_at": mr1.now()})
                elif sig == "CONT":
                    mr1.netsh("release", "a", relay)
                    HELD.append({"relay": relay, "released_at": mr1.now()})
                return [0]
        return _signal_pattern(pattern, sig)

    def cut_off(node):
        if node != "b":
            return _cut_off(node)
        for relay in mr1.RELAYS:
            b_block(relay)

    def reconnect(node):
        if node != "b":
            return _reconnect(node)
        for relay in mr1.RELAYS:
            b_unblock(relay)

    def stage():
        _stage()
        # Both nodes pin the relays' CA from the node files, at the same path
        # on both hosts.
        target = ROOT / "etc" / "relay-ca.pem"
        target.write_bytes(CA.read_bytes())
        target.chmod(0o600)
        mr1.CA = target
        stage_on_b()

    def relay_envelope_sizes(snapshot_dir: Path) -> list[int]:
        """This run's stored envelopes in one relay's snapshot: an envelope
        that was already stored before the run is not one of them."""
        relay = RELAY_BY_NAME[snapshot_dir.name]
        return [path.stat().st_size - mr1.RELAY_META_BYTES for path in sorted(snapshot_dir.rglob("*"))
                if path.is_file() and "envelopes" in path.parts and
                path.relative_to(snapshot_dir).as_posix() not in relay.preexisting]

    def relay_search_and_sizes():
        # The live relay state at the end (a last copy) and each relay's log
        # since the run started are searched along with the earlier copies.
        fd.evidence["relay_final_state"] = relay_snapshot("final")
        for relay in RELAYS:
            journal = on_relay(relay, f"journalctl -u {shlex.quote(relay.unit)} --since @{relay.since} -o short-iso "
                                      "--no-pager", check=False, keep_stdout=False).raw.decode(errors="replace")
            (WORK / f"{relay.name}.log").write_text(scrub(journal))
        return _relay_search()

    def finish():
        remote_finish_before()
        try:
            _finish()
        finally:
            remote_finish_after()

    mr1.in_ns, mr1.fox, mr1.mcall, mr1.fox_json = in_ns, fox, mcall, fox_json
    mr1.start_signer, mr1.start_daemon, mr1.stop_daemon = start_signer, start_daemon, stop_daemon
    mr1.start_serve, mr1.stop_serve = start_serve, stop_serve
    mr1.signal_pattern, mr1.cut_off, mr1.reconnect = signal_pattern, cut_off, reconnect
    mr1.stage, mr1.finish = stage, finish
    mr1.relay_envelope_sizes, mr1.relay_search_and_sizes = relay_envelope_sizes, relay_search_and_sizes
    mr1.write_configs, mr1.start_forwarders = write_configs, start_forwarders
    mr1.isolation, mr1.hidden_files, mr1.relay_reachability = isolation, hidden_files, relay_reachability
    mr1.acceptance = acceptance
    # The relays: external URLs and units in place of local namespaces.
    for name in mr1.RELAYS:
        mr1.RELAY_URL[name] = RELAY_BY_NAME[name].url
        mr1.ADDRESS[name] = RELAY_BY_NAME[name].host
    mr1.RELAY_URLS[:] = sorted(mr1.RELAY_URL.values())
    mr1.start_relay, mr1.stop_relay = start_relay_unit, stop_relay_unit
    mr1.snapshot = relay_snapshot
    for node in LOCAL_NODES:
        mr1.HIDE[node] = [mr1.PRIVATE, *(ROOT / other for other in mr1.NODES if other != node)]
    _continue = mr1.continue_wrapper
    mr1.continue_wrapper = lambda key: None if key.endswith("-b") else _continue(key)


HELD: list[dict] = []


def relay_snapshot(name: str) -> dict:
    """Copies of both relays' state directories, taken on their hosts by a
    read-only tar, for the plaintext search. Counts are of this run's
    envelopes; envelopes stored before the run are counted apart."""
    result = {}
    for relay in RELAYS:
        tar = on_relay(relay, f"tar -C {shlex.quote(str(relay.state))} --exclude=./LOCK --exclude=./tmp -cf - .; "
                              "status=$?; [ $status -le 1 ]", keep_stdout=False).raw
        target = mr1.SNAPSHOTS / name / relay.name
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
            archive.extractall(target, filter="data")
        files = [p for p in target.rglob("*") if p.is_file()]
        envelopes = [p for p in files if "envelopes" in p.parts]
        own = [p for p in envelopes if p.relative_to(target).as_posix() not in relay.preexisting]
        result[relay.name] = {"files": len(files), "envelope_files": len(own),
                              "envelope_bytes": sorted(p.stat().st_size for p in own),
                              "envelopes_stored_before_the_run": len(envelopes) - len(own)}
    return result


# --- Remote setup steps replacing the phase-1 namespace ones -----------------------

def start_forwarders() -> None:
    """The chain RPC for A and C (forwarders through the bridge, as in phase
    1), and for B the reverse tunnel."""
    ports = [str(port) for port in fd.RPC_PORTS]
    log = (WORK / "forward-host.log").open("ab")
    mr1.PROCESSES["forward-host"] = subprocess.Popen([SYSTEM_PYTHON, "-I", str(mr1.FORWARD), mr1.HOST_IP, "127.0.0.1",
                                                      *ports], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    ok = mr1.wait_line("forward-host", "ready")
    for node in LOCAL_NODES:
        mr1.spawn(node, f"forward-{node}", [SYSTEM_PYTHON, "-I", mr1.FORWARD, "127.0.0.1", mr1.HOST_IP, *ports],
                  "the chain RPC forwarder")
        ok = mr1.wait_line(f"forward-{node}", "ready") and ok
    fd.require("the chain RPC is forwarded for A and C: host 10.231.78.1 to the validators on 127.0.0.1, and in each "
               "of their namespaces 127.0.0.1 to 10.231.78.1, for the JSON-RPC ports only", ok,
               {key: mr1.log_text(key)[-200:] for key in ("forward-host", *(f"forward-{n}" for n in LOCAL_NODES))})
    start_tunnel()


def isolation() -> None:
    """A and C on this host: no path between their namespaces, none to the
    host's services or the internet; then the cross-host probe."""
    for node in LOCAL_NODES:
        mr1.spawn(node, f"probe-listener-{node}", [SYSTEM_PYTHON, "-I", "-c", mr1.LISTEN, mr1.ADDRESS[node], 47000],
                  "probe listener")
    listening = all(mr1.wait_line(f"probe-listener-{node}", "listening") for node in LOCAL_NODES)
    pairs = [("a", "c"), ("c", "a")]
    before = {f"{x} to {y}": mr1.probe(x, mr1.ADDRESS[y], 47000) for x, y in pairs}
    mr1.netsh("firewall")
    after = {f"{x} to {y}": mr1.probe(x, mr1.ADDRESS[y], 47000) for x, y in pairs}
    after["a to its own listener"] = mr1.probe("a", mr1.ADDRESS["a"], 47000)
    b_host = B_SSH.rsplit("@", 1)[-1]
    others = {"a to host ssh 10.231.78.1:22": mr1.probe("a", mr1.HOST_IP, 22),
              "c to host ssh 10.231.78.1:22": mr1.probe("c", mr1.HOST_IP, 22),
              "a to an internet address 1.1.1.1:443": mr1.probe("a", "1.1.1.1", 443),
              "c to an internet address 1.1.1.1:443": mr1.probe("c", "1.1.1.1", 443),
              "c to B's SSH port": mr1.probe("c", b_host, 22)}
    for node in LOCAL_NODES:
        mr1.PROCESSES.pop(f"probe-listener-{node}").terminate()
    mr1.signal_pattern("^" + SYSTEM_PYTHON + " -I -c import socket,sys", "TERM")
    evidence = {"before_rules": before, "after_rules": after, "other_paths": others, "listeners_started": listening}
    fd.evidence["isolation_probe"] = evidence
    mr1.gate("1", "no direct path on this host: before the rules A and C reach a listener in each other's namespace; "
             "after them every connection between them is dropped both ways, while A still reaches its own listener",
             listening and all(v == "connected" for v in before.values()) and
             all(after[f"{x} to {y}"].startswith("refused") for x, y in pairs) and
             after["a to its own listener"] == "connected", evidence)
    mr1.gate("1", "A and C reach neither this host's services, nor the internet, nor B's host except through the "
             "relays", all(value.startswith("refused") for value in others.values()), others)
    direct_path()


def hidden_files() -> None:
    seen = {}
    for name in LOCAL_NODES:
        paths = [str(path) for path in mr1.HIDE[name]]
        seen[name] = mr1.in_ns(name, [SYSTEM_PYTHON, "-I", "-c", mr1.LIST_HIDDEN, *paths], "file visibility probe",
                               timeout=30).stdout.strip().splitlines()
    fd.evidence["file_isolation"] = seen
    mr1.gate("1", "no shared file or socket: A and C each see the other nodes' directories (B's included, a copy of "
             "B's host's files) and the run's private files as empty; B is another machine",
             all(line.endswith(": []") for lines in seen.values() for line in lines) and
             all(len(seen[name]) == len(mr1.HIDE[name]) for name in seen), seen)


def relay_reachability() -> None:
    reached = {f"{node} to {relay.name}": mr1.probe(node, relay.host, relay.port)
               for node in LOCAL_NODES for relay in RELAYS}
    for relay in RELAYS:
        reached[f"b to {relay.name}"] = b_connect(relay.host, [relay.port]).get(str(relay.port), "")
    fd.evidence["isolation_probe"]["relay_reachability"] = reached
    fd.require("each node reaches both relays' TLS port (A and C through this host's NAT, B from its own host)",
               all(v == "connected" for v in reached.values()), reached)
    b_cut_probe()


def write_configs() -> None:
    """As phase 1; B's two files are written here and copied to B's host
    before its daemon checks them."""
    with MIRROR_LOCK:
        for node in mr1.NODES:
            for name, body in (("config.json", mr1.daemon_config(node)),
                               ("publication.json", mr1.publication_config(node))):
                path = mr1.mdir(node) / name
                path.write_text(json.dumps(body, indent=2) + "\n")
                path.chmod(0o600)
        push_to_b(mr1.mdir("b") / "config.json", mr1.mdir("b") / "publication.json")
    for node in mr1.NODES:
        check = mr1.in_ns(node, [ROOT / "bin" / "tos-messengerd", "-config", mr1.mdir(node) / "config.json",
                                 "-publication-operator-config", mr1.mdir(node) / "publication.json", "-check"],
                          "tos-messengerd -check", check=False, timeout=60)
        fd.require(f"{node}: tos-messengerd accepts its configuration (-check)", check.returncode == 0,
                   (check.stderr + check.stdout)[-1500:])
    fd.evidence["daemon_configuration"] = {
        "transport": "agent-packet-relay", "discovery": "contact-files", "publication": "prekeys, relay-only descriptor",
        "admission": {"a": "allow-list: B", "b": "allow-list: A (C unknown, require-admission)",
                      "c": "allow-list: B"},
        "redeposit_interval_seconds": mr1.REDEPOSIT, "descriptor_max_lifetime_seconds": mr1.DESCRIPTOR_LIFETIME,
        "publish_interval_seconds": mr1.PUBLISH_INTERVAL, "carrier_timeout_seconds": mr1.CHAT_TIMEOUT,
        "note": "the re-deposit interval is the shortest the daemon accepts (a test MAY set 10 min to 20 h, spec 4); "
                "the descriptor lifetime is short so the evidence pull and the descriptor-expired retry run live"}


def setup() -> None:
    B_STATE["firewall_before"] = b_firewall_state()
    (WORK / "net").mkdir(exist_ok=True)
    for name, text in B_STATE["firewall_before"].items():
        (WORK / "net" / f"b-{name}-before.txt").write_text(redact(text))
    machines()
    for relay in RELAYS:
        prepare_relay(relay)
    mr1.stage()
    mr1.start_forwarders()
    mr1.isolation()
    mr1.hidden_files()
    mr1.relay_reachability()
    mr1.trust_negative_control()
    mr1.init_nodes()
    mr1.domain()
    mr1.identities()
    mr1.write_configs()
    for node in mr1.NODES:
        mr1.start_signer(node)
        mr1.start_node(node)
    mr1.contacts()
    mr1.hold("setup")


def acceptance() -> None:
    relays = {relay.name: {"url": relay.url, "unit": relay.unit} for relay in RELAYS}
    fd.evidence.update({
        "mode": "remote: four machines",
        "qualifies_as_public_acceptance": False,
        "reason": "the two relays are the core team's test deployment (installed units on two VPS, -ttl 1h) and the "
                  "chain is a three-validator test network the run boots on the A/C host; B is a separate VPS and A "
                  "is behind that host's NAT, but no third party operates any relay, host or chain",
        "relays": relays,
        "relay_retention": "the relays run with -ttl 1h (test environment; see relay_units.*.arguments); an "
                           f"unacknowledged copy is re-deposited by its sender every {mr1.REDEPOSIT} s (client "
                           "setting)",
        "topology": {
            "a_c_and_chain_host": "node A (tosmr-a, 10.231.78.10) and the stranger C (tosmr-c, 10.231.78.12) in "
                                  "network namespaces on bridge tosmr-br0 (host end 10.231.78.1); each routes through "
                                  "the host, which forwards and masquerades only TCP to the two relays' TLS port "
                                  "(tagged iptables rules, removed at the end); the three validators listen on "
                                  f"127.0.0.1, JSON-RPC ports {fd.RPC_PORTS}",
            "b_host": "node B on a separate VPS over SSH, every file inside one scratch directory removed at the "
                      "end; its processes run as root there (the scratch directory is 0700); the chain's JSON-RPC "
                      "reaches it only through an SSH reverse tunnel bound to its 127.0.0.1",
            "relays": "two installed tos-service-packet-relay units on two further VPS, TLS under the pinned test CA",
            "firewall": "A and C: outgoing only to the relays' TLS port and the forwarder ports, no incoming "
                        "connection, and a host bridge table drops every frame between them; B: its host firewall "
                        "is untouched except for the cut-off rules in an nft table of the run's own",
            "files": "B's node files are at the same absolute path on both hosts: staged to B once and mirrored back "
                     "to this host read-only (rsync over SSH), so the harness reads B's journals, cards and logs",
            "thermal_guard": "pauses and resumes this host's run and validators; B and the relays are not paused"},
        "outage": "relay 1's installed unit is stopped (systemctl stop) for the whole conversation and started again",
        "crash_window_a": "phase 1 opened A's crash window by pausing both relay daemons; here A's packets to both "
                          "relays are silently dropped in A's namespace instead (the relays stay up), so A's deposit "
                          "is in flight while its daemon is killed and completes once the drop is lifted"})
    fd.evidence["not_openfox"] = fd.evidence.get("not_openfox", []) + [
        "staging B's node files to its host and mirroring them back (rsync over SSH), the supervisor that runs B's "
        "processes there, and the SSH reverse tunnel for B's chain RPC",
        "the cut-off rules on B's host (an nft table of the run's own) and relay 1's systemctl stop/start",
        "the harness's tosctl actions for B (the delegation and the Agent revocation) run on the A/C host with a "
        "copy of B's vault: B's wallet was created there before it was staged"]
    setup()
    mr1.scenario()


# --- The end of the run: every remote change reversed and verified ---------------

def remote_finish_before() -> None:
    """B's processes are stopped on B's host before the phase-1 teardown,
    which handles only this host's processes."""
    for key in ("serve-b", "messengerd-b", "signer-b"):
        process = mr1.PROCESSES.pop(key, None)
        if process is None or not isinstance(process, RemoteProcess):
            continue
        try:
            if process.poll() is None:
                process.signal("CONT")
                process.signal("TERM")
                process.wait(60)
        except (subprocess.TimeoutExpired, RuntimeError):
            process.signal("KILL")
            try:
                process.wait(30)
            except (subprocess.TimeoutExpired, RuntimeError) as error:
                fd.record(f"teardown: {key} stopped on B's host", False, redact(str(error))[-300:])
    try:
        sync_b()
    except (OSError, subprocess.SubprocessError):
        pass
    MIRROR["stop"] = True
    if MIRROR["thread"]:
        MIRROR["thread"].join(timeout=30)


def remote_finish_after() -> None:
    try:
        reverse_remote_changes()
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("every remote change is reversed", False, redact(repr(error))[-1500:])
    scrub_work_files()


def reverse_remote_changes() -> None:
    reversal: dict = {}
    # B: nothing of the run left running, its firewall exactly as before, no
    # file written outside the scratch directory, the scratch directory gone.
    if B_STATE.get("firewall_before"):
        left = on_b(f"pgrep -f -- {shlex.quote('^(' + SYSTEM_PYTHON + ' -I )?' + str(B_BASE))} || true",
                    check=False).stdout.split()
        if left:
            on_b(f"kill -KILL {' '.join(left)} 2>/dev/null; true", check=False)
        reversal["b_processes_left_and_killed"] = len(left)
        reversal["b_table_removed_at_end"] = b_remove_table()
        after = b_firewall_state()
        for name, text in after.items():
            (WORK / "net" / f"b-{name}-after.txt").write_text(redact(text))
        before = B_STATE["firewall_before"]
        reversal["b_firewall"] = {name: {"before_sha256": hashlib.sha256(before[name].encode()).hexdigest(),
                                         "after_sha256": hashlib.sha256(after[name].encode()).hexdigest()}
                                  for name in before}
        fd.record("B's host firewall is exactly as before the run: `ufw status verbose` and `nft list ruleset` are "
                  "identical (the run's own nft table removed)",
                  all(before[name] == after[name] for name in before) and
                  B_TABLE not in after["nft"], reversal["b_firewall"])
    if "base_created" in B_STATE:
        outside = on_b(f"find /root /tmp /var/tmp -xdev -mindepth 1 -maxdepth 2 -newer {shlex.quote(str(B_BASE))}/started "
                       "-not -name 'systemd-private-*' -print 2>/dev/null; true", check=False).stdout.split()
        reversal["b_files_written_outside_scratch"] = [redact(p) for p in outside]
        removed = on_b(f"case {shlex.quote(str(B_BASE))} in {shlex.quote(str(SCRATCH_BASE))}/?*) "
                       f"find {shlex.quote(str(B_BASE))} -depth -delete ;; esac; "
                       f"test ! -e {shlex.quote(str(B_BASE))} && echo absent", check=False).stdout.strip()
        if removed.endswith("absent"):
            change(f"B host: removed {B_BASE} (reversed)")
        if B_STATE["base_created"]:
            on_b(f"rmdir {shlex.quote(str(SCRATCH_BASE))} 2>/dev/null; true", check=False)
            change(f"B host: removed {SCRATCH_BASE} (reversed)")
        reversal["b_scratch_absent"] = removed.endswith("absent")
        fd.record("B's host: the run's scratch directory is removed and verified absent, nothing of the run is left "
                  "running, and no file under /root, /tmp or /var/tmp changed during the run",
                  removed.endswith("absent") and not outside, {k: reversal.get(k) for k in (
                      "b_scratch_absent", "b_processes_left_and_killed", "b_files_written_outside_scratch")})
    # Relays: both units active again, none left marked as stopped.
    units = {}
    for relay in RELAYS:
        state = unit_state(relay)
        units[relay.name] = {"active_state": state.get("ActiveState"), "answers": relay_up(relay),
                             "n_restarts": state.get("NRestarts")}
        fd.evidence.setdefault("relay_units", {}).setdefault(relay.name, {})["metrics_after"] = metrics(relay)
        fd.evidence["relay_units"][relay.name]["after_run"] = state
    marked = STOPPED_MARKER.read_text().split() if STOPPED_MARKER.exists() else []
    reversal["relays"] = units
    fd.record("both relay units are active and answer again, and the run left none stopped",
              all(u["active_state"] == "active" and u["answers"] for u in units.values()) and not marked,
              {"units": units, "still_marked_stopped": marked})
    # This host: the forwarding rules are gone (iptables-save identical).
    before_rules, after_rules = WORK / "net" / "iptables-before.txt", WORK / "net" / "iptables-after.txt"
    if before_rules.exists():
        same = after_rules.exists() and before_rules.read_text() == after_rules.read_text()
        reversal["this_host_iptables_identical"] = same
        fd.record("this host's iptables rules are exactly as before the run (the tagged forwarding rules removed)",
                  same, {"identical": same})
    reversal["mirror"] = {"syncs": MIRROR["syncs"], "failed_syncs": MIRROR["failures"]}
    reversal["crash_window_holds"] = HELD
    fd.evidence["remote_reversal"] = reversal
    fd.evidence["host_changes"] = CHANGES.read_text().splitlines() if CHANGES.exists() else []


# --- Dry run: the reusable remote primitives, read-only ---------------------------

def dry_run() -> None:
    fd.evidence.update({
        "schema": "tos.messaging.relay-carriage.acceptance.v1", "milestone": "M-R1", "mode": "remote dry run",
        "qualifies_as_public_acceptance": False,
        "reason": "MR1_DRYRUN: only the non-destructive remote primitives were exercised; no chat was sent, no relay "
                  "unit was stopped, and nothing was written to B. Not an acceptance.",
        "started_utc": mr1.datetime.datetime.now(mr1.datetime.timezone.utc).isoformat()})
    machines()
    for relay in RELAYS:
        prepare_relay(relay)
    seen_address()
    fd.evidence["b_firewall_sha256"] = {name: hashlib.sha256(text.encode()).hexdigest()
                                        for name, text in b_firewall_state().items()}
    fd.evidence["b_reaches_relays"] = {relay.name: b_connect(relay.host, [relay.port]) for relay in RELAYS}
    present = on_b(f"test -e {shlex.quote(str(B_BASE))} && echo present || echo absent", check=False).stdout.strip()
    fd.require("B's scratch directory for this run does not exist after the dry run", present == "absent", present)
    for relay in RELAYS:
        fd.evidence["relay_units"][relay.name]["metrics_after"] = metrics(relay)
    fd.evidence["finished_utc"] = mr1.datetime.datetime.now(mr1.datetime.timezone.utc).isoformat()
    fd.evidence["dev_scripts_executed"] = []
    fd.evidence["steps"] = fd.steps
    fd.evidence["pass_count"] = sum(1 for step in fd.steps if step["pass"])
    passed = bool(fd.steps) and all(step["pass"] for step in fd.steps)
    fd.evidence["result"] = "DRY RUN PASS" if passed else "FAIL"
    text = json.dumps(fd.redact_value(fd.evidence), default=str)
    leaked = fd.personal_data(text)
    fd.record("no home path, login name, address or SSH key path in evidence.json", not leaked, leaked)
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed and not leaked else "FAIL")


def main() -> int:
    if DRYRUN:
        mr1.PRIVATE.mkdir(mode=0o700, exist_ok=True)
        dry_run()
        return 0 if fd.steps and all(step["pass"] for step in fd.steps) else 1
    if B_BASE.parent != SCRATCH_BASE:
        raise SystemExit("the node files must sit at <B_REMOTE_BASE>/<run>/<run> (E2E_ROOT_BASE)")
    install_overrides()
    return asyncio.run(mr1.main())


if __name__ == "__main__":
    raise SystemExit(main())
