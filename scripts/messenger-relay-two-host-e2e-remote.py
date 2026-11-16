#!/usr/bin/env python3
"""Phase 2 of the Messenger relay carriage M-R1 acceptance: the phase-1 run
across machines. Node A and the stranger node C run in network namespaces on
this host; node B runs on another host over SSH; the two relays are installed
systemd units on their own hosts; the chain runs here and reaches B only
through an SSH reverse tunnel to B's loopback.

This module reuses the phase-1 harness (messenger-relay-two-host-e2e.py) and
redirects node B's operations to its host and the relays to their units. The
reusable remote primitives -- the SSH executor, the external relay control
(with a marker so the teardown restarts only the units this run stopped), the
reverse tunnel, and B's direct-path and no-listener probes -- are validated
read-only with MR1_DRYRUN=1 before any destructive live run.

Addresses, SSH targets and key paths are replaced by labels in the transcript
and in the evidence; no key file is read for its contents.
"""

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mr1", HERE / "messenger-relay-two-host-e2e.py")
mr1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr1)
fd = mr1.fd

WORK = mr1.WORK
B_SSH, B_KEY = os.environ["B_SSH"], os.environ["B_SSH_KEY"]
CA = Path(os.environ["E2E_RELAY_CA_FILE"])
B_BASE = Path(os.environ.get("B_REMOTE_BASE", "/opt/tos-relay-test")) / WORK.name
DRYRUN = os.environ.get("MR1_DRYRUN") == "1"
SYSTEM_PYTHON = "/usr/bin/python3"
CONTROL = Path(tempfile.mkdtemp(prefix="mr1r-"))
TLS_CONTEXT = mr1.ssl.create_default_context(cafile=str(CA))


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


def personal_data(text: str) -> list[str]:
    kinds = _personal(text)
    if EMAIL.search(text):
        kinds.append("e-mail address")
    if ".ssh/" in text or any(Path(key).name in text for key in (B_KEY, *(relay.key for relay in RELAYS))):
        kinds.append("SSH key path")
    return kinds


fd.personal_data = personal_data


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
    """The relay's deposit counters, scraped on its host (127.0.0.1 only)."""
    out = on_relay(relay, f"curl -s --max-time 5 http://{relay.metrics}/metrics", check=False).stdout
    counters = {}
    for line in out.splitlines():
        match = re.match(r"packet_relay_requests_total\{route=\"(\w+)\",code=\"(\d+)\"\}\s+(\d+)", line)
        if match:
            counters[f"{match.group(1)}:{match.group(2)}"] = int(match.group(3))
    return counters


def prepare_relay(relay: Relay) -> None:
    state = unit_state(relay)
    uid, up = relay_uid(relay), relay_up(relay)
    remote = on_relay(relay, f"sha256sum {shlex.quote(str(relay.binary))}").stdout.split()[0]
    local = hashlib.sha256((mr1.BIN / "tos-service-packet-relay").read_bytes()).hexdigest()
    relay.since = on_relay(relay, "date +%s").stdout.strip()
    fd.evidence.setdefault("relay_units", {})[relay.name] = {
        "before_run": state, "uid": uid, "binary_on_host": remote, "binary_built_here": local,
        "metrics_before": metrics(relay)}
    fd.require(f"{relay.name}: the installed relay unit is active and enabled, runs as an unprivileged user "
               f"(uid {uid}) and serves TLS at its public URL, verified against the pinned CA; its binary is "
               "byte-identical to the one built here from the named ai commit",
               state.get("ActiveState") == "active" and state.get("UnitFileState") == "enabled" and up and
               uid.isdigit() and int(uid) != 0 and remote == local,
               {"unit": state, "uid": uid, "answers": up, "binary_on_host": remote, "binary_built_here": local})


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
    on_relay(unit, f"systemctl stop {shlex.quote(unit.unit)}", check=False)
    state = on_relay(unit, f"systemctl show -p ActiveState --value {shlex.quote(unit.unit)}", check=False).stdout.strip()
    down = not relay_up(unit)
    fd.require(f"{label_}: {relay}'s unit stopped on SIGTERM and no longer answers",
               state == "inactive" and down, {"active_state": state, "answers": not down})


def start_relay_unit(relay: str, label_: str) -> None:
    unit = RELAY_BY_NAME[relay]
    index = RELAYS.index(unit)
    on_relay(unit, f"systemctl start {shlex.quote(unit.unit)}")
    up = fd.poll(lambda: relay_up(unit), 60, 1)
    unmark_stopped(index)
    fd.require(f"{label_}: {relay}'s unit runs again and serves TLS", bool(up), {"answers": bool(up)})


# --- Node-B operations over SSH ---------------------------------------------------

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


def direct_path() -> None:
    """From B's host nothing opens to this host's public address, on any port;
    both B and this host reach both relays' TLS port."""
    seen = logged(ssh_argv(B_SSH, B_KEY) + ['printf "%s\\n" "${SSH_CLIENT%% *}"'], keep_stdout=False).raw.decode().strip()
    ipaddress.ip_address(seen)
    label(seen, "<a-c-host-public-address>")
    local_addresses = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True).stdout
    behind_nat = re.search(r"\binet6? " + re.escape(seen) + r"/", local_addresses) is None
    connect = ("import socket,sys\nhost=sys.argv[1]\nfor port in sys.argv[2:]:\n    try:\n"
               "        socket.create_connection((host, int(port)), timeout=5).close(); print(port, 'connected')\n"
               "    except OSError as e:\n        print(port, 'refused or unreachable: ' + type(e).__name__)\n")
    ports = ["22", "80", "443", "8443", *map(str, fd.RPC_PORTS), "47000"]
    def parse(text):
        return {line.split(" ", 1)[0]: line.split(" ", 1)[1] for line in text.strip().splitlines() if " " in line}
    probe = parse(on_b(f"{SYSTEM_PYTHON} -I -c {shlex.quote(connect)} {seen} {' '.join(ports)}", timeout=120).stdout)
    to_relay, from_here = {}, {}
    for relay in RELAYS:
        to_relay[relay.name] = parse(on_b(f"{SYSTEM_PYTHON} -I -c {shlex.quote(connect)} {relay.host} "
                                          f"{relay.port}").stdout)
        from_here[relay.name] = parse(subprocess.run([SYSTEM_PYTHON, "-I", "-c", connect, relay.host, str(relay.port)],
                                                     capture_output=True, text=True).stdout)
    fd.evidence["direct_path_probe"] = {"b_to_a_c_host_public_address": probe, "a_c_host_behind_nat": behind_nat,
                                        "b_to_relay": to_relay, "a_c_host_to_relay": from_here}
    fd.require("no direct path: the A/C host is behind NAT (its public address is on no local interface) and from "
               "B's host no TCP connection to that address opens on any probed port",
               behind_nat and len(probe) == len(ports) and all(v.startswith("refused") for v in probe.values()),
               fd.evidence["direct_path_probe"])
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


# --- Dry run: the reusable remote primitives, read-only ---------------------------

def dry_run() -> None:
    fd.evidence.update({
        "schema": "tos.messaging.relay-carriage.acceptance.v1", "milestone": "M-R1", "mode": "remote dry run",
        "qualifies_as_public_acceptance": False,
        "reason": "MR1_DRYRUN: only the non-destructive remote primitives were exercised; no chat was sent, no relay "
                  "unit was stopped, and B wrote nothing persistent. Not an acceptance.",
        "relay_retention": "the relays run with -ttl 1h (test environment); an unacknowledged copy is re-deposited "
                           f"by its sender every {mr1.REDEPOSIT} s (client setting)",
        "started_utc": mr1.datetime.datetime.now(mr1.datetime.timezone.utc).isoformat()})
    machines()
    for relay in RELAYS:
        prepare_relay(relay)
    start_tunnel()
    # Stand up only enough of the chain for the tunnel probe: reuse phase-1's
    # namespace bring-up is not needed here; the dry run checks remote reach.
    direct_path()
    # B wrote nothing; confirm the scratch base is absent or empty of this run.
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
        try:
            dry_run()
        finally:
            tunnel = mr1.PROCESSES.pop("tunnel", None)
            if tunnel is not None:
                tunnel.terminate()
        return 0 if fd.steps and all(step["pass"] for step in fd.steps) else 1
    # The full live scenario (A and C in namespaces here, B over SSH, external
    # relays, the reverse tunnel) is wired by overriding the phase-1 node and
    # relay operations below; it is not run until this is complete and ai #23
    # has merged, so the evidence names ai main.
    raise SystemExit("the full remote scenario is not wired yet; run with MR1_DRYRUN=1 for the remote primitives")


if __name__ == "__main__":
    raise SystemExit(main())
