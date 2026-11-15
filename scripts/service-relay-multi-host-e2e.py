#!/usr/bin/env python3
"""A paid software-work sale between two OpenFox nodes on different
machines, carried only by a real Agent Packet Relay daemon on a third
machine over the public internet.

Three hosts:

- this host runs the three-validator chain on 127.0.0.1 and the provider
  node; it opens no port to the others;
- the buyer host (BUYER_SSH) runs the buyer node. The chain's JSON-RPC
  ports reach it only through an SSH reverse tunnel from this host to the
  buyer host's 127.0.0.1, because a node takes plain-HTTP RPC endpoints
  only on loopback. Every buyer command runs there over SSH; its vault URL
  reaches it on standard input, never on a command line;
- the relay host (RELAY_SSH) runs tos-service-packet-relay as an
  unprivileged user in a transient systemd unit this run starts and stops,
  serving TLS with a certificate of a private CA.

Both nodes name only the relay (`--relay-url`) and pin its CA
(`--relay-ca-file`); no node names a direct peer or a Messenger socket, and
neither node's environment sets SSL_CERT_FILE or SSL_CERT_DIR. The run shows
that the system trust store does not verify the relay, that the buyer host
cannot open a TCP connection to this host's public address, and that the
provider node listens on no TCP or UDP port.

The sale itself is the front-door run's (service-front-door-e2e.py, loaded
as a module: the same commands, checks and chain reads). One live relay
outage is added: the provider is paused and stopped, the buyer pays and its
task waits at the relay; the provider starts and takes the task, the relay
is stopped while the result is pending (the buyer node is stopped too, so
the result waits at the relay once accepted), the provider is resumed,
executes and responds on chain while its result deposits fail, and the
relay restarts on the same state directory; the result is accepted, the
buyer starts again and the sale completes.

Copies of the relay's state directory taken while it held the task, while it
held the result and after the run, and its journal, are searched for the
source archive, the artifact, the buyer wallet address and the Quote
package: none is found; a control file proves the search finds each.

External relays (RELAY_EXTERNAL=1): instead of a transient unit, the run uses
relays already installed as systemd units, one host each, and both nodes
name all of them (`--relay-url` once per relay). The run checks each unit is
active and enabled and runs the binary built here, stops and starts the units
for its outages, and leaves every unit running. The carrier outage above
stops every relay still up, so no relay of either card can take the result.
With every relay up for the sale, the run also requires that every relay
holds the task and that every envelope either node sent was accepted by every
relay of the recipient's card. With RELAY_DOWN naming one relay, that relay is
stopped before the first purchase and started only after the last sale step:
the run requires that its unit did not run in between, that it accepted none
of the nodes' envelopes, and that the other relays accepted every one.

Public addresses, SSH targets and key paths are replaced by labels in every
transcript and in the evidence; the relay is identified by its TLS public
key hash. No live adversarial case runs here. Run it through
scripts/service-relay-multi-host-e2e.sh.
"""

import asyncio
import base64
import datetime
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("front_door", HERE / "service-front-door-e2e.py")
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)

WORK, PRIVATE, ROOT, BIN = fd.WORK, fd.PRIVATE, fd.ROOT, fd.BIN
UID = os.getuid()
BUYER_SSH, BUYER_KEY = os.environ["BUYER_SSH"], os.environ["BUYER_SSH_KEY"]
CA = Path(os.environ["E2E_RELAY_CA_FILE"])
REMOTE_BASE = Path(os.environ.get("BUYER_REMOTE_BASE", "/opt/tos-relay-test")) / WORK.name
REMOTE_ROOT = REMOTE_BASE / "nodes"
REMOTE_LOG = REMOTE_BASE / "buyer-serve.log"
# External relays (RELAY_EXTERNAL=1): relays already installed as systemd
# units on their hosts, one per URL in RELAY_URLS, reached through RELAY_SSHS
# and RELAY_SSH_KEYS (same order) and named by RELAY_UNITS. This run does not
# install, configure or remove them; its outages stop and start those units,
# and every unit is left running. RELAY_DOWN names one of them ("relay-<n>",
# by position) that stays stopped for the whole sale. Otherwise one relay is
# run as a transient unit this run starts and stops.
EXTERNAL = os.environ.get("RELAY_EXTERNAL") == "1"
if EXTERNAL:
    _urls, _sshs, _keys = (os.environ[name].split() for name in ("RELAY_URLS", "RELAY_SSHS", "RELAY_SSH_KEYS"))
    _units = os.environ.get("RELAY_UNITS", "").split() or ["tos-service-packet-relay"] * len(_urls)
    if not 1 <= len(_urls) <= 4 or not len(_urls) == len(_sshs) == len(_keys) == len(_units):
        raise SystemExit("RELAY_URLS, RELAY_SSHS, RELAY_SSH_KEYS and RELAY_UNITS must name 1 to 4 relays each")
    RELAY_SPECS = [(f"relay-{index + 1}", *spec) for index, spec in enumerate(zip(_urls, _sshs, _keys, _units))]
else:
    RELAY_USER = os.environ["RELAY_RUN_USER"]
    RELAY_SPECS = [("relay", fd.RELAY_URL, os.environ["RELAY_SSH"], os.environ["RELAY_SSH_KEY"],
                    os.environ.get("RELAY_UNIT", "tos-relay-test"))]
if sorted(spec[1] for spec in RELAY_SPECS) != fd.RELAY_URLS:
    raise SystemExit("the relay URLs given to this run and to the nodes differ")
RELAY_DIR = Path(os.environ.get("RELAY_REMOTE_DIR", "/opt/tos-relay-test"))
RELAY_RUN = RELAY_DIR / "runs" / WORK.name
SNAPSHOTS = WORK / "relay-snapshots"


class Relay:
    """One relay of the nodes' cards: its URL, its host and its unit."""

    def __init__(self, name: str, url: str, ssh: str, key: str, unit: str) -> None:
        self.name, self.url, self.ssh, self.key, self.unit = name, url, ssh, key, unit
        parts = urllib.parse.urlsplit(url)
        self.host, self.port = parts.hostname, parts.port or 443
        self.since = ""
        if EXTERNAL:
            self.state = Path(os.environ.get("RELAY_STATE_DIR", "/var/lib/private/tos-service-packet-relay"))
            self.binary = Path(os.environ.get("RELAY_BIN", "/usr/local/bin/tos-service-packet-relay"))
            self.cert_file = Path(os.environ.get("RELAY_CERT_FILE", "/etc/tos-service/packet-relay/tls-cert.pem"))
            self.argv, self.properties = [], []
            return
        self.state = RELAY_RUN / "state"
        self.binary = RELAY_DIR / "bin" / "tos-service-packet-relay"
        self.cert_file = RELAY_DIR / "tls" / "relay-cert.pem"
        credentials = Path("/run/credentials") / f"{unit}.service"
        self.argv = [str(self.binary), "-listen", f"0.0.0.0:{self.port}", "-tls-cert", str(credentials / "tls-cert"),
                     "-tls-key", str(credentials / "tls-key"), "-state-dir", str(self.state),
                     "-global-max-entries", "10000", "-global-max-bytes", "268435456", "-sweep-interval", "10s"]
        # The transient unit: an unprivileged user, the certificate and key
        # handed in as credentials (read by systemd from root-only files),
        # and a read-only file system except the state directory.
        self.properties = ["Type=exec", f"User={RELAY_USER}", f"Group={RELAY_USER}",
                           f"LoadCredential=tls-cert:{self.cert_file}",
                           f"LoadCredential=tls-key:{RELAY_DIR / 'tls' / 'relay-key.pem'}",
                           "NoNewPrivileges=yes", "ProtectSystem=strict", f"ReadWritePaths={self.state}",
                           "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "UMask=0077", "MemoryMax=512M",
                           "Environment=GOMEMLIMIT=384MiB", "TimeoutStopSec=20s"] + (
            ["AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"]
            if self.port < 1024 else ["CapabilityBoundingSet="])

    def tag(self, text: str) -> str:
        """text, prefixed with the relay's name when the cards name several."""
        return text if len(RELAYS) == 1 else f"{self.name}: {text}"


RELAYS = [Relay(*spec) for spec in RELAY_SPECS]
DOWN_NAME = os.environ.get("RELAY_DOWN", "")
DOWN = next((relay for relay in RELAYS if relay.name == DOWN_NAME), None)
if DOWN_NAME and (DOWN is None or not EXTERNAL or len(RELAYS) < 2):
    raise SystemExit("RELAY_DOWN names one of at least two external relays")
LIVE = [relay for relay in RELAYS if relay is not DOWN]
REDUNDANT = len(RELAYS) > 1 and DOWN is None
# SSH connection sharing; a Unix socket path must stay short.
CONTROL = Path(tempfile.mkdtemp(prefix="ofmh-"))
SYSTEM_PYTHON = "/usr/bin/python3"
PROCESSES: dict = {}
TLS_CONTEXT = ssl.create_default_context(cafile=str(CA))
TRANSCRIPT = fd.TRANSCRIPT

# --- Labels for addresses, SSH targets and key paths ------------------------

LABELS: dict[str, str] = {}


def label(raw: str, name: str) -> None:
    if raw:
        LABELS[raw] = name


label(BUYER_SSH, "<buyer-ssh>")
label(BUYER_KEY, "<ssh-key>")
label(BUYER_SSH.rsplit("@", 1)[-1], "<buyer-host>")
for _relay in RELAYS:
    label(_relay.ssh, f"<{_relay.name}-ssh>")
    label(_relay.key, "<ssh-key>")
    label(_relay.ssh.rsplit("@", 1)[-1], f"<{_relay.name}-host>")
    label(_relay.host, f"<{_relay.name}-host>")
_redact = fd.redact


def redact(text) -> str:
    text = _redact(text)
    for raw in sorted(LABELS, key=len, reverse=True):
        text = text.replace(raw, LABELS[raw])
    return text


fd.redact = redact
_personal = fd.personal_data
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def personal_data(text: str) -> list[str]:
    """The front-door kinds, and an e-mail address or an SSH key path."""
    kinds = _personal(text)
    if EMAIL.search(text):
        kinds.append("e-mail address")
    if ".ssh/" in text or any(Path(key).name in text for key in (BUYER_KEY, *(relay.key for relay in RELAYS))):
        kinds.append("SSH key path")
    return kinds


fd.personal_data = personal_data


def raw_addresses(text: str) -> list[str]:
    """Which labelled raw values (public addresses, SSH targets, key paths)
    text still holds."""
    return sorted({LABELS[raw] for raw in LABELS if raw in text})


# --- SSH ------------------------------------------------------------------------

SSH_CONNECT_FAILURE = re.compile(r"^(ssh: connect to host|kex_exchange_identification|Connection timed out during "
                                 r"banner|mux_client_request_session|Control socket connect)", re.MULTILINE)


def ssh_argv(target: str, key: str) -> list[str]:
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=8", "-o", "ControlMaster=auto",
            "-o", f"ControlPath={CONTROL}/%C", "-o", "ControlPersist=300", "-i", key, target, "--"]


def logged(argv: list[str], *, data: bytes | None = None, check: bool = True, timeout: float = 240,
           keep_stdout: bool = True) -> subprocess.CompletedProcess:
    """A command whose redacted argv, exit and output are appended to the
    transcript, as the front-door run_logged does; standard input is never
    recorded. A failure to open an SSH connection is retried: the command
    never ran."""
    shown = [redact(str(part)) for part in argv]
    for attempt in range(6):
        started = time.time()
        try:
            result = subprocess.run(argv, input=data if data is not None else b"", capture_output=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired:
            with TRANSCRIPT.open("a") as handle:
                handle.write(json.dumps({"argv": shown, "timeout": True}) + "\n")
            raise RuntimeError(f"{' '.join(shown[-6:])} timed out") from None
        err = redact(result.stderr.decode(errors="replace"))
        out = redact(result.stdout.decode(errors="replace")) if keep_stdout else f"<{len(result.stdout)} bytes>"
        with TRANSCRIPT.open("a") as handle:
            handle.write(json.dumps({"argv": shown, "exit": result.returncode, "seconds": round(time.time() - started, 2),
                                     "stdout": out[-40000:], "stderr": err[-40000:]}) + "\n")
        if result.returncode == 255 and SSH_CONNECT_FAILURE.search(result.stderr.decode(errors="replace")):
            fd.evidence.setdefault("ssh_connection_retries", []).append({"attempt": attempt + 1, "stderr": err[-300:]})
            time.sleep(10)
            continue
        break
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(shown[-8:])[:600]} failed ({result.returncode}): {err[-2000:]}")
    text = subprocess.CompletedProcess(argv, result.returncode, result.stdout.decode(errors="replace") if keep_stdout
                                       else "", result.stderr.decode(errors="replace"))
    text.raw = result.stdout
    return text


def on_buyer(argv: list, *, data: bytes | None = None, check: bool = True, timeout: float = 240,
             keep_stdout: bool = True) -> subprocess.CompletedProcess:
    return logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [shlex.join(str(part) for part in argv)], data=data, check=check,
                  timeout=timeout, keep_stdout=keep_stdout)


def on_relay(relay: Relay, script: str, *, check: bool = True, timeout: float = 120, keep_stdout: bool = True):
    return logged(ssh_argv(relay.ssh, relay.key) + [script], check=check, timeout=timeout, keep_stdout=keep_stdout)


def remote_path(value) -> str:
    return str(value).replace(str(ROOT), str(REMOTE_ROOT))


def is_buyer(args) -> bool:
    return any(str(ROOT / "buyer") in str(part) for part in args)


def buyer_vault() -> bytes:
    return f"file://{REMOTE_ROOT}/buyer/vault.json?master_key={fd.MASTER_KEYS['buyer']}\n".encode()


def upload(source: Path, target: str, mode: str) -> None:
    q = shlex.quote(target)
    logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [f"umask 077; cat > {q}.part && chmod {mode} {q}.part && mv {q}.part {q}"],
           data=Path(source).read_bytes())


def fetch(path: str) -> bytes:
    return on_buyer(["cat", path], keep_stdout=False).raw


# --- The front-door commands, with the buyer moved to its host -------------

_as_node, _fox, _install_node = fd.as_node, fd.fox, fd.install_node
_start_serve, _stop_serve, _serve_log = fd.start_serve, fd.stop_serve, fd.serve_log


def as_node(*args, env: dict | None = None, check: bool = True, timeout: float = 240):
    if not is_buyer(args):
        return _as_node(*args, env=env, check=check, timeout=timeout)
    return on_buyer([remote_path(part) for part in args], check=check, timeout=timeout)


def fox(node: str, *args: str, check: bool = True, timeout: float = 900):
    if node != "buyer":
        return _fox(node, *args, check=check, timeout=timeout)
    argv = [remote_path(part) for part in fd.fox_argv(*args)]
    script = "IFS= read -r VAULT_URL && export VAULT_URL && exec " + shlex.join(argv) + " < /dev/null"
    return logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [script], data=buyer_vault(), check=check, timeout=timeout)


def install_node(source: Path, target: Path, mode: str = "0600") -> None:
    if is_buyer([target]):
        upload(source, remote_path(target), mode)
    else:
        _install_node(source, target, mode)


# Started on the buyer host by `serve`: it reads the vault URL from its
# standard input, detaches, runs the node with its output in the log and
# records the node's pid and, when it exits, its exit status.
SUPERVISOR = '''import os, subprocess, sys
log, pid_file, exit_file, *argv = sys.argv[1:]
vault = sys.stdin.readline().rstrip("\\n")
if os.fork():
    sys.exit(0)
os.setsid()
null = os.open(os.devnull, os.O_RDWR)
for number in (0, 1, 2):
    os.dup2(null, number)
with open(log, "ab") as out:
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=out, cwd="/",
                             env=dict(os.environ, VAULT_URL=vault))
with open(pid_file + ".part", "w") as handle:
    handle.write(str(child.pid))
os.rename(pid_file + ".part", pid_file)
code = child.wait()
with open(exit_file + ".part", "w") as handle:
    handle.write(str(code))
os.rename(exit_file + ".part", exit_file)
'''


class RemoteServe:
    """The buyer's `serve` on its host, with the Popen methods the
    front-door run uses."""
    count = 0

    def __init__(self) -> None:
        RemoteServe.count += 1
        self.pid_file = str(REMOTE_BASE / f"serve-{RemoteServe.count}.pid")
        self.exit_file = str(REMOTE_BASE / f"serve-{RemoteServe.count}.exit")
        self.code = None
        self.pid = None

    def poll(self):
        if self.code is not None:
            return self.code
        script = (f'if [ -e {self.exit_file} ]; then cat {self.exit_file}; elif kill -0 "$(cat {self.pid_file})" '
                  f'2> /dev/null; then echo running; else echo gone; fi')
        result = logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [script], check=False)
        answer = result.stdout.strip()
        if re.fullmatch(r"-?\d+", answer):
            self.code = int(answer)
            return self.code
        return -1000 if answer == "gone" else None

    def wait(self, timeout: float):
        code = fd.poll(lambda: (lambda value: True if value is not None else None)(self.poll()), timeout, 1)
        if code is None:
            raise subprocess.TimeoutExpired("serve", timeout)
        return self.code

    def signal(self, name: str) -> None:
        if self.pid:
            on_buyer(["kill", f"-{name}", str(self.pid)], check=False)


def start_serve(node: str) -> None:
    if node != "buyer":
        _start_serve(node)
        return
    serve = RemoteServe()
    argv = [remote_path(part) for part in fd.fox_argv("serve", "--rail-config", fd.rail("buyer"))]
    on_buyer([SYSTEM_PYTHON, "-I", str(REMOTE_BASE / "serve-supervisor.py"), str(REMOTE_LOG), serve.pid_file,
              serve.exit_file, *argv], data=buyer_vault(), timeout=60)
    pid = fd.poll(lambda: on_buyer(["cat", serve.pid_file], check=False).stdout.strip() or None, 30, 0.5)
    serve.pid = pid
    fd.SERVING["buyer"] = serve


def stop_serve(node: str):
    if node != "buyer":
        return _stop_serve(node)
    serve = fd.SERVING.pop("buyer", None)
    if serve is None:
        return None
    if serve.poll() is None:
        serve.signal("TERM")
    try:
        code = serve.wait(60)
    except subprocess.TimeoutExpired:
        serve.signal("QUIT")
        time.sleep(3)
        serve.signal("KILL")
        code = serve.wait(30)
    serve_log("buyer")
    return code


def serve_log(node: str) -> str:
    if node != "buyer":
        return _serve_log(node)
    result = on_buyer(["tail", "-c", "400000", str(REMOTE_LOG)], check=False, keep_stdout=False)
    (WORK / "buyer-serve.log").write_bytes(result.raw)
    return redact(result.raw.decode(errors="replace"))[-4000:]


fd.as_node, fd.fox, fd.install_node = as_node, fox, install_node
fd.start_serve, fd.stop_serve, fd.serve_log = start_serve, stop_serve, serve_log

# --- Probes -----------------------------------------------------------------

CONNECT = ("import socket,sys\nhost=sys.argv[1]\nfor port in sys.argv[2:]:\n    try:\n"
           "        socket.create_connection((host, int(port)), timeout=5).close(); print(port, 'connected')\n"
           "    except OSError as e:\n        print(port, 'refused or unreachable: ' + type(e).__name__)\n")
SYSTEM_TRUST = ("import ssl,sys,urllib.request\ntry:\n    urllib.request.urlopen(sys.argv[1] + '/v1/relay', timeout=15)\n"
                "    print('verified')\nexcept urllib.error.URLError as e:\n"
                "    print('refused: ' + type(e.reason).__name__ + ': ' + str(getattr(e.reason, 'verify_message', '')))\n"
                "except Exception as e:\n    print('error: ' + type(e).__name__)\n")


def connect_results(lines: str) -> dict:
    return {line.split(" ", 1)[0]: line.split(" ", 1)[1] for line in lines.strip().splitlines() if " " in line}


def host_facts(run) -> dict:
    script = ("printf '%s\\n' \"$(sha256sum /etc/machine-id | cut -c1-16)\" \"$(nproc)\" "
              "\"$(awk '/MemTotal/ {print $2}' /proc/meminfo)\" \"$(uname -r)\" \"$(. /etc/os-release; echo $PRETTY_NAME)\"")
    lines = run(script).stdout.strip().splitlines()
    return dict(zip(("machine_id_sha256_prefix", "vcpus", "mem_kib", "kernel", "os"), lines))


def machines() -> None:
    local = host_facts(lambda s: subprocess.run(["sh", "-c", s], capture_output=True, text=True))
    buyer = host_facts(lambda s: logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [s]))
    facts = {"provider_and_chain_host": local, "buyer_host": buyer}
    for relay in RELAYS:
        facts[relay.name.replace("-", "_") + "_host"] = host_facts(lambda s, relay=relay: on_relay(relay, s))
    fd.evidence["machines"] = facts
    ids = {item.get("machine_id_sha256_prefix") for item in facts.values()}
    hosts = "the relay host" if len(RELAYS) == 1 else f"each of the {len(RELAYS)} relay hosts"
    fd.require(f"{len(facts)} different machines: the provider and chain host, the buyer host and {hosts} have "
               "distinct machine ids", len(ids) == len(facts) == 2 + len(RELAYS) and all(ids), facts)


def direct_path() -> None:
    """The buyer host sees this host's public address only as the source of
    its SSH session; nothing it opens to that address connects."""
    # Not transcribed before it has a label.
    seen = logged(ssh_argv(BUYER_SSH, BUYER_KEY) + ['printf "%s\\n" "${SSH_CLIENT%% *}"'],
                  keep_stdout=False).raw.decode().strip()
    ipaddress.ip_address(seen)
    label(seen, "<provider-host-public-address>")
    local_addresses = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True).stdout
    behind_nat = re.search(r"\binet6? " + re.escape(seen) + r"/", local_addresses) is None
    relay_ports = list(dict.fromkeys(str(relay.port) for relay in RELAYS))
    ports = ["22", "80", "443", *[port for port in relay_ports if port not in ("22", "80", "443")],
             *map(str, fd.RPC_PORTS), "47000"]
    probe = connect_results(on_buyer([SYSTEM_PYTHON, "-I", "-c", CONNECT, seen, *ports], timeout=120).stdout)
    to_relay, from_here = {}, {}
    for relay in RELAYS:
        to_relay[relay.name] = connect_results(on_buyer([SYSTEM_PYTHON, "-I", "-c", CONNECT, relay.host,
                                                         str(relay.port)]).stdout)
        from_here[relay.name] = connect_results(subprocess.run([SYSTEM_PYTHON, "-I", "-c", CONNECT, relay.host,
                                                                str(relay.port)], capture_output=True, text=True).stdout)
    single = len(RELAYS) == 1
    fd.evidence["direct_path_probe"] = {"buyer_to_provider_host_public_address": probe,
                                        "provider_host_public_address_is_on_a_local_interface": not behind_nat,
                                        "buyer_to_relay": to_relay[RELAYS[0].name] if single else to_relay,
                                        "provider_host_to_relay": from_here[RELAYS[0].name] if single else from_here}
    fd.require("no direct path: the provider host is behind NAT (its public address is on no local interface) and "
               "from the buyer host no TCP connection to that address opens, on any probed port",
               behind_nat and len(probe) == len(ports) and all(v.startswith("refused") for v in probe.values()),
               fd.evidence["direct_path_probe"])
    fd.require("both nodes' hosts reach the relay's TLS port over the internet" if single else
               "both nodes' hosts reach every relay's TLS port over the internet",
               all(to_relay[relay.name].get(str(relay.port)) == "connected" and
                   from_here[relay.name].get(str(relay.port)) == "connected" for relay in RELAYS),
               {"buyer": to_relay, "provider": from_here})


def listening_sockets(output: str, pid) -> list[str]:
    return [line for line in output.splitlines() if f"pid={pid}," in line]


def no_listeners() -> None:
    provider = fd.SERVING["provider"].pid
    local = subprocess.run(["ss", "-ltunpH"], capture_output=True, text=True).stdout
    buyer_pid = fd.SERVING["buyer"].pid
    remote = on_buyer(["ss", "-ltunpH"]).stdout
    found = {"provider": listening_sockets(local, provider), "buyer": listening_sockets(remote, buyer_pid)}
    fd.evidence["node_listening_sockets"] = found
    fd.require("neither node listens on a TCP or UDP port: the provider has no inbound port, and every packet goes "
               "out to the relay", not found["provider"] and not found["buyer"] and bool(provider) and bool(buyer_pid),
               found)


def spki_of_der(der: bytes) -> str:
    public = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"], input=der,
                            capture_output=True, check=True).stdout
    raw = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, capture_output=True,
                         check=True).stdout
    return hashlib.sha256(raw).hexdigest()


def validity(pem_or_der: bytes, form: str) -> dict:
    """notBefore, notAfter and the length in days of one certificate."""
    out = subprocess.run(["openssl", "x509", "-inform", form, "-noout", "-startdate", "-enddate"], input=pem_or_der,
                         capture_output=True, check=True, text=False).stdout.decode()
    fields = dict(line.split("=", 1) for line in out.strip().splitlines())
    parse = lambda value: datetime.datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z")  # noqa: E731
    start, end = parse(fields["notBefore"]), parse(fields["notAfter"])
    return {"not_before": start.isoformat() + "Z", "not_after": end.isoformat() + "Z",
            "days": round((end - start).total_seconds() / 86400, 2)}


def relay_tls(relay: Relay) -> dict:
    """What one relay presents: the live certificate key against the file on
    its host, the TLS version, and the system trust store's verdict from both
    nodes' hosts."""
    with socket.create_connection((relay.host, relay.port), timeout=15) as raw, \
            TLS_CONTEXT.wrap_socket(raw, server_hostname=relay.host) as tls:
        der, version = tls.getpeercert(binary_form=True), tls.version()
    stored = on_relay(relay, f"openssl x509 -in {shlex.quote(str(relay.cert_file))} -pubkey -noout | "
                             "openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1").stdout.strip()
    here = subprocess.run([SYSTEM_PYTHON, "-I", "-c", SYSTEM_TRUST, relay.url], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin"}).stdout.strip()
    there = on_buyer(["env", "-u", "SSL_CERT_FILE", "-u", "SSL_CERT_DIR", SYSTEM_PYTHON, "-I", "-c", SYSTEM_TRUST,
                      relay.url]).stdout.strip()
    return {"relay_spki_sha256": spki_of_der(der), "relay_certificate_file_spki_sha256": stored, "tls_version": version,
            "relay_certificate_validity": validity(der, "DER"), "system_trust_store_from_provider_host": here,
            "system_trust_store_from_buyer_host": there}


def tls_mode() -> None:
    presented = {relay.name: relay_tls(relay) for relay in RELAYS}
    buyer_env = on_buyer(["sh", "-c", "env | cut -d= -f1 | grep -E '^SSL_CERT_(FILE|DIR)$' || true"]).stdout.split()
    ca_sha = hashlib.sha256(CA.read_bytes()).hexdigest()
    configs = {node: fd.root_json(fd.rail(node)) for node in fd.NODES}
    pins = {node: {"relay_ca_sha256": c.get("relay_ca_sha256"), "relay_ca_file_in_state": str(c.get("relay_ca_file", ""))
                   .startswith(str(REMOTE_ROOT if node == "buyer" else ROOT) + f"/{node}/state/")}
            for node, c in configs.items()}
    preflight = fd.fox_again("provider", "preflight", "--rail-config", fd.rail("provider"))
    checks = {c["id"]: c for c in (fd.strict_json(preflight).get("checks") or [])}
    trust = checks.get("relay.trust", {})
    trust_text = json.dumps(trust)
    # Each relay the nodes name is verified against the pinned CA only.
    pinned_only = {relay.name: any(f"{url}: the pinned CA file only" in trust_text
                                   for url in (relay.url, redact(relay.url))) for relay in RELAYS}
    fd.evidence["tls"] = {
        "mode": ("direct TLS on the relay host's public address, certificate issued by a private P-256 CA generated "
                 "for this run (SAN: the relay's public IP address); both nodes pin that CA with init --relay-ca-file"
                 if not EXTERNAL else
                 "direct TLS on each relay host's public address, each certificate issued by one private P-256 test CA "
                 "(SAN: that relay's public IP address); both nodes pin that CA with init --relay-ca-file"),
        "pinned_ca_sha256": ca_sha, "node_pins": pins, "ca_validity": validity(CA.read_bytes(), "PEM"),
        "ssl_cert_env_in_provider_run": sorted(k for k in ("SSL_CERT_FILE", "SSL_CERT_DIR") if k in os.environ),
        "ssl_cert_env_on_buyer_host": buyer_env,
        "provider_preflight_relay_trust": {k: trust.get(k) for k in ("status", "detail", "message") if k in trust},
        "provider_preflight_relay_reachable": checks.get("relay.reachable", {}).get("status"),
        "preflight_pinned_ca_only_per_relay": pinned_only, "plain_http": False}
    if len(RELAYS) == 1:
        fd.evidence["tls"].update(presented[RELAYS[0].name])
    else:
        fd.evidence["tls"]["relays"] = presented
    validities = {"ca_validity": fd.evidence["tls"]["ca_validity"],
                  **{f"{name}_certificate_validity": item["relay_certificate_validity"]
                     for name, item in presented.items()}}
    fd.require("the run's CA and the relay certificate are each valid for at least 90 days, so no pinned-certificate "
               "expiry warning applies" if len(RELAYS) == 1 else
               "the pinned CA and every relay certificate are each valid for at least 90 days, so no pinned-certificate "
               "expiry warning applies", all(item["days"] >= 90 for item in validities.values()), validities)
    fd.require("TLS pinned-CA mode: the live relay presents the certificate key of the file on the relay host; both "
               "nodes pin the run's CA in their own state; neither node's environment names SSL_CERT_FILE or "
               "SSL_CERT_DIR; the system trust store refuses the relay on both hosts; preflight verifies the relay "
               "against the pinned CA file only and reaches it" if len(RELAYS) == 1 else
               "TLS pinned-CA mode: every live relay presents the certificate key of the file on its host; both nodes "
               "pin the CA in their own state; neither node's environment names SSL_CERT_FILE or SSL_CERT_DIR; the "
               "system trust store refuses every relay on both hosts; preflight verifies every relay against the "
               "pinned CA file only and reaches all of them",
               all(item["relay_spki_sha256"] == item["relay_certificate_file_spki_sha256"] and
                   item["system_trust_store_from_provider_host"].startswith("refused: SSLCertVerificationError") and
                   item["system_trust_store_from_buyer_host"].startswith("refused: SSLCertVerificationError")
                   for item in presented.values()) and
               all(p["relay_ca_sha256"] == ca_sha and p["relay_ca_file_in_state"] for p in pins.values()) and
               not fd.evidence["tls"]["ssl_cert_env_in_provider_run"] and not buyer_env and
               trust.get("status") == "pass" and all(pinned_only.values()) and
               checks.get("relay.reachable", {}).get("status") == "pass", fd.evidence["tls"])


# --- Relay daemon on its host -------------------------------------------------

def relay_request(relay: Relay, path: str, timeout: float = 15):
    with urllib.request.urlopen(relay.url + path, context=TLS_CONTEXT, timeout=timeout) as response:
        return response.status, response.read()


def relay_up(relay: Relay) -> bool:
    try:
        status, body = relay_request(relay, "/v1/relay", timeout=5)
        return status == 200 and json.loads(body).get("schema") == "tos.service.agent-packet-relay.relay.v1"
    except (OSError, ValueError):
        return False


def listing(agent: str, relay: Relay) -> list[str]:
    status, body = relay_request(relay, f"/v1/mailboxes/{agent}/envelopes")
    if status != 200:
        raise RuntimeError(f"listing answered {status}")
    return [entry["envelope_id"] for entry in json.loads(body)["envelopes"]]


def listings(agent: str, relays: list) -> dict[str, list[str]]:
    return {relay.name: listing(agent, relay) for relay in relays}


UNIT_PROPERTIES = "ActiveState,UnitFileState,User,DynamicUser,ExecMainStartTimestampMonotonic," \
                  "InactiveEnterTimestampMonotonic,NRestarts"


def unit_state(relay: Relay) -> dict:
    out = on_relay(relay, f"systemctl show -p {UNIT_PROPERTIES} {shlex.quote(relay.unit)}", check=False).stdout
    return dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)


def relay_uid(relay: Relay) -> str:
    return on_relay(relay, f"ps -o uid= -p \"$(systemctl show -p MainPID --value {shlex.quote(relay.unit)})\"",
                    check=False).stdout.strip()


def prepare_relay(relay: Relay) -> None:
    q = shlex.quote
    if EXTERNAL:
        # An installed unit: it must already serve, start at boot and run as
        # an unprivileged user; this run only stops and starts it.
        state = unit_state(relay)
        uid, up = relay_uid(relay), relay_up(relay)
        fd.evidence.setdefault("relay_units", {})[relay.name] = {"unit": relay.unit, "before_run": state, "uid": uid}
        fd.require(relay.tag("the installed relay unit is active and enabled on its host, runs as an unprivileged "
                             f"user (uid {uid}) and serves TLS at its public URL, verified against the pinned CA"),
                   state.get("ActiveState") == "active" and state.get("UnitFileState") == "enabled" and up and
                   uid.isdigit() and int(uid) != 0, {"unit": state, "uid": uid, "answers": up})
    else:
        active = on_relay(relay, f"systemctl is-active {q(relay.unit)}", check=False).stdout.strip()
        exists = on_relay(relay, f"test -e {q(str(RELAY_RUN))}", check=False).returncode == 0
        fd.require("the relay host runs no relay unit of this name and has no directory of this run",
                   active != "active" and not exists, {"unit": active, "run_directory_exists": exists})
        on_relay(relay, f"install -d -o root -g root -m 0755 {q(str(RELAY_RUN))} && "
                        f"install -d -o {q(RELAY_USER)} -g {q(RELAY_USER)} -m 0700 {q(str(relay.state))}")
    remote = on_relay(relay, f"sha256sum {q(str(relay.binary))}").stdout.split()[0]
    local = hashlib.sha256((BIN / "tos-service-packet-relay").read_bytes()).hexdigest()
    relay.since = on_relay(relay, "date +%s").stdout.strip()
    if len(RELAYS) == 1:
        fd.evidence["relay_since"] = relay.since
    else:
        fd.evidence.setdefault("relay_since", {})[relay.name] = relay.since
    binary = fd.evidence.setdefault("binaries", {}).setdefault("tos-service-packet-relay", {"sha256": local})
    binary["on_relay_host" if len(RELAYS) == 1 else f"on_{relay.name}_host"] = remote
    fd.require(relay.tag("the relay binary on the relay host is byte-identical to the one built here from the named "
                         "ai commit"), remote == local, {"relay_host": remote, "built": local})


def start_relay(relay: Relay, label_: str) -> None:
    if EXTERNAL:
        on_relay(relay, f"systemctl start {shlex.quote(relay.unit)}")
    else:
        properties = " ".join(f"-p {shlex.quote(item)}" for item in relay.properties)
        on_relay(relay, f"systemctl reset-failed {relay.unit} 2> /dev/null; systemd-run --unit={relay.unit} "
                        f"{properties} -- " + shlex.join(relay.argv))
    up = fd.poll(lambda: relay_up(relay), 60, 1)
    uid = relay_uid(relay)
    fd.evidence.setdefault("relay_process_uids", []).append(uid if len(RELAYS) == 1 else f"{relay.name}:{uid}")
    fd.require(relay.tag(f"{label_}: the relay daemon runs on the relay host as an unprivileged user (uid {uid}) and "
                         "serves TLS at its public URL, verified against the pinned CA"),
               bool(up) and uid.isdigit() and int(uid) != 0, {"uid": uid, "answers": bool(up)})


def stop_relay(relay: Relay, label_: str) -> None:
    on_relay(relay, f"systemctl stop {shlex.quote(relay.unit)}", check=False)
    state = on_relay(relay, f"systemctl show -p ActiveState --value {shlex.quote(relay.unit)}",
                     check=False).stdout.strip()
    down = not relay_up(relay)
    fd.require(relay.tag(f"{label_}: the relay daemon stopped cleanly on SIGTERM and no longer answers"),
               state == "inactive" and down, {"active_state": state, "answers": not down})


def snapshot(name: str, relay: Relay, recipient: str = "") -> dict:
    """A copy of the relay's state directory on its host, for the plaintext
    search. With recipient, also how many stored envelopes are in that
    Agent's mailbox (state files are named by the Agent digest in hex)."""
    # Exit 1 means a file changed while it was read (the relay is live).
    tar = on_relay(relay, f"tar -C {shlex.quote(str(relay.state))} --exclude=./LOCK --exclude=./tmp -cf - .; "
                          "status=$?; [ $status -le 1 ]", keep_stdout=False).raw
    target = SNAPSHOTS / (name if len(RELAYS) == 1 else f"{name}-{relay.name}")
    target.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        if hasattr(tarfile, "data_filter"):
            archive.extractall(target, filter="data")
        else:
            archive.extractall(target)
    files = [path for path in target.rglob("*") if path.is_file()]
    envelopes = [path for path in files if "envelopes" in path.parts]
    summary = {"files": len(files), "envelope_files": len(envelopes),
               "envelope_bytes": sum(path.stat().st_size for path in envelopes)}
    if recipient:
        prefix = recipient[len("agent_"):] + "-"
        summary["recipient_envelope_files"] = sum(1 for path in envelopes if path.name.startswith(prefix))
    return summary


def relay_journal(relay: Relay) -> str:
    text = on_relay(relay, f"journalctl _SYSTEMD_UNIT={relay.unit}.service --since @{relay.since} -o cat --no-pager",
                    check=False, keep_stdout=False).raw.decode(errors="replace")
    (WORK / ("relay.log" if len(RELAYS) == 1 else f"{relay.name}.log")).write_text(text)
    return text


# --- Buyer host -----------------------------------------------------------------

def start_tunnel() -> None:
    listening = on_buyer(["ss", "-ltnH"]).stdout
    taken = [port for port in fd.RPC_PORTS if re.search(rf":{port}\s", listening)]
    fd.require("the RPC ports are free on the buyer host", not taken, taken)
    forwards = [arg for port in fd.RPC_PORTS for arg in ("-R", f"127.0.0.1:{port}:127.0.0.1:{port}")]
    argv = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=20", "-o", "ControlMaster=no", "-o",
            "ControlPath=none", "-i", BUYER_KEY, *forwards, BUYER_SSH]
    log = (WORK / "tunnel.log").open("ab")
    PROCESSES["tunnel"] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    fd.evidence["chain_tunnel"] = {"argv": [redact(part) for part in argv]}
    probe = ("import json,sys,urllib.request\nfor port in sys.argv[1:]:\n    body=json.dumps({'jsonrpc':'2.0','id':1,"
             "'method':'getMasterchainInfo','params':{}}).encode()\n    r=urllib.request.Request("
             "f'http://127.0.0.1:{port}/jsonRPC',data=body,headers={'Content-Type':'application/json'})\n"
             "    print(port, 'result' in json.loads(urllib.request.urlopen(r,timeout=10).read()))\n")

    def answered():
        result = on_buyer([SYSTEM_PYTHON, "-I", "-c", probe, *map(str, fd.RPC_PORTS)], check=False)
        return result.returncode == 0 and result.stdout.count("True") == len(fd.RPC_PORTS)
    ok = fd.poll(answered, 60, 3)
    bound = [line.split()[3] for line in on_buyer(["ss", "-ltnH"]).stdout.splitlines()
             if any(line.split()[3].endswith(f":{port}") for port in fd.RPC_PORTS)]
    fd.evidence["chain_tunnel"]["listening_on_buyer_host"] = bound
    fd.require("the chain's JSON-RPC reaches the buyer host only through the SSH reverse tunnel, bound to its "
               "127.0.0.1", bool(ok) and PROCESSES["tunnel"].poll() is None and bool(bound) and
               all(address.startswith("127.0.0.1:") for address in bound), fd.evidence["chain_tunnel"])


def stage() -> None:
    """The provider's files here, the buyer's on its host; one owner-only
    directory per node."""
    if ROOT.exists():
        raise RuntimeError(f"{ROOT} already exists")
    for directory in (ROOT.parent, ROOT, ROOT / "bin", ROOT / "etc", ROOT / "provider"):
        directory.mkdir(mode=0o700)
    fd.install_node(BIN / "openfox", fd.OPENFOX, "0755")
    fd.install_node(fd.TOSCTL, ROOT / "bin" / "tosctl", "0700")
    fd.install_node(WORK / "global.json", ROOT / "etc" / "global.json")
    fd.install_node(fd.REGISTRY_BOC, ROOT / "etc" / "registry-code.boc")
    fd.install_node(CA, ROOT / "etc" / "relay-ca.pem")
    fd.RELAY_CA_FILE = str(ROOT / "etc" / "relay-ca.pem")
    for name in ("tosctl-config.json", "vault.json"):
        fd.install_node(PRIVATE / "provider" / name, ROOT / "provider" / name)
    (PRIVATE / "source.tar").write_bytes(fd.source_archive())

    base = shlex.quote(str(REMOTE_BASE))
    exists = on_buyer(["test", "-e", str(REMOTE_BASE)], check=False).returncode == 0
    fd.require("the buyer host has no directory of this run", not exists, str(REMOTE_BASE))
    logged(ssh_argv(BUYER_SSH, BUYER_KEY) + [
        f"install -d -m 0755 {shlex.quote(str(REMOTE_BASE.parent))} && install -d -m 0700 {base} && "
        f"install -d -m 0700 " + " ".join(shlex.quote(str(REMOTE_ROOT / p)) for p in ("", "bin", "etc", "buyer"))])
    upload(BIN / "openfox", remote_path(fd.OPENFOX), "0755")
    upload(fd.TOSCTL, str(REMOTE_ROOT / "bin" / "tosctl"), "0700")
    upload(WORK / "global.json", str(REMOTE_ROOT / "etc" / "global.json"), "0600")
    upload(fd.REGISTRY_BOC, str(REMOTE_ROOT / "etc" / "registry-code.boc"), "0600")
    upload(CA, str(REMOTE_ROOT / "etc" / "relay-ca.pem"), "0600")
    upload(PRIVATE / "source.tar", str(REMOTE_ROOT / "buyer" / "source.tar"), "0600")
    for name in ("tosctl-config.json", "vault.json"):
        upload(PRIVATE / "buyer" / name, str(REMOTE_ROOT / "buyer" / name), "0600")
    supervisor = PRIVATE / "serve-supervisor.py"
    supervisor.write_text(SUPERVISOR)
    upload(supervisor, str(REMOTE_BASE / "serve-supervisor.py"), "0600")

    binaries = {"openfox": BIN / "openfox", "tosctl": fd.TOSCTL}
    built = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    remote = {name: on_buyer(["sha256sum", str(REMOTE_ROOT / "bin" / name)]).stdout.split()[0] for name in binaries}
    local = {name: fd.root_sha256(ROOT / "bin" / name) for name in binaries}
    ownership = {"provider_host": fd.as_node("stat", "-c", "%u:%g %a %n", ROOT, ROOT / "provider").stdout.split("\n"),
                 "buyer_host": on_buyer(["stat", "-c", "%u:%g %a %n", str(REMOTE_BASE), str(REMOTE_ROOT),
                                         str(REMOTE_ROOT / "buyer"), str(REMOTE_ROOT / "buyer" / "vault.json")])
                 .stdout.split("\n")}
    fd.evidence.setdefault("binaries", {}).update({name: {"sha256": built[name], "on_buyer_host": remote[name],
                                                          "on_provider_host": local[name]} for name in binaries})
    fd.evidence["node_files"] = {"provider_uid": UID, "buyer_uid": int(on_buyer(["id", "-u"]).stdout.strip()),
                                 "buyer_run_directory": str(REMOTE_BASE), "ownership": ownership}
    fd.require("the nodes' files are staged owner-only: the provider's here as uid %d, the buyer's on its host; the "
               "openfox and tosctl binaries on both hosts hash to the ones built and pinned here" % UID,
               os.geteuid() != 0 and remote == built and local == built, fd.evidence["binaries"])


def outbox(node: str) -> list[dict]:
    directory = ROOT / node / "state" / "relay" / "outbox"
    if not directory.is_dir():
        return []
    return [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]


def to_buyer() -> list[dict]:
    return [row for row in outbox("provider") if row.get("recipient") == fd.RUN["buyer_agent"]]


# --- The sale with one relay outage --------------------------------------------

def outage_sale() -> dict:
    """The sale with one carrier outage: every relay still up (LIVE) stops
    while the result is pending, so no relay of the card can take it, and
    starts again on its own state."""
    provider, buyer = fd.RUN["provider_agent"], fd.RUN["buyer_agent"]
    live_urls = {relay.url for relay in LIVE}
    single = len(RELAYS) == 1
    paused = fd.fox_json("provider", "pause", "--rail-config", fd.rail("provider"), "--reason", "relay outage case")
    fd.stop_serve("provider")
    fd.require("the provider is paused and stopped before the purchase, so only the relay can hold the task",
               paused.get("paused") is True and "provider" not in fd.SERVING, paused)
    purchase = fd.buy("first purchase")
    # The buyer deposits its task at every relay of the provider's card that
    # answers; with several, every live relay must come to hold it.
    listed = fd.poll(lambda: (lambda found: found if all(found.values()) else None)(listings(provider, LIVE)),
                     300, 2) or {}
    tasks = sorted({envelope for found in listed.values() for envelope in found})
    task_snapshots = {relay.name: snapshot("task-held", relay, provider) for relay in LIVE}
    fd.require("the buyer's task, sealed to the provider's key card, is held by the relay in the provider's mailbox"
               if single else "the buyer's task, sealed to the provider's key card, is held in the provider's mailbox "
               "by every live relay of the card: " + ", ".join(relay.name for relay in LIVE),
               bool(tasks) and len(listed) == len(LIVE) and all(listed.values()) and
               all(item["envelope_files"] > 0 and item["recipient_envelope_files"] > 0
                   for item in task_snapshots.values()),
               {"listed": listed, "snapshot": task_snapshots})
    fd.start_serve("provider")
    held = fd.poll(lambda: "task(s) held" in fd.serve_log("provider") and
                   not any(set(tasks) & set(found) for found in listings(provider, LIVE).values()), 300, 2)
    facts = fd.actor_facts(fd.RUN["actor"])
    fd.require("the provider took the task from the relay and holds it while paused: nothing executed or responded"
               if single else "the provider took the task, acknowledged it at every live relay, and holds it while "
               "paused: nothing executed or responded",
               bool(held) and not facts["responds"] and fd.executions() == [],
               {"responds": len(facts["responds"]), "executions": fd.executions()})
    early = {row["envelope_id"] for row in to_buyer() if row.get("accepted")}

    for relay in LIVE:
        stop_relay(relay, "outage begins with the result pending")
    fd.stop_serve("buyer")
    fd.record("the buyer node is stopped during the outage, so the result waits at the relay once accepted", True)
    resumed = fd.fox_json("provider", "resume", "--rail-config", fd.rail("provider"))
    responded = fd.poll(lambda: len(fd.actor_facts(fd.RUN["actor"])["responds"]) == 1, 900, 5)
    # Every relay of the buyer's card is down: no deposit can be accepted.
    pending = fd.poll(lambda: [row["envelope_id"] for row in to_buyer()
                               if not row.get("accepted") and {r.url for r in RELAYS} <= set(row.get("relays", []))],
                      600, 5) or []
    fd.require("during the outage the provider executed and responded on chain while its result deposits fail and "
               "stay journaled", resumed.get("paused") is False and bool(responded) and bool(pending) and
               len(fd.executions()) == 1,
               {"responded": bool(responded), "pending_envelopes": pending, "executions": fd.executions()})
    for relay in LIVE:
        start_relay(relay, "outage ends: restart on the same state directory")
    accepted = fd.poll(lambda: [row["envelope_id"] for row in to_buyer()
                                if live_urls & set(row.get("accepted", [])) and row["envelope_id"] not in early],
                       1500, 5) or []
    in_mailbox = listings(buyer, LIVE)
    result_snapshots = {relay.name: snapshot("result-held", relay, buyer) for relay in LIVE}
    # Which relay holds which accepted envelope, from the provider's journal.
    accepted_at = {row["envelope_id"]: sorted(set(row.get("accepted", [])) & live_urls) for row in to_buyer()
                   if row["envelope_id"] in accepted}
    fd.require("after the restart the provider's courier deposits the result and the relay holds it for the buyer",
               bool(accepted) and all(envelope in in_mailbox[relay.name] for envelope, urls in accepted_at.items()
                                      for relay in LIVE if relay.url in urls) and
               any(item["recipient_envelope_files"] > 0 for item in result_snapshots.values()),
               {"failed_while_down": pending, "accepted_after_restart": accepted,
                "accepted_at": {envelope: [redact(url) for url in urls] for envelope, urls in accepted_at.items()},
                "listed_for_buyer": in_mailbox})
    if REDUNDANT:
        # Redundant deposits: the courier keeps depositing at the other
        # relays of the card after the first accepted.
        everywhere = fd.poll(lambda: (lambda rows: rows if rows and all({r.url for r in RELAYS} <=
                                                                       set(row.get("accepted", [])) for row in rows)
                                      else None)([row for row in to_buyer() if row["envelope_id"] in accepted]),
                             600, 5) or []
        mailboxes = listings(buyer, RELAYS)
        fd.require("the second relay carries the result too: every result envelope deposited after the outage is "
                   "accepted by every relay of the buyer's card and listed in the buyer's mailbox at each of them",
                   bool(everywhere) and all(set(accepted) <= set(found) for found in mailboxes.values()),
                   {"accepted_by": {row["envelope_id"]: [redact(url) for url in row.get("accepted", [])]
                                    for row in everywhere}, "listed_for_buyer": mailboxes})
    fd.start_serve("buyer")
    fd.require("buyer serve is running again", bool(fd.poll(lambda: fd.SERVING["buyer"].poll() is None, 20, 2)),
               fd.serve_log("buyer"))
    fd.evidence["relay_outage"] = {
        "task_envelopes": tasks, "failed_while_down": pending, "accepted_after_restart": accepted,
        "relays_stopped_for_the_outage": [relay.name for relay in LIVE],
        "snapshots": ({"task-held": task_snapshots[RELAYS[0].name], "result-held": result_snapshots[RELAYS[0].name]}
                      if single else {"task-held": task_snapshots, "result-held": result_snapshots})}
    if not single:
        fd.evidence["relay_outage"]["task_listed_at"] = listed
    return purchase


# --- No plaintext at the relay --------------------------------------------------

def public_values() -> list[bytes]:
    out = []
    for agent in (fd.RUN["provider_agent"], fd.RUN["buyer_agent"]):
        out += [agent.encode(), agent[len("agent_"):].encode(), bytes.fromhex(agent[len("agent_"):])]
    return out


def windows(data: bytes, size: int = 48, step: int = 1024) -> list[bytes]:
    public = public_values()
    return [window for window in (data[offset:offset + size] for offset in range(0, max(len(data) - size, 1), step))
            if len(set(window)) > 8 and not any(window in value for value in public)]


def needles() -> dict[str, list[bytes]]:
    from pytosiq_core import Address
    source = (PRIVATE / "source.tar").read_bytes()
    artifact = fetch(remote_path(ROOT / "buyer" / "state" / "purchases" / fd.RUN["first"]["request_hash"] /
                                 "artifact.tar"))
    wallet = fd.RUN["wallets"]["buyer"]
    forms = {wallet, wallet.split(":", 1)[1], wallet.split(":", 1)[1].upper()}
    for bounceable in (True, False):
        for url_safe in (True, False):
            try:
                forms.add(Address(wallet).to_str(is_user_friendly=True, is_bounceable=bounceable, is_url_safe=url_safe))
            except TypeError:
                pass
    package = base64.b64decode(fd.request_of(fd.RUN["first"]["request_hash"]).get("package_base64", ""))
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


def no_plaintext(journal: str) -> None:
    wanted = needles()
    control = PRIVATE / "plaintext-control.bin"
    control.write_bytes(b"".join(secrets.token_bytes(64) + items[-1] for items in wanted.values()))
    control_found, _ = search([control], wanted)
    fd.require("the plaintext search finds every searched value in a control file holding one slice of each",
               set(control_found) == set(wanted), sorted(control_found))
    journals = [WORK / ("relay.log" if len(RELAYS) == 1 else f"{relay.name}.log") for relay in RELAYS]
    targets = [SNAPSHOTS, *journals]
    found, scanned = search(targets, wanted)
    snapshots = {path.name: sum(1 for p in path.rglob("*") if p.is_file()) for path in SNAPSHOTS.iterdir()}
    fd.evidence["plaintext_search"] = {
        "searched": "copies of the relay host's state directory (taken over SSH with tar while the relay held the "
                    "task, while it held the result, and after the run) and its journal" if len(RELAYS) == 1 else
                    "copies of every relay host's state directory (taken over SSH with tar while the live relays held "
                    "the task, while they held the result, and of every relay after the run) and every relay's "
                    "journal since this run began",
        "copies": snapshots, "scanned": scanned, "values": {kind: len(items) for kind, items in wanted.items()},
        "found": found}
    held = fd.evidence["relay_outage"]["snapshots"]
    copies = list(held.values()) if len(RELAYS) == 1 else [item for per in held.values() for item in per.values()]
    fd.require("nothing in clear at the relay: no state file it wrote, while it held the task, while it held the "
               "result or after the run, nor its journal, contains the source archive, the artifact, the buyer wallet "
               "address or the Quote package" if len(RELAYS) == 1 else
               "nothing in clear at any relay: no state file they wrote, while they held the task, while they held "
               "the result or after the run, nor their journals, contains the source archive, the artifact, the buyer "
               "wallet address or the Quote package",
               not found and bool(copies) and all(item["envelope_files"] > 0 for item in copies),
               {"found": found, "scanned": scanned})
    addresses = [raw for raw, name in LABELS.items() if name in ("<buyer-host>", "<provider-host-public-address>")]
    named = [redact(value) for value in (fd.RUN["provider_agent"], fd.RUN["buyer_agent"], *addresses) if value in journal]
    fd.require("the relay journal names no Agent and no client address", not named, named)


# --- Evidence ---------------------------------------------------------------------

ADVERSARIAL_COVERAGE = {
    "statement": "No live adversarial case was run against the relay in this run. The adversarial cases are covered by "
                 "merged in-repository tests (listed in the two-host namespace evidence), not by this run."}


def git(path, *args) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True).stdout.strip()


# The public fields of a node's envelope journal record; the record's
# acknowledgement secret, envelope and packet bytes are never read out.
OUTBOX_FIELDS = ("recipient", "envelope_id", "relays", "accepted", "stopped")
READ_OUTBOX = ("import json,pathlib,sys\nfor p in sorted(pathlib.Path(sys.argv[1]).glob('*.json')):\n"
               "    r=json.loads(p.read_text())\n    print(json.dumps({k: r.get(k) for k in sys.argv[2:]}))\n")


def node_outboxes() -> dict[str, list[dict]]:
    """Every envelope each node journaled for its peer's relays: the
    provider's read here, the buyer's on its host."""
    remote = remote_path(ROOT / "buyer" / "state" / "relay" / "outbox")
    listed = on_buyer(["sh", "-c", 'd=$1 s=$2; shift 2; test -d "$d" || exit 0; exec "$0" -I -c "$s" "$d" "$@"',
                       SYSTEM_PYTHON, remote, READ_OUTBOX, *OUTBOX_FIELDS]).stdout
    return {"provider": [{key: row.get(key) for key in OUTBOX_FIELDS} for row in outbox("provider")],
            "buyer": [json.loads(line) for line in listed.splitlines() if line.strip()]}


def accepted_view(outboxes: dict) -> dict:
    return {node: {row.get("envelope_id"): [redact(url) for url in row.get("accepted") or []] for row in rows}
            for node, rows in outboxes.items()}


def take_down() -> None:
    """G3: one relay of every card is stopped before the first purchase and
    stays stopped until the last sale step is done."""
    stop_relay(DOWN, "stopped before the first purchase, for the whole sale")
    state = unit_state(DOWN)
    fd.evidence["relay_down"] = {"relay": DOWN.name, "stopped_utc": datetime.datetime.now(datetime.timezone.utc)
                                 .isoformat(), "unit_after_stop": state}


def bring_up() -> None:
    """The stopped relay never ran during the sale, it took no envelope of
    either node, and the other relays took every one; then it starts again."""
    live_urls = {relay.url for relay in LIVE}
    every_url = {relay.url for relay in RELAYS}
    stopped = fd.evidence["relay_down"]["unit_after_stop"]
    outboxes = fd.poll(lambda: (lambda found: found if all(
        live_urls & took(row) for rows in found.values() for row in rows) else None)(node_outboxes()), 300, 5) \
        or node_outboxes()
    rows = [row for found in outboxes.values() for row in found]
    state = unit_state(DOWN)
    fd.evidence["relay_down"].update({"unit_before_restart": state, "accepted_by": accepted_view(outboxes),
                                      "answers_before_restart": relay_up(DOWN)})
    fd.require(f"{DOWN.name} stayed stopped for the whole sale (its unit did not start again between the stop before "
               "the first purchase and the end of the last sale step) and accepted none of the envelopes either node "
               "sent, although every one was addressed to it by the recipient's card; " +
               " and ".join(relay.name for relay in LIVE) + " accepted every one, so it alone carried every task, "
               "result and acknowledgement",
               state.get("ActiveState") == "inactive" and not fd.evidence["relay_down"]["answers_before_restart"] and
               all(state.get(key) == stopped.get(key) for key in ("ExecMainStartTimestampMonotonic",
                                                                  "InactiveEnterTimestampMonotonic")) and
               bool(outboxes.get("provider")) and bool(outboxes.get("buyer")) and
               all(set(row.get("relays") or []) == every_url and DOWN.url not in took(row) and
                   live_urls & took(row) for row in rows), fd.evidence["relay_down"])
    start_relay(DOWN, "restarted after the sale")


def took(row: dict) -> set:
    """The relays that durably accepted one journaled envelope."""
    return set(row.get("accepted") or [])


def carried_everywhere() -> None:
    """G2: with every relay up, the redundant deposits put every envelope
    either node sent at every relay of the recipient's card."""
    urls = {relay.url for relay in RELAYS}
    outboxes = fd.poll(lambda: (lambda found: found if all(
        urls <= took(row) for rows in found.values() for row in rows) else None)(node_outboxes()), 600, 5) \
        or node_outboxes()
    rows = [row for found in outboxes.values() for row in found]
    fd.evidence["redundant_carriage"] = {"accepted_by": accepted_view(outboxes)}
    fd.require("the second relay carried the sale as well: every envelope either node sent (tasks, results and "
               "acknowledgements) was addressed to every relay by the recipient's card and accepted by each of them",
               bool(outboxes.get("provider")) and bool(outboxes.get("buyer")) and
               all(set(row.get("relays") or []) == urls and urls <= took(row) for row in rows),
               fd.evidence["redundant_carriage"])


def sale() -> None:
    stage()
    machines()
    start_tunnel()
    for relay in RELAYS:
        prepare_relay(relay)
        if not EXTERNAL:
            start_relay(relay, "start")
    direct_path()
    fd.setup_nodes()
    tls_mode()
    no_listeners()
    handed = ROOT / "buyer" / "offer.json"
    fd.install_node(Path(fd.RUN["offer_path"]), handed)
    fd.RUN["offer_path"] = str(handed)
    configs = {node: fd.root_json(fd.rail(node)) for node in fd.NODES}
    fd.require("relay only: both nodes name the relay's public URL and no direct peer or Messenger socket"
               if len(RELAYS) == 1 else
               "relays only: both nodes name every relay's public URL and no direct peer or Messenger socket",
               all(c.get("relay_urls") == fd.RELAY_URLS and not c.get("direct_peers") and not c.get("messenger_socket")
                   for c in configs.values()), {n: c.get("relay_urls") for n, c in configs.items()})
    if DOWN is not None:
        take_down()
    purchase = outage_sale()
    fd.verify_sale(purchase)
    fd.relay_delivery()
    fd.withdraw()
    fd.run_again()
    fd.tampered_offer()
    fd.paused_purchase()
    if REDUNDANT:
        carried_everywhere()
    if DOWN is not None:
        bring_up()


def finish() -> None:
    if set(fd.SERVING) == set(fd.NODES):
        fd.stop_nodes()
    for node in list(fd.SERVING):
        fd.stop_serve(node)
    try:
        prepared = [relay for relay in RELAYS if relay.since]
        for relay in prepared:
            if EXTERNAL:
                # An installed relay is left serving, whatever happened.
                if not relay_up(relay):
                    start_relay(relay, "end of run: the installed relay is started again")
            elif relay_up(relay):
                stop_relay(relay, "end of run")
        for relay in prepared:
            snapshot("after-run", relay)
        journal = "\n".join(relay_journal(relay) for relay in prepared)
        if prepared and fd.RUN.get("first"):
            no_plaintext(journal)
    except fd.Stop:
        pass
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("the relay copy and plaintext search ran", False, redact(repr(error)))
    tunnel = PROCESSES.pop("tunnel", None)
    if tunnel is not None:
        tunnel.terminate()
        tunnel.wait(timeout=30)
    try:
        left = on_buyer(["sh", "-c", f"pgrep -af {shlex.quote(str(REMOTE_BASE))} || true; ss -ltnH"], check=False).stdout
        relay_left = {relay.name: on_relay(relay, f"systemctl is-active {shlex.quote(relay.unit)}; "
                                                  f"pgrep -c -f {shlex.quote(str(relay.binary))} || true",
                                           check=False).stdout.split() for relay in RELAYS}
        files = on_buyer(["find", str(REMOTE_BASE), "-maxdepth", "1"], check=False).stdout.split()
        tunnelled = [port for port in fd.RPC_PORTS if f"127.0.0.1:{port} " in left]
        fd.evidence["teardown"] = {"buyer_processes_of_this_run": [line for line in left.splitlines()
                                                                    if str(REMOTE_BASE) in line and
                                                                    "pgrep" not in line],
                                   "tunnel_ports_still_bound_on_buyer_host": tunnelled,
                                   "relay_unit": relay_left[RELAYS[0].name] if len(RELAYS) == 1 else relay_left,
                                   "left_for_inspection": {"buyer_host": files,
                                                           "relay_host": [] if EXTERNAL else [str(RELAY_RUN)]}}
        clean = not fd.evidence["teardown"]["buyer_processes_of_this_run"] and not tunnelled
        if EXTERNAL:
            fd.record("teardown: no node process of this run on the buyer host, the tunnel is closed and every "
                      "installed relay unit is active again", clean and
                      all(found[:1] == ["active"] for found in relay_left.values()), fd.evidence["teardown"])
        else:
            fd.record("teardown: no node process of this run on the buyer host, the tunnel is closed and the relay "
                      "unit is stopped", clean and relay_left[RELAYS[0].name][:1] != ["active"],
                      fd.evidence["teardown"])
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("teardown ran", False, redact(repr(error)))
    for target, key in ((BUYER_SSH, BUYER_KEY), *((relay.ssh, relay.key) for relay in RELAYS)):
        subprocess.run(["ssh", "-o", f"ControlPath={CONTROL}/%C", "-O", "exit", "-i", key, target],
                       capture_output=True, timeout=30)
    try:
        CONTROL.rmdir()
    except OSError:
        pass
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
        "schema": "tos.openfox.service-relay-multi-host.acceptance.v1",
        "qualifies_as_public_acceptance": False,
        "reason": "the relay is operated by us; the chain is a local three-validator test network on the provider's "
                  "host, reached by the buyer only through an SSH reverse tunnel; the provider runs on our host; no "
                  "live adversarial case runs",
        "proves": "two OpenFox nodes on different physical machines complete a paid sale whose task and result travel "
                  "only through an Agent Packet Relay daemon on a third machine, over the public internet, with the "
                  "relay's private CA pinned on both nodes",
        "executor_mode": "executor service socket",
        "carrier": "Agent Packet Relay daemon on a third host, public URL https://<relay-host>:%d, the only transport "
                   "of both nodes" % RELAYS[0].port,
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "openfox_commit": git(fd.REPO, "rev-parse", "HEAD"), "openfox_tree_status": tree, "openfox_tree_dirty": bool(tree),
        "tos_commit": git(fd.SOURCE, "rev-parse", "HEAD"),
        "relay_daemon": {"ai_commit": git(relay_source, "rev-parse", "HEAD"), "ai_tree_status": relay_tree,
                         "build": "GOWORK=off CGO_ENABLED=0 go build -trimpath ./protocol/cmd/tos-service-packet-relay",
                         "argv": [redact(part) for part in RELAYS[0].argv], "unit_properties": RELAYS[0].properties,
                         "launch": "systemd-run transient unit on the relay host (not an installed unit), as a "
                                   "dedicated unprivileged system user",
                         "chain_rpc_configured": False, "key_material": "its TLS key only, as a systemd credential"},
        "topology": {
            "provider_and_chain_host": "the three validators on 127.0.0.1 and the provider node; behind NAT, no "
                                       "inbound port",
            "buyer_host": "a VPS on the public internet running the buyer node; it reaches the chain's JSON-RPC only "
                          "through an SSH reverse tunnel from the provider host to its 127.0.0.1",
            "relay_host": "a third VPS on the public internet running the relay daemon on TCP %d, the one port "
                          "opened for this run" % RELAYS[0].port},
        "actor_code_hash": fd.ACTOR_CODE_HASH, "network_label": fd.NETWORK_LABEL,
        "terms": {"price": fd.PRICE, "storage_fee": fd.STORAGE_FEE, "cleanup_bounty": fd.CLEANUP_BOUNTY},
        "adversarial_coverage": ADVERSARIAL_COVERAGE,
        "not_verified": ["a relay operated by a third party",
                         ("a public chain (the chain is a local test network reached through an SSH tunnel)"),
                         "a provider on a host we do not operate", "a second relay in the card",
                         ("live adversarial envelopes, quota pressure and the public-id race (unit tests only)"),
                         "key expiry and rotation (unit tests only)",
                         "crash windows of the nodes"],
        "not_openfox": ["booting the three-validator network (tostester)",
                        "creating, funding and activating the two wallets with tosctl and the zerostate faucet",
                        "the SSH reverse tunnel, the copies to the buyer host and the relay unit",
                        "the container runtime and the root-run executor service in front of it",
                        "this script's own JSON-RPC reads, relay listings and probes, used only to verify"]})
    if EXTERNAL:
        names = ", ".join(relay.name for relay in RELAYS)
        case = (f"{DOWN.name} is stopped from before the first purchase until after the last sale step, so "
                f"{', '.join(relay.name for relay in LIVE)} alone carries the sale" if DOWN is not None else
                "every relay is up for the sale, apart from the carrier outage")
        fd.evidence.update({
            "reason": "the relays are operated by us; the chain is a local three-validator test network on the "
                      "provider's host, reached by the buyer only through an SSH reverse tunnel; the provider runs on "
                      "our host; no live adversarial case runs",
            "proves": f"two OpenFox nodes on different physical machines complete a paid sale whose task and result "
                      f"travel only through the installed Agent Packet Relay daemons {names}, each on its own machine, "
                      f"over the public internet, with the relays' private CA pinned on both nodes; {case}",
            "carrier": "Agent Packet Relay daemons " + ", ".join(f"{relay.name} at https://<{relay.name}-host>:"
                                                                 f"{relay.port}" for relay in RELAYS) +
                       ", named together in both nodes' cards and the only transport of both nodes",
            "relay_case": {"relays": [relay.name for relay in RELAYS], "down_for_the_whole_sale": DOWN_NAME or None,
                           "stopped_for_the_carrier_outage": [relay.name for relay in LIVE]},
            "relay_daemon": {"ai_commit": git(relay_source, "rev-parse", "HEAD"), "ai_tree_status": relay_tree,
                             "build": "GOWORK=off CGO_ENABLED=0 go build -trimpath ./protocol/cmd/tos-service-packet-relay",
                             "launch": "installed systemd unit on each relay host (DynamicUser), not started or "
                                       "configured by this run; the run stops and starts it for the outages",
                             "units": {relay.name: relay.unit for relay in RELAYS},
                             "chain_rpc_configured": False, "key_material": "its TLS key only, as a systemd credential"},
            "topology": {
                "provider_and_chain_host": "the three validators on 127.0.0.1 and the provider node; behind NAT, no "
                                           "inbound port",
                "buyer_host": "a VPS on the public internet running the buyer node; it reaches the chain's JSON-RPC "
                              "only through an SSH reverse tunnel from the provider host to its 127.0.0.1",
                **{f"{relay.name.replace('-', '_')}_host": f"a VPS on the public internet running the relay daemon "
                                                           f"{relay.name} on TCP {relay.port}" for relay in RELAYS}},
            "not_verified": ["a relay operated by a third party",
                             "relays at more than one provider (both relay hosts are at one provider)",
                             ("a public chain (the chain is a local test network reached through an SSH tunnel)"),
                             "a provider on a host we do not operate",
                             ("live adversarial envelopes, quota pressure and the public-id race (unit tests only)"),
                             "key expiry and rotation (unit tests only)",
                             "crash windows of the nodes"],
            "not_openfox": ["booting the three-validator network (tostester)",
                            "creating, funding and activating the two wallets with tosctl and the zerostate faucet",
                            ("the SSH reverse tunnel, the copies to the buyer host, and stopping and starting the "
                             "relay units"),
                            "the container runtime and the root-run executor service in front of it",
                            "this script's own JSON-RPC reads, relay listings and probes, used only to verify"]})
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
                fd.record("the sale ran without an exception", False, redact(trace)[-3000:])
            finally:
                await asyncio.to_thread(finish)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("run completed without an exception", False, redact(repr(error)))
    fd.evidence["ran_as_root"] = {
        "provider_host": [], "buyer_host": "the buyer node and its file commands run as the SSH user of the buyer host "
                                          "(uid %s)" % fd.evidence.get("node_files", {}).get("buyer_uid"),
        "relay_host" if len(RELAYS) == 1 else "relay_hosts":
            ("systemctl, journalctl, ps, openssl on the certificate file, tar of the state directory and sha256sum, "
             "over SSH; the relay daemons themselves run unprivileged" if EXTERNAL else
             "systemd-run, systemctl, journalctl, tar of the state directory and sha256sum, over SSH; the "
             "relay daemon itself runs unprivileged")}
    fd.evidence["steps"] = fd.steps
    fd.evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    text = json.dumps(fd.redact_value(fd.evidence), default=str)
    leaked = fd.personal_data(text) + [f"unlabelled {name}" for name in raw_addresses(text)]
    fd.record("no home directory path, login name, e-mail address, SSH key path, public address or SSH target in "
              "evidence.json", not leaked, leaked)
    passed = bool(fd.steps) and all(step["pass"] for step in fd.steps)
    fd.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
