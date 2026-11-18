#!/usr/bin/env python3
"""Service Actor sales between two OpenFox nodes on a public TOS test network,
with Quotes from a real gateway and every packet carried by installed Agent
Packet Relays. It covers the three terminal outcomes of a call: responded,
refunded and swept.

It reuses the multi-host run (service-relay-multi-host-e2e.py, loaded as a
module, which loads the front-door run): the same staging, buyer-host
commands, reverse SSH tunnel, TLS checks and sale verification. What differs:

- the chain is a public network this run does not operate. Its JSON-RPC is
  reached through SSH forwards the launcher opens (E2E_RPC_PORTS on this
  host); the buyer reaches the same ports through the reverse tunnel;
- the wallets are funded by the network's operator, not from a faucet. The
  run has two commands: `prepare` creates the wallets offline and prints
  their addresses and the live fee parameters; `run` starts only once every
  wallet holds its planned amount;
- the relays are installed units on hosts this run never logs in to
  (RELAY_OBSERVE_ONLY=1): they are read over HTTPS only, never stopped or
  started, and the run has no relay outage;
- Quotes come from the gateway (gateway/cmd/api, with protocol
  tos-service-rpc behind it) that this run starts on this host's loopback,
  behind a TLS terminator; the buyer reaches it through the reverse tunnel.
  Only the first purchase uses the provider's offer file, because that is
  how a buyer learns the provider's relay key card; the next purchases are
  quoted by the gateway;
- after the responded sales, the provider pauses admission. Sale S is
  bought, its task deposited, and the buyer node stopped, so nobody claims
  its refund. Once S is overdue, sale F is bought; once S's refund-claim
  window has lapsed and F is overdue, the buyer node starts again: its
  refund duty expires and refunds F and finds S lapsed, and a third wallet
  (the sweeper) sweeps S for the cleanup bounty.

Every value-moving step this script sends itself (a wallet activation, a
purchase, the sweep) writes an attempt marker with O_EXCL first; a step whose
marker exists is never sent again, and a rerun refuses until the operator
reconciles it from the chain.

Run it through scripts/service-relay-public-e2e.sh.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMAND = sys.argv[1] if len(sys.argv) > 1 else ""
if COMMAND not in ("prepare", "run"):
    raise SystemExit("usage: service-relay-public-e2e.py prepare|run")

WORK = Path(os.environ["E2E_WORKDIR"])
PRIVATE = WORK / "private"
PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)

# Node vault keys persist across the two commands, owner-only: `prepare`
# creates the wallets, and `run` must open the same vaults.
KEY_FILE = PRIVATE / "master-keys.json"
SWEEPER, GATEWAY_WALLET = "sweeper", "gateway"
VAULTS = ("provider", "buyer", SWEEPER, GATEWAY_WALLET)
if not KEY_FILE.exists():
    fd_ = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd_, "w") as handle:
        json.dump({name: secrets.token_hex(32) for name in VAULTS}, handle)
MASTER = json.loads(KEY_FILE.read_text())

_spec = importlib.util.spec_from_file_location("multi_host", HERE / "service-relay-multi-host-e2e.py")
mh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mh)
fd = mh.fd
if not mh.OBSERVE_ONLY:
    raise SystemExit("this run takes the installed relays observe-only: RELAY_EXTERNAL=1 RELAY_OBSERVE_ONLY=1")
fd.MASTER_KEYS.update({node: MASTER[node] for node in fd.NODES})
# The front-door module sets a random authorization tag for the local
# networks it boots; a public network has its own, which tosctl reads from
# the chain.
os.environ.pop("TOS_AUTH_NETWORK_TAG", None)

GLOBAL_CONFIG = Path(os.environ["E2E_GLOBAL_CONFIG"])
GENESIS_ROOT = os.environ["E2E_GENESIS_ROOT_HASH"]  # sha256:<hex>
GENESIS_FILE = os.environ["E2E_GENESIS_FILE_HASH"]
REGISTRY_CODE_HASH = os.environ["E2E_REGISTRY_CODE_HASH"]
GATEWAY_API = Path(os.environ["E2E_GATEWAY_API"])
SERVICE_RPC = Path(os.environ["E2E_SERVICE_RPC"])
GATEWAY_PORT = int(os.environ.get("E2E_GATEWAY_PORT", "18890"))  # TLS terminator, here and on the buyer host
GATEWAY_BACKEND_PORT = GATEWAY_PORT + 1
SERVICE_RPC_PORT = GATEWAY_PORT + 2
FUNDING = {name: int(round(float(value) * fd.NANO)) for name, value in
           (item.split("=", 1) for item in os.environ["E2E_FUNDING_TOS"].split())}
if set(FUNDING) != {"provider", "buyer", SWEEPER}:
    raise SystemExit("E2E_FUNDING_TOS names provider=, buyer= and sweeper=")
# A send this close to a validator-set boundary waits (seconds).
QUIET_S = 600

# The terms. The contract's minimum response SLA and refund window are one
# hour each; the storage fee is at least 0.1 TOS.
fd.PRICE, fd.STORAGE_FEE, fd.CLEANUP_BOUNTY = "0.1", "0.1", "0.1"
fd.PRICE_NANO, fd.STORAGE_FEE_NANO = 100_000_000, 100_000_000
BOUNTY_NANO = 100_000_000
SLA_S = REFUND_WINDOW_S = 3600

MARKERS = WORK / "markers"
STATE = WORK / "run-state.json"
redact = mh.redact


# --- Once-only markers --------------------------------------------------------

def marker_path(label: str) -> Path:
    return MARKERS / f"{label}.attempt.json"


def attempt(label: str, detail: dict) -> None:
    """The attempt marker of one value step, written before the step runs; a
    second attempt of the label is refused."""
    MARKERS.mkdir(mode=0o700, exist_ok=True)
    try:
        handle = os.open(marker_path(label), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise fd.Stop(f"{label} was attempted before; it is never sent again (reconcile from the chain)") from None
    with os.fdopen(handle, "w") as out:
        json.dump({"label": label, "utc": now_utc(), **detail}, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())


def done(label: str, result: dict) -> None:
    (MARKERS / f"{label}.done.json").write_text(json.dumps({"label": label, "utc": now_utc(), **result},
                                                           sort_keys=True, default=str))


def result_of(label: str) -> dict | None:
    path = MARKERS / f"{label}.done.json"
    return json.loads(path.read_text()) if path.exists() else None


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save_state() -> None:
    STATE.write_text(json.dumps({key: value for key, value in fd.RUN.items()}, indent=2, sort_keys=True, default=str))


# --- Chain facts ----------------------------------------------------------------

def rpc_on(port: int, method: str, **params):
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/jsonRPC", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def network_facts() -> dict:
    """Genesis and global version on every endpoint: they must agree and be
    the pinned network."""
    facts = {}
    for port in fd.RPC_PORTS:
        info = rpc_on(port, "getMasterchainInfo")["result"]
        init = info["init"]
        facts[str(port)] = {
            "genesis_root_hash": "sha256:" + base64.b64decode(init["root_hash"]).hex(),
            "genesis_file_hash": "sha256:" + base64.b64decode(init["file_hash"]).hex(),
            "head_seqno": info["last"]["seqno"],
            "global_version": config_global_version(port)}
    return facts


def config_global_version(port: int) -> int:
    raw = base64.b64decode(rpc_on(port, "getConfigParam", config_id=8)["result"]["config"]["bytes"])
    from pytosiq_core import Cell
    data = Cell.one_from_boc(raw).begin_parse()
    if data.load_uint(8) != 0xC4:
        raise RuntimeError("ConfigParam 8 tag")
    return data.load_uint(32)


def rotation_bounds() -> tuple[int, int]:
    raw = base64.b64decode(fd.rpc("getConfigParam", config_id=34)["result"]["config"]["bytes"])
    from pytosiq_core import Cell
    data = Cell.one_from_boc(raw).begin_parse()
    if data.load_uint(8) not in (0x11, 0x12):
        raise RuntimeError("ConfigParam 34 tag")
    return data.load_uint(32), data.load_uint(32)


def quiet_window() -> None:
    """Wait while a validator-set boundary is closer than QUIET_S: the
    installed set's start and end, and the next set's start every elected
    period after it."""
    while True:
        since, until = rotation_bounds()
        distance = min(abs(time.time() - since), abs(until - time.time()))
        if distance >= QUIET_S:
            return
        print(f"waiting: {int(distance)} s from a validator-set boundary", flush=True)
        time.sleep(30)


def fee_parameters() -> dict:
    """The live gas and forwarding prices, as raw ConfigParam cells and the
    basechain gas price decoded from ConfigParam 21."""
    params = {}
    for index in (20, 21, 24, 25):
        params[str(index)] = fd.rpc("getConfigParam", config_id=index)["result"]["config"]["bytes"]
    from pytosiq_core import Cell
    data = Cell.one_from_boc(base64.b64decode(params["21"])).begin_parse()
    decoded = {}
    tag = data.load_uint(8)
    if tag == 0xD1:  # gas_flat_pfx flat_gas_limit flat_gas_price other
        decoded["flat_gas_limit"], decoded["flat_gas_price"] = data.load_uint(64), data.load_uint(64)
        tag = data.load_uint(8)
    if tag in (0xDD, 0xDE):
        decoded["gas_price_units_per_65536"] = data.load_uint(64)
        decoded["gas_price_nanotos_per_gas"] = decoded["gas_price_units_per_65536"] / 65536
    return {"config_params_base64": params, "basechain_gas": decoded}


def tosctl_local(name: str, *args: str, check: bool = True):
    config = PRIVATE / name / "tosctl-config.json"
    env = dict(os.environ, VAULT_URL=f"file://{PRIVATE / name}/vault.json?master_key={MASTER[name]}")
    return fd.run_logged([str(fd.TOSCTL), *args, "-c", str(config)], env=env, check=check)


def create_wallet(name: str, rpc_urls: list[str]) -> str:
    directory = PRIVATE / name
    directory.mkdir(mode=0o700, exist_ok=True)
    config_path = directory / "tosctl-config.json"
    if not config_path.exists():
        fd.run_logged([str(fd.TOSCTL), "config", "generate", "-o", str(config_path), "--force",
                       "-c", str(config_path)], env=dict(os.environ))
        config = json.loads(config_path.read_text())
        config["chain_rpc"] = {"urls": rpc_urls, "api_key": None}
        config["elections"] = None
        config_path.write_text(json.dumps(config, indent=2))
        config_path.chmod(0o600)
    listed = json.loads(tosctl_local(name, "wallet", "ls", "--format", "json").stdout)
    if not any(entry.get("name") == name for entry in listed):
        tosctl_local(name, "wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
        listed = json.loads(tosctl_local(name, "wallet", "ls", "--format", "json").stdout)
    return next(fd.norm(entry["address"]) for entry in listed if entry["name"] == name and entry.get("address"))


def node_rpc_urls() -> list[str]:
    return [f"http://127.0.0.1:{port}" for port in fd.RPC_PORTS]


# --- prepare --------------------------------------------------------------------

def prepare() -> int:
    facts = network_facts()
    agree = all(item["genesis_root_hash"] == GENESIS_ROOT and item["genesis_file_hash"] == GENESIS_FILE and
                item["global_version"] >= 16 for item in facts.values())
    if not agree:
        print(json.dumps({"refused": "an endpoint serves another network or global version", "facts": facts}))
        return 3
    wallets = {name: create_wallet(name, node_rpc_urls()) for name in ("provider", "buyer", SWEEPER)}
    # The gateway's relay payer exists so protocol RPC can start; it is never
    # funded and the run relays nothing through the gateway.
    wallets[GATEWAY_WALLET] = create_wallet(GATEWAY_WALLET, [f"http://127.0.0.1:{fd.RPC_PORTS[0]}/jsonRPC"])
    plan = {"wallets": wallets, "funding_nanotos": FUNDING, "total_nanotos": sum(FUNDING.values()),
            "gateway_wallet_funded": False, "network": facts, "fees": fee_parameters(), "utc": now_utc()}
    (WORK / "funding-plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


# --- The gateway, on this host's loopback ---------------------------------------

GATEWAY_DIR = PRIVATE / "gateway"
PROCESSES: dict = {}


def tls_material() -> tuple[Path, Path, Path]:
    """A private CA for this run and a server certificate for 127.0.0.1."""
    directory = GATEWAY_DIR / "tls"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca_key, ca_cert = directory / "ca-key.pem", directory / "ca-cert.pem"
    key, cert = directory / "server-key.pem", directory / "server-cert.pem"
    if not cert.exists():
        def openssl(*args):
            fd.run_logged(["openssl", *args], env=dict(os.environ))
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
        openssl("req", "-x509", "-new", "-key", str(ca_key), "-sha256", "-days", "30", "-subj",
                "/CN=gateway rehearsal CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign", "-out", str(ca_cert))
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        csr = directory / "server.csr"
        openssl("req", "-new", "-key", str(key), "-subj", "/CN=127.0.0.1", "-out", str(csr))
        ext = directory / "server.ext"
        ext.write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                "-days", "30", "-sha256", "-extfile", str(ext), "-out", str(cert))
        for path in directory.iterdir():
            path.chmod(0o600)
    return ca_cert, cert, key


class TLSFront:
    """TLS termination in front of the gateway's loopback HTTP listener, as a
    production terminator would stand: it relays bytes and holds no state."""

    def __init__(self, cert: Path, key: Path, listen: int, backend: int) -> None:
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(cert), str(key))
        self.listen, self.backend = listen, backend
        self.server = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)

        async def pipe(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def handle(reader, writer):
            try:
                up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.backend)
            except OSError:
                writer.close()
                return
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))

        async def start():
            self.server = await asyncio.start_server(handle, "127.0.0.1", self.listen, ssl=self.context)
            self.ready.set()
            await self.server.serve_forever()

        try:
            self.loop.run_until_complete(start())
        except asyncio.CancelledError:
            pass

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("the gateway TLS terminator did not start")

    def stop(self) -> None:
        if self.server is not None:
            self.loop.call_soon_threadsafe(self.server.close)


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as out:
        out.write(data)


def start_gateway() -> None:
    """Protocol RPC, the gateway and its TLS terminator, configured for the
    provider's Capability: the Quote profile names the provider Agent, the
    canonical manifest of the offer and the agent-packet transport."""
    offer = fd.RUN["offer_file"]
    provider_agent = fd.RUN["provider_agent"]
    GATEWAY_DIR.mkdir(mode=0o700, exist_ok=True)
    for sub in ("rpc-state", "quote-state", "catalog"):
        (GATEWAY_DIR / sub).mkdir(mode=0o700, exist_ok=True)
    tokens = {name: secrets.token_hex(32) for name in ("read", "relay", "backend")}
    for value in tokens.values():
        fd.register_secret(value)
    with (PRIVATE / "scan-secrets").open("a") as handle:
        handle.write("".join(value + "\n" for value in tokens.values()))
    write_private(GATEWAY_DIR / "read-token", (tokens["read"] + "\n").encode())
    manifest = GATEWAY_DIR / "manifest.cbor"
    write_private(manifest, base64.b64decode(offer["manifest_cbor_base64"]))
    registry_b64 = fd.REGISTRY_BOC.read_text().strip()
    write_private(GATEWAY_DIR / "registry-code.boc", (registry_b64 + "\n").encode())
    endpoints = fd.rpc_endpoints()
    profile = {"schema": "tos.service.provider-quote-profile.v2", "provider_agent_id": provider_agent,
               "manifest_cbor_file": str(manifest),
               "transport": {"security_mode": 2, "max_request_bytes": 1048576,
                             "base_url": f"agent-packet:{provider_agent}"},
               "proposal_ttl_seconds": 900, "tos_rpc_endpoints": endpoints,
               "registry_code_boc_file": str(GATEWAY_DIR / "registry-code.boc"),
               "service_actor_code_hash": fd.ACTOR_CODE_HASH, "state_directory": str(GATEWAY_DIR / "quote-state")}
    write_private(GATEWAY_DIR / "quote-profile.json", json.dumps(profile, indent=2).encode())
    tosctl_sha = hashlib.sha256(fd.TOSCTL.read_bytes()).hexdigest()
    chain_root = base64.b64encode(bytes.fromhex(GENESIS_ROOT.removeprefix("sha256:"))).decode()
    chain_file = base64.b64encode(bytes.fromhex(GENESIS_FILE.removeprefix("sha256:"))).decode()
    gateway_vault = f"file://{PRIVATE / GATEWAY_WALLET}/vault.json?master_key={MASTER[GATEWAY_WALLET]}"
    native = {"protocol": "tos_service_v1",
              "network": {"network_id": fd.NETWORK_LABEL, "genesis_root_hash": GENESIS_ROOT,
                          "genesis_file_hash": GENESIS_FILE},
              "endpoints": endpoints, "quorum": len(endpoints) // 2 + 1, "registry_workchain": 0,
              "contract_code_boc_base64": registry_b64, "contract_code_hash": REGISTRY_CODE_HASH,
              "funding_nanotos": 200_000_000, "relay_window_seconds": 3600, "max_actions_per_target": 1,
              "max_funding_per_target_nanotos": 200_000_000, "max_actions_per_wallet": 1,
              "max_funding_per_wallet_nanotos": 200_000_000, "recovery_relay_safety_seconds": 300,
              "state_directory": str(GATEWAY_DIR / "rpc-state"),
              "sender": {"network": fd.NETWORK_LABEL, "binary": str(fd.TOSCTL),
                         "configPath": str(PRIVATE / GATEWAY_WALLET / "tosctl-config.json"),
                         "vaultUrl": gateway_vault, "rpcUrl": endpoints[0],
                         "genesisRootHash": chain_root, "genesisFileHash": chain_file,
                         "walletName": GATEWAY_WALLET, "payer": fd.RUN["gateway_wallet"]},
              "signature_helper": {"binary": str(fd.TOSCTL), "sha256": tosctl_sha}}
    fd.register_secret(MASTER[GATEWAY_WALLET])
    write_private(GATEWAY_DIR / "native-v1.json", json.dumps(native, indent=2).encode())
    log = (WORK / "service-rpc.log").open("ab")
    PROCESSES["service-rpc"] = subprocess.Popen(
        [str(SERVICE_RPC), "-listen", f"127.0.0.1:{SERVICE_RPC_PORT}", "-native-v1-config",
         str(GATEWAY_DIR / "native-v1.json")], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
        env=dict(os.environ, TOS_SERVICE_RPC_TOKEN=tokens["backend"]))
    rpc_up = fd.poll(lambda: socket.create_connection(("127.0.0.1", SERVICE_RPC_PORT), timeout=2).close() or True,
                     60, 1)
    fd.require("protocol RPC (tos-service-rpc) serves on this host's loopback with the network's genesis, the "
               "registry release and three endpoints", bool(rpc_up) and PROCESSES["service-rpc"].poll() is None,
               (WORK / "service-rpc.log").read_text()[-1500:])
    env = dict(os.environ, TOS_SERVICE_READ_TOKEN=tokens["read"], TOS_SERVICE_RELAY_TOKEN=tokens["relay"],
               TOS_SERVICE_ADDR=f"127.0.0.1:{GATEWAY_BACKEND_PORT}",
               TOS_SERVICE_PUBLIC_BASE_URL=f"https://127.0.0.1:{GATEWAY_PORT}",
               TOS_SERVICE_TOS_RPC_URL=f"http://127.0.0.1:{SERVICE_RPC_PORT}",
               TOS_SERVICE_TOS_RPC_TOKEN=tokens["backend"], TOS_SERVICE_TOS_RPC_INSECURE="true",
               TOS_SERVICE_CAPABILITY_CATALOG_DIRECTORY=str(GATEWAY_DIR / "catalog"),
               TOS_SERVICE_NETWORK_ID=fd.NETWORK_LABEL, TOS_SERVICE_GENESIS_ROOT_HASH=GENESIS_ROOT,
               TOS_SERVICE_GENESIS_FILE_HASH=GENESIS_FILE, TOS_SERVICE_REGISTRY_CODE_HASH=REGISTRY_CODE_HASH,
               TOS_SERVICE_PROVIDER_QUOTE_PROFILE_FILE=str(GATEWAY_DIR / "quote-profile.json"),
               TOS_SERVICE_CLIENT_ADDRESS_HEADER="none")
    log = (WORK / "gateway.log").open("ab")
    PROCESSES["gateway"] = subprocess.Popen([str(GATEWAY_API)], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                            env=env)
    ca_cert, cert, key = tls_material()
    front = TLSFront(cert, key, GATEWAY_PORT, GATEWAY_BACKEND_PORT)
    front.start()
    PROCESSES["tls-front"] = front
    context = ssl.create_default_context(cafile=str(ca_cert))

    def ready():
        import urllib.request
        with urllib.request.urlopen(f"https://127.0.0.1:{GATEWAY_PORT}/readyz", context=context, timeout=10) as answer:
            return answer.status == 200
    up = fd.poll(ready, 120, 2)
    fd.evidence["gateway"] = {
        "binaries": {"gateway_api": hashlib.sha256(GATEWAY_API.read_bytes()).hexdigest(),
                     "tos_service_rpc": hashlib.sha256(SERVICE_RPC.read_bytes()).hexdigest()},
        "listen": "gateway on 127.0.0.1 behind a TLS terminator run by this script (private CA, SAN 127.0.0.1); "
                  "protocol RPC on 127.0.0.1; the buyer reaches the gateway only through the reverse SSH tunnel",
        "quote_profile": {key_: value for key_, value in profile.items() if key_ not in ("manifest_cbor_file",
                                                                                          "registry_code_boc_file",
                                                                                          "state_directory")},
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "relay_payer_funded": False}
    fd.require("the gateway is ready over TLS on this host's loopback: /readyz answers 200 once protocol RPC is "
               "reachable", bool(up) and PROCESSES["gateway"].poll() is None,
               (WORK / "gateway.log").read_text()[-2000:])
    fd.RUN["gateway_ca"] = str(ca_cert)


def stop_gateway() -> None:
    front = PROCESSES.pop("tls-front", None)
    if front is not None:
        front.stop()
    for name in ("gateway", "service-rpc"):
        process = PROCESSES.pop(name, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()


# --- Buyer host: the chain and gateway tunnel ----------------------------------

def start_tunnel() -> None:
    """The reverse tunnel of the multi-host run, plus the gateway port."""
    listening = mh.on_buyer(["ss", "-ltnH"]).stdout
    ports = [*fd.RPC_PORTS, GATEWAY_PORT]
    taken = [port for port in ports if f":{port} " in listening]
    fd.require("the chain and gateway ports are free on the buyer host", not taken, taken)
    forwards = [arg for port in ports for arg in ("-R", f"127.0.0.1:{port}:127.0.0.1:{port}")]
    argv = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
            "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=20", "-o",
            "ControlMaster=no", "-o", "ControlPath=none", "-i", mh.BUYER_KEY, *forwards, mh.BUYER_SSH]
    log = (WORK / "tunnel.log").open("ab")
    mh.PROCESSES["tunnel"] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    fd.evidence["chain_tunnel"] = {"argv": [redact(part) for part in argv]}
    probe = ("import json,sys,urllib.request\nfor port in sys.argv[1:]:\n    body=json.dumps({'jsonrpc':'2.0','id':1,"
             "'method':'getMasterchainInfo','params':{}}).encode()\n    r=urllib.request.Request("
             "f'http://127.0.0.1:{port}/jsonRPC',data=body,headers={'Content-Type':'application/json'})\n"
             "    print(port, 'result' in json.loads(urllib.request.urlopen(r,timeout=10).read()))\n")

    def answered():
        result = mh.on_buyer([mh.SYSTEM_PYTHON, "-I", "-c", probe, *map(str, fd.RPC_PORTS)], check=False)
        return result.returncode == 0 and result.stdout.count("True") == len(fd.RPC_PORTS)
    ok = fd.poll(answered, 60, 3)
    fd.require("the chain's JSON-RPC reaches the buyer host only through the reverse SSH tunnel, bound to its "
               "127.0.0.1", bool(ok) and mh.PROCESSES["tunnel"].poll() is None, fd.evidence["chain_tunnel"])


# --- Setup: wallets, nodes, gateway ---------------------------------------------

def balance_everywhere(address: str) -> dict[str, int]:
    return {str(port): int(rpc_on(port, "getAddressInformation", address=address)["result"]["balance"])
            for port in fd.RPC_PORTS}


def activate(name: str, address: str) -> None:
    label = f"activate-{name}"
    if fd.account_state(address) == "active":
        return
    quiet_window()
    attempt(label, {"address": address})
    tosctl_local(name, "wallet", "activate", "-n", name)
    active = fd.poll(lambda: fd.account_state(address) == "active", 180, 3)
    done(label, {"active": bool(active)})
    fd.require(f"not OpenFox: the {name} wallet is activated with tosctl", bool(active), address)


def wallets_ready() -> None:
    plan = json.loads((WORK / "funding-plan.json").read_text())
    wallets = plan["wallets"]
    facts = network_facts()
    fd.evidence["network"] = {"network_id": fd.NETWORK_LABEL, "genesis_root_hash": GENESIS_ROOT,
                              "genesis_file_hash": GENESIS_FILE, "endpoints": facts,
                              "json_rpc": "three validator loopback JSON-RPC listeners reached through SSH forwards"}
    fd.require("every endpoint serves the pinned network at global version 16 or later",
               all(item["genesis_root_hash"] == GENESIS_ROOT and item["genesis_file_hash"] == GENESIS_FILE and
                   item["global_version"] >= 16 for item in facts.values()), facts)
    funded = {name: balance_everywhere(wallets[name]) for name in FUNDING}
    fd.evidence["funding"] = {"plan": FUNDING, "balances_at_start": funded, "source": "the network operator"}
    fd.require("not OpenFox: every wallet holds its planned funding on every endpoint (sent by the operator)",
               all(min(values.values()) >= FUNDING[name] or fd.account_state(wallets[name]) == "active"
                   for name, values in funded.items()), funded)
    for name in FUNDING:
        activate(name, wallets[name])
    fd.RUN["wallets"] = {"provider": wallets["provider"], "buyer": wallets["buyer"]}
    fd.RUN["sweeper"] = wallets[SWEEPER]
    fd.RUN["gateway_wallet"] = wallets[GATEWAY_WALLET]
    fd.evidence["wallets"] = {**fd.RUN["wallets"], SWEEPER: wallets[SWEEPER]}
    # The nodes' vaults and configurations, where staging takes them.
    for node in fd.NODES:
        source = PRIVATE / node
        if not (source / "vault.json").exists():
            raise RuntimeError(f"{node} vault is missing")


def setup_nodes() -> None:
    """The front-door setup with the gateway in the buyer's configuration."""
    provider_wallet = fd.RUN["wallets"]["provider"]
    quiet_window()
    init = fd.fox_json("provider", "init", *fd.init_flags("provider"), "--yes")
    provider_agent, agent_address = init.get("agent_id", ""), init.get("agent_address", "")
    fd.require("provider init registered the node's Agent and wrote the rail configuration",
               init.get("confirmed") is True and provider_agent.startswith("agent_") and
               fd.account_state(agent_address) == "active" and init.get("wallet_address") == provider_wallet, init)
    quiet_window()
    offer = fd.fox_json("provider", "offer", *fd.offer_flags(), "--yes")
    plan = offer.get("preview") or {}
    actor, capability_address = plan.get("actor", ""), plan.get("capability_address", "")
    data = fd.service_data(actor) if actor else {}
    fd.require("provider offer deployed a fresh Service Actor, registered the Capability and set the policy (read "
               "from the chain)", offer.get("confirmed") is True and fd.account_state(actor) == "active" and
               fd.account_state(capability_address) == "active" and data.get("active") == 1 and
               data.get("price") == fd.PRICE_NANO and data.get("storage_fee") == fd.STORAGE_FEE_NANO and
               data.get("next_request_id") == 0, {"offer": offer, "service_data": data})
    code = actor_code_everywhere(actor)
    fd.require("the deployed actor's code hash is the pinned Service Actor release on every endpoint",
               all(value == fd.ACTOR_CODE_HASH for value in code.values()), code)
    offer_file = fd.root_json(offer.get("offer_file", ""))
    fd.RUN.update(provider_agent=provider_agent, provider_agent_address=agent_address, actor=actor,
                  capability_address=capability_address, offer_path=offer.get("offer_file", ""),
                  offer_file=offer_file, capability_id=plan.get("capability_id"))
    fd.evidence["objects"] = {"provider_agent_id": provider_agent, "provider_agent_address": agent_address,
                              "actor": actor, "actor_code_hash_per_endpoint": code,
                              "capability_id": plan.get("capability_id"), "capability_address": capability_address,
                              "manifest_digest": plan.get("manifest_digest"), "metadata_hash": plan.get("metadata_hash")}
    save_state()
    start_gateway()
    token = mh.REMOTE_ROOT / "buyer" / "gateway-token"
    mh.upload(GATEWAY_DIR / "read-token", str(token), "0600")
    mh.upload(Path(fd.RUN["gateway_ca"]), str(mh.REMOTE_ROOT / "etc" / "gateway-ca.pem"), "0600")
    gateway_flags = ["--gateway-url", f"https://127.0.0.1:{GATEWAY_PORT}",
                     "--gateway-token-file", str(fd.ROOT / "buyer" / "gateway-token"),
                     "--gateway-ca-file", str(fd.ROOT / "etc" / "gateway-ca.pem"),
                     "--caller-id", "gated-rehearsal-buyer"]
    quiet_window()
    buyer_init = fd.fox_json("buyer", "init", *fd.init_flags("buyer"), "--allow-provider", provider_agent,
                             *gateway_flags, "--yes")
    buyer_agent = buyer_init.get("agent_id", "")
    fd.require("buyer init registered the buyer's Agent, allows the provider and names the gateway",
               buyer_init.get("confirmed") is True and buyer_agent.startswith("agent_") and
               fd.account_state(buyer_init.get("agent_address", "")) == "active" and buyer_agent != provider_agent,
               buyer_init)
    fd.RUN.update(buyer_agent=buyer_agent, buyer_agent_address=buyer_init["agent_address"])
    fd.evidence["objects"].update(buyer_agent_id=buyer_agent, buyer_agent_address=buyer_init["agent_address"])
    configs = {node: fd.root_json(fd.rail(node)) for node in fd.NODES}
    fd.require("both nodes name only the installed relays and no direct peer; the buyer names the gateway",
               all(c.get("relay_urls") == fd.RELAY_URLS and not c.get("direct_peers") for c in configs.values()) and
               (configs["buyer"].get("buyer") or {}).get("gateway_url") == f"https://127.0.0.1:{GATEWAY_PORT}",
               {node: {key: c.get(key) for key in ("relay_urls", "direct_peers")} for node, c in configs.items()})
    save_state()
    fd.start_serve("buyer")
    preflight = fd.fox_again("provider", "preflight", "--rail-config", fd.rail("provider"))
    report = fd.strict_json(preflight)
    failing = [check for check in report.get("checks", []) if check.get("status") == "fail"]
    fd.evidence["preflight_not_passing"] = [c for c in report.get("checks", []) if c.get("status") != "pass"]
    fd.require("provider preflight is ok", preflight.returncode == 0 and report.get("ok") is True and not failing,
               failing)
    fd.start_serve("provider")
    fd.require("both serve processes run", fd.SERVING["provider"].poll() is None and
               fd.SERVING["buyer"].poll() is None, {"provider": fd.serve_log("provider")[-800:]})


def actor_code_everywhere(actor: str) -> dict:
    from pytosiq_core import Cell
    codes = {}
    for port in fd.RPC_PORTS:
        info = rpc_on(port, "getAddressInformation", address=actor)["result"]
        codes[str(port)] = "tvm-cell-sha256:" + Cell.one_from_boc(base64.b64decode(info["code"])).hash.hex()
    return codes


# --- Purchases ------------------------------------------------------------------

def buy(label: str, use_offer: bool) -> dict:
    """One purchase, once: its marker is written before `buy` runs. With
    use_offer the Quote is built from the provider's offer file (and the
    buyer learns the provider's relay key card); otherwise the gateway
    quotes it."""
    previous = result_of(label)
    if previous is not None:
        return previous["purchase"]
    quiet_window()
    before = fd.service_data(fd.RUN["actor"])["next_request_id"]
    attempt(label, {"next_request_id_before": before, "quote_source": "offer file" if use_offer else "gateway"})
    source = ["--offer", fd.RUN["offer_path"]] if use_offer else \
        ["--capability-id", fd.RUN["capability_id"], "--version", "1.0.0"]
    bought = fd.fox("buyer", "buy", "--rail-config", fd.rail("buyer"), *source,
                    "--source", str(fd.ROOT / "buyer" / "source.tar"), "--yes", check=False)
    purchase = fd.strict_json(bought) if bought.returncode == 0 and bought.stdout.strip() else {}
    done(label, {"exit": bought.returncode, "purchase": purchase, "stderr": redact(bought.stderr[-1500:])})
    fd.require(f"{label}: buyer buy ({'offer file' if use_offer else 'gateway Quote'}) called the actor",
               bought.returncode == 0 and purchase.get("phase") == "called" and
               purchase.get("actor") == fd.RUN["actor"] and purchase.get("price_nanotos") == str(fd.PRICE_NANO),
               bought.stderr[-2000:] or purchase)
    fd.RUN.setdefault("purchases", {})[label] = purchase["request_hash"]
    save_state()
    return purchase


def wait_phase(request_hash: str, phases: tuple, timeout: float) -> dict:
    return fd.poll(lambda: (lambda row: row if row.get("phase") in phases else None)(fd.purchase_of(request_hash)),
                   timeout, 10) or fd.purchase_of(request_hash)


def verify_responded(label: str, purchase: dict) -> None:
    request_hash = purchase["request_hash"]
    finished = wait_phase(request_hash, ("completed", "receipt-mismatch", "refused", "not-called"), 1200)
    request = fd.poll(lambda: (lambda row: row if row.get("state") == "acked" else None)(fd.request_of(request_hash)),
                      300, 10) or fd.request_of(request_hash)
    facts = fd.actor_facts(fd.RUN["actor"])
    responds = [row for row in facts["responds"] if row.get("request_id") == finished.get("request_id")]
    fd.require(f"{label}: responded: the buyer accepted the result, the provider holds the acknowledgement, and "
               "the chain holds one respond for the request whose response hash is the one both nodes report",
               finished.get("phase") == "completed" and finished.get("status") == "responded" and
               request.get("chain_fact") == "responded" and request.get("state") == "acked" and len(responds) == 1 and
               responds[0].get("response_hash") == finished.get("response_hash") == request.get("response_hash"),
               {"purchase": {k: v for k, v in finished.items() if k != "cost_disclosure"},
                "provider_request": request, "responds": responds})
    fd.evidence.setdefault("sales", {})[label] = {"request_hash": request_hash, "request_id": finished.get("request_id"),
                                                  "outcome": "responded", "response_hash": finished.get("response_hash"),
                                                  "respond": responds[0]}


def request_state(request_id: int) -> dict:
    """The actor's own view of one request (tosctl, read only)."""
    result = tosctl_local(SWEEPER, "agent", "service", "request-show", "--address", fd.RUN["actor"],
                          "--request-id", str(request_id), "--format", "json", check=False)
    try:
        return json.loads(result.stdout) if result.returncode == 0 else {"exit": result.returncode}
    except ValueError:
        return {"unparsed": result.stdout[-500:]}


def sweep(label: str, request_id: int) -> dict:
    previous = result_of(label)
    if previous is not None:
        return previous
    quiet_window()
    before = fd.balance(fd.RUN["sweeper"])
    attempt(label, {"request_id": request_id, "sweeper_balance_before": before})
    sent = tosctl_local(SWEEPER, "agent", "service", "send", "--operation", "sweep-expired-request",
                        "--address", fd.RUN["actor"], "--from", SWEEPER, "--request-id", str(request_id), "--yes",
                        check=False)
    outcome = {"exit": sent.returncode, "stderr": redact(sent.stderr[-1500:])}
    done(label, outcome)
    return outcome


def deadline_of(request_hash: str, field: str) -> int:
    row = fd.purchase_of(request_hash)
    value = row.get(field)
    if not value:
        raise RuntimeError(f"{field} of {request_hash} is unknown")
    return int(value)


def chain_time() -> int:
    return int(fd.rpc("getMasterchainInfo")["result"].get("last_utime") or time.time())


def wait_until(unix: int, why: str) -> None:
    while time.time() < unix:
        left = int(unix - time.time())
        print(f"waiting {left} s: {why}", flush=True)
        time.sleep(min(300, max(5, left)))


def unanswered_sales() -> None:
    """Sale S (swept) and sale F (refunded), with the provider paused."""
    paused = fd.fox_json("provider", "pause", "--rail-config", fd.rail("provider"), "--reason",
                         "public rehearsal: unanswered sales")
    fd.require("provider pause is in effect", paused.get("paused") is True, paused)
    s = buy("sale-s", use_offer=False)
    s_hash = s["request_hash"]
    sent = wait_phase(s_hash, ("task-sent",), 600)
    fd.record("sale S: the task is deposited at the relays while the provider is paused",
              sent.get("phase") == "task-sent", {k: v for k, v in sent.items() if k != "cost_disclosure"})
    code = fd.stop_serve("buyer")
    fd.record("sale S: the buyer node is stopped, so nobody claims its refund", code == 0, code)
    response_deadline = deadline_of(s_hash, "response_deadline")
    refund_deadline = deadline_of(s_hash, "refund_claim_deadline")
    fd.evidence["sale_s_deadlines"] = {"response_deadline": response_deadline, "refund_claim_deadline": refund_deadline}
    save_state()
    wait_until(response_deadline + 60, "sale S's response deadline")
    f = buy("sale-f", use_offer=False)
    f_hash = f["request_hash"]
    fd.evidence["sale_f_called"] = {k: v for k, v in f.items() if k != "cost_disclosure"}
    save_state()
    # The buyer node stays stopped until S's refund window has lapsed; F is
    # then overdue too, and the buyer's refund duty takes it.
    f_row = fd.purchase_of(f_hash)
    f_deadline = int(f_row.get("response_deadline") or 0) or (int(time.time()) + SLA_S)
    wait_until(max(refund_deadline, f_deadline) + 90, "sale S's refund window and sale F's response deadline")
    early = request_state(int(s.get("request_id") or fd.purchase_of(s_hash).get("request_id")))
    fd.evidence["sale_s_before_sweep"] = early
    fd.start_serve("buyer")
    refunded = wait_phase(f_hash, ("refunded", "lapsed", "swept", "refused"), 1800)
    fd.require("sale F: refunded: the buyer's refund duty sent expire and claim_refund after the response deadline "
               "and the purchase is refunded", refunded.get("phase") == "refunded" and
               refunded.get("status") == "refunded",
               {k: v for k, v in refunded.items() if k != "cost_disclosure"})
    lapsed = wait_phase(s_hash, ("lapsed", "swept", "refunded"), 600)
    fd.record("sale S: the buyer finds its refund window lapsed and claims nothing",
              lapsed.get("phase") in ("lapsed", "swept") and lapsed.get("phase") != "refunded",
              {k: v for k, v in lapsed.items() if k != "cost_disclosure"})
    request_id = int(lapsed.get("request_id"))
    sweeper_before = fd.balance(fd.RUN["sweeper"])
    outcome = sweep("sweep-sale-s", request_id)
    swept = wait_phase(s_hash, ("swept",), 900)
    facts = fd.transactions(fd.RUN["actor"])
    sweeps = [row for row in facts if row.get("op") == 0x53564305 and row["in_source"] == fd.RUN["sweeper"]
              and not row["aborted"]]
    bounty = [out for row in sweeps for out in row["outs"] if out["destination"] == fd.RUN["sweeper"]]
    fd.require("sale S: swept: the sweeper's sweep_expired_request succeeded on chain, paid the sweeper the "
               "cleanup bounty, and the buyer reports the purchase swept",
               outcome.get("exit") == 0 and len(sweeps) == 1 and bool(bounty) and
               any(out["value"] >= BOUNTY_NANO for out in bounty) and swept.get("phase") == "swept",
               {"sweep": outcome, "transactions": sweeps, "purchase": {k: v for k, v in swept.items()
                                                                        if k != "cost_disclosure"},
                "sweeper_balance_before": sweeper_before})
    fd.evidence.setdefault("sales", {}).update({
        "sale-f": {"request_hash": f_hash, "request_id": refunded.get("request_id"), "outcome": "refunded"},
        "sale-s": {"request_hash": s_hash, "request_id": request_id, "outcome": "swept", "sweep": sweeps[0]}})
    resumed = fd.fox_json("provider", "resume", "--rail-config", fd.rail("provider"))
    fd.record("provider resume is in effect", resumed.get("paused") is False, resumed)


def final_withdraw() -> None:
    quiet_window()
    result = fd.fox_again("provider", "withdraw", "--rail-config", fd.rail("provider"), "--all", "--yes")
    rows = fd.poll(lambda: (lambda rows: rows if rows and rows[0].get("state") in ("finalized", "failed",
                                                                                     "not_included") else None)(
        (fd.fox_again("provider", "withdraw", "--rail-config", fd.rail("provider"), "--all", "--yes") and
         fd.provider_status().get("withdrawals", []))), 600, 20) or []
    data = fd.service_data(fd.RUN["actor"])
    fd.record("provider withdraw --all: the last withdrawal is finalized and no revenue is left credited",
              bool(rows) and rows[0].get("state") == "finalized" and data["withdrawable_revenue"] == 0,
              {"withdrawals": rows[:3], "service_data": data, "stderr": result.stderr[-800:]})


def relays_answer() -> dict:
    return {relay.name: mh.relay_up(relay) for relay in mh.RELAYS}


def sale() -> None:
    wallets_ready()
    mh.stage()
    start_tunnel()
    before = relays_answer()
    fd.require("every installed relay answers over TLS with the pinned CA (read only; no relay host is logged in "
               "to)", all(before.values()), before)
    setup_nodes()
    first = buy("sale-r0", use_offer=True)
    fd.verify_sale(first)
    fd.withdraw()
    second = buy("sale-r1", use_offer=False)
    verify_responded("sale-r1", second)
    unanswered_sales()
    final_withdraw()
    after = relays_answer()
    fd.record("every installed relay still answers at the end (never stopped or started by this run)",
              all(after.values()), after)


def finish() -> None:
    if set(fd.SERVING) == set(fd.NODES):
        fd.stop_nodes()
    for node in list(fd.SERVING):
        fd.stop_serve(node)
    stop_gateway()
    tunnel = mh.PROCESSES.pop("tunnel", None)
    if tunnel is not None:
        tunnel.terminate()
        tunnel.wait(timeout=30)
    try:
        left = mh.on_buyer(["sh", "-c", f"pgrep -af {shlex.quote(str(mh.REMOTE_BASE))} || true; ss -ltnH"],
                           check=False).stdout
        tunnelled = [port for port in (*fd.RPC_PORTS, GATEWAY_PORT) if f"127.0.0.1:{port} " in left]
        fd.evidence["teardown"] = {"buyer_processes_of_this_run": [line for line in left.splitlines()
                                                                    if str(mh.REMOTE_BASE) in line and
                                                                    "pgrep" not in line],
                                   "tunnel_ports_still_bound_on_buyer_host": tunnelled,
                                   "left_on_buyer_host": str(mh.REMOTE_BASE)}
        fd.record("teardown: no node process of this run on the buyer host and the tunnel is closed",
                  not fd.evidence["teardown"]["buyer_processes_of_this_run"] and not tunnelled,
                  fd.evidence["teardown"])
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("teardown ran", False, redact(repr(error)))
    subprocess.run(["ssh", "-o", f"ControlPath={mh.CONTROL}/%C", "-O", "exit", "-i", mh.BUYER_KEY, mh.BUYER_SSH],
                   capture_output=True, timeout=30)
    fd.scan_artifacts()


def run() -> int:
    for key in MASTER.values():
        fd.register_secret(key)
    secret_file = PRIVATE / "scan-secrets"
    secret_file.write_text("".join(key + "\n" for key in MASTER.values()))
    secret_file.chmod(0o600)
    tree = mh.git(fd.REPO, "status", "--porcelain").splitlines()
    fd.evidence.update({
        "schema": "tos.openfox.service-relay-public.rehearsal.v1",
        "qualifies_as_public_acceptance": False,
        "reason": "a rehearsal on a public test network: the relays, the gateway, the provider and the buyer are "
                  "all operated by the project; the gateway is on loopback behind a TLS terminator, not public "
                  "HTTPS",
        "proves": "OpenFox nodes on two machines sell software work through a fresh Service Actor on a public TOS "
                  "test network, with Quotes from the gateway and every packet carried by the installed relays; "
                  "the sales end responded, refunded and swept",
        "started_utc": now_utc(), "openfox_commit": mh.git(fd.REPO, "rev-parse", "HEAD"),
        "openfox_tree_status": tree, "tos_commit": mh.git(fd.SOURCE, "rev-parse", "HEAD"),
        "actor_code_hash": fd.ACTOR_CODE_HASH, "registry_code_hash": REGISTRY_CODE_HASH,
        "network_label": fd.NETWORK_LABEL,
        "terms": {"price": fd.PRICE, "storage_fee": fd.STORAGE_FEE, "cleanup_bounty": fd.CLEANUP_BOUNTY,
                  "response_sla_s": SLA_S, "refund_claim_window_s": REFUND_WINDOW_S},
        "relays": {"urls": [f"<{relay.name}>" for relay in mh.RELAYS], "access": "HTTPS only; never stopped, "
                   "started or logged in to"},
        "not_verified": ["a relay, gateway or provider operated by a third party",
                         "a public HTTPS gateway (loopback here; Gate F)",
                         "gateway discovery (List/Search) and catalog publication",
                         "a third-party Service Actor resolve/verify tool (none exists yet)",
                         "crash windows of the nodes"],
        "known_effects": ["the relay TTL is 1 h: the deposited task of a refunded or swept sale expires at the "
                          "relays unread, as intended"],
        "not_openfox": ["creating the wallets and activating them with tosctl; their funding by the operator",
                        "the gateway, protocol RPC and the TLS terminator in front of the gateway",
                        "the SSH forwards to the validators and the reverse tunnel to the buyer host",
                        "the sweeper's sweep_expired_request, sent with tosctl",
                        "the executor service and its container runtime",
                        "this script's own JSON-RPC reads, used only to verify"]})
    fd.record("the OpenFox tree is clean at the commit the evidence names", not tree, tree or "clean")
    shutil_copy(GLOBAL_CONFIG, WORK / "global.json")
    try:
        sale()
    except fd.Stop:
        pass
    except Exception:  # noqa: BLE001 - the evidence records the failure
        import traceback
        fd.record("the run completed without an exception", False, redact(traceback.format_exc())[-3000:])
    finally:
        finish()
    fd.evidence["steps"] = fd.steps
    fd.evidence["finished_utc"] = now_utc()
    text = json.dumps(fd.redact_value(fd.evidence), default=str)
    leaked = fd.personal_data(text) + [f"unlabelled {name}" for name in mh.raw_addresses(text)]
    fd.record("no home directory path, login name, e-mail address, SSH key path, public address or SSH target in "
              "evidence.json", not leaked, leaked)
    passed = bool(fd.steps) and all(step["pass"] for step in fd.steps)
    fd.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


def shutil_copy(source: Path, target: Path) -> None:
    target.write_bytes(source.read_bytes())
    target.chmod(0o600)


if __name__ == "__main__":
    sys.exit(prepare() if COMMAND == "prepare" else run())
