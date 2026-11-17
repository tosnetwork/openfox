#!/usr/bin/env python3
"""Messenger relay carriage milestone M-R2 (spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md
sections 8 and 11): private MLS rooms and invites between three OpenFox
nodes A, B and C, each with its own finalized Agent, tos-messengerd (with the
OpenMLS driver) and chat key, carried only by two Agent Packet Relay daemons.
A is the room's authority.

Local mode (the default): one host, the M-R1 namespace layout
(scripts/messenger-relay-two-host-net.sh) with two more node namespaces,
tosmr-d and tosmr-e, for the two filler joiners D and E: Agents A adds and
removes only so the authority makes the Commits the gate asks for (the
daemon has no operation for an MLS-only refresh Commit). D and E never post.
The relays run with a short TTL (MR2_RELAY_TTL) standing in for the test
relays' 1 h; the record states it.

This module reuses the M-R1 harness (messenger-relay-two-host-e2e.py) for the
chain, the namespaces, the processes, the identities and the relay reads, and
adds the room steps. Every M-R2 gate item is either a run step (the
evidence's `gate_items` maps each item to its steps) or listed in
`not_verified` with the named unit tests that cover it.

Owner decisions are made as the owner makes them: openfox prepares the
decision (`openfox earning chat room ...`, `chat contact import --invite`),
the owner key signs it with `tos-messenger-owner sign` (the run plays the
owner; openfox never reads the key), and openfox submits it (`chat owner
submit`). C's invites are issued with `tos-messenger-owner prepare-invite`
and `submit`, as C's owner would.

Run it through scripts/messenger-relay-three-host-rooms-e2e.sh.
"""

import asyncio
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mr1", HERE / "messenger-relay-two-host-e2e.py")
mr1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr1)
fd = mr1.fd

WORK, PRIVATE, ROOT, BIN = mr1.WORK, mr1.PRIVATE, mr1.ROOT, mr1.BIN
NODES = ("a", "b", "c", "d", "e")
MEMBERS = ("a", "b", "c")
FILLERS = ("d", "e")
mr1.NODES = NODES
mr1.ADDRESS.update({"d": "10.231.78.13", "e": "10.231.78.14"})
mr1.NAMESPACE.update({name: f"tosmr-{name}" for name in ("d", "e")})
mr1.HIDE = {node: [PRIVATE, *(ROOT / other for other in NODES if other != node), *(WORK / r for r in mr1.RELAYS)]
            for node in NODES}
mr1.HIDE.update({relay: [PRIVATE, ROOT.parent, *(WORK / r for r in mr1.RELAYS if r != relay)]
                 for relay in mr1.RELAYS})
fd.NODES = NODES
fd.MASTER_KEYS = {node: secrets.token_hex(32) for node in NODES}

RELAYS, RELAY_URL, RELAY_URLS = mr1.RELAYS, mr1.RELAY_URL, mr1.RELAY_URLS
RUN, SENT = mr1.RUN, mr1.SENT
record, require, poll = fd.record, fd.require, fd.poll
nd, sock, rail, mdir, card_path, read_json = mr1.nd, mr1.sock, mr1.rail, mr1.mdir, mr1.card_path, mr1.read_json
in_ns, node_env, now, mcall, idem = mr1.in_ns, mr1.node_env, mr1.now, mr1.mcall, mr1.idem
frames_of, inbound_texts, take, deliveries = mr1.frames_of, mr1.inbound_texts, mr1.take, mr1.deliveries
stop_node, start_node, stop_daemon, start_daemon = mr1.stop_node, mr1.start_node, mr1.stop_daemon, mr1.start_daemon
stop_serve, start_serve, listed_ids, deposit = mr1.stop_serve, mr1.start_serve, mr1.listed_ids, mr1.deposit
craft, hand_file, snapshot, log_text = mr1.craft, mr1.hand_file, mr1.snapshot, mr1.log_text

TEXT = mr1.TEXT
MLS_DRIVER = BIN / "tos-openmls-driver"
RELAY_TTL = int(os.environ.get("MR2_RELAY_TTL", "900"))
REDEPOSIT = mr1.REDEPOSIT
ROOMTEST = os.environ.get("MR2_ROOMTEST") == "1"
PART_BYTES = int(os.environ.get("MR2_ROOM_PART_BYTES", "0"))
RETENTION = int(os.environ.get("MR2_HANDSHAKE_RETENTION", "0"))
AUTHORIZATION = int(os.environ.get("MR2_AUTHORIZATION_SECONDS", "0"))
ROOM = "room_" + secrets.token_hex(32)
CONV = "conv_" + secrets.token_hex(32)
GATE: dict[str, list[str]] = {}
NOT_VERIFIED: list = []
SECRETS_HANDED: list[str] = []


def gate(item: str, name: str, ok: bool, detail=None, required: bool = True) -> bool:
    """A step that proves (part of) one M-R2 gate item."""
    GATE.setdefault(item, []).append(name)
    if required:
        require(f"[M-R2 {item}] {name}", ok, detail)
        return True
    return record(f"[M-R2 {item}] {name}", ok, detail)


def mr1_gate(item: str, name: str, ok: bool, detail=None, required: bool = True) -> bool:
    # The reused M-R1 setup proves M-R1 item 1 (relay only), which M-R2's
    # preamble requires as written there.
    return gate("relay-only" if item == "1" else f"M-R1 {item}", name, ok, detail, required)


mr1.gate = mr1_gate


# --- Configuration ------------------------------------------------------------------

ALLOW = {"a": ["b", "c", "d", "e"], "b": ["a"], "c": [], "d": ["a"], "e": ["a"]}


def relay_argv(relay: str) -> list[str]:
    return [*_mr1_relay_argv(relay), "-ttl", f"{RELAY_TTL}s"]


_mr1_relay_argv = mr1.relay_argv
mr1.relay_argv = relay_argv


def daemon_config(node: str) -> dict:
    """The M-R1 daemon configuration with this run's allow-lists and the
    room runtime (the OpenMLS driver and the own relays' TTL)."""
    identity = RUN[node]["identity"]
    config = {
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
                      "known_agent_ids": sorted(RUN[p]["agent"] for p in ALLOW[node]),
                      "max_content_bytes": 128 << 10, "max_clock_skew_seconds": 300},
        "firewall": {"unattended_ceiling": "message", "own_initiative_ceiling": "message"},
        "transport": "agent-packet-relay",
        "relay_carriage": {"carry_socket_path": str(sock(node, "chat-carrier.sock")),
                           "listen_socket_path": str(sock(node, "carrier.sock")),
                           "card_path": str(card_path(node)), "evidence_export_dir": str(mdir(node) / "export"),
                           "timeout_seconds": mr1.CHAT_TIMEOUT, "redeposit_interval_seconds": REDEPOSIT},
        "sweep_interval_seconds": 2,
        "maintenance_interval_seconds": 3600,
    }
    carriage = config["relay_carriage"]
    carriage["mls_driver_path"] = str(ROOT / "bin" / "tos-openmls-driver")
    carriage["own_relay_max_ttl_seconds"] = RELAY_TTL
    if PART_BYTES:
        carriage["room_part_bytes"] = PART_BYTES
    if RETENTION:
        carriage["room_handshake_retention_seconds"] = RETENTION
    if AUTHORIZATION:
        carriage["room_authorization_seconds"] = AUTHORIZATION
    return config


mr1.daemon_config = daemon_config


def init_nodes() -> None:
    """The M-R1 node initialisation for every node of this run."""
    for node in NODES:
        init = mr1.fox_json(node, "service", "init", *mr1.init_flags(node), "--yes")
        agent, address = init.get("agent_id", ""), init.get("agent_address", "")
        require(f"{node}: `openfox earning service init` registered the node's Agent and wrote a chat section",
                init.get("confirmed") is True and agent.startswith("agent_") and
                fd.account_state(address) == "active", init)
        config = read_json(rail(node))
        RUN[node] = {"agent": agent, "agent_address": address, "controller": config["packet_controller"],
                     "key_id": config["packet_key_id"], "wallet": config["wallet_address"]}
        chat = mr1.fox_json(node, "chat", "init", "--rail-config", str(rail(node)))
        RUN[node]["chat_key"] = chat.get("key_id")
        require(f"{node}: `openfox earning chat init` issued the chat key and published a card naming both relays",
                chat.get("agent_id") == agent and chat.get("relays") == RELAY_URLS and card_path(node).is_file(), chat)
    agents = {node: RUN[node]["agent"] for node in NODES}
    fd.evidence["objects"] = {node: {"agent_id": RUN[node]["agent"], "agent_address": RUN[node]["agent_address"]}
                              for node in NODES}
    require(f"{len(NODES)} distinct Agents", len(set(agents.values())) == len(NODES), agents)
    configs = {node: read_json(rail(node)) for node in NODES}
    ca = mr1.CA.read_bytes()
    gate("relay-only", "every node names both relays for rail and chat, pins the run's CA and names no direct peer "
         "and no Messenger packet socket",
         all(c.get("relay_urls") == RELAY_URLS and not c.get("direct_peers") and not c.get("messenger_socket") and
             c.get("relay_ca_sha256") == hashlib.sha256(ca).hexdigest() and
             Path(c.get("relay_ca_file", "")).read_bytes() == ca and (c.get("chat") or {}).get(
                 "messenger_carrier_socket") == str(sock(n, "carrier.sock")) for n, c in configs.items()),
         {n: {k: c.get(k) for k in ("relay_urls", "direct_peers", "messenger_socket", "relay_ca_sha256")}
          for n, c in configs.items()})


def identities() -> None:
    """The M-R1 Messaging Endpoint identities, with a delegation that also
    grants the room event class (room.invite, room.key-package and the room
    messages)."""
    for node in NODES:
        out = in_ns(node, [ROOT / "bin" / "messenger-relay-e2e-tool", "identity", "--agent", RUN[node]["agent"],
                           "--network-id", RUN["domain"]["network_id"], "--genesis-root", RUN["domain"]["genesis_root"],
                           "--genesis-file", RUN["domain"]["genesis_file"], "--rule", "allow-list",
                           "--unknown", "require-admission", "--descriptor-lifetime", str(mr1.DESCRIPTOR_LIFETIME),
                           "--delegation-lifetime", str(2 * 86400), "--session-lifetime", str(86400),
                           "--classes", "agent.packet,room,text",
                           "--private-dir", nd(node) / "keys", "--public-dir", mdir(node)],
                    "messenger-relay-e2e-tool identity", timeout=60)
        RUN[node]["identity"] = json.loads(out.stdout)
        action = mr1.registry_action(node, "delegate", "--delegation", RUN[node]["identity"]["delegation_digest_hex"])
        ok = bool(action["landed"]) and all(row["compute_success"] and not row["aborted"] for row in action["landed"])
        require(f"not OpenFox: {node}'s Messaging Endpoint delegation (relay-only, classes agent.packet, room and "
                "text, allow-list inbox) is committed by its Agent on chain", ok,
                {"identity": RUN[node]["identity"], "action": action})
    fd.evidence["messenger_identities"] = {node: {key: RUN[node]["identity"][key] for key in (
        "endpoint_id", "device_id", "delegation_digest", "descriptor_policy_digest", "inbox_policy_digest")}
        for node in NODES}


def chat_owner_socket() -> None:
    """The owner points each node's chat section at its daemon's owner
    socket, which `chat room`, `chat invite` and `chat owner submit` use."""
    for node in NODES:
        config = read_json(rail(node))
        config["chat"]["owner_socket"] = str(sock(node, "owner.sock"))
        rail(node).write_text(json.dumps(config, indent=2) + "\n")
        rail(node).chmod(0o600)
    fd.evidence["chat_owner_socket"] = "each node's rail configuration names chat.owner_socket, the daemon's " \
                                       "owner_socket_path"


def room_settings_check() -> None:
    fd.evidence["daemon_configuration"]["admission"] = {
        node: "allow-list: " + (", ".join(p.upper() for p in ALLOW[node]) or "nobody") +
        " (unknown senders: require-admission)" for node in NODES}
    lines = {}
    for node in NODES:
        check = in_ns(node, [ROOT / "bin" / "tos-messengerd", "-config", mdir(node) / "config.json",
                             "-publication-operator-config", mdir(node) / "publication.json", "-check"],
                      "tos-messengerd -check", check=False, timeout=60)
        lines[node] = [line for line in check.stdout.splitlines() if line.startswith("room_settings")]
    fd.evidence["room_settings"] = {
        "relay_ttl_seconds": RELAY_TTL, "roomtest_build": ROOMTEST, "room_part_bytes": PART_BYTES or "production cut",
        "room_handshake_retention_seconds": RETENTION or "production (7 days)",
        "room_authorization_seconds": AUTHORIZATION or "production (24 h)",
        "redeposit_interval_seconds": REDEPOSIT, "daemon_check_lines": lines,
        "daemon_build_tags": "roomtest" if ROOMTEST else "none (production build)",
        "note": "the relay TTL stands in for the test relays' 1 h; test settings are set only in a roomtest build"}


# --- Owner decisions ---------------------------------------------------------------------

DECISIONS: list[dict] = []


def fox(node: str, *args: str, check: bool = True):
    return mr1.fox(node, *args, check=check)


def owner_sign(node: str, prepared: Path) -> Path:
    """The owner signs a prepared decision with its own tool and key; the
    run plays the owner, openfox never reads the key."""
    signed = prepared.with_name(prepared.stem + "-signed.json")
    in_ns(node, [ROOT / "bin" / "tos-messenger-owner", "-out", signed, "sign", "-key", nd(node) / "keys" / "owner.key",
                 "-decision", prepared], "tos-messenger-owner sign", timeout=60)
    return signed


def decision_path(node: str, name: str) -> Path:
    directory = nd(node) / "decisions"
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory / f"{len(DECISIONS):03d}-{name}.json"


def submit(node: str, signed: Path) -> dict:
    result = fox(node, "chat", "owner", "submit", "--rail-config", str(rail(node)), "--decision", str(signed),
                 check=False)
    try:
        answer = json.loads(result.stdout) if result.returncode == 0 else {}
    except ValueError:
        answer = {}
    # `chat owner submit` prints the daemon's answer and exits non-zero on a
    # refusal.
    answer["ok"] = result.returncode == 0 and bool(answer)
    if result.returncode != 0:
        answer["error"] = fd.redact(result.stderr)[-800:]
    return answer


def room_op(node: str, op: str, agent: str | None = None) -> dict:
    """One room membership decision through openfox, signed by the owner."""
    prepared = decision_path(node, f"room-{op}")
    args = ["chat", "room", op, "--rail-config", str(rail(node)), "--room", ROOM, "--out", str(prepared)]
    if op in ("add", "remove"):
        args += ["--agent", RUN[agent]["agent"]]
    elif op == "join":
        args += ["--authority", RUN[agent]["agent"]]
    fox(node, *args)
    answer = submit(node, owner_sign(node, prepared))
    DECISIONS.append({"node": node, "op": f"rooms.{op}", "agent": agent, "at": now(), "ok": bool(answer.get("ok")),
                      "code": answer.get("code")})
    return answer


def issue_invite(issuer: str, holder: str, expires_at: int, name: str) -> Path:
    """The issuer's owner makes an unscoped invite (invites.create) and hands
    the token to the holder's owner out of band, in an owner-only file."""
    prepared = decision_path(issuer, f"invite-{name}")
    owner = ROOT / "bin" / "tos-messenger-owner"
    in_ns(issuer, [owner, "-socket", sock(issuer, "owner.sock"), "-out", prepared, "prepare-invite",
                   "-expires-at", str(expires_at)], "tos-messenger-owner prepare-invite", timeout=60)
    signed = owner_sign(issuer, prepared)
    response = nd(issuer) / "decisions" / f"invite-{name}-response.json"
    in_ns(issuer, [owner, "-socket", sock(issuer, "owner.sock"), "-out", response, "submit", "-decision", signed],
          "tos-messenger-owner submit (invites.create)", timeout=60)
    token = read_json(response).get("admission_token", "")
    require(f"{issuer}'s owner issued invite {name} (invites.create), expiring at {expires_at}",
            token.startswith("invite_"), {"expires_at_unix": expires_at})
    fd.register_secret(token)
    SECRETS_HANDED.append(token)
    with (PRIVATE / "scan-secrets").open("a") as handle:
        handle.write(token + "\n")
    handed = nd(holder) / "handed" / f"invite-{name}.token"
    handed.write_text(token + "\n")
    handed.chmod(0o600)
    DECISIONS.append({"node": issuer, "op": "invites.create", "name": name, "at": now(), "ok": True})
    return handed


def present_invite(node: str, recipient: str, token_file: Path, expires_at: int, name: str) -> dict:
    prepared = decision_path(node, f"present-{name}")
    fox(node, "chat", "invite", "present", "--rail-config", str(rail(node)), "--recipient", RUN[recipient]["agent"],
        "--token-file", str(token_file), "--expires-at", str(expires_at), "--out", str(prepared))
    answer = submit(node, owner_sign(node, prepared))
    DECISIONS.append({"node": node, "op": "invites.present", "name": name, "at": now(), "ok": bool(answer.get("ok"))})
    return answer


def remove_contact(node: str, contact: str) -> dict:
    prepared = decision_path(node, "remove-contact")
    in_ns(node, [ROOT / "bin" / "tos-messenger-owner", "-socket", sock(node, "owner.sock"), "-out", prepared,
                 "prepare-remove-contact", "-agent", RUN[contact]["agent"]], "tos-messenger-owner prepare-remove-contact",
          timeout=60)
    answer = submit(node, owner_sign(node, prepared))
    DECISIONS.append({"node": node, "op": "contacts.remove", "agent": contact, "at": now(),
                      "ok": bool(answer.get("ok"))})
    return answer


# --- Rooms: reads ----------------------------------------------------------------------

def rooms(node: str) -> list[dict]:
    return mcall(node, {"op": "rooms.list"}).get("rooms") or []


def room_of(node: str) -> dict:
    return next((row for row in rooms(node) if row.get("room_id") == ROOM), {})


def wait_room(node: str, predicate, timeout: float = 600) -> dict:
    return poll(lambda: (lambda row: row if row and predicate(row) else None)(room_of(node)), timeout, 3) or \
        room_of(node)


def joined_at(node: str, room_epoch: int, timeout: float = 600) -> dict:
    return wait_room(node, lambda row: row.get("state") == "joined" and row.get("room_epoch", 0) >= room_epoch,
                     timeout)


def gaps(node: str) -> list[dict]:
    return mcall(node, {"op": "rooms.gaps", "room_id": ROOM}).get("room_gaps") or []


def room_frames(node: str, kind: int = 3) -> list[dict]:
    return [row for row in frames_of(node) if row["frame"].get("kind") == kind]


def room_acks(node: str) -> list[dict]:
    return [row for row in frames_of(node) if row["frame"].get("kind") == 2 and row["frame"].get("room_ack")]


def handshake_objects(node: str = "a") -> dict[str, dict]:
    """The authority's handshake objects as its chat outbox shows them:
    object digest -> type, epochs and the parts deposited to each member."""
    out: dict[str, dict] = {}
    digests_type: dict[str, dict] = {}
    for row in room_frames(node):
        frame = row["frame"]
        if frame.get("part_index") == 0:
            digests_type[frame["object_digest"]] = frame
    for row in room_frames(node):
        frame = row["frame"]
        head = digests_type.get(frame.get("object_digest"), {})
        if head.get("room_object_type") == 3:
            continue
        entry = out.setdefault(frame["object_digest"], {"type": head.get("room_object_type"),
                                                       "room_epoch": head.get("room_epoch"),
                                                       "mls_epoch": head.get("mls_epoch"), "members": {}})
        member = entry["members"].setdefault(row["packet"]["recipient_agent_id"], {"parts": set(), "records": 0})
        member["parts"].add(frame.get("part_index"))
        member["records"] += 1
    return out


def acks_for(node: str, object_digest: str) -> list[dict]:
    return [row["frame"] for row in room_acks(node) if row["frame"].get("room_ack_object_digest") == object_digest]


# --- Rooms: room messages ------------------------------------------------------------

def compose(node: str, label: str, body: str | None = None) -> dict:
    text = body if body is not None else mr1.marker(label)
    room = room_of(node)
    answer = mcall(node, {"op": "outbox.compose", "room_id": ROOM, "conversation_id": CONV, "media_type": TEXT,
                          "body": text, "idempotency_key": idem(), "membership_epoch": room.get("room_epoch", 0),
                          "expires_at_unix": now() + 3600})
    SENT[label] = {"from": node, "room": True, "text": text, "event_id": answer.get("event_id", ""),
                   "answer": answer, "sent_at": now(), "room_epoch": room.get("room_epoch"),
                   "mls_epoch": room.get("mls_epoch")}
    require(f"the runtime of {node} composed the room message '{label}' at room epoch {room.get('room_epoch')}",
            bool(answer.get("ok")) and SENT[label]["event_id"].startswith("evt_"), answer)
    return SENT[label]


def event_text(node: str, event_id: str) -> str:
    """The listed Event of node's runtime, as text, with its content decoded
    when it is base64."""
    for item in mr1.pending(node):
        if item.get("event_id") != event_id:
            continue
        event = item.get("event")
        event = json.loads(event) if isinstance(event, str) else event
        text = json.dumps(event)
        content = (event or {}).get("content_base64") or (event or {}).get("content")
        if isinstance(content, str):
            try:
                text += base64.b64decode(content).decode("utf-8", "replace")
            except ValueError:
                pass
        return text
    return ""


def room_applied(node: str, label: str, timeout: float = 420) -> dict:
    """The member's runtime lists the room message with its exact body and
    applies it once."""
    row = SENT[label]
    listed = poll(lambda: row["text"] in event_text(node, row["event_id"]) or None, timeout, 2)
    taken = take(node, row["event_id"]) if listed else {}
    return {"listed": bool(listed), "applied": bool(taken.get("completed")),
            "listed_again_after": row["event_id"] in inbound_texts(node)}


def exchange(senders: tuple, label: str, timeout: float = 600) -> dict:
    """Each sender posts once; every other member listed in the room applies
    it once."""
    results = {}
    for sender in senders:
        message = compose(sender, f"{label}-{sender}")
        for member in MEMBERS:
            if member == sender or member not in ROOM_MEMBERS:
                continue
            results[f"{sender}->{member}"] = room_applied(member, f"{label}-{sender}", timeout)
        message["results"] = results
    return results


ROOM_MEMBERS: set[str] = set()


# --- Counters sampled during the run (item 9) -------------------------------------------

COUNTS = {"stop": False, "samples": 0, "max_room": {}, "max_chat": {}, "thread": None}


def sample_counts() -> None:
    while not COUNTS["stop"]:
        for node in MEMBERS:
            try:
                status = mr1.chat_status(node)
            except Exception:  # noqa: BLE001 - a node that is stopped is sampled later
                continue
            for row in status.get("peer_envelopes") or []:
                key = f"{node}->{row.get('agent_id', '')[:14]}"
                COUNTS["max_room"][key] = max(COUNTS["max_room"].get(key, 0), row.get("room_envelopes", 0))
                COUNTS["max_chat"][key] = max(COUNTS["max_chat"].get(key, 0), row.get("envelopes", 0))
            COUNTS["samples"] += 1
        for _ in range(30):
            if COUNTS["stop"]:
                return
            time.sleep(1)


def start_sampler() -> None:
    COUNTS["thread"] = threading.Thread(target=sample_counts, daemon=True)
    COUNTS["thread"].start()


# --- Setup ----------------------------------------------------------------------------

def contacts() -> None:
    """Out-of-band exchanges: B's, D's and E's contact files to A's owner
    (A's allow-list admits them). C's contact file reaches A only with C's
    invite (item 1). B and C import nothing: they learn A in band, and each
    other only from rosters."""
    for node in NODES:
        mr1.export_contact(node)
    imported = {f"a<-{peer}": mr1.import_contact("a", peer) for peer in ("b", "d", "e")}
    require("A imports B's, D's and E's contact files; B, C, D and E import nothing yet",
            all(v.get("agent_id") == RUN[k[-1]]["agent"] for k, v in imported.items()) and
            all(not list((mdir(n) / "contacts").iterdir()) for n in ("b", "c", "d", "e")), imported)
    fd.evidence["contact_exchange"] = {"imports": imported, "handed": ["b -> a", "d -> a", "e -> a",
                                                                      "c -> a with C's invite (item 1)"],
                                       "not_handed": "nothing to B, C, D or E: they learn A in band"}


def setup() -> None:
    mr1.stage()
    MLS_DRIVER_ROOT = ROOT / "bin" / "tos-openmls-driver"
    fd.install_node(MLS_DRIVER, MLS_DRIVER_ROOT, "0755")
    fd.evidence["binaries"]["tos-openmls-driver"] = {"sha256": hashlib.sha256(MLS_DRIVER.read_bytes()).hexdigest()}
    mr1.start_forwarders()
    mr1.isolation()
    mr1.hidden_files()
    for relay in RELAYS:
        mr1.start_relay(relay, "start")
    mr1.relay_reachability()
    mr1.trust_negative_control()
    init_nodes()
    chat_owner_socket()
    mr1.domain()
    identities()
    mr1.write_configs()
    room_settings_check()
    for node in NODES:
        mr1.start_signer(node)
        start_node(node)
    contacts()
    start_sampler()
    mr1.hold("setup")


# --- Scenario -------------------------------------------------------------------------

STEPS: list = []


def step(function):
    """A scenario step, run in the order written; MR1_HOLD_AT may name it."""
    STEPS.append(function)
    return function


@step
def invite_first_contact() -> None:
    """Item 1, first half: C holds no allow-list entry for A or B and refuses
    unknown senders without an invite. C's owner issues an unscoped invite
    and hands it to A's owner with C's contact file; A presents it; A's first
    copy to C carries it sealed while C is offline, across a re-deposit."""
    expires = now() + 86400
    RUN["invite1"] = {"expires_at": expires}
    token = issue_invite("c", "a", expires, "1")
    contact_c = mr1.hand_contact("c", "a")
    prepared = decision_path("a", "import-c-invite")
    imported = json.loads(fox("a", "chat", "contact", "import", "--rail-config", str(rail("a")), "--file",
                              str(contact_c), "--invite", str(token), "--invite-expires-at", str(expires),
                              "--invite-out", str(prepared)).stdout)
    presented = submit("a", owner_sign("a", prepared))
    DECISIONS.append({"node": "a", "op": "invites.present (contact import --invite)", "at": now(),
                      "ok": bool(presented.get("ok"))})
    gate("1", "A's owner imports C's contact file with C's unscoped invite and presents it (invites.present, "
         "signed by A's owner)", imported.get("agent_id") == RUN["c"]["agent"] and bool(presented.get("ok")),
         {"imported": {k: imported.get(k) for k in ("agent_id", "key_id")}, "presented": presented.get("ok")})
    committed = poll(lambda: (mdir("a") / "state" / "relay-evidence" / (RUN["c"]["agent"][6:] + ".json")).is_file()
                     or None, 180, 2)
    require("A's daemon verified and committed C's relay evidence from the imported contact file", bool(committed))
    stop_node("c")
    RUN["c_offline_at"] = now()
    m = (mr1.send("a", "c", "inv1"), mr1.require_sent("inv1"))[1]
    first = poll(lambda: [r for r in mr1.copy_frames("a", m) if r["record"].get("accepted")], 120, 1) or []
    gate("1", "A's first copy to C carries C's invite sealed inside the kind-1 frame (never in a packet field, "
         "card or evidence)", bool(first) and first[0]["frame"].get("carries_admission_token") is True and
         SECRETS_HANDED[0] not in json.dumps(first[0]["packet"]), first[0]["frame"] if first else None)
    RUN["inv1_gen1"] = first[0]["record"]["envelope_id"] if first else ""


@step
def create_and_add_b() -> None:
    """Item 2, first half (while C is offline): A founds the room and adds B;
    B learns A in band from the room.invite and joins; A commits the Add and
    B installs the Welcome and the full roster."""
    created = room_op("a", "create")
    founded = wait_room("a", lambda row: row.get("is_authority"), 60)
    gate("2", "A's owner founds the room (rooms.create): A is its authority, the only member",
         bool(created.get("ok")) and founded.get("members") == [RUN["a"]["agent"]], founded)
    added = room_op("a", "add", "b")
    invited = wait_room("b", lambda row: row.get("state") == "invited", 300)
    gate("2", "A's owner adds B (rooms.add): the room.invite reaches B over the 1:1 path as a kind-1 copy and "
         "leaves a pending join", bool(added.get("ok")) and invited.get("state") == "invited", invited)
    joined = room_op("b", "join", "a")
    member = joined_at("b", 2)
    ROOM_MEMBERS.update({"a", "b"})
    gate("2", "B's owner joins (rooms.join): B's KeyPackage reaches A, A commits the Add, and B installs the "
         "Welcome and the full roster (room epoch 2)", bool(joined.get("ok")) and member.get("state") == "joined"
         and member.get("room_epoch") == 2, member)
    results = exchange(("a", "b"), "ab")
    gate("2", "A and B exchange room messages, each applied once", all(
        r["applied"] and not r["listed_again_after"] for r in results.values()), results)


@step
def invite_claimed() -> None:
    """Item 1, second half: generation 2 of A's first copy is deposited and
    generation 1 withdrawn while C is offline; C, restarted, admits A's copy
    by the invite, and the claim makes A a contact of C."""
    m = SENT["inv1"]["event_id"]
    second = poll(lambda: mr1.delivery_of("a", m).get("relay_generation", 0) >= 2 and mr1.delivery_of("a", m),
                  REDEPOSIT + 600, 10)
    gen1 = RUN.get("inv1_gen1", "")
    gone = poll(lambda: (lambda codes: codes if all(code in (404, 410) for code in codes.values()) else None)(
        {relay: mr1.envelope_status(relay, RUN["c"]["agent"], gen1) for relay in RELAYS}), 300, 5)
    gate("1", "while C is offline A re-deposits its first copy as generation 2 (the same token sealed again) and "
         "withdraws generation 1", bool(second) and bool(gone) and all(
             row["frame"].get("carries_admission_token") for row in mr1.copy_frames("a", m)),
         {"generations": (second or {}).get("relay_generations"), "generation_1_status": gone})
    start_node("c", "after the invite copy was held")
    done = mr1.wait_delivered("a", m)
    applied = mr1.apply_once("c", "inv1")
    gate("1", "C, with no allow-list entry for A, admits A's first copy by the invite and its runtime applies it "
         "once; A's copy becomes delivered", done.get("state") == "delivered" and applied["applied"] and
         not applied["listed_again_after"], {"applied": applied})
    # Another generation of the same Event: a fresh envelope carrying A's
    # generation-1 frame, signed by A and sealed to C's card.
    record_ = mr1.copy_frames("a", m)[0]["record"]
    payload = base64.b64decode(json.loads(base64.b64decode(record_["packet_base64"]))["payload_base64"])
    frame_file = nd("a") / "handed" / "inv1-frame.bin"
    frame_file.write_bytes(payload)
    replay = craft("a", "c", hand_file(card_path("c"), "a", "card-c.json"), "inv1-again", payload=frame_file)
    status = deposit("relay1", RUN["c"]["agent"], replay["envelope_id"], replay["path"].read_bytes())
    dup = poll(lambda: [row for row in mr1.copy_frames("c", m, kind=2)
                        if row["frame"].get("ack_outcome") == "duplicate"], 180, 2)
    gate("1", "another generation of that Event is answered `duplicate` and not listed to C's runtime again",
         status in (200, 201) and bool(dup) and m not in inbound_texts("c"), {"deposit": status})
    m2 = (mr1.send("a", "c", "inv2"), mr1.require_sent("inv2"))[1]
    done2 = mr1.wait_delivered("a", m2)
    applied2 = mr1.apply_once("c", "inv2")
    carries = [row["frame"].get("carries_admission_token") for row in mr1.copy_frames("a", m2)]
    gate("1", "the claim made A a known contact of C (D12): A's next Event carries no token and is admitted",
         done2.get("state") == "delivered" and applied2["applied"] and not any(carries),
         {"carries_token": carries, "c_files_naming_a": mr1.files_naming(mdir("c") / "state",
                                                                          [RUN["a"]["agent"]])[:12]})


@step
def add_c() -> None:
    """Items 2 and 18: A adds C (a second Commit and Welcome); B, already
    joined, applies the Add Commit, accepts the roster of added members and
    learns C's card and evidence from it; all three exchange messages."""
    added = room_op("a", "add", "c")
    invited = wait_room("c", lambda row: row.get("state") == "invited", 300)
    joined = room_op("c", "join", "a")
    c_room = joined_at("c", 3)
    b_room = joined_at("b", 3)
    ROOM_MEMBERS.add("c")
    gate("2", "A adds C: the room.invite reaches C, C's owner joins, A commits the Add (room epoch 3), C installs "
         "its Welcome and roster and B applies the Add Commit", bool(added.get("ok")) and invited.get("state") ==
         "invited" and bool(joined.get("ok")) and c_room.get("room_epoch") == 3 and b_room.get("room_epoch") == 3,
         {"b": b_room, "c": c_room})
    objects = handshake_objects()
    # The split is shown on C's full roster (about 22 KB in a three-member
    # room); the Welcome (about 1.9 KB) is below any part size that also fits
    # the roster in 8 parts.
    roster_c = [d for d, o in objects.items() if o["type"] == 4 and RUN["c"]["agent"] in o["members"]]
    parts = {d[:16]: sorted(objects[d]["members"][RUN["c"]["agent"]]["parts"]) for d in roster_c}
    welcome_c = [d for d, o in objects.items() if o["type"] == 2 and RUN["c"]["agent"] in o["members"]]
    RUN["roster_c"] = roster_c
    if PART_BYTES:
        gate("2", f"C's full roster is cut at the test part size P = {PART_BYTES} into several parts and "
             "reassembled by C (its Welcome is a single part)", bool(roster_c) and bool(welcome_c) and
             all(len(v) > 1 for v in parts.values()), {"roster_parts": parts})
    else:
        gate("2", "C's Welcome and full roster are carried at the production cut, each one part (the local "
             "record; the split at a test P is shown in the three-host record)", bool(roster_c) and
             bool(welcome_c), {"roster_parts": parts})
    rosters_b = [d for d, o in objects.items() if o["type"] == 4 and RUN["b"]["agent"] in o["members"] and
                 o["room_epoch"] == 3]
    acks = {d[:16]: [f.get("ack_outcome") for f in acks_for("b", d)] for d in rosters_b}
    cards_b = mr1.peer_cards("b")
    evidence = mdir("b") / "state" / "relay-evidence" / (RUN["c"]["agent"][6:] + ".json")
    gate("18", "B, already joined, accepts the roster of added members (answered `accepted`, not `room-fork`) and "
         "learns C's chat card and relay evidence from it",
         bool(rosters_b) and all(v and set(v) <= {"accepted"} for v in acks.values()) and
         RUN["c"]["agent"] in cards_b and evidence.is_file(), {"acks": acks, "b_holds_c_card":
                                                                RUN["c"]["agent"] in cards_b})
    results = exchange(("a", "b", "c"), "abc")
    gate("2", "all three exchange room messages, each applied once", all(
        r["applied"] and not r["listed_again_after"] for r in results.values()), results)
    gate("18", "B and C, no contacts of each other, exchange room messages",
         results.get("b->c", {}).get("applied") and results.get("c->b", {}).get("applied"),
         {k: results.get(k) for k in ("b->c", "c->b")})
    RUN["renewal"] = [{"at": now(), "b->c": results.get("b->c"), "c->b": results.get("c->b")}]


def state_view(node: str) -> dict:
    """Digests of what a refusal must leave unchanged at a node: its Messenger
    journal's Event and admission records, contacts, rollback boundary and the
    OpenFox chat-card store."""
    base = mdir(node) / "state"
    view = {}
    for name in sorted(p.name for p in base.iterdir()) if base.is_dir() else []:
        path = base / name
        if name in VOLATILE_STATE:
            continue
        files = sorted(f for f in path.rglob("*") if f.is_file()) if path.is_dir() else [path]
        digest = hashlib.sha256()
        for f in files:
            digest.update(str(f.relative_to(base)).encode() + b"\0")
            try:
                digest.update(f.read_bytes())
            except OSError:
                pass
        view[name] = digest.hexdigest()[:16]
    peers = nd(node) / "state" / "relay" / "chat-peers"
    view["openfox chat-peers"] = hashlib.sha256(b"".join(
        f.read_bytes() for f in sorted(peers.rglob("*")) if f.is_file()) if peers.is_dir() else b"").hexdigest()[:16]
    return view


# State a node rewrites on its own timers, whatever it receives.
VOLATILE_STATE = {"chain.checkpoint", "prekeys", "publication", "LOCK", "maintenance"}


@step
def refusals_at_c() -> None:
    """Items 1 (refusals) and 12: B is a room member but no contact of C. A 1:1
    copy of B's not naming the room meets C's normal policy and is refused;
    B presenting the spent token, and B presenting a second invite that has
    expired by the time C reads it, are refused too. No refusal changes C's
    journal, contacts, rollback boundary or chat-card store."""
    results = {}
    for label, prepare in (("plain", None), ("spent", "spent"), ("expired", "expired")):
        if prepare == "spent":
            token = hand_file(nd("a") / "handed" / "invite-1.token", "b", "invite-1.token")
            results["present-spent"] = present_invite("b", "c", token, RUN["invite1"]["expires_at"], "spent")
        if prepare == "expired":
            expires = now() + 150
            token = issue_invite("c", "b", expires, "2")
            results["present-expired"] = present_invite("b", "c", token, expires, "expired")
            stop_node("c")
        before = state_view("c")
        m = (mr1.send("b", "c", f"refused-{label}"), mr1.require_sent(f"refused-{label}"))[1]
        sent = poll(lambda: [r for r in mr1.copy_frames("b", m) if r["record"].get("accepted")], 120, 1) or []
        envelopes = [r["record"]["envelope_id"] for r in sent]
        if prepare == "expired":
            poll(lambda: now() > expires + 5 or None, 400, 5)
            start_node("c", "after the second invite expired")
            before = state_view("c")
        acked = poll(lambda: all(all(e not in listed_ids(relay, RUN["c"]["agent"]) for relay in RELAYS)
                                 for e in envelopes) or None, 300, 3)
        time.sleep(5)
        after = state_view("c")
        changed = sorted(k for k in before if before.get(k) != after.get(k))
        results[label] = {"carries_token": [r["frame"].get("carries_admission_token") for r in sent],
                          "relay_acknowledged": bool(acked), "listed_at_c": m in inbound_texts("c"),
                          "state_changed": changed, "b_delivery": mr1.delivery_of("b", m).get("state")}
        ok = bool(envelopes) and bool(acked) and not results[label]["listed_at_c"] and not changed
        item = "12" if label == "plain" else "1"
        gate(item, {"plain": "a 1:1 copy of B (a member, no contact of C) not naming the room meets C's normal "
                             "policy: refused and relay-acknowledged, C's state unchanged",
                    "spent": "B presenting A's spent token: the copy carries it, C re-runs its policy without it "
                             "and refuses; C's journal, contacts, rollback boundary and chat-card store unchanged",
                    "expired": "B presenting C's second invite, expired when C reads the copy: refused; C's "
                               "state unchanged"}[label], ok, results[label])
    fd.evidence["refusals_at_c"] = {k: v for k, v in results.items() if not k.startswith("present")}
    gate("12", "B's room messages are admitted by room-scoped admission while its 1:1 copies are refused",
         RUN["renewal"][0]["b->c"]["applied"], RUN["renewal"][0])


def filler_joins(filler: str, room_epoch: int) -> dict:
    """A adds a filler joiner, whose owner joins; the Add is one Commit."""
    added = room_op("a", "add", filler)
    wait_room(filler, lambda row: row.get("state") == "invited", 300)
    joined = room_op(filler, "join", "a")
    row = joined_at(filler, room_epoch)
    require(f"filler {filler.upper()} joins at room epoch {room_epoch} (one Add Commit by A)",
            bool(added.get("ok")) and bool(joined.get("ok")) and row.get("room_epoch") == room_epoch, row)
    return row


def snapshot_held(name: str) -> None:
    RUN.setdefault("snapshots", {})[name] = snapshot(name)


def ack_time(node: str, object_digest: str) -> int:
    times = [row["record"].get("accepted_at_unix", 0) for row in room_acks(node)
             if row["frame"].get("room_ack_object_digest") == object_digest]
    return min(times) if times else 0


def deposit_times(node: str, object_digest: str, recipient: str) -> list[int]:
    return sorted(row["record"].get("accepted_at_unix", 0) for row in room_frames(node)
                  if row["frame"].get("object_digest") == object_digest and
                  row["packet"]["recipient_agent_id"] == RUN[recipient]["agent"])


def commits_to(member: str, after_epoch: int) -> list[tuple[int, str]]:
    return sorted((o["mls_epoch"] or 0, d) for d, o in handshake_objects().items()
                  if o["type"] == 1 and RUN[member]["agent"] in o["members"] and (o["room_epoch"] or 0) > after_epoch)


@step
def catch_up_in_order() -> None:
    """Items 3 and 14: C is stopped while A commits twice (adds and removes
    filler D) and B posts in the newest epoch; on restart C gets the second
    Commit only after acking the first, applies both in order and opens the
    buffered newer-epoch message."""
    base = room_of("c")
    stop_node("c")
    stopped_at = now()
    filler_joins("d", base["room_epoch"] + 1)
    removed = room_op("a", "remove", "d")
    a_room = wait_room("a", lambda row: row.get("room_epoch", 0) >= base["room_epoch"] + 2, 300)
    b_room = wait_room("b", lambda row: row.get("room_epoch", 0) >= base["room_epoch"] + 2, 600)
    require("A removes D (the second Commit while C is stopped); B follows", bool(removed.get("ok")) and
            b_room.get("room_epoch") == a_room.get("room_epoch"), {"a": a_room, "b": b_room})
    newer = compose("b", "buffered-b")
    snapshot_held("c-catch-up-held")
    if AUTHORIZATION:
        poll(lambda: now() > stopped_at + AUTHORIZATION + 30 or None, AUTHORIZATION + 120, 5)
    offline = now() - stopped_at
    start_node("c", "after the catch-up gap")
    c_room = joined_at("c", a_room["room_epoch"], 900)
    commits = commits_to("c", base["room_epoch"])
    order = [{"mls_epoch": e, "first_deposit": (deposit_times("a", d, "c") or [0])[0], "acked": ack_time("c", d)}
             for e, d in commits]
    in_order = len(order) >= 2 and all(order[i + 1]["first_deposit"] >= order[i]["acked"] > 0
                                       for i in range(len(order) - 1))
    gate("3", "C, restarted, got the second Commit only after its room ack of the first and applied both in "
         "epoch order", c_room.get("room_epoch") == a_room.get("room_epoch") and in_order,
         {"commits": order, "c": c_room, "offline_seconds": offline})
    opened = room_applied("c", "buffered-b", 600)
    gate("3", "C opens B's message sealed in the newer epoch, buffered until the Commits were applied",
         opened["applied"], {"opened": opened, "sealed_at_mls_epoch": newer.get("mls_epoch")})
    results = exchange(("c",), "after-catch-up")
    if AUTHORIZATION:
        gate("14", f"C was stopped {offline} s, longer than the test authorization lifetime "
             f"({AUTHORIZATION} s) and shorter than the test handshake retention ({RETENTION} s); it applied both "
             "Commits in order and exchanges messages", offline > AUTHORIZATION and
             (not RETENTION or offline < RETENTION) and in_order and all(r["applied"] for r in results.values()),
             {"offline_seconds": offline, "results": results})
    else:
        gate("3", "C exchanges messages after the catch-up", all(r["applied"] for r in results.values()), results)
    renewal_exchange()


def driver_children(node: str) -> list[int]:
    daemon = mr1.pids(mr1.daemon_pattern(node))
    out = []
    for pid in mr1.pids(f"^{ROOT / 'bin' / 'tos-openmls-driver'}"):
        try:
            parent = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if parent in daemon:
            out.append(pid)
    return out


@step
def offline_beyond_ttl() -> None:
    """Items 4 and 15 (C's crash window): B is stopped beyond the relay TTL
    while A commits (adds filler E) and C posts. C's daemon is paused while
    the Commit reaches it, its serve killed after handing the object over,
    so C applies it with no room ack sent; restarted, C answers the same
    envelope `duplicate`. B, restarted after the TTL, applies the
    re-deposited Commit (generations and withdrawals recorded) and gets a
    room.gap naming C."""
    base = room_of("b")
    stop_node("b")
    stopped_at = now()
    mr1.signal_pattern(mr1.daemon_pattern("c"), "STOP")
    filler_joins("e", base["room_epoch"] + 1)
    commit = (commits_to("c", base["room_epoch"]) or [(0, "")])[-1][1]
    RUN["commit_e"] = commit
    unanswered = "the Messenger carrier socket did not answer"
    before = log_text("serve-c").count(unanswered)
    waiting = poll(lambda: log_text("serve-c").count(unanswered) > before, 480, 2)
    stop_serve("c", "KILL")
    mr1.signal_pattern(mr1.daemon_pattern("c"), "CONT")
    mr1.continue_wrapper("messengerd-c")
    c_room = wait_room("c", lambda row: row.get("room_epoch", 0) > base["room_epoch"], 120)
    gate("15", "C's serve is killed after handing the Commit to C's paused daemon: the daemon applies it, no room "
         "ack is sent and the envelope stays at the relays", bool(waiting) and
         c_room.get("room_epoch") == base["room_epoch"] + 1 and not acks_for("c", commit),
         {"c": c_room, "acks": acks_for("c", commit)})
    start_serve("c", "after the crash window")
    dup = poll(lambda: [f for f in acks_for("c", commit) if f.get("ack_outcome") == "duplicate"], 600, 3)
    gate("15", "restarted, C finds the same envelope, answers it `duplicate` and its room stays usable",
         bool(dup), {"acks": acks_for("c", commit)})
    lost = compose("c", "lost-to-b")
    poll(lambda: now() > stopped_at + RELAY_TTL + 120 or None, RELAY_TTL + 400, 10)
    generations = sorted({row["record"]["envelope_id"] for row in room_frames("a")
                          if row["frame"].get("object_digest") == commit and
                          row["packet"]["recipient_agent_id"] == RUN["b"]["agent"]})
    parts = {row["frame"].get("part_sha256") for row in room_frames("a")
             if row["frame"].get("object_digest") == commit and
             row["packet"]["recipient_agent_id"] == RUN["b"]["agent"] and row["frame"].get("part_index") == 0}
    withdrawn = {e[:12]: {relay: mr1.envelope_status(relay, RUN["b"]["agent"], e) for relay in RELAYS}
                 for e in generations[:-1]}
    gate("4", f"B is stopped {now() - stopped_at} s, beyond the relay TTL ({RELAY_TTL} s); A re-deposits its Commit "
         "to B in new generations, byte-identical, and withdraws the older ones",
         len(generations) >= 2 and len(parts) == 1 and all(code in (404, 410) for codes in withdrawn.values()
                                                            for code in codes.values()),
         {"generations": len(generations), "withdrawn": withdrawn})
    start_node("b", "after the TTL")
    b_room = joined_at("b", base["room_epoch"] + 1, 900)
    gate("4", "B, restarted, applies the re-deposited Commit", b_room.get("room_epoch") == base["room_epoch"] + 1,
         b_room)
    compose("c", "after-gap-c")
    applied = room_applied("b", "after-gap-c", 600)
    gap = poll(lambda: [g for g in gaps("b") if g.get("sender_agent_id") == RUN["c"]["agent"]] or None,
               RELAY_TTL + 900, 15)
    gate("4", "B never received C's message sealed while it was offline (expired at the relays) and gets a "
         "room.gap naming C once C's next message arrived", applied["applied"] and bool(gap) and
         SENT["lost-to-b"]["event_id"] not in inbound_texts("b"), {"gap": gap, "next": applied})
    renewal_exchange()


@step
def crafted_objects() -> None:
    """Items 6 (live refusal) and 10 (the production cut): B, a member but not
    the authority, sends C a Commit (an MLS-only refresh shape with a 1 MiB
    body) cut by the production rule into 6 parts. C reassembles and refuses
    it `not-authentic`; every part is relay-acknowledged, nothing changes."""
    out = nd("b") / "handed" / "crafted-commit"
    room = room_of("c")
    contact = hand_file(mdir("b") / "export" / "relay-contact.json", "b", "own-relay-contact.json")
    cut = json.loads(in_ns("b", [ROOT / "bin" / "messenger-relay-e2e-tool", "room-frames", "--type", "1",
                                 "--room", ROOM, "--room-epoch", str(room["room_epoch"]), "--mls-epoch",
                                 str(room["mls_epoch"] + 1), "--body-bytes", str(1 << 20), "--contact", contact,
                                 "--out-dir", out], "messenger-relay-e2e-tool room-frames", timeout=60).stdout)
    card = hand_file(card_path("c"), "b", "card-c.json")
    stop_serve("c")
    envelopes = []
    for index in range(cut["parts"]):
        crafted = craft("b", "c", card, f"crafted-part-{index}", payload=out / f"part-{index}.bin")
        status = deposit("relay2", RUN["c"]["agent"], crafted["envelope_id"], crafted["path"].read_bytes())
        envelopes.append({"envelope_id": crafted["envelope_id"], "bytes": crafted["bytes"], "deposit": status})
    snapshot_held("crafted-6-part-held")
    sizes = cut["frame_bytes"]
    stored = mr1.relay_envelope_sizes(mr1.SNAPSHOTS / "crafted-6-part-held" / "relay2")
    gate("10", "a production-cut 6-part object (1 MiB body): parts 0..4 are 190,464-byte frames, the last is its "
         "smallest bucket, and each stored envelope matches 1,373 + F + 4·⌈B/3⌉",
         cut["parts"] == 6 and sizes[:-1] == [190464] * 5 and sizes[-1] in mr1.relayframe_buckets() and
         all(e["deposit"] == 201 for e in envelopes) and
         all(mr1.relayframe_envelope_size(e["bytes"]) for e in envelopes) and
         all(mr1.relayframe_envelope_size(size) for size in stored),
         {"cut": cut, "envelope_bytes": [e["bytes"] for e in envelopes]})
    before = state_view("c")
    start_serve("c", "after the crafted deposit")
    acked = poll(lambda: all(e["envelope_id"] not in listed_ids("relay2", RUN["c"]["agent"]) for e in envelopes)
                 or None, 300, 3)
    after_room = room_of("c")
    refused = [line for line in log_text("messengerd-c").splitlines() if "not-authentic" in line]
    gate("6", "a Commit from B (a member, not the authority) is reassembled by C and refused `not-authentic`: "
         "every part relay-acknowledged, C's room epoch and MLS epoch unchanged",
         bool(acked) and after_room.get("mls_epoch") == room["mls_epoch"] and
         after_room.get("room_epoch") == room["room_epoch"] and bool(refused),
         {"room_before": room, "room_after": after_room, "refusal_lines": refused[-2:],
          "state_changed": sorted(k for k in before if before[k] != state_view("c").get(k))})
    fd.evidence["crafted_6_part_object"] = {"cut": cut, "envelopes": envelopes}
    renewal_exchange()


@step
def remove_c_with_authority_crash() -> None:
    """Items 5 and 15 (A's crash window): with C's serve stopped (A's Commit
    adding E... already delivered; A's next Commit to C is in flight), A
    removes E then C. A's daemon is killed while its OpenMLS driver runs
    the Remove; after the restart the Remove is published once or the
    decision is made again, and no member forks."""
    stop_serve("c")
    room_op("a", "remove", "e")
    in_flight = poll(lambda: commits_to("c", room_of("a").get("room_epoch", 0) - 1) or None, 120, 2)
    base = room_of("a")
    holder = {}

    def kill_during_driver() -> None:
        children = poll(lambda: driver_children("a") or None, 60, 0.05)
        if children:
            mr1.signal_pattern(mr1.daemon_pattern("a"), "KILL")
            holder["killed_during_driver"] = children
    killer = threading.Thread(target=kill_during_driver)
    killer.start()
    answer = room_op("a", "remove", "c")
    killer.join()
    mr1.PROCESSES.pop("messengerd-a", None)
    start_daemon("a", "after the crash during the Remove")
    after = room_of("a")
    if RUN["c"]["agent"] in (after.get("members") or []):
        again = room_op("a", "remove", "c")
        holder["decision_made_again"] = bool(again.get("ok"))
        after = wait_room("a", lambda row: RUN["c"]["agent"] not in (row.get("members") or []), 300)
    removed_epoch = after.get("room_epoch", 0)
    b_room = joined_at("b", removed_epoch, 900)
    gate("15", "A's daemon is killed while its driver runs the Remove; after the restart the Remove is published "
         "once (or the decision is made again), and B follows to the same epoch with the same MLS epoch (no fork)",
         bool(holder.get("killed_during_driver")) and RUN["c"]["agent"] not in (after.get("members") or []) and
         b_room.get("room_epoch") == removed_epoch and b_room.get("mls_epoch") == after.get("mls_epoch"),
         {"first_answer": answer, "holder": holder, "a": after, "b": b_room})
    stale = [d for _, d in (in_flight or [])]
    statuses = {}
    for row in room_frames("a"):
        if row["frame"].get("object_digest") in stale and row["packet"]["recipient_agent_id"] == RUN["c"]["agent"]:
            statuses[row["record"]["envelope_id"][:12]] = {relay: mr1.envelope_status(relay, RUN["c"]["agent"],
                                                                                      row["record"]["envelope_id"])
                                                           for relay in RELAYS}
    gate("5", "A's in-flight handshake envelopes to C are withdrawn after the Remove",
         bool(statuses) and all(code in (404, 410) for codes in statuses.values() for code in codes.values()),
         statuses)
    after_a = compose("a", "after-remove-a")
    after_b = compose("b", "after-remove-b")
    ROOM_MEMBERS.discard("c")
    addressed = [row["packet"]["recipient_agent_id"][:14] for node in ("a", "b") for row in room_frames(node)
                 if row["frame"].get("part_index") == 0 and (row["frame"].get("room_epoch") or 0) >= removed_epoch
                 and row["packet"]["recipient_agent_id"] == RUN["c"]["agent"] and
                 row["frame"].get("room_object_type") == 3]
    gate("5", "later room messages of A and B are not addressed to C (their chat outboxes)", not addressed and
         room_applied("b", "after-remove-a")["applied"] and room_applied("a", "after-remove-b")["applied"],
         addressed)
    start_serve("c", "after the Remove")
    c_room = wait_room("c", lambda row: row.get("state") != "joined" or
                       row.get("room_epoch", 0) >= removed_epoch, 300)
    attempt = mcall("c", {"op": "outbox.compose", "room_id": ROOM, "conversation_id": CONV, "media_type": TEXT,
                          "body": mr1.marker("removed-c"), "idempotency_key": idem(),
                          "membership_epoch": c_room.get("room_epoch", 0), "expires_at_unix": now() + 3600})
    gate("5", "C, told by the removing Commit, has its room messages refused `not-a-room-member`",
         not attempt.get("ok") and "not-a-room-member" in json.dumps(attempt), {"c": c_room, "answer": attempt})
    # A's application to B, sealed after the Remove, handed to C by the harness.
    row = next(r for r in room_frames("a") if r["frame"].get("room_object_type") == 3 and
               r["packet"]["recipient_agent_id"] == RUN["b"]["agent"] and
               (r["frame"].get("room_epoch") or 0) >= removed_epoch)
    payload = base64.b64decode(json.loads(base64.b64decode(row["record"]["packet_base64"]))["payload_base64"])
    frame_file = nd("a") / "handed" / "after-remove-frame.bin"
    frame_file.write_bytes(payload)
    handed = craft("a", "c", hand_file(card_path("c"), "a", "card-c-removed.json"), "after-remove-to-c",
                   payload=frame_file)
    status = deposit("relay1", RUN["c"]["agent"], handed["envelope_id"], handed["path"].read_bytes())
    acked = poll(lambda: handed["envelope_id"] not in listed_ids("relay1", RUN["c"]["agent"]) or None, 180, 3)
    gate("5", "C's driver fails to open a later room message the harness handed it: relay-acknowledged, never "
         "listed to C's runtime", status == 201 and bool(acked) and
         SENT["after-remove-a"]["event_id"] not in inbound_texts("c"), {"deposit": status})
    cards_b = mr1.peer_cards("b")
    evidence = mdir("b") / "state" / "relay-evidence" / (RUN["c"]["agent"][6:] + ".json")
    forgotten = poll(lambda: (RUN["c"]["agent"] not in mr1.peer_cards("b") and not evidence.is_file()) or None,
                     300, 5)
    gate("5", "B, for whom C is no contact, has forgotten C's chat card and relay evidence", bool(forgotten),
         {"b_holds_c_card": RUN["c"]["agent"] in cards_b, "b_holds_c_evidence": evidence.is_file()})
    removed = remove_contact("c", "a")
    m = (mr1.send("a", "c", "after-contact-removed"), mr1.require_sent("after-contact-removed"))[1]
    sent = poll(lambda: [r for r in mr1.copy_frames("a", m) if r["record"].get("accepted")], 120, 1) or []
    acked = poll(lambda: all(all(r["record"]["envelope_id"] not in listed_ids(relay, RUN["c"]["agent"])
                                 for relay in RELAYS) for r in sent) or None, 300, 3)
    gate("1", "after C's owner removes A (contacts.remove), A's next Event meets C's policy again and is refused",
         bool(removed.get("ok")) and bool(sent) and bool(acked) and m not in inbound_texts("c"), removed)


@step
def renewal_among_non_contacts() -> None:
    """Item 16: B and C exchanged room messages across the run; their
    descriptors (test lifetime MR1_DESCRIPTOR_LIFETIME) expired several times
    and each renewed the other's only through kind-3 part 0."""
    span = RUN["renewal"][-1]["at"] - RUN["renewal"][0]["at"]
    expiries = sorted({row["frame"].get("descriptor_expires_at_unix") for row in room_frames("c")
                       if row["packet"]["recipient_agent_id"] == RUN["b"]["agent"] and
                       row["frame"].get("descriptor_expires_at_unix")})
    kind4 = [row for node, peer in (("b", "c"), ("c", "b")) for row in frames_of(node)
             if row["frame"].get("kind") == 4 and row["packet"]["recipient_agent_id"] == RUN[peer]["agent"]]
    gate("16", f"B and C (no contacts) exchanged room messages over {span} s while C's descriptor (lifetime "
         f"{mr1.DESCRIPTOR_LIFETIME} s) was renewed {len(expiries)} times in its kind-3 part 0 to B, with no "
         "kind-4 evidence exchange between them", len(expiries) >= 3 and not kind4 and
         all(r["b->c"]["applied"] and r["c->b"]["applied"] for r in RUN["renewal"]),
         {"descriptor_expiries": expiries, "exchanges": RUN["renewal"]})


def renewal_exchange() -> None:
    results = exchange(("b", "c"), f"renewal-{len(RUN['renewal'])}")
    RUN["renewal"].append({"at": now(), "b->c": results.get("b->c"), "c->b": results.get("c->b")})


@step
def states_counters_sizes_search() -> None:
    """Items 8, 9, 10 and 11, read from the journals, the counters sampled
    during the run and the relay snapshots."""
    objects = handshake_objects()
    settled, unsettled = {}, {}
    for digest, entry in objects.items():
        for agent in entry["members"]:
            member = next(n for n in NODES if RUN[n]["agent"] == agent)
            outcomes = [f.get("ack_outcome") for f in acks_for(member, digest)]
            key = f"{digest[:12]}->{member} (type {entry['type']}, mls {entry['mls_epoch']})"
            (settled if set(outcomes) & {"accepted", "duplicate"} else unsettled)[key] = outcomes
    removal_commits = {k for k in unsettled if k.endswith("(type 1, mls %s)" % k.split("mls ")[-1][:-1])}
    application_acked = [row for node in MEMBERS for row in room_acks(node)
                         if row["frame"].get("room_ack_object_digest") not in objects]
    gate("8", "every handshake object reached each member and settled on that member's verified room ack "
         "(`accepted` or `duplicate`), except a removed member's removing Commit and objects to a member removed "
         "while they were in flight; no application object is ever room-acked",
         bool(settled) and not application_acked,
         {"settled": settled, "unsettled": unsettled, "removal_commits": sorted(removal_commits)}, required=False)
    room_max = max(COUNTS["max_room"].values() or [0])
    chat_max = max(COUNTS["max_chat"].values() or [0])
    pacing = {}
    for node in MEMBERS:
        times = sorted(row["record"].get("accepted_at_unix", 0) for row in room_frames(node))
        worst = 0
        for i, start in enumerate(times):
            j = i
            while j < len(times) and times[j] < start + 60:
                j += 1
            worst = max(worst, j - i)
        pacing[node] = {"kind3_deposits": len(times), "most_in_any_60_s": worst}
    gate("9", "no peer held more than 16 kind-3 or 24 chat envelopes (sampled every 30 s from `chat status`), and "
         "no node deposited more kind-3 envelopes in any 60 s than the 30-per-minute, burst-16 bucket allows (46)",
         COUNTS["samples"] > 0 and room_max <= 16 and chat_max <= 24 and
         all(v["most_in_any_60_s"] <= 46 for v in pacing.values()),
         {"samples": COUNTS["samples"], "max_kind3": room_max, "max_chat": chat_max, "pacing": pacing})
    sizes, envelope_ok, nonfinal = [], [], []
    for node in NODES:
        for row in room_frames(node):
            frame = row["frame"]
            sizes.append(frame.get("frame_bytes"))
            envelope_ok.append(frame.get("frame_bytes") == frame.get("smallest_bucket"))
            if frame.get("part_index", 0) + 1 < frame.get("part_count", 1):
                nonfinal.append(frame.get("frame_bytes"))
            if row["record"].get("envelope_base64") and row["packet"].get("expected_envelope_bytes"):
                envelope_ok.append(len(base64.b64decode(row["record"]["envelope_base64"])) ==
                                   row["packet"]["expected_envelope_bytes"])
    stored = {name: {relay: mr1.relay_envelope_sizes(mr1.SNAPSHOTS / name / relay) for relay in RELAYS}
              for name in RUN.get("snapshots", {})}
    stored_ok = all(mr1.relayframe_envelope_size(size) for v in stored.values() for sizes_ in v.values()
                    for size in sizes_)
    production = not PART_BYTES
    gate("10", "every kind-3 frame the daemons cut is its smallest bucket" +
         (", non-final parts are 190,464 bytes" if production else " (cut at the test P: buckets only)") +
         ", and every stored envelope matches 1,373 + F + 4·⌈B/3⌉",
         bool(sizes) and all(envelope_ok) and stored_ok and (not production or all(n == 190464 for n in nonfinal)),
         {"frame_sizes": sorted(set(sizes)), "nonfinal": sorted(set(nonfinal)), "stored": stored})
    texts = [SENT[label]["text"].encode() for label in SENT if SENT[label].get("text")]
    agents = {RUN[n]["agent"] for n in NODES}
    endpoints = {RUN[n]["identity"]["endpoint_id"] for n in NODES} | {RUN[n]["identity"]["device_id"] for n in NODES}
    events = {SENT[label]["event_id"] for label in SENT if SENT[label].get("event_id")}
    needles = {"message text": texts, "room id": mr1.hexforms({ROOM}), "conversation id": mr1.hexforms({CONV}),
               "event id": mr1.hexforms(events), "member or sender agent id": mr1.hexforms(agents),
               "endpoint or device id": mr1.hexforms(endpoints),
               "invite token": [t.encode() for t in SECRETS_HANDED],
               "chat key id (roster contents)": [RUN[n]["chat_key"].encode() for n in NODES if RUN[n].get("chat_key")]}
    needles = {k: [i for i in v if i and len(i) >= 8] for k, v in needles.items()}
    control = PRIVATE / "plaintext-control.bin"
    control.write_bytes(b"".join(secrets.token_bytes(32) + items[0] for items in needles.values() if items))
    control_found = mr1.search([control], needles)
    require("the relay plaintext search finds every searched value in a control file holding one of each",
            set(control_found) == {k for k, v in needles.items() if v}, sorted(control_found))
    roots = [WORK / relay / "state" for relay in RELAYS] + [mr1.SNAPSHOTS] + [WORK / f"{r}.log" for r in RELAYS]
    found = mr1.search([root for root in roots if root.exists()], needles)
    gate("11", "nothing readable at the relays: no live relay state, no snapshot (taken while relays held room "
         "objects and acks) and no relay log holds a message text, the room id, a member, conversation, Event, "
         "Endpoint or device id, a roster's chat key id or the invite token", not found and
         bool(RUN.get("snapshots")), {"found": found, "snapshots": sorted(RUN.get("snapshots", {}))})
    fd.evidence["sizes"] = {"kind3_frame_sizes": sorted(set(sizes)), "stored_envelope_sizes": stored}


@step
def unit_items() -> None:
    NOT_VERIFIED.extend([
        {"item": "7 (reassembly caps)", "reason": "named unit tests (section 4 caps, an oversize object, a "
         "non-member's part, inconsistent part counts, a digest mismatch, an incomplete object expiring)",
         "unit_tests": ["ai messenger/pkg/relayframe TestReassemblerEnforcesEachBound",
                        "ai messenger/pkg/relayframe TestReassemblerReleasesAnObjectInAnyOrderOnce",
                        "ai messenger/pkg/eventlog TestRoomPartStoreHoldsNoMoreThanTheReassemblerBounds",
                        "ai messenger/pkg/eventlog TestRoomPartUnsettledObjectsAreBounded"]},
        {"item": "6 (a second Commit for one epoch is refused room-fork)", "reason": "only the authority could "
         "make it (a restored backup); named unit test",
         "unit_tests": ["ai messenger/pkg/daemon TestRoomCommitForkAndGapAreAnswered"]},
        {"item": "12 (a room Event whose packet sender is not in the latest committed roster at its epoch)",
         "reason": "unit", "unit_tests": ["ai messenger/pkg/daemon TestRoomCommitFromAnotherMemberIsRefusedAndStoresNothing"]},
        {"item": "13 (owner-only management)", "reason": "unit",
         "unit_tests": ["ai messenger/pkg/localapi TestRoomManagementIsOwnerOnly"]},
        {"item": "17 (driver bounds)", "reason": "unit",
         "unit_tests": ["ai messenger/pkg/daemon TestPrivateRoomCapacityProfile"]},
        {"item": "18 (roster refusals and late rosters)", "reason": "unit",
         "unit_tests": ["ai messenger/pkg/eventlog TestRoomRosterJudgement"]},
        {"item": "16 (test-shortened chat card lifetime)", "reason": "openfox has no test setting for the chat "
         "card lifetime (30 days); only the descriptor lifetime is test-shortened, so card renewal through part 0 "
         "is not shown live", "unit_tests": []},
        {"item": "14 (a header older than the handshake retention W is refused)", "reason": "unit",
         "unit_tests": ["ai messenger/pkg/daemon TestRoomCommitAuthorizationOutsideTheRelayWindowIsRefused"]},
    ])
    if not AUTHORIZATION:
        NOT_VERIFIED.append({"item": "14 (catch-up beyond the authorization window)", "reason": "this run's "
                             "daemons are a production build, which refuses the test authorization lifetime; the "
                             "catch-up in order is shown live under item 3",
                             "unit_tests": ["ai messenger/pkg/daemon TestRoomCommitAuthorizationOutsideTheRelayWindowIsRefused"]})


def scenario() -> None:
    for function in STEPS:
        function()
        mr1.hold(function.__name__)


# --- Run ------------------------------------------------------------------------------

def finish() -> None:
    COUNTS["stop"] = True
    fd.evidence.setdefault("room_settings", {})["daemon_startup_lines"] = {
        node: sorted({line for line in log_text(f"messengerd-{node}").splitlines() if line.startswith("room_settings")})
        for node in NODES}
    mr1.finish()


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
    openfox_source = Path(os.environ.get("E2E_OPENFOX_SOURCE") or fd.REPO)
    git = mr1.git
    tree = git(fd.REPO, "status", "--porcelain").splitlines()
    openfox_tree = git(openfox_source, "status", "--porcelain").splitlines()
    ai_tree = git(ai_source, "status", "--porcelain").splitlines()
    tags = "-tags roomtest " if ROOMTEST else ""
    fd.evidence.update({
        "schema": "tos.messaging.relay-carriage.acceptance.v1",
        "milestone": "M-R2",
        "mode": "local: one host, network namespaces",
        "qualifies_as_public_acceptance": False,
        "reason": "one physical host: the nodes, the relays and the chain are separated by Linux network namespaces "
                  "and firewall rules, not by machines; the relays and the chain are operated by the run itself; no "
                  "internet path exists",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "harness_commit": git(fd.REPO, "rev-parse", "HEAD"), "harness_tree_status": tree,
        "openfox_commit": git(openfox_source, "rev-parse", "HEAD"), "openfox_tree_status": openfox_tree,
        "openfox_tree_dirty": bool(openfox_tree), "tos_commit": git(fd.SOURCE, "rev-parse", "HEAD"),
        "ai_commit": git(ai_source, "rev-parse", "HEAD"), "ai_tree_status": ai_tree,
        "room_id": ROOM,
        "builds": {"openfox": "GOWORK=off CGO_ENABLED=0 go build -trimpath -tags goolm,stdjson ./cmd/openfox",
                   "ai": f"GOWORK=off CGO_ENABLED=0 go build -trimpath {tags}./messenger/cmd/tos-messengerd; "
                         "go build -trimpath ./messenger/cmd/tos-messenger-owner ./protocol/cmd/tos-service-packet-relay",
                   "mls_driver": "cargo build --locked --release --manifest-path "
                                 "messenger/rust/openmls-driver/Cargo.toml",
                   "tool": "GOWORK=off CGO_ENABLED=0 go build -trimpath ./scripts/messenger-relay-e2e-tool"},
        "relays": {relay: {"url": RELAY_URL[relay], "ttl_seconds": RELAY_TTL,
                           "argv": [p.replace(str(WORK), "<workdir>") for p in relay_argv(relay)]}
                   for relay in RELAYS},
        "topology": {
            "bridge": "tosmr-br0 10.231.78.0/24, host end 10.231.78.1, no default route in any namespace",
            "namespaces": {mr1.NAMESPACE[name]: mr1.ADDRESS[name] for name in mr1.ADDRESS},
            "roles": {"a": "node A, the room's authority", "b": "node B, a member", "c": "node C, a member that "
                      "refuses unknown senders without an invite", "d": "filler joiner D (A adds and removes it "
                      "only to make Commits; it never posts)", "e": "filler joiner E (likewise)"},
            "chain": f"three validators in the host namespace on 127.0.0.1, JSON-RPC ports {fd.RPC_PORTS}",
            "firewall": "node namespaces: outgoing only to the relays' port %d and 10.231.78.1 JSON-RPC ports, no "
                        "incoming connection; relay namespaces: incoming only to port %d, no outgoing connection; "
                        "host bridge table: every node-to-node frame dropped" % (mr1.RELAY_PORT, mr1.RELAY_PORT),
            "files": "each namespace process runs with empty read-only tmpfs mounts over the other parties' "
                     "directories and the run's private files"},
        "network_label": fd.NETWORK_LABEL,
        "not_openfox": [
            "booting the three-validator network (tostester)",
            "creating, funding and activating the wallets with tosctl and the zerostate faucet",
            "each node's Messaging Endpoint identity and its commitment on chain (scripts/messenger-relay-e2e-tool "
            "identity; tosctl agent native-registry action --kind delegate)",
            "the test Endpoint signer (scripts/messenger-relay-e2e-tool signer)",
            "signing owner decisions with the owner key (tos-messenger-owner sign) and issuing C's invites "
            "(tos-messenger-owner prepare-invite and submit), as each node's owner",
            "the network namespaces, firewall rules, forwarders and the relay daemons",
            "the Messenger runtime calls (scripts/messenger-relay-e2e-tool call): this script is the Agent runtime "
            "of every node",
            "the crafted room objects (scripts/messenger-relay-e2e-tool room-frames and craft) and this script's "
            "relay reads and deposits"]})
    record("the harness tree is clean at the commit the evidence names", not tree, tree or "clean")
    record("the OpenFox binary is built from a clean tree at the commit the evidence names", not openfox_tree,
           openfox_tree or "clean")
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
                mr1.hold("failure")
            except Exception:  # noqa: BLE001 - the evidence records the failure
                import traceback
                trace = traceback.format_exc().replace(str(fd.REPO), "<repo>").replace(os.path.expanduser("~"), "~")
                fd.record("the run ran without an exception", False, fd.redact(trace)[-3000:])
                mr1.hold("failure")
            finally:
                await asyncio.to_thread(finish)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        fd.record("run completed without an exception", False, repr(error))
    log = WORK / "net" / "root-commands.log"
    commands = log.read_text().splitlines() if log.exists() else []
    fd.evidence["ran_as_root"] = {
        "network_setup_and_teardown": sorted({line.replace(str(WORK), "<workdir>") for line in commands}),
        "namespace_entry": mr1.LAUNCHED, "launcher_signals": mr1.ROOT_SIGNALS}
    fd.evidence["owner_decisions"] = DECISIONS
    fd.evidence["peer_counters"] = {"samples": COUNTS["samples"], "max_kind3_per_peer": COUNTS["max_room"],
                                    "max_chat_per_peer": COUNTS["max_chat"]}
    fd.evidence["gate_items"] = GATE
    fd.evidence["not_verified"] = NOT_VERIFIED
    fd.evidence["hold_at"] = mr1.HOLD_AT or None
    fd.evidence["dev_scripts_executed"] = mr1.DEV_SCRIPTS_RUN
    fd.evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    text = json.dumps(fd.redact_value(fd.evidence), default=str)
    leaked = fd.personal_data(text)
    fd.record("no home directory path or login name in evidence.json", not leaked, leaked)
    fd.record("no invite token in evidence.json", not any(token in text for token in SECRETS_HANDED))
    passed = bool(fd.steps) and all(step_["pass"] for step_ in fd.steps) and not mr1.DEV_SCRIPTS_RUN
    fd.evidence["steps"] = fd.steps
    fd.evidence["pass_count"] = sum(1 for step_ in fd.steps if step_["pass"])
    if mr1.DEV_SCRIPTS_RUN:
        fd.evidence["result"] = "NOT A VALID ACCEPTANCE: dev scripts were executed during the run"
    else:
        fd.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(fd.redact_value(fd.evidence), indent=2, default=str) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
