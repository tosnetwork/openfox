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
    config = _mr1_daemon_config(node)
    config["admission"]["known_agent_ids"] = sorted(RUN[p]["agent"] for p in ALLOW[node])
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


_mr1_daemon_config = mr1.daemon_config
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
        answer = json.loads(result.stdout)
    except ValueError:
        answer = {"ok": False, "error": fd.redact(result.stderr)[-800:]}
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
        content = (event or {}).get("content")
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
    mr1.identities()
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


def scenario() -> None:
    for function in STEPS:
        function()
        mr1.hold(function.__name__)


# --- Run ------------------------------------------------------------------------------

def finish() -> None:
    COUNTS["stop"] = True
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
