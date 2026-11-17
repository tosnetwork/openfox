#!/usr/bin/env python3
"""Red control of the room carrier's caps and security checks.

Each mutation disables one check with an exact, single-occurrence edit of
the source. The mutated package must build (go vet type-checks it and its
tests): a mutation that does not build is an error of this script, never a
catch. Its named guarding tests are then run, and at least one of them must
report `--- FAIL`. The edit is then reversed (the mutated text replaced by
the original) and the file must hold its original bytes again. A final run
requires the same tests to pass on the restored tree.

Run from the repository root:

    python3 scripts/red-control-room-carrier.py

The Go environment (GOWORK, GOTOOLCHAIN, GOFLAGS and the tosctl helper
variables the package's other tests need) is taken from the caller.
"""

import hashlib
import pathlib
import subprocess
import sys

PACKAGE = "./pkg/servicebridge/"
SOURCE = pathlib.Path("pkg/servicebridge")

MUTATIONS = [
    (
        "the kind-3 share of the per-peer cap",
        "relay_chat.go",
        "if !carrierapi.PeerCapAllows(kind, count, roomCount) {",
        "if !carrierapi.PeerCapAllows(relayframe.KindCopy, count, roomCount) {",
        "TestTheKind3CapIsSixteenBesideTheChatCapOfTwentyFour|TestAnUnreadableJournalRecordCountsAsKind3ForEveryPeer",
    ),
    (
        "an unreadable record counting as kind 3",
        "relay_transport.go",
        "IdempotencyKey: \"idem_\" + strings.TrimSuffix(name, \".json\"), Pending: true, FrameKind: relayframe.KindRoom,",
        "IdempotencyKey: \"idem_\" + strings.TrimSuffix(name, \".json\"), Pending: true,",
        "TestAnUnreadableJournalRecordCountsAsKind3ForEveryPeer",
    ),
    (
        "an empty pacing bucket",
        "relay_room.go",
        "if bucket.tokens <= 0 {\n\t\treturn false\n\t}",
        "if bucket.tokens <= 0 {\n\t\treturn true\n\t}",
        "TestTheRoomPacerIsATokenBucketOfThirtyPerMinuteBurstSixteen|TestKind3DepositsArePacedPerRelayAndOtherKindsAreNot",
    ),
    (
        "pacing kind 3 only",
        "relay_room.go",
        "if kind != relayframe.KindRoom {\n\t\treturn true\n\t}",
        "if kind == 255 {\n\t\treturn true\n\t}",
        "TestTheRoomPacerIsATokenBucketOfThirtyPerMinuteBurstSixteen|TestKind3DepositsArePacedPerRelayAndOtherKindsAreNot",
    ),
    (
        "the bound on pacing buckets",
        "relay_room.go",
        "if len(p.buckets) >= maxRoomPacingRelays {\n\t\t\tp.dropFullLocked(now)",
        "if false {\n\t\t\tp.dropFullLocked(now)",
        "TestTheRoomPacerBoundsItsRelaysAndDropsFullBucketsFirst",
    ),
    (
        "the application lifetime of one relay TTL",
        "relay_chat.go",
        "if frame.Kind == relayframe.KindEvidence || application {",
        "if frame.Kind == relayframe.KindEvidence || application && false {",
        "TestARoomObjectIsCarriedInPartsWithItsFrameKindJournaled",
    ),
    (
        "a malformed room part 0",
        "relay_chat.go",
        "application, err := roomFrameIsApplication(frame)\n\tif err != nil {",
        "application, err := roomFrameIsApplication(frame)\n\tif err != nil && false {",
        "TestCarryRefusesMalformedRoomFrames",
    ),
    (
        "inbound kind 3 to carrier.deliver",
        "relay_chat.go",
        "case relayframe.KindCopy, relayframe.KindEvidence, relayframe.KindRoom:",
        "case relayframe.KindCopy, relayframe.KindEvidence:",
        "TestARoomObjectIsCarriedInPartsWithItsFrameKindJournaled",
    ),
    (
        "room traffic creating no admission",
        "relay_room.go",
        "if !held {\n\t\t\t\t// No admission holds the sender",
        "if !held && false {\n\t\t\t\t// No admission holds the sender",
        "TestARoomObjectIsCarriedInPartsWithItsFrameKindJournaled|"
        "TestARoomAckReturnsToTheAuthorityAndPart0RenewsOnlyUnderAnAdmission",
    ),
    (
        "forgetting only without another admission",
        "relay_room.go",
        "remaining, removed := record.withoutRoom(roomID)\n\tif remaining.holds() {",
        "remaining, removed := record.withoutRoom(roomID)\n\tif false {",
        "TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission",
    ),
    (
        "cards held before a room count as direct",
        "relay_room.go",
        "record = roomAdmissionRecord{Schema: roomAdmissionSchema, AgentID: agentID, Direct: held}",
        "record = roomAdmissionRecord{Schema: roomAdmissionSchema, AgentID: agentID, Direct: held && false}",
        "TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission",
    ),
    (
        "a contact import as a direct admission",
        "relay_chat_setup.go",
        "setDirectAdmission(chatRoomAdmissionsDir(cards.directory), contact.AgentID, true)",
        "setDirectAdmission(chatRoomAdmissionsDir(cards.directory), contact.AgentID, false)",
        "TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission",
    ),
    (
        "an accepted copy as a direct admission",
        "relay_chat.go",
        "case outcome == relayframe.OutcomeAccepted, outcome == relayframe.OutcomeDuplicate:\n\t\treturn cardEstablished",
        "case outcome == relayframe.OutcomeAccepted, outcome == relayframe.OutcomeDuplicate:\n\t\treturn cardRenewed",
        "TestAnAcceptedCopyMakesARoomOnlyCardDirect",
    ),
    (
        "refusing this node's own card",
        "relay_room.go",
        "if offered.AgentID == c.agentID || err != nil",
        "if offered.AgentID == \"\" || err != nil",
        "TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission",
    ),
    (
        "refusing a card that does not verify",
        "relay_room.go",
        "card, err := c.Cards.verified(ctx, raw, offered.AgentID, \"\")",
        "card, err := decodePeerCard(raw, offered.AgentID, \"\")",
        "TestARoomCardIsVerifiedAgainstFinalizedStateBeforeItIsStored",
    ),
    (
        "the room bound per peer",
        "relay_room.go",
        "if len(record.Rooms) >= maxAgentRoomAdmissions {",
        "if false {",
        "TestAPeerIsAdmittedUnderAtMostSixtyFourRooms",
    ),
    (
        "the bounds of a room-cards request",
        "relay_room.go",
        "if len(request.ForgetAgentIDs) == 0 || len(request.ForgetAgentIDs) > carrierapi.MaxRoomCards ||",
        "if len(request.ForgetAgentIDs) == 0 || len(request.ForgetAgentIDs) > 1<<20 ||",
        "TestRoomCardsRequestsAreBounded",
    ),
    (
        "a withdrawal for the journaled peer only",
        "relay_room.go",
        "if entry.Packet.RecipientAgentID != peer {",
        "if false {",
        "TestCarrierWithdrawWithdrawsTheJournaledEnvelope",
    ),
    (
        "an unreadable admission record failing the preflight",
        "preflight_relay.go",
        "if len(unreadable) > 0 {",
        "if false {",
        "TestStatusAndPreflightShowRoomsAndTheKind3Counters",
    ),
    (
        "a split application object refused at carry",
        "relay_room.go",
        "if objectType == relayframe.RoomApplication && frame.PartCount != 1 {",
        "if objectType == relayframe.RoomApplication && frame.PartCount > relayframe.MaxParts {",
        "TestCarryRefusesMalformedRoomFrames",
    ),
    (
        "the admission record put back after a failed card store",
        "relay_room.go",
        "restoreErr := c.rooms.restore(previous, found, agentID)",
        "restoreErr := error(nil)",
        "TestAFailedCardStorePutsTheAdmissionRecordBack",
    ),
    (
        "a contact remove keeping the cards a room holds",
        "relay_chat_setup.go",
        "if card.AgentID != agent || len(rooms) > 0 {",
        "if card.AgentID != agent {",
        "TestRemovingAContactKeepsTheCardsARoomStillHolds|"
        "TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission",
    ),
    (
        "serve taking the inter-process admission lock",
        "relay_room.go",
        "unlock, err := lockRoomAdmissions(c.Cards.directory)\n\tif err != nil {\n\t\tc.admissions.Unlock()",
        "unlock, err := func() (func(), error) { return func() {}, nil }()\n\tif err != nil {\n\t\tc.admissions.Unlock()",
        "TestTheRoomAdmissionLockExcludesAnotherHandle",
    ),
    (
        "the contact commands taking the admission lock",
        "relay_chat_setup.go",
        "unlock, err := lockRoomAdmissions(cardsDir)",
        "unlock, err := func() (func(), error) { return func() {}, nil }()",
        "TestTheRoomAdmissionLockExcludesAnotherHandle",
    ),
]


def builds() -> bool:
    """Whether the package and its tests compile (go vet type-checks both)."""
    result = subprocess.run(["go", "vet", PACKAGE], capture_output=True, text=True)
    return result.returncode == 0


def run(tests: str) -> tuple[bool, list[str]]:
    """Runs the named tests; reports whether they passed and which of them
    reported --- FAIL."""
    command = ["go", "test", "-count=1", "-v", "-run", f"^({tests})$", PACKAGE]
    result = subprocess.run(command, capture_output=True, text=True)
    failed = [test for test in tests.split("|") if f"--- FAIL: {test} " in result.stdout]
    return result.returncode == 0, failed


def main() -> int:
    failures = []
    all_tests = set()
    if not builds():
        print("FAIL: the unmutated package does not build")
        return 1
    for name, file, original, mutated, tests in MUTATIONS:
        all_tests.update(tests.split("|"))
        path = SOURCE / file
        before = path.read_bytes()
        text = before.decode()
        if text.count(original) != 1:
            failures.append(f"{name}: the original text occurs {text.count(original)} times in {file}")
            continue
        changed = text.replace(original, mutated)
        if changed.count(mutated) != 1:
            failures.append(f"{name}: the mutated text would not be unique in {file}, so it cannot be reversed")
            continue
        path.write_text(changed)
        try:
            # A mutation that does not build proves nothing: it is an error of
            # this script, never a catch.
            built = builds()
            passed, failed = run(tests) if built else (False, [])
        finally:
            current = path.read_text()
            if current.count(mutated) != 1:
                raise SystemExit(f"{name}: cannot reverse the edit in {file}")
            path.write_text(current.replace(mutated, original))
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(before).digest():
            raise SystemExit(f"{name}: {file} is not restored to its original bytes")
        if not built:
            print(f"{name}: DOES NOT BUILD (script error)", flush=True)
            failures.append(f"{name}: the mutated package does not build")
        elif failed:
            print(f"{name}: caught by {', '.join(failed)}", flush=True)
        else:
            status = "PASSED (not caught)" if passed else "failed without a named test failing"
            print(f"{name}: {status}", flush=True)
            failures.append(f"{name}: no named guarding test reported --- FAIL")
    passed, _ = run("|".join(sorted(all_tests)))
    if not passed:
        failures.append("the guarding tests fail on the restored tree")
    else:
        print("restored tree: the guarding tests pass", flush=True)
    for failure in failures:
        print("FAIL:", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
