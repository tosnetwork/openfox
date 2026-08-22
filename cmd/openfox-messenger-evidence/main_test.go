package main

import (
	"strings"
	"testing"
)

func TestVerifyPairRequiresExactCrossTranscriptRoundTripAndRestart(t *testing.T) {
	aID := "agent_" + strings.Repeat("a", 64)
	bID := "agent_" + strings.Repeat("b", 64)
	e1 := "evt_" + strings.Repeat("1", 64)
	e2 := "evt_" + strings.Repeat("2", 64)
	r1 := "run_" + strings.Repeat("3", 32)
	r2 := "run_" + strings.Repeat("4", 32)
	a := evidence{Schema: controlSchema, AgentID: aID, RunID: r1, Transcript: []transcriptLine{
		{Direction: "outbound", RecipientInput: "bob.tos", EventID: e1, Content: "ping:hello", RunID: r1, AppliedUnix: 1},
		{Direction: "inbound", PeerAgentID: bID, EventID: e2, ReplyToEventID: e1, Content: "ack", RunID: r1, AppliedUnix: 2},
	}}
	b := evidence{Schema: controlSchema, AgentID: bID, RunID: r2, Transcript: []transcriptLine{
		{Direction: "inbound", PeerAgentID: aID, EventID: e1, Content: "ping:hello", RunID: r1, AppliedUnix: 1},
		{Direction: "outbound", EventID: e2, ReplyToEventID: e1, Content: "ack", RunID: r2, AppliedUnix: 2},
	}}
	if err := verifyPair(a, b, bID); err != nil {
		t.Fatal(err)
	}
	b.Transcript[0].PeerAgentID = bID
	if err := verifyPair(a, b, bID); err == nil {
		t.Fatal("peer substitution passed")
	}
}

func TestVerifyPairRejectsReplyContentOrCausalitySubstitution(t *testing.T) {
	aID := "agent_" + strings.Repeat("a", 64)
	bID := "agent_" + strings.Repeat("b", 64)
	e1 := "evt_" + strings.Repeat("1", 64)
	e2 := "evt_" + strings.Repeat("2", 64)
	run := "run_" + strings.Repeat("3", 32)
	a := evidence{Schema: controlSchema, AgentID: aID, RunID: run, Transcript: []transcriptLine{
		{Direction: "outbound", EventID: e1, Content: "ping", RunID: run, AppliedUnix: 1},
		{Direction: "inbound", PeerAgentID: bID, EventID: e2, ReplyToEventID: e1, Content: "different", RunID: run, AppliedUnix: 2},
	}}
	b := evidence{Schema: controlSchema, AgentID: bID, RunID: run, Transcript: []transcriptLine{
		{Direction: "inbound", PeerAgentID: aID, EventID: e1, Content: "ping", RunID: run, AppliedUnix: 1},
		{Direction: "outbound", EventID: e2, ReplyToEventID: e1, Content: "ack", RunID: run, AppliedUnix: 2},
	}}
	if err := verifyPair(a, b, ""); err == nil {
		t.Fatal("reply substitution passed")
	}
}
