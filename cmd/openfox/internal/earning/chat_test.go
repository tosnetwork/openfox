package earning

import (
	"bytes"
	"strings"
	"testing"
)

// The room, invite and owner commands exist with the flags their decisions
// need, and an invite on a contact import needs all three of its flags.
func TestTheChatRoomInviteAndOwnerCommandsTakeTheirFlags(t *testing.T) {
	root := chatCommand()
	for path, flags := range map[string][]string{
		"room create":    {"rail-config", "room", "out"},
		"room add":       {"rail-config", "room", "agent", "out"},
		"room remove":    {"rail-config", "room", "agent", "out"},
		"room join":      {"rail-config", "room", "authority", "out"},
		"room list":      {"rail-config"},
		"invite present": {"rail-config", "recipient", "token-file", "expires-at", "out"},
		"owner submit":   {"rail-config", "decision"},
		"contact import": {"rail-config", "file", "invite", "invite-expires-at", "invite-out"},
	} {
		command, rest, err := root.Find(strings.Fields(path))
		if err != nil || len(rest) != 0 || command.Name() != strings.Fields(path)[1] {
			t.Fatalf("%s: not found (%v)", path, err)
		}
		for _, flag := range flags {
			if command.Flags().Lookup(flag) == nil {
				t.Fatalf("%s: no --%s", path, flag)
			}
		}
	}
	root.SetArgs([]string{
		"contact", "import", "--rail-config", "/x/rail.json", "--file", "/x/contact.json",
		"--invite", "/x/token",
	})
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invite-out") {
		t.Fatalf("an invite without its expiry and output: %v", err)
	}
}
