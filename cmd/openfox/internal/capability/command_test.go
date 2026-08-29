package capability

import "testing"

func TestLifecycleCommandsArePublicAndTyped(t *testing.T) {
	command := NewCommand()
	wanted := map[string]bool{
		"bootstrap": false, "rotate-policy": false, "issue-session": false,
		"quarantine": false, "verify": false, "admit": false, "promote": false,
		"install": false, "recover-outcome": false,
	}
	for _, child := range command.Commands() {
		if _, ok := wanted[child.Name()]; ok {
			wanted[child.Name()] = true
			if child.Flag("request-file") == nil {
				t.Fatalf("%s lacks an exact request-file interface", child.Name())
			}
		}
	}
	for name, present := range wanted {
		if !present {
			t.Fatalf("public lifecycle command %s is missing", name)
		}
	}
	for _, forbidden := range []string{"activate", "revoke", "remove", "pause", "resume"} {
		if child, _, err := command.Find([]string{forbidden}); err == nil && child != command {
			t.Fatalf("unsigned authority-bearing command %s is public", forbidden)
		}
	}
}
