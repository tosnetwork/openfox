package servicebridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The operator's packet controller rotation: the Agent's finalized policy
// moves to a new packet key by a policy update sent outside OpenFox, and the
// node is re-established in a new state directory with the new controller.
const rotatedPacketController = "rotated-packet"

// moveToNewStateDir points the fixture's init at a fresh state directory
// and the new packet controller, keeping the rail configuration that names
// the Agent.
func moveToNewStateDir(t *testing.T, f *setupFixture) string {
	t.Helper()
	state := filepath.Join(f.root, "state-rotated")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	f.init.StateDir, f.init.PacketController, f.init.ReceiverSocket = state, rotatedPacketController, ""
	f.change(func(w *fakeWorld) { w.Controllers[rotatedPacketController] = true })
	return state
}

// rotateOnChain is the finalized effect of the policy update: the Agent's
// only controller is now the new packet key.
func rotateOnChain(f *setupFixture, agentID string) {
	f.change(func(w *fakeWorld) { w.Agents[agentID] = fakeKey(rotatedPacketController).Text() })
}

func TestInitInANewStateDirAdoptsTheAgentAfterItsPacketControllerRotated(t *testing.T) {
	f := newSetupFixture(t)
	first := f.mustInit(t)
	rotateOnChain(f, first.AgentID)
	state := moveToNewStateDir(t, f)
	sends := f.world().sends()
	registrations := f.world().count("agent native-registry register-agent")
	again := f.mustInit(t)
	world := f.world()
	if again.AgentID != first.AgentID || world.sends() != sends ||
		world.count("agent native-registry register-agent") != registrations || len(world.Agents) != 1 {
		t.Fatalf("the rotation re-run registered or sent: %s vs %s, %d sends, %v", again.AgentID, first.AgentID,
			world.sends()-sends, world.Agents)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.AgentID != first.AgentID || config.PacketController != rotatedPacketController ||
		config.PacketKeyID != fakeKey(rotatedPacketController).Text() || config.StateDir != state ||
		config.ReceiverSocket != filepath.Join(state, "rail-receiver.sock") {
		t.Fatalf("the configuration was not moved to the new controller and state directory: %+v", config)
	}
}

func TestInitInANewStateDirRefusesANewPacketControllerTheAgentDoesNotHold(t *testing.T) {
	f := newSetupFixture(t)
	f.mustInit(t)
	moveToNewStateDir(t, f)
	sends := f.world().sends()
	_, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, nil, "registered but its policy does not hold packet key")
	if f.world().sends() != sends {
		t.Fatal("a refused rotation sent a message")
	}
}

func TestOfferFromTheNewStateDirKeepsTheActorAndRegistersANewCapability(t *testing.T) {
	f := newSetupFixture(t)
	first := f.mustInit(t)
	before := f.mustOffer(t)
	rotateOnChain(f, first.AgentID)
	moveToNewStateDir(t, f)
	f.mustInit(t)
	world := f.world()
	deploys, policies := world.count("agent service deploy"), world.count("agent service send update-policy")
	after := f.mustOffer(t)
	world = f.world()
	if after.Preview.Actor != before.Preview.Actor || world.count("agent service deploy") != deploys ||
		world.Actor == nil || world.Actor.Address != before.Preview.Actor {
		t.Fatalf("the actor moved or was deployed again: %s vs %s, %d deploys", after.Preview.Actor,
			before.Preview.Actor, world.count("agent service deploy")-deploys)
	}
	if after.Preview.CapabilityID == before.Preview.CapabilityID {
		t.Fatal("no new Capability was registered")
	}
	capability, registered := world.Capabilities[after.Preview.CapabilityID]
	if !registered || capability.Owner != first.AgentID {
		t.Fatalf("the new Capability is not registered to the Agent: %+v", world.Capabilities)
	}
	if _, kept := world.Capabilities[before.Preview.CapabilityID]; !kept {
		t.Fatal("the old Capability disappeared")
	}
	register := world.last("agent native-registry action")
	if fakeArgument(register.Args, "--signer") != rotatedPacketController {
		t.Fatalf("the Capability registration was signed by %q", fakeArgument(register.Args, "--signer"))
	}
	if world.count("agent service send update-policy") != policies+1 ||
		world.Actor.Metadata != after.Preview.MetadataHash || after.Preview.MetadataHash == before.Preview.MetadataHash {
		t.Fatalf("the actor's policy does not name the new Capability: metadata %s, preview %s", world.Actor.Metadata,
			after.Preview.MetadataHash)
	}
}
