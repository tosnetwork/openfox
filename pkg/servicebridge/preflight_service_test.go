package servicebridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/execution/pkg/executorservice"
)

// newSocketPreflightFixture is a ready provider node that executes through
// an executor service the test serves.
func newSocketPreflightFixture(t *testing.T) (*pfFixture, *scriptedExecutor) {
	t.Helper()
	f := newPreflightFixture(t)
	service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer { return scriptedAnswer{Drop: true} })
	provider := f.config.Provider
	provider.ExecutorSocket = service.socket
	provider.ExecutorBinary, provider.ExecutorSHA256, provider.ContainerdSocket, provider.FIFODir = "", "", "", ""
	f.env.ExecutorService = func(socket string) (ExecutorService, error) { return ownClient(t, socket), nil }
	return f, service
}

var socketPreflightChecks = []string{
	"config.parse", "config.provider", "state_dir.private", "state_dir.disk_free", "admission.pause",
	"process.user", "tosctl.pin", "tosctl.config", "tosctl.vault_env", "transport.peers",
	"manifest.local", "executor.service", "executor.image", "executor.limits",
	"rpc.endpoints", "rpc.independence", "chain.open", "rpc.genesis", "chain.finalized",
	"clock.skew", "chain.registry", "chain.capability", "chain.actor", "chain.attestor", "chain.admission",
	"signer.attestor", "signer.packet", "signer.wallet",
}

func TestPreflightOfAnUnprivilegedNodeAsksTheExecutorService(t *testing.T) {
	f, _ := newSocketPreflightFixture(t)
	report, checks := f.run(t)
	if !report.OK {
		t.Fatalf("a ready provider failed: %+v", report)
	}
	for _, id := range socketPreflightChecks {
		check, ok := checks[id]
		if !ok {
			t.Fatalf("check %s is missing", id)
		}
		want := CheckPass
		if id == "rpc.independence" || id == "signer.wallet" {
			want = CheckUnknown
		}
		if check.Status != want || check.Message == "" {
			t.Fatalf("check %s: %s (%s), want %s", id, check.Status, check.Message, want)
		}
	}
	// The checks of the executor run as the node's own child need paths
	// only that mode has and are not reported.
	if len(checks) != len(socketPreflightChecks) {
		t.Fatalf("%d checks reported, want %d: %+v", len(checks), len(socketPreflightChecks), report.Checks)
	}
}

func TestEachExecutorServiceCheckFailsWithAnActionableMessage(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		status  string
		message string
		// others are the statuses the remaining service checks must have.
		others map[string]string
		break_ func(t *testing.T, f *pfFixture, service *scriptedExecutor)
	}{
		{
			"no service", "executor.service", CheckFail, "does not answer",
			map[string]string{"executor.image": CheckUnknown, "executor.limits": CheckUnknown},
			func(t *testing.T, f *pfFixture, _ *scriptedExecutor) {
				f.config.Provider.ExecutorSocket = filepath.Join(shortSocketDir(t), "absent.sock")
			},
		},
		{
			"a socket not served by root", "executor.service", CheckFail, "not served by root",
			map[string]string{"executor.image": CheckUnknown, "executor.limits": CheckUnknown},
			func(t *testing.T, f *pfFixture, _ *scriptedExecutor) {
				if os.Getuid() == 0 {
					t.Fatal("this case serves the socket as the test user; run it unprivileged")
				}
				f.env.ExecutorService = OpenExecutorService
			},
		},
		{
			"a uid the service refuses", "executor.service", CheckFail, "TOS_EXECUTOR_ALLOWED_UID",
			map[string]string{"executor.image": CheckUnknown, "executor.limits": CheckUnknown},
			func(t *testing.T, f *pfFixture, _ *scriptedExecutor) {
				refusing := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, func(c *executorservice.Config) {
					other := uint32(os.Getuid()) + 1
					c.AllowedUID = &other
				})
				f.config.Provider.ExecutorSocket = refusing.socket
			},
		},
		{
			"a backend that is not ready", "executor.service", CheckFail, "not ready",
			map[string]string{"executor.image": CheckFail, "executor.limits": CheckPass},
			func(_ *testing.T, _ *pfFixture, service *scriptedExecutor) {
				description := goodDescription()
				description.Ready = false
				service.setDescription(description)
			},
		},
		{
			"another image", "executor.image", CheckFail, "not the manifest toolchain",
			map[string]string{"executor.service": CheckPass, "executor.limits": CheckPass},
			func(_ *testing.T, _ *pfFixture, service *scriptedExecutor) {
				description := goodDescription()
				description.ImageDigest = sha256Text(sha256Sum([]byte("another image")))
				service.setDescription(description)
			},
		},
		{
			"tighter limits", "executor.limits", CheckFail, "wall_clock_millis",
			map[string]string{"executor.service": CheckPass, "executor.image": CheckPass},
			func(_ *testing.T, _ *pfFixture, service *scriptedExecutor) {
				description := goodDescription()
				description.Limits.WallClockMillis = 1000
				service.setDescription(description)
			},
		},
		{
			"no local manifest", "manifest.local", CheckFail, "",
			map[string]string{
				"executor.service": CheckPass, "executor.image": CheckUnknown,
				"executor.limits": CheckUnknown,
			},
			func(_ *testing.T, f *pfFixture, _ *scriptedExecutor) {
				f.config.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("89", 32)
			},
		},
		{
			"a root node", "process.user", CheckFail, "unprivileged",
			map[string]string{"executor.service": CheckPass},
			func(_ *testing.T, f *pfFixture, _ *scriptedExecutor) { f.euid = 0 },
		},
		{
			"both executors", "config.provider", CheckFail, "exactly one executor",
			map[string]string{"executor.service": CheckUnknown},
			func(_ *testing.T, f *pfFixture, _ *scriptedExecutor) {
				f.config.Provider.ExecutorBinary = "/opt/software-work-execute"
			},
		},
		{
			"no executor", "config.provider", CheckFail, "names no executor",
			map[string]string{"executor.service": CheckUnknown},
			func(_ *testing.T, f *pfFixture, _ *scriptedExecutor) { f.config.Provider.ExecutorSocket = "" },
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f, service := newSocketPreflightFixture(t)
			test.break_(t, f, service)
			report, checks := f.run(t)
			check := checks[test.id]
			if check.Status != test.status || !strings.Contains(check.Message, test.message) {
				t.Fatalf("%s: %s (%s), want %s mentioning %q", test.id, check.Status, check.Message, test.status,
					test.message)
			}
			if report.OK {
				t.Fatal("the report is ok with a failed check")
			}
			for id, want := range test.others {
				if checks[id].Status != want {
					t.Fatalf("%s: %s (%s), want %s", id, checks[id].Status, checks[id].Message, want)
				}
			}
		})
	}
}

// With the executor run as the node's own child, a root node is what a
// root-only container runtime requires: it stays a warning.
func TestARootNodeOnlyFailsPreflightWhenTheExecutorServiceMakesRootUnnecessary(t *testing.T) {
	f := newPreflightFixture(t)
	f.euid = 0
	report, checks := f.run(t)
	if checks["process.user"].Status != CheckWarn || !report.OK {
		t.Fatalf("a root node with its own executor: %+v", checks["process.user"])
	}
	if _, reported := checks["executor.service"]; reported {
		t.Fatal("the executor service was checked for a node that does not use it")
	}
}

func TestPreflightTellsAStaleLoginSessionFromAMissingGroup(t *testing.T) {
	stale := groupSessionHint(984, "tos-executor", []int{1000, 27}, []string{"1000", "27", "984"})
	if !strings.Contains(stale, "new login session") || !strings.Contains(stale, "sg tos-executor") {
		t.Fatalf("a user listed in the group without the gid in its process: %q", stale)
	}
	absent := groupSessionHint(984, "tos-executor", []int{1000, 27}, []string{"1000", "27"})
	if !strings.Contains(absent, "not a member") || strings.Contains(absent, "sg tos-executor") {
		t.Fatalf("a user outside the group: %q", absent)
	}
	if hint := groupSessionHint(984, "tos-executor", []int{1000, 984}, []string{"1000"}); hint != "" {
		t.Fatalf("a process that carries the group was given the hint %q", hint)
	}
	// A directory this user owns, or one open to everyone, is not a group
	// problem.
	if hint := socketGroupHint(filepath.Join(t.TempDir(), "executor.sock")); hint != "" {
		t.Fatalf("the user's own directory was given the hint %q", hint)
	}

	f, _ := newSocketPreflightFixture(t)
	f.config.Provider.ExecutorSocket = filepath.Join(shortSocketDir(t), "absent.sock")
	f.env.SocketGroupHint = func(socket string) string {
		if socket != f.config.Provider.ExecutorSocket {
			t.Errorf("the hint was asked for %s", socket)
		}
		return stale
	}
	_, checks := f.run(t)
	if check := checks["executor.service"]; check.Status != CheckFail || !strings.Contains(check.Message, stale) {
		t.Fatalf("executor.service: %s (%s)", check.Status, check.Message)
	}
	// A service that answers is not given the hint.
	f, _ = newSocketPreflightFixture(t)
	f.env.SocketGroupHint = func(string) string { return stale }
	_, checks = f.run(t)
	if check := checks["executor.service"]; check.Status != CheckPass || strings.Contains(check.Message, "login") {
		t.Fatalf("executor.service: %s (%s)", check.Status, check.Message)
	}
}
