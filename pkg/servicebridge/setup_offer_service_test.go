package servicebridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/execution/pkg/executorservice"
)

// socketOffer is an offer that names no executor of its own.
func socketOffer(t *testing.T) *setupFixture {
	t.Helper()
	f := newSetupFixture(t)
	f.mustInit(t)
	f.offer.ExecutorBinary, f.offer.ContainerdSocket = "", ""
	return f
}

func TestOfferUsesTheExecutorServiceUnlessAnExecutorIsGiven(t *testing.T) {
	f := socketOffer(t)
	var asked []string
	env := f.env()
	env.ExecutorService = func(socket string) (ExecutorService, error) {
		asked = append(asked, socket)
		return &memoryExecutor{description: goodDescription()}, nil
	}
	result, err := RunOffer(context.Background(), f.offer, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != DefaultExecutorSocket || result.ExecutorSocket != DefaultExecutorSocket ||
		result.ExecutorSHA256 != "" {
		t.Fatalf("the offer asked %v and reports %+v", asked, result)
	}
	config, err := LoadNodeConfig(f.offer.RailConfigPath)
	if err != nil || config.Provider == nil {
		t.Fatalf("provider section: %v", err)
	}
	if mode, modeErr := config.Provider.ExecutorMode(); modeErr != nil || mode != ExecutorModeSocket ||
		config.Provider.ExecutorSocket != DefaultExecutorSocket {
		t.Fatalf("the written section names %s: %v (%+v)", mode, modeErr, config.Provider)
	}
	raw, err := os.ReadFile(f.offer.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"executor_binary", "executor_sha256", "containerd_socket", "fifo_dir"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("the configuration of a socket provider names %s", field)
		}
	}

	// A socket the owner names is the one asked and written.
	other := socketOffer(t)
	other.offer.ExecutorSocket = "/run/another/executor.sock"
	asked = nil
	env = other.env()
	env.ExecutorService = func(socket string) (ExecutorService, error) {
		asked = append(asked, socket)
		return &memoryExecutor{description: goodDescription()}, nil
	}
	if _, err = RunOffer(context.Background(), other.offer, env); err != nil {
		t.Fatal(err)
	}
	config, err = LoadNodeConfig(other.offer.RailConfigPath)
	if err != nil || len(asked) != 1 || asked[0] != "/run/another/executor.sock" ||
		config.Provider.ExecutorSocket != "/run/another/executor.sock" {
		t.Fatalf("the named socket was not used: asked %v, %v", asked, err)
	}
}

// The default must not select a socket nothing trustworthy serves: `offer`
// stops before it creates a key or sends a message.
func TestOfferSendsNothingUnlessTheExecutorServiceCanRunTheOffer(t *testing.T) {
	unready := goodDescription()
	unready.Ready = false
	otherImage := goodDescription()
	otherImage.ImageDigest = sha256Text(sha256Sum([]byte("another image")))
	tighter := goodDescription()
	tighter.Limits.OutputBytes = 1024
	cases := map[string]*memoryExecutor{
		"the service does not answer": {describeErr: errors.New("executor service: connect to the service socket")},
		"the backend is not ready":    {description: unready},
		"another image":               {description: otherImage},
		"tighter limits":              {description: tighter},
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			f := socketOffer(t)
			calls := len(f.world().Calls)
			env := f.env()
			env.ExecutorService = func(string) (ExecutorService, error) { return client, nil }
			if _, err := RunOffer(context.Background(), f.offer, env); err == nil {
				t.Fatal("the offer was published")
			}
			if len(f.world().Calls) != calls {
				t.Fatalf("tosctl was run without an executor: %+v", f.world().Calls[calls:])
			}
			if config, err := LoadNodeConfig(f.offer.RailConfigPath); err != nil || config.Provider != nil {
				t.Fatalf("a provider section was written: %v", err)
			}
		})
	}
	t.Run("the node's own client", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Fatal("this case serves a socket as the test user; run it unprivileged")
		}
		service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer { return scriptedAnswer{Drop: true} })
		for socket, want := range map[string]error{
			filepath.Join(shortSocketDir(t), "absent.sock"): nil,
			service.socket: executorservice.ErrServerIdentity,
		} {
			f := socketOffer(t)
			f.offer.ExecutorSocket = socket
			calls := len(f.world().Calls)
			// The environment's own opener: root must serve the socket.
			_, err := RunOffer(context.Background(), f.offer, f.env())
			if err == nil || (want != nil && !errors.Is(err, want)) {
				t.Fatalf("%s: the offer was published or refused for another reason: %v", socket, err)
			}
			if len(f.world().Calls) != calls {
				t.Fatalf("tosctl was run for a socket root does not serve: %+v", f.world().Calls[calls:])
			}
		}
	})
}

func TestOfferRefusesAnAmbiguousExecutorChoice(t *testing.T) {
	cases := map[string]func(*OfferInput, string){
		"a socket and a binary":         func(in *OfferInput, root string) { in.ExecutorBinary = filepath.Join(root, "executor") },
		"a socket and a runtime socket": func(in *OfferInput, root string) { in.ContainerdSocket = filepath.Join(root, "c.sock") },
		"a socket and a pin":            func(in *OfferInput, _ string) { in.ExecutorSHA256 = strings.Repeat("0", 64) },
		"a socket and a FIFO directory": func(in *OfferInput, root string) { in.FIFODir = filepath.Join(root, "fifo") },
		"a relative socket":             func(in *OfferInput, _ string) { in.ExecutorSocket = "executor.sock" },
		"a binary without a runtime socket": func(in *OfferInput, root string) {
			in.ExecutorSocket, in.ExecutorBinary = "", filepath.Join(root, "executor")
		},
		"a runtime socket without a binary": func(in *OfferInput, root string) {
			in.ExecutorSocket, in.ContainerdSocket = "", filepath.Join(root, "c.sock")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := socketOffer(t)
			f.offer.ExecutorSocket = DefaultExecutorSocket
			mutate(&f.offer, f.root)
			calls := len(f.world().Calls)
			env := f.env()
			asked := 0
			env.ExecutorService = func(string) (ExecutorService, error) {
				asked++
				return &memoryExecutor{description: goodDescription()}, nil
			}
			if _, err := RunOffer(context.Background(), f.offer, env); err == nil {
				t.Fatal("accepted")
			}
			if len(f.world().Calls) != calls || asked != 0 {
				t.Fatalf("an ambiguous offer reached tosctl or the service (%d probes)", asked)
			}
		})
	}
}
