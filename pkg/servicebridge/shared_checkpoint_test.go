package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// checkpointChain is a three-endpoint finalized chain whose head the test
// moves. No account is active, so every registry read ends "not found"
// after passing the reader's checkpoint fences.
type checkpointChain struct {
	head atomic.Uint64
	urls []string
}

func newCheckpointChain(t *testing.T, head uint64, root, file []byte) *checkpointChain {
	t.Helper()
	chain := &checkpointChain{}
	chain.head.Store(head)
	block := func(seqno uint64) map[string]any {
		suffix := string(rune('a' + seqno%26))
		return map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": seqno,
			"root_hash": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("r", 31) + suffix)),
			"file_hash": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("f", 31) + suffix))}
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		head, now := chain.head.Load(), time.Now().Unix()
		var result any
		switch call.Method {
		case "getConsensusBlock":
			result = map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": head, "timestamp": now,
				"last_block_utime": now}
		case "getMasterchainInfo":
			result = map[string]any{"@type": "blocks.masterchainInfo", "last": block(head),
				"init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(root),
					"file_hash": base64.StdEncoding.EncodeToString(file)}}
		case "getAddressInformation":
			var params struct {
				Seqno uint64 `json:"seqno"`
			}
			_ = json.Unmarshal(call.Params, &params)
			result = map[string]any{"@type": "raw.fullAccountState", "block_id": block(params.Seqno), "state": "uninitialized"}
		default:
			http.Error(response, "unknown method", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	})
	for range 3 {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		chain.urls = append(chain.urls, server.URL)
	}
	return chain
}

// sharedStateConfig is a node configuration over the chain, with the
// release registry code, whose readers keep their fences in stateDir as
// every `openfox earning service` command and `serve` of one node do.
func sharedStateConfig(t *testing.T, chain *checkpointChain, root, file []byte) NodeConfig {
	t.Helper()
	path := filepath.Join("testdata", "native-registry-code.boc.base64")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	boc, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(encoded)), ""))
	if err != nil {
		t.Fatal(err)
	}
	code, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return NodeConfig{
		Network: NetworkConfig{NetworkID: "tos:shared-checkpoint-test", GenesisRootHash: "sha256:" + hex.EncodeToString(root),
			GenesisFileHash: "sha256:" + hex.EncodeToString(file)},
		RPCEndpoints: chain.urls, Quorum: 2, RegistryCodeBOC: absolute,
		RegistryCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code.Hash()),
		ActorCodeHash:    "tvm-cell-sha256:" + strings.Repeat("ab", 32),
	}
}

// A buyer's `buy` checks the offer and builds its Quote at one finalized
// checkpoint, reading the Capability twice, while the buyer's `serve` keeps
// reading newer checkpoints through the same state directory. The purchase
// must not fail because serve moved the shared fence past the purchase's
// checkpoint in between.
func TestBuyReadsAtItsCheckpointWhileServeAdvancesTheSharedFence(t *testing.T) {
	root, file := []byte(strings.Repeat("g", 32)), []byte(strings.Repeat("h", 32))
	chain := newCheckpointChain(t, 1000, root, file)
	config := sharedStateConfig(t, chain, root, file)
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	buy, err := openServiceActorReader(config, networkOf(config), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	serve, err := openServiceActorReader(config, networkOf(config), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	capability := "cap_" + strings.Repeat("33", 32)
	ctx := context.Background()

	// Deterministic interleaving: buy pins 1000 and reads; serve reads 1005;
	// buy reads again at 1000.
	session, err := buy.Begin(ctx)
	if err != nil || session.Checkpoint() != 1000 {
		t.Fatalf("buy's session: %v", err)
	}
	if _, _, err := session.ResolveRegistry(ctx, capability); err != nil {
		t.Fatalf("buy's offer check: %v", err)
	}
	chain.head.Store(1005)
	served, err := serve.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := served.ResolveRegistry(ctx, capability); err != nil {
		t.Fatalf("serve's read: %v", err)
	}
	if _, _, err := session.ResolveRegistry(ctx, capability); err != nil {
		t.Fatalf("buy's Quote read at its checkpoint after serve advanced the shared fence: %v", err)
	}

	// The same, concurrently: serve keeps advancing while purchases run.
	var wait sync.WaitGroup
	stop := make(chan struct{})
	serveErrors := make(chan error, 1)
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// serve's own pace is seconds; a millisecond keeps the fence
			// moving through every purchase below.
			time.Sleep(time.Millisecond)
			chain.head.Add(1)
			next, err := serve.Begin(ctx)
			if err == nil {
				_, _, err = next.ResolveRegistry(ctx, capability)
			}
			if err != nil {
				select {
				case serveErrors <- err:
				default:
				}
				return
			}
		}
	}()
	for purchase := 0; purchase < 20; purchase++ {
		pinned, err := buy.Begin(ctx)
		if err != nil {
			close(stop)
			wait.Wait()
			t.Fatalf("purchase %d: open: %v", purchase, err)
		}
		for read := 0; read < 2; read++ {
			if _, _, err := pinned.ResolveRegistry(ctx, capability); err != nil {
				close(stop)
				wait.Wait()
				t.Fatalf("purchase %d read %d at checkpoint %d: %v", purchase, read, pinned.Checkpoint(), err)
			}
		}
	}
	close(stop)
	wait.Wait()
	select {
	case err := <-serveErrors:
		t.Fatalf("serve: %v", err)
	default:
	}
}
