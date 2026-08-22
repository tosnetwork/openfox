// Command tos-service-alias resolves a human-readable .tos discovery input and
// emits reviewable Native identity evidence. It never authorizes or purchases.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"

	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("tos-service-alias", flag.ContinueOnError)
	name := flags.String("name", "", "human-readable .tos name")
	kindName := flags.String("kind", "", "agent or capability")
	gateway := flags.String("gateway", "", "TOS Native gateway HTTPS base URL")
	tokenFile := flags.String("bearer-token-file", "", "owner-private gateway bearer token")
	caller := flags.String("caller-id", "", "calling Native Agent ID")
	networkID := flags.String("network-id", "", "expected TOS network ID")
	genesisRoot := flags.String("genesis-root-hash", "", "expected TOS genesis root hash")
	genesisFile := flags.String("genesis-file-hash", "", "expected TOS genesis file hash")
	caFile := flags.String("ca", "", "optional private gateway CA PEM")
	clientCert := flags.String("client-cert", "", "optional mTLS client certificate")
	clientKey := flags.String("client-key", "", "optional mTLS client key")
	output := flags.String("output", "", "new review evidence JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *name == "" || *kindName == "" ||
		*gateway == "" || *tokenFile == "" || *caller == "" || *networkID == "" || *genesisRoot == "" ||
		*genesisFile == "" || *output == "" {
		return errors.New("alias resolution requires name, kind, gateway, token, caller, pinned network, and output")
	}
	kind, err := parseKind(*kindName)
	if err != nil {
		return err
	}
	token, err := readPrivateToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := nativeclient.New(nativeclient.Config{
		BaseURL: *gateway, BearerToken: token,
		Timeout: 30 * time.Second, CAFile: *caFile, ClientCertFile: *clientCert, ClientKeyFile: *clientKey,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	network := &nativev1.NetworkDomain{
		NetworkId:       *networkID,
		GenesisRootHash: *genesisRoot,
		GenesisFileHash: *genesisFile,
	}
	evidence, err := nativeimpl.ResolveDNSNameInput(ctx, client, network, *name, *caller, kind, time.Now())
	if err != nil {
		return err
	}
	account := evidence.ResolvedAccount
	document := struct {
		Schema          string   `json:"schema"`
		Verdict         string   `json:"verdict"`
		InputName       string   `json:"input_name"`
		CanonicalName   string   `json:"canonical_name"`
		Kind            string   `json:"kind"`
		NativeObjectID  string   `json:"native_object_id"`
		ResolvedAccount string   `json:"resolved_account"`
		Checkpoint      uint64   `json:"checkpoint"`
		RootHash        string   `json:"root_hash_hex"`
		FileHash        string   `json:"file_hash_hex"`
		RenewalDeadline uint64   `json:"renewal_deadline_unix_seconds"`
		ResolverPath    []string `json:"resolver_path"`
	}{
		Schema: "tos.openfox.dns-alias-review.v1", Verdict: "DISCOVERY_ONLY_REVERIFY_NATIVE_ID",
		InputName: *name, CanonicalName: evidence.CanonicalName, Kind: *kindName,
		NativeObjectID:  evidence.NativeObjectId,
		ResolvedAccount: fmt.Sprintf("%d:%s", account.Workchain, hex.EncodeToString(account.AccountId)),
		Checkpoint:      evidence.Checkpoint.Sequence, RootHash: hex.EncodeToString(evidence.Checkpoint.RootHash),
		FileHash:        hex.EncodeToString(evidence.Checkpoint.FileHash),
		RenewalDeadline: evidence.Lifecycle.RenewalDeadlineUnixSeconds,
		ResolverPath:    make([]string, 0, len(evidence.ResolverPath)),
	}
	for _, address := range evidence.ResolverPath {
		document.ResolverPath = append(document.ResolverPath,
			fmt.Sprintf("%d:%s", address.Workchain, hex.EncodeToString(address.AccountId)))
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create new alias review artifact")
	}
	defer file.Close()
	if _, err := file.Write(append(body, '\n')); err != nil {
		return errors.New("write alias review artifact")
	}
	return nil
}

func parseKind(value string) (nativev1.DNSAliasKindV1, error) {
	switch value {
	case "agent":
		return nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, nil
	case "capability":
		return nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY, nil
	default:
		return 0, errors.New("kind must be agent or capability")
	}
}

func readPrivateToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("bearer token must be an owner-private regular file")
	}
	raw, err := os.ReadFile(path)
	value := strings.TrimSpace(string(raw))
	if err != nil || len(value) < 32 {
		return "", errors.New("read gateway bearer token")
	}
	return value, nil
}
