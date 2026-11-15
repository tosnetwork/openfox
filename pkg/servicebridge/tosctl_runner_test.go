package servicebridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for tosctl: the sealed runner
// executes real pinned bytes, so its tests need a real executable whose
// behavior they choose. Invoked as `<binary> stand-in-tosctl <mode> ...`
// it acts as that executable and never runs a test.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "stand-in-tosctl" {
		standInTOSCTL(os.Args[2], os.Args[3:])
	}
	os.Exit(m.Run())
}

func standInTOSCTL(mode string, rest []string) {
	switch mode {
	case "echo":
		directory, _ := os.Getwd()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"environment": os.Environ(), "arguments": rest, "directory": directory,
		})
	case "flood":
		fmt.Print(strings.Repeat("x", 80<<10))
	case "fail":
		// A diagnostic that quotes custody, as tosctl's can.
		fmt.Fprintf(os.Stderr, "command failed: %s config %s: %s\n", os.Getenv("VAULT_URL"),
			strings.Join(rest, " "), strings.Join(rest[:1], ""))
		os.Exit(1)
	case "noisy":
		// More diagnostics than are kept, then a normal answer.
		fmt.Fprint(os.Stderr, strings.Repeat("d", 200<<10))
		fmt.Print("{\"address\":\"0:aa\"}\n")
	case "sleep":
		// Shorter than the default timeout, so only a call's own shorter
		// timeout cuts it off before the marker is written.
		time.Sleep(standInSleep)
		if len(rest) > 0 && filepath.IsAbs(rest[0]) {
			_ = os.WriteFile(rest[0], nil, 0o600)
		}
	case "text-then-json":
		fmt.Print("Transfer summary:\n  {not json}\nOK sent\n{\"address\":\"0:aa\"}\n")
	case "trailing":
		fmt.Print("{\"address\":\"0:aa\"}\n{\"address\":\"0:bb\"}\n")
	case "unknown-field":
		fmt.Print("{\"address\":\"0:aa\",\"secret\":\"s\"}\n")
	}
	os.Exit(0)
}

// standInSleep is how long the "sleep" stand-in runs: derived from the
// default timeout so that a runner applying the default instead of a call's
// own timeout lets it finish, and long enough that no plausible pause of
// the test lets it finish before a one-second timeout's kill lands.
const standInSleep = defaultLifecycleTime * 3 / 4

func standInRunner(t *testing.T) (*SealedTOSCTL, TOSCTLConfig) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := HashTOSCTL(binary)
	if err != nil {
		t.Fatal(err)
	}
	config := TOSCTLConfig{Binary: binary, SHA256: pin, ConfigPath: filepath.Join(t.TempDir(), "tosctl-config.json")}
	runner, err := NewSealedTOSCTL(config, pfSecretVault)
	if err != nil {
		t.Fatal(err)
	}
	return runner, config
}

func standIn(mode string, rest ...string) TOSCTLCall {
	return TOSCTLCall{Label: "stand-in " + mode, Args: append([]string{"stand-in-tosctl", mode}, rest...)}
}

func TestTheSealedRunnerGivesTOSCTLOnlyTheVaultURLAndItsOwnConfiguration(t *testing.T) {
	runner, config := standInRunner(t)
	t.Setenv("OPENFOX_MUST_NOT_REACH_TOSCTL", "leaked")
	output, err := runner.Run(context.Background(), standIn("echo", "--name", "x"))
	if err != nil {
		t.Fatal(err)
	}
	var seen struct {
		Environment []string `json:"environment"`
		Arguments   []string `json:"arguments"`
		Directory   string   `json:"directory"`
	}
	if err := json.Unmarshal(output, &seen); err != nil {
		t.Fatal(err)
	}
	if len(seen.Environment) != 1 || seen.Environment[0] != "VAULT_URL="+pfSecretVault {
		t.Fatalf("environment = %v", seen.Environment)
	}
	want := []string{"--name", "x", "--config", config.ConfigPath}
	if strings.Join(seen.Arguments, " ") != strings.Join(want, " ") || seen.Directory != "/" {
		t.Fatalf("arguments = %v in %s", seen.Arguments, seen.Directory)
	}
	// A caller cannot point tosctl at another configuration.
	for _, argument := range []string{"--config", "-c", "--config=/tmp/other.json", "--config-fd"} {
		if _, err := runner.Run(context.Background(), standIn("echo", argument, "/tmp/other.json")); err == nil {
			t.Fatalf("a caller-supplied %s was passed to tosctl", argument)
		}
	}
}

func TestTheSealedRunnerRunsOnlyThePinnedBytes(t *testing.T) {
	_, config := standInRunner(t)
	wrong := config
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err := NewSealedTOSCTL(wrong, ""); err == nil || !strings.Contains(err.Error(), "pinned SHA-256") {
		t.Fatalf("another binary than the pinned one was accepted: %v", err)
	}
	for name, mutate := range map[string]func(*TOSCTLConfig){
		"relative binary": func(c *TOSCTLConfig) { c.Binary = "tosctl" },
		"relative config": func(c *TOSCTLConfig) { c.ConfigPath = "tosctl-config.json" },
		"missing binary":  func(c *TOSCTLConfig) { c.Binary = "/nonexistent/tosctl" },
	} {
		broken := config
		mutate(&broken)
		if _, err := NewSealedTOSCTL(broken, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewSealedTOSCTL(config, "https://vault.example/secret"); err == nil {
		t.Fatal("a vault URL of another scheme was accepted")
	}
}

func TestTheSealedRunnerBoundsOutputAndTimeAndRedactsFailures(t *testing.T) {
	runner, config := standInRunner(t)
	if _, err := runner.Run(context.Background(), standIn("flood")); err == nil {
		t.Fatal("output over the bound was accepted")
	}
	call := standIn("flood")
	call.MaxOutput = 128 << 10
	if output, err := runner.Run(context.Background(), call); err != nil || len(output) != 80<<10 {
		t.Fatalf("output within a raised bound: %d %v", len(output), err)
	}
	// Diagnostics beyond what is kept are dropped; they never fail a call.
	if output, err := runner.Run(
		context.Background(),
		standIn("noisy"),
	); err != nil ||
		!strings.Contains(string(output), "0:aa") {
		t.Fatalf("long diagnostics failed a successful call: %v", err)
	}
	// The stand-in sleeps for less than the default timeout and then
	// leaves a marker. The call's own one-second timeout must end it: the
	// error says it timed out, no marker exists (the stand-in was killed
	// before its end, so neither its own exit nor the default timeout ended
	// the call), and at least the timeout elapsed. No upper bound is put on
	// the elapsed wall-clock time: a pause of the whole process group (a
	// thermal guard's SIGSTOP) stretches it without the bound being broken.
	finished := filepath.Join(t.TempDir(), "finished")
	slow := standIn("sleep", finished)
	slow.Timeout = time.Second
	started := time.Now()
	signalSlowCall(t)
	_, err := runner.Run(context.Background(), slow)
	elapsed := time.Since(started)
	var failure *TOSCTLError
	if !errors.As(err, &failure) || failure.Status != "timed out" || elapsed < slow.Timeout {
		t.Fatalf("a slow tosctl was not cut off at its timeout: %v after %s", err, elapsed)
	}
	if _, statErr := os.Stat(finished); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the slow tosctl ran to its end instead of being cut off at its timeout: %v", statErr)
	}
	// The diagnostic quotes the vault URL and the configuration path; the
	// error carries the label, the exit status and a fixed class only.
	_, err = runner.Run(context.Background(), standIn("fail", "[E100: Not found]"))
	if !errors.As(err, &failure) || failure.Reason != TOSCTLFailureNotFound || failure.Status != "exit status 1" {
		t.Fatalf("failure = %+v", err)
	}
	for _, secret := range []string{pfSecretVault, "master_key", config.ConfigPath, "command failed"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error repeats tosctl's diagnostic: %v", err)
		}
	}
	if _, err = runner.Run(context.Background(), standIn("fail", "something else")); !errors.As(err, &failure) ||
		failure.Reason != TOSCTLFailureUnclassified {
		t.Fatalf("an unrecognized diagnostic was classified: %+v", err)
	}
	for _, bounds := range []TOSCTLCall{
		{Label: "x", Args: []string{"a"}, Timeout: time.Millisecond},
		{Label: "x", Args: []string{"a"}, Timeout: time.Hour},
		{Label: "x", Args: []string{"a"}, MaxOutput: maxTOSCTLJSONOutput + 1},
		{Label: "", Args: []string{"a"}},
		{Label: "x"},
	} {
		if _, err := runner.Run(context.Background(), bounds); err == nil {
			t.Errorf("call %+v was run", bounds)
		}
	}
}

func TestTOSCTLFailuresAreClassifiedByFixedPhrases(t *testing.T) {
	for cause, want := range map[string]TOSCTLFailure{
		"read the registry controller native-registry-x: [E100: Not found] Secret": TOSCTLFailureNotFound,
		"[E101: Already exists] Secret with id":                                    TOSCTLFailureAlreadyExists,
		"funding wallet has insufficient balance":                                  TOSCTLFailureBalance,
		"Wrong amount value 2 TOS. Wallet balance is 1 TOS":                        TOSCTLFailureBalance,
		"funding wallet is not active":                                             TOSCTLFailureWalletState,
		"wallet 'provider' is uninitialized":                                       TOSCTLFailureWalletState,
		"an account already exists at 0:ab":                                        TOSCTLFailureOccupied,
		"Transaction timeout expired":                                              TOSCTLFailureUnconfirmed,
		"the RPC serves another chain than the global config's zero state":         TOSCTLFailureWrongChain,
		"persistence directory /x is inside /y, which another user can modify":     TOSCTLFailureUnsafeDirectory,
		"error sending request for url":                                            TOSCTLFailureUnclassified,
	} {
		final := tosctlErrorPrefix + cause
		for _, diagnostic := range []string{final, final + "\n", "Sending...\nwarning: slow RPC\n" + final + "\r\n"} {
			if got := classifyTOSCTLDiagnostic([]byte(diagnostic), false); got != want {
				t.Errorf("%q classified as %q, want %q", diagnostic, got, want)
			}
		}
		// The same words anywhere but in tosctl's final error line say
		// nothing about why the run ended.
		for _, diagnostic := range []string{
			cause,
			"note: " + final,
			final + "\n" + tosctlErrorPrefix + "error sending request for url",
			"warning: " + cause + "\n" + tosctlErrorPrefix + "Transaction was sent; waiting failed",
			final + "\nsomething printed after the error line",
		} {
			if got := classifyTOSCTLDiagnostic([]byte(diagnostic), false); got != TOSCTLFailureUnclassified {
				t.Errorf("%q was classified as %q by words outside the final error line", diagnostic, got)
			}
		}
		// Diagnostics cut at the bound may have lost the final line.
		if got := classifyTOSCTLDiagnostic([]byte(final), true); got != TOSCTLFailureUnclassified {
			t.Errorf("truncated diagnostics were classified as %q", got)
		}
	}
	// The directory refusal is reported, but it does not clear a step.
	if refusedBeforeBroadcast(&TOSCTLError{Reason: TOSCTLFailureUnsafeDirectory}) {
		t.Error("an unsafe directory was taken for a pre-broadcast refusal")
	}
	// Only failures tosctl checks before broadcasting clear a step.
	for failure, before := range map[TOSCTLFailure]bool{
		TOSCTLFailureBalance: true, TOSCTLFailureWalletState: true, TOSCTLFailureNotFound: true,
		TOSCTLFailureOccupied: true, TOSCTLFailureWrongChain: true, TOSCTLFailureAlreadyExists: true,
		TOSCTLFailureUnconfirmed: false, TOSCTLFailureUnclassified: false,
	} {
		if got := refusedBeforeBroadcast(
			&TOSCTLError{Label: "x", Status: "exit status 1", Reason: failure},
		); got != before {
			t.Errorf("%q: refusedBeforeBroadcast = %v", failure, got)
		}
	}
	if refusedBeforeBroadcast(errors.New("anything else")) {
		t.Error("an arbitrary error was taken as proof that nothing was broadcast")
	}
}

func TestTOSCTLJSONIsDecodedStrictlyAndTextIsToleratedOnlyWhereAsked(t *testing.T) {
	runner, _ := standInRunner(t)
	var answer struct {
		Address string `json:"address"`
	}
	ctx := context.Background()
	if err := runTOSCTLJSON(
		ctx,
		runner,
		standIn("text-then-json"),
		true,
		&answer,
	); err != nil ||
		answer.Address != "0:aa" {
		t.Fatalf("progress text before the JSON line: %v %+v", err, answer)
	}
	if err := runTOSCTLJSON(ctx, runner, standIn("text-then-json"), false, &answer); err == nil {
		t.Fatal("text before JSON was tolerated for a command that prints none")
	}
	if err := runTOSCTLJSON(ctx, runner, standIn("trailing"), false, &answer); err == nil {
		t.Fatal("trailing data was accepted")
	}
	if err := runTOSCTLJSON(ctx, runner, standIn("unknown-field"), false, &answer); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if err := runTOSCTLJSON(ctx, runner, standIn("unknown-field"), true, &answer); err == nil {
		t.Fatal("an unknown field was accepted on the last line")
	}
	if err := runTOSCTLJSON(ctx, nil, standIn("echo"), false, &answer); err == nil {
		t.Fatal("ran without a runner")
	}
}

func TestTOSAmountsAreParsedAndFormattedExactly(t *testing.T) {
	for text, want := range map[string]uint64{
		"0": 0, "1": NanoPerTOS, "0.1": 100_000_000, "1.5": 1_500_000_000, "0.000000001": 1,
		"12.345678901": 12_345_678_901, "18446744073.709551615": 18_446_744_073_709_551_615,
	} {
		if got, err := ParseTOSAmount(text); err != nil || got != want {
			t.Errorf("ParseTOSAmount(%q) = %d, %v; want %d", text, got, err, want)
		}
	}
	for _, text := range []string{
		"", "-1", "+1", "1e3", "1.", ".5", "01", "1.0000000001", "0x10", " 1", "1 ", "1,5", "NaN",
		"18446744073.709551616", "18446744074", "99999999999999999999",
	} {
		if got, err := ParseTOSAmount(text); err == nil {
			t.Errorf("ParseTOSAmount(%q) = %d, accepted", text, got)
		}
	}
	if FormatTOSAmount(1_250_000_001) != "1.250000001" || FormatTOSAmount(0) != "0.000000000" {
		t.Fatal("format")
	}
	if _, err := tosctlAmount(MaxTOSCTLAmountNano+1, "x", false); err == nil {
		t.Fatal("an amount beyond the exact bound was handed to tosctl")
	}
	if _, err := tosctlAmount(0, "x", false); err == nil {
		t.Fatal("zero was handed to tosctl as a positive amount")
	}
	if _, err := checkedAdd(^uint64(0), 1); !errors.Is(err, ErrAmountOverflow) {
		t.Fatal("an overflowing sum was returned")
	}
	if _, err := checkedSub(1, 2); !errors.Is(err, ErrAmountOverflow) {
		t.Fatal("a negative difference was returned")
	}
	if _, err := checkedMul(1<<40, 1<<40); !errors.Is(err, ErrAmountOverflow) {
		t.Fatal("an overflowing product was returned")
	}
}

// A controller answer is taken only if its public key derives the key id it
// states, so a vault entry cannot be passed off under another identity.
func TestControllerAnswersMustDeriveTheirOwnKeyID(t *testing.T) {
	key := fakeKey("service-attestor")
	good := controllerAnswer{
		Name: "service-attestor", Suite: "ML-DSA-44", KeyID: hex.EncodeToString(key.KeyID[:]),
		PublicKey: hex.EncodeToString(key.PublicKey),
	}
	if parsed, err := good.key("service-attestor"); err != nil || parsed.KeyID != key.KeyID {
		t.Fatalf("a consistent answer was refused: %v", err)
	}
	other := fakeKey("someone-else")
	for name, mutate := range map[string]func(*controllerAnswer){
		"another key's id":   func(a *controllerAnswer) { a.KeyID = hex.EncodeToString(other.KeyID[:]) },
		"another public key": func(a *controllerAnswer) { a.PublicKey = hex.EncodeToString(other.PublicKey) },
		"another name":       func(a *controllerAnswer) { a.Name = "other" },
		"another suite":      func(a *controllerAnswer) { a.Suite = "Ed25519" },
		"a short public key": func(a *controllerAnswer) { a.PublicKey = a.PublicKey[:64] },
		"an uppercase id":    func(a *controllerAnswer) { a.KeyID = strings.ToUpper(a.KeyID) },
	} {
		answer := good
		mutate(&answer)
		if _, err := answer.key("service-attestor"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
