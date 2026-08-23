package nativeimpl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// StaticAgentGiftAddressAuthority is an owner-configured recipient address.
// It is selected locally for each intent and never accepts model, Relay,
// profile, or historical Gift input.
type StaticAgentGiftAddressAuthority struct{ address string }

func NewStaticAgentGiftAddressAuthority(address string) (*StaticAgentGiftAddressAuthority, error) {
	canonical, err := toschain.CanonicalAddress(address)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid owner-configured Gift destination")
	}
	return &StaticAgentGiftAddressAuthority{address: canonical}, nil
}

func (a *StaticAgentGiftAddressAuthority) SelectDestination(context.Context, string) (string, error) {
	if a == nil || a.address == "" {
		return "", errors.New("nativeimpl: no owner-configured Gift destination")
	}
	return a.address, nil
}

// TTYAgentGiftOwnerConfirmer renders the complete private review directly on
// the controlling terminal. It never writes the review through application
// logs and requires an intent-specific phrase before returning approval.
type TTYAgentGiftOwnerConfirmer struct {
	path string
	open func(string, int, os.FileMode) (*os.File, error)
}

func NewTTYAgentGiftOwnerConfirmer() *TTYAgentGiftOwnerConfirmer {
	return &TTYAgentGiftOwnerConfirmer{path: "/dev/tty", open: os.OpenFile}
}

func (c *TTYAgentGiftOwnerConfirmer) ConfirmAgentGift(ctx context.Context, review openfoxgift.OwnerReview) error {
	if c == nil || ctx == nil || review.IntentID == "" || review.FundsLocked || c.open == nil {
		return errors.New("nativeimpl: invalid terminal owner review")
	}
	terminal, err := c.open(c.path, os.O_RDWR, 0)
	if err != nil {
		return errors.New("nativeimpl: controlling terminal is unavailable; Gift remains unauthorized")
	}
	defer terminal.Close()
	info, err := terminal.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("nativeimpl: owner confirmation endpoint is not a terminal")
	}
	return confirmAgentGiftOnTerminal(ctx, terminal, terminal, review)
}

func confirmAgentGiftOnTerminal(ctx context.Context, input io.Reader, output io.Writer, review openfoxgift.OwnerReview) error {
	if ctx == nil || input == nil || output == nil || review.IntentID == "" || review.FundsLocked {
		return errors.New("nativeimpl: invalid terminal owner review")
	}
	rendered := struct {
		Review   openfoxgift.OwnerReview `json:"review"`
		Warnings []string                `json:"warnings"`
	}{Review: review, Warnings: []string{
		"Funds are not locked or guaranteed before finalized execution.",
		"The Gift may expire, be invalidated, or fail for insufficient balance.",
		"Only finalized exact destination credit means paid.",
	}}
	raw, err := json.MarshalIndent(rendered, "", "  ")
	if err != nil {
		return errors.New("nativeimpl: render owner review")
	}
	phrase := "AUTHORIZE " + review.Action + " " + review.IntentID
	if _, err := fmt.Fprintf(output, "%s\nType exactly: %s\n> ", raw, phrase); err != nil {
		return errors.New("nativeimpl: display owner review")
	}
	result := make(chan string, 1)
	readErr := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 512)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			readErr <- err
			return
		}
		result <- strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	}()
	select {
	case <-ctx.Done():
		return errors.New("nativeimpl: owner confirmation cancelled")
	case <-readErr:
		return errors.New("nativeimpl: read owner confirmation")
	case answer := <-result:
		if answer != phrase {
			return errors.New("nativeimpl: owner declined Agent Gift review")
		}
		return nil
	}
}

var _ openfoxgift.AddressAuthority = (*StaticAgentGiftAddressAuthority)(nil)
var _ AgentGiftOwnerConfirmer = (*TTYAgentGiftOwnerConfirmer)(nil)
