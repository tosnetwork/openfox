// Package atosbridge connects the OpenFox agent runtime to the existing ATOS
// Native commercial lifecycle (discover -> Quote -> Accepted Quote -> escrow ->
// task dispatch -> Receipt -> settlement). It does not create a second
// marketplace, ledger, trust mode, or settlement protocol.
//
// This package holds the transport- and SDK-agnostic CORE: the owner spending
// policy, the crash-safe purchase-journal phase machine, and the buyer/provider
// orchestrators with their authority invariants. Concrete resolvers, quote
// clients, custody signers, and transports are injected through interfaces so
// the core stays dependency-free and testable. Every authority decision is
// re-derived from finalized TOS state by the injected NativeResolver; a Gateway
// or transport response is never treated as canonical.
package atosbridge

import "time"

// Network is the canonical network domain a Capability and escrow live in.
type Network struct {
	ID              string
	GenesisRootHash string
	GenesisFileHash string
}

// AssetIdentity is the exact TOS-network stablecoin identity. A ticker or a
// Gateway balance view is never sufficient; both the master and the wallet code
// hash must match.
type AssetIdentity struct {
	Master         string // stablecoin master contract address
	WalletCodeHash string // jetton wallet code hash
}

// CapabilityRef identifies a Capability and the invariants that must match
// finalized Registry state before any spend.
type CapabilityRef struct {
	AgentID          string
	CapabilityID     string
	Version          string
	ManifestDigest   string
	RegistryCodeHash string
	Network          Network
}

// QuoteProposal is discovery input and is NEVER canonical. It becomes canonical
// only through the on-chain Accepted Quote commitment.
type QuoteProposal struct {
	Capability      CapabilityRef
	Asset           AssetIdentity
	MaxAtomicAmount uint64
	Expiry          time.Time
	ExecutionSigner string // execution-signer public key committed by the quote
	EndpointCommit  string // endpoint commitment digest
	DisputeTerms    string // dispute-terms digest
}

// AcceptedQuote is the canonical acceptance: its commitment and the derived
// deterministic escrow address are the only authoritative locators.
type AcceptedQuote struct {
	Proposal        QuoteProposal
	QuoteCommitment string
	EscrowAddress   string
	EscrowStateInit []byte
	FundingQueryID  uint64
}

// Task is the exact claim admitted to the runner. It is identical across every
// transport; the shared execution Gate is keyed by (QuoteCommitment,
// EscrowAddress).
type Task struct {
	EscrowAddress   string
	QuoteCommitment string
	ExecutionID     string
	InputDigest     string
	SourceDigest    string
	SourceArchive   []byte
}

// EscrowState is the finalized escrow observation. Payment means Funded holds
// the exact quoted amount; a broadcast acknowledgement is not payment.
type EscrowState struct {
	Address         string
	Found           bool
	FundedAtomic    uint64
	SettledAtomic   uint64
	ReceiptCommit   string
	AwaitingFunding bool
	Checkpoint      uint64
}

// Outcome is the provider execution result the Receipt is built from.
type Outcome struct {
	ExecutionID     string
	QuoteCommitment string
	ArtifactDigest  string
	ReportDigest    string
	ExitCode        int
	CompletedUnix   int64
}

// Receipt is the canonical settlement-bearing object.
type Receipt struct {
	Commitment      string
	QuoteCommitment string
	ExecutionID     string
	ChargedAtomic   uint64
	ReleaseQueryID  uint64
}

// Settlement is the finalized terminal economic result, resolved read-only from
// finalized escrow and wallet state.
type Settlement struct {
	Released             bool
	Refunded             bool
	ProviderCreditAtomic uint64
	BuyerBalanceAtomic   uint64
	Checkpoint           uint64
}

// Transport names the task-admitting transports. All of them pass the same
// shared Native execution Gate before the runner is invoked.
type Transport string

const (
	TransportA2A         Transport = "a2a"
	TransportMCP         Transport = "mcp"
	TransportAgentPacket Transport = "agent_packet"
)
