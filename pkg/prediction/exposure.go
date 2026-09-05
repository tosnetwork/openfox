package prediction

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/tosnetwork/tosutils-go/address"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const exposureStateFile = "oracle-exposure.json"

type OracleExposureProfile struct {
	NetworkDomainHash      string `json:"network_domain_hash"`
	EventFamilyHash        string `json:"event_family_hash"`
	OracleEpochHash        string `json:"oracle_epoch_hash"`
	ContractCodeHash       string `json:"contract_code_hash"`
	MaximumExposure        uint64 `json:"maximum_exposure_atomic"`
	MaximumMarketsPerEpoch uint32 `json:"maximum_markets_per_epoch"`
}

type MarketExposureAdmission struct {
	MarketID         string `json:"market_id"`
	MarketAddress    string `json:"market_address"`
	MarketConfigHash string `json:"market_config_hash"`
	ExposureCeiling  uint64 `json:"exposure_ceiling_atomic"`
}

type MarketExposureObservation struct {
	MarketID           string
	MarketAddress      string
	MarketConfigHash   string
	ContractCodeHash   string
	LockedCollateral   uint64
	MasterchainSeqno   uint64
	FinalityViewID     string
	QuorumFinalized    bool
	TerminalCompacted  bool
	LiabilitiesCleared bool
}

type exposureRecord struct {
	MarketExposureAdmission
	LockedCollateral uint64 `json:"locked_collateral_atomic"`
	MasterchainSeqno uint64 `json:"masterchain_seqno"`
	FinalityViewID   string `json:"finality_view_id,omitempty"`
	Released         bool   `json:"released"`
}

type exposureDocument struct {
	SchemaVersion uint16                    `json:"schema_version"`
	Revision      uint64                    `json:"revision"`
	Profile       OracleExposureProfile     `json:"profile"`
	Markets       map[string]exposureRecord `json:"markets"`
}

type OracleExposureLedger struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	doc       exposureDocument
}

func OpenOracleExposureLedger(
	directory string,
	profile OracleExposureProfile,
) (*OracleExposureLedger, error) {
	if validateExposureProfile(profile) != nil {
		return nil, errors.New("prediction oracle exposure profile is invalid")
	}
	lock, err := openPrivateLockedDirectory(directory)
	if err != nil {
		return nil, err
	}
	ledger := &OracleExposureLedger{
		directory: directory,
		lock:      lock,
		doc: exposureDocument{
			SchemaVersion: 1,
			Profile:       profile,
			Markets:       map[string]exposureRecord{},
		},
	}
	if err := ledger.loadOrInitialize(); err != nil {
		_ = releaseBookLock(lock)
		return nil, err
	}
	return ledger, nil
}

func (ledger *OracleExposureLedger) Close() error {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.lock == nil {
		return nil
	}
	err := releaseBookLock(ledger.lock)
	ledger.lock = nil
	return err
}

// AdmitMarket reserves the immutable worst-case exposure ceiling before an
// official market is listed. Current low utilization never lets concurrently
// admitted markets overcommit the same Oracle epoch.
func (ledger *OracleExposureLedger) AdmitMarket(admission MarketExposureAdmission) error {
	if ledger == nil || validateExposureAdmission(admission) != nil {
		return errors.New("prediction market exposure admission is invalid")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.lock == nil {
		return errors.New("prediction oracle exposure ledger is closed")
	}
	if prior, ok := ledger.doc.Markets[admission.MarketID]; ok {
		if !reflect.DeepEqual(prior.MarketExposureAdmission, admission) {
			return errors.New("prediction market exposure admission conflicts with durable identity")
		}
		if prior.Released {
			return errors.New("released prediction market exposure cannot be reactivated")
		}
		return nil
	}
	if uint32(len(ledger.doc.Markets)) >= ledger.doc.Profile.MaximumMarketsPerEpoch {
		return errors.New("prediction oracle epoch market capacity reached")
	}
	reserved, ok := aggregateExposureCeilings(ledger.doc.Markets)
	if !ok || reserved > ledger.doc.Profile.MaximumExposure ||
		admission.ExposureCeiling > ledger.doc.Profile.MaximumExposure-reserved {
		return errors.New("prediction oracle aggregate exposure limit exceeded")
	}
	next := cloneExposureDocument(ledger.doc)
	next.Revision++
	next.Markets[admission.MarketID] = exposureRecord{MarketExposureAdmission: admission}
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

// ObserveMarket advances only on strict-majority finalized chain evidence.
// A terminal market releases its reserved ceiling only after every liability
// has cleared and terminal compaction is itself finalized.
func (ledger *OracleExposureLedger) ObserveMarket(observation MarketExposureObservation) error {
	if ledger == nil || !observation.QuorumFinalized || observation.MasterchainSeqno == 0 ||
		!canonicalDigest(observation.FinalityViewID, "sha256:") {
		return errors.New("prediction market exposure observation is not finalized")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.lock == nil {
		return errors.New("prediction oracle exposure ledger is closed")
	}
	record, ok := ledger.doc.Markets[observation.MarketID]
	if !ok || observation.MarketAddress != record.MarketAddress ||
		observation.MarketConfigHash != record.MarketConfigHash ||
		observation.ContractCodeHash != ledger.doc.Profile.ContractCodeHash ||
		observation.LockedCollateral > record.ExposureCeiling {
		return errors.New("prediction market exposure observation conflicts with admission")
	}
	if record.Released {
		if observation.TerminalCompacted && observation.LiabilitiesCleared && observation.LockedCollateral == 0 &&
			observation.MasterchainSeqno == record.MasterchainSeqno && observation.FinalityViewID == record.FinalityViewID {
			return nil
		}
		return errors.New("released prediction market exposure received non-idempotent evidence")
	}
	if observation.MasterchainSeqno < record.MasterchainSeqno {
		return errors.New("prediction market exposure observation rolled back finalized state")
	}
	if observation.MasterchainSeqno == record.MasterchainSeqno {
		if observation.FinalityViewID != record.FinalityViewID ||
			observation.LockedCollateral != record.LockedCollateral || observation.TerminalCompacted {
			return errors.New("prediction market exposure observation conflicts at one checkpoint")
		}
		return nil
	}
	if observation.TerminalCompacted && (!observation.LiabilitiesCleared || observation.LockedCollateral != 0) {
		return errors.New("prediction market attempted to release exposure with live liabilities")
	}
	next := cloneExposureDocument(ledger.doc)
	next.Revision++
	if observation.TerminalCompacted {
		record.LockedCollateral = 0
		record.MasterchainSeqno = observation.MasterchainSeqno
		record.FinalityViewID = observation.FinalityViewID
		record.Released = true
		next.Markets[observation.MarketID] = record
	} else {
		record.LockedCollateral = observation.LockedCollateral
		record.MasterchainSeqno = observation.MasterchainSeqno
		record.FinalityViewID = observation.FinalityViewID
		next.Markets[observation.MarketID] = record
	}
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

func (ledger *OracleExposureLedger) ActiveMarkets() []MarketExposureAdmission {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	result := make([]MarketExposureAdmission, 0, len(ledger.doc.Markets))
	for _, record := range ledger.doc.Markets {
		if record.Released {
			continue
		}
		result = append(result, record.MarketExposureAdmission)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].MarketID < result[j].MarketID })
	return result
}

func validateExposureProfile(profile OracleExposureProfile) error {
	if !canonicalDigest(profile.NetworkDomainHash, "sha256:") ||
		!canonicalDigest(profile.EventFamilyHash, "sha256:") ||
		!canonicalDigest(profile.OracleEpochHash, "sha256:") ||
		!canonicalDigest(profile.ContractCodeHash, "tvm-cell-sha256:") ||
		profile.MaximumExposure == 0 || profile.MaximumMarketsPerEpoch == 0 ||
		profile.MaximumMarketsPerEpoch > 10_000 {
		return errors.New("invalid Oracle exposure profile")
	}
	return nil
}

func validateExposureAdmission(admission MarketExposureAdmission) error {
	market, err := address.ParseRawAddr(admission.MarketAddress)
	if !canonicalDigest(admission.MarketID, "sha256:") ||
		!canonicalDigest(admission.MarketConfigHash, "tvm-cell-sha256:") || err != nil || market == nil ||
		market.Type() != address.StdAddress || market.StringRaw() != admission.MarketAddress ||
		admission.ExposureCeiling == 0 {
		return errors.New("invalid market exposure admission")
	}
	return nil
}

func aggregateExposureCeilings(markets map[string]exposureRecord) (uint64, bool) {
	total := uint64(0)
	for _, record := range markets {
		if record.Released {
			continue
		}
		if total > ^uint64(0)-record.ExposureCeiling {
			return 0, false
		}
		total += record.ExposureCeiling
	}
	return total, true
}

func (ledger *OracleExposureLedger) loadOrInitialize() error {
	raw, err := os.ReadFile(filepath.Join(ledger.directory, exposureStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return ledger.persist(ledger.doc)
	}
	if err != nil || len(raw) > 8<<20 {
		return errors.New("prediction oracle exposure state is unavailable")
	}
	var loaded exposureDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&loaded) != nil || decoder.Decode(&struct{}{}) != io.EOF || loaded.SchemaVersion != 1 ||
		loaded.Markets == nil || !reflect.DeepEqual(loaded.Profile, ledger.doc.Profile) ||
		uint32(len(loaded.Markets)) > loaded.Profile.MaximumMarketsPerEpoch {
		return errors.New("prediction oracle exposure state identity or shape is invalid")
	}
	for key, record := range loaded.Markets {
		if key != record.MarketID || validateExposureAdmission(record.MarketExposureAdmission) != nil ||
			record.LockedCollateral > record.ExposureCeiling ||
			(record.Released && (record.LockedCollateral != 0 || record.MasterchainSeqno == 0)) ||
			(record.MasterchainSeqno == 0) != (record.FinalityViewID == "") ||
			(record.FinalityViewID != "" && !canonicalDigest(record.FinalityViewID, "sha256:")) {
			return errors.New("prediction oracle exposure state contains an invalid market")
		}
	}
	reserved, ok := aggregateExposureCeilings(loaded.Markets)
	if !ok || reserved > loaded.Profile.MaximumExposure {
		return errors.New("prediction oracle exposure state exceeds its aggregate limit")
	}
	ledger.doc = loaded
	return nil
}

func (ledger *OracleExposureLedger) persist(next exposureDocument) error {
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 8<<20 {
		return errors.New("prediction oracle exposure state exceeds its durable bound")
	}
	return fileutil.WriteFileAtomic(filepath.Join(ledger.directory, exposureStateFile), raw, 0o600)
}

func cloneExposureDocument(value exposureDocument) exposureDocument {
	next := value
	next.Markets = make(map[string]exposureRecord, len(value.Markets))
	for key, record := range value.Markets {
		next.Markets[key] = record
	}
	return next
}
