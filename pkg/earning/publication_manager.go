package earning

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const publicationJournalSchema = "tos.openfox.autonomous-publications.v1"

type PublicationEconomics struct {
	RevenueAtomic   string `json:"revenue_atomic"`
	UnitCostAtomic  string `json:"unit_cost_atomic"`
	AssetNamespace  string `json:"asset_namespace"`
	AssetIdentifier string `json:"asset_identifier"`
	ValueHintRole   string `json:"value_hint_role"`
	Unit            string `json:"unit"`
	EvidenceDigest  string `json:"evidence_digest"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
}

type PublicationDraft struct {
	Body      commerce.AgentIntentBody `json:"body"`
	Economics PublicationEconomics     `json:"economics"`
}

type PublicationPolicy struct {
	MinimumTTL                   time.Duration
	MaximumTTL                   time.Duration
	MinimumMarginPPM             uint32
	MaximumPriceChangePPM        uint32
	MaximumActive                uint32
	MaximumRevisionsPerObject    uint32
	MaximumPublicationsPerPeriod uint32
	Period                       time.Duration
	AllowedAudiences             []string
	AllowDemand                  bool
}

type PublicationRecord struct {
	ObjectID          string                               `json:"object_id"`
	Latest            commerce.SignedAgentIntent           `json:"latest"`
	LatestDigest      string                               `json:"latest_digest"`
	Economics         PublicationEconomics                 `json:"economics"`
	CarrierActions    map[string]commerce.ActionResolution `json:"carrier_actions"`
	WithdrawalActions map[string]commerce.ActionResolution `json:"withdrawal_actions,omitempty"`
	RevisionCount     uint32                               `json:"revision_count"`
	Status            string                               `json:"status"`
	UpdatedAtUnix     uint64                               `json:"updated_at_unix"`
}

type publicationJournal struct {
	Schema           string                       `json:"schema"`
	Revision         uint64                       `json:"revision"`
	Records          map[string]PublicationRecord `json:"records"`
	PublicationTimes []uint64                     `json:"publication_times"`
}

type SupplyDrafter interface {
	DraftSupply(context.Context, InventorySnapshot) (PublicationDraft, error)
}

// PublicationManager is the deterministic policy boundary around AI-proposed
// supply. It retains every signed revision and every per-Carrier resolution;
// a model proposal never reaches a Carrier without fresh Inventory, price,
// rate, writer-fence, and AuthorizedAction checks.
type PublicationManager struct {
	Engine      *Engine
	Inventory   InventorySource
	Drafter     SupplyDrafter
	Policy      PublicationPolicy
	IdentityKey ed25519.PrivateKey
	path        string
	lock        *os.File
	doc         publicationJournal
	now         func() time.Time
}

func OpenPublicationManager(directory string, engine *Engine, inventory InventorySource, key ed25519.PrivateKey,
	policy PublicationPolicy) (*PublicationManager, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || engine == nil || engine.Authority == nil ||
		inventory == nil || len(key) != ed25519.PrivateKeySize || policy.MinimumTTL < time.Minute ||
		policy.MaximumTTL < policy.MinimumTTL || policy.MaximumTTL > 90*24*time.Hour || policy.MaximumActive == 0 ||
		policy.MaximumRevisionsPerObject == 0 || policy.MaximumPublicationsPerPeriod == 0 || policy.Period < time.Minute ||
		policy.MinimumMarginPPM > 10_000_000 || policy.MaximumPriceChangePPM > 10_000_000 {
		return nil, errors.New("publication manager configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("publication journal directory must be owner-private")
	}
	lock, err := acquireAuthorityLock(directory)
	if err != nil {
		return nil, err
	}
	manager := &PublicationManager{Engine: engine, Inventory: inventory, Policy: policy, IdentityKey: append(ed25519.PrivateKey(nil), key...),
		path: filepath.Join(directory, "publications.json"), lock: lock, now: time.Now,
		doc: publicationJournal{Schema: publicationJournalSchema, Revision: 1, Records: map[string]PublicationRecord{}}}
	if _, err := os.Lstat(manager.path); errors.Is(err, os.ErrNotExist) {
		err = manager.persist(manager.doc)
	} else if err == nil {
		err = manager.load()
	}
	if err != nil {
		_ = releaseAuthorityLock(lock)
		return nil, err
	}
	return manager, nil
}

func (manager *PublicationManager) Close() error {
	if manager == nil || manager.lock == nil {
		return nil
	}
	err := releaseAuthorityLock(manager.lock)
	manager.lock = nil
	for i := range manager.IdentityKey {
		manager.IdentityKey[i] = 0
	}
	return err
}

func (manager *PublicationManager) Draft(ctx context.Context) (PublicationDraft, error) {
	if manager == nil || manager.Drafter == nil {
		return PublicationDraft{}, errors.New("supply drafter is unavailable")
	}
	inventory, err := manager.Inventory.Snapshot(ctx)
	if err != nil {
		return PublicationDraft{}, err
	}
	draft, err := manager.Drafter.DraftSupply(ctx, inventory)
	if err != nil {
		return PublicationDraft{}, err
	}
	return draft, manager.validateDraft(draft, inventory, false)
}

// IntentByDigest resolves only this owner daemon's durable signed publication
// history. A Carrier lookup cannot substitute for issuer state when an
// application is promoted into an Agreement.
func (manager *PublicationManager) IntentByDigest(digest string) (commerce.SignedAgentIntent, bool) {
	if manager == nil || digest == "" {
		return commerce.SignedAgentIntent{}, false
	}
	for _, record := range manager.doc.Records {
		if record.LatestDigest == digest && record.Status != "withdrawn" {
			return record.Latest, true
		}
	}
	return commerce.SignedAgentIntent{}, false
}

// MaintainSupply publishes a new deterministic service object or creates the
// next issuer-linked revision only when its signed payload/economics changed.
// Timestamps alone never create a revision, which keeps an autonomous loop
// from turning every wake-up into publication spam.
func (manager *PublicationManager) MaintainSupply(ctx context.Context, carrierIDs []string,
	policyRevision uint64, fence commerce.WriterFence) (PublicationRecord, bool, error) {
	if manager == nil || manager.Drafter == nil {
		return PublicationRecord{}, false, errors.New("supply drafter is unavailable")
	}
	inventory, err := manager.Inventory.Snapshot(ctx)
	if err != nil {
		return PublicationRecord{}, false, err
	}
	draft, err := manager.Drafter.DraftSupply(ctx, inventory)
	if err != nil {
		return PublicationRecord{}, false, err
	}
	prior, found := manager.doc.Records[draft.Body.ObjectID]
	if !found || prior.Status == "withdrawn" {
		record, publishErr := manager.Publish(ctx, draft, carrierIDs, policyRevision, fence)
		return record, publishErr == nil, publishErr
	}
	priorPayload, _ := codec.Digest("tos.agent-intent-payload.v1", prior.Latest.Body.Payload)
	draftPayload, _ := codec.Digest("tos.agent-intent-payload.v1", draft.Body.Payload)
	if priorPayload == draftPayload && samePublicationEconomics(prior.Economics, draft.Economics) {
		return prior, false, nil
	}
	draft.Body.Revision = prior.Latest.Body.Revision + 1
	draft.Body.PredecessorDigest = prior.LatestDigest
	record, reviseErr := manager.Revise(ctx, draft, carrierIDs, policyRevision, fence)
	return record, reviseErr == nil, reviseErr
}

func samePublicationEconomics(left, right PublicationEconomics) bool {
	return left.RevenueAtomic == right.RevenueAtomic && left.UnitCostAtomic == right.UnitCostAtomic &&
		left.AssetNamespace == right.AssetNamespace && left.AssetIdentifier == right.AssetIdentifier &&
		left.ValueHintRole == right.ValueHintRole && left.Unit == right.Unit
}

func (manager *PublicationManager) Publish(ctx context.Context, draft PublicationDraft, carrierIDs []string,
	policyRevision uint64, fence commerce.WriterFence) (PublicationRecord, error) {
	return manager.publish(ctx, draft, carrierIDs, policyRevision, fence, false)
}

func (manager *PublicationManager) Revise(ctx context.Context, draft PublicationDraft, carrierIDs []string,
	policyRevision uint64, fence commerce.WriterFence) (PublicationRecord, error) {
	return manager.publish(ctx, draft, carrierIDs, policyRevision, fence, true)
}

func (manager *PublicationManager) publish(ctx context.Context, draft PublicationDraft, carrierIDs []string,
	policyRevision uint64, fence commerce.WriterFence, revision bool) (PublicationRecord, error) {
	if manager == nil || manager.lock == nil || len(carrierIDs) == 0 {
		return PublicationRecord{}, errors.New("publication request is incomplete")
	}
	carrierIDs = append([]string(nil), carrierIDs...)
	sort.Strings(carrierIDs)
	for i, id := range carrierIDs {
		if id == "" || i > 0 && id == carrierIDs[i-1] {
			return PublicationRecord{}, errors.New("publication Carrier set is invalid")
		}
	}
	inventory, err := manager.Inventory.Snapshot(ctx)
	if err != nil {
		return PublicationRecord{}, err
	}
	if err := manager.validateDraft(draft, inventory, revision); err != nil {
		return PublicationRecord{}, err
	}
	signed, err := commerce.SignIntent(draft.Body, manager.IdentityKey)
	if err != nil {
		return PublicationRecord{}, err
	}
	digest, _ := commerce.IntentBodyDigest(signed.Body)
	record, found := manager.doc.Records[draft.Body.ObjectID]
	if !found {
		record = PublicationRecord{ObjectID: draft.Body.ObjectID, CarrierActions: map[string]commerce.ActionResolution{}, WithdrawalActions: map[string]commerce.ActionResolution{}}
	}
	if record.LatestDigest != "" && record.LatestDigest != digest && record.Latest.Body.Revision >= draft.Body.Revision {
		return PublicationRecord{}, errors.New("publication journal already has this or a later semantic revision")
	}
	if record.LatestDigest != digest {
		record.Latest, record.LatestDigest, record.Economics = signed, digest, draft.Economics
		record.CarrierActions, record.WithdrawalActions = map[string]commerce.ActionResolution{}, map[string]commerce.ActionResolution{}
		record.RevisionCount++
		record.Status = "publishing"
		record.UpdatedAtUnix = uint64(manager.now().UTC().Unix())
		if err := manager.storeRecord(record, true); err != nil {
			return PublicationRecord{}, err
		}
	}
	for _, carrierID := range carrierIDs {
		if prior, ok := record.CarrierActions[carrierID]; ok && (prior.State == commerce.ActionTerminal || prior.State == commerce.ActionAccepted) {
			continue
		}
		resolution, publishErr := manager.Engine.PublishIntent(ctx, carrierID, signed, policyRevision, fence)
		if publishErr != nil {
			return record, publishErr
		}
		if resolution.State != commerce.ActionTerminal && resolution.State != commerce.ActionAccepted {
			return record, errors.New("Carrier publication remains unresolved")
		}
		record.CarrierActions[carrierID] = resolution
		record.UpdatedAtUnix = uint64(manager.now().UTC().Unix())
		if err := manager.storeRecord(record, false); err != nil {
			return record, err
		}
	}
	record.Status = "active"
	if err := manager.storeRecord(record, false); err != nil {
		return record, err
	}
	return record, nil
}

func (manager *PublicationManager) Withdraw(ctx context.Context, objectID, reason string, policyRevision uint64,
	fence commerce.WriterFence) (PublicationRecord, error) {
	if manager == nil || manager.lock == nil || reason == "" {
		return PublicationRecord{}, errors.New("withdrawal request is incomplete")
	}
	record, found := manager.doc.Records[objectID]
	if !found || record.Status == "withdrawn" {
		return record, errors.New("publication is not active")
	}
	now := manager.now().UTC()
	withdrawal, err := commerce.SignIntentWithdrawal(commerce.AgentIntentWithdrawalBody{SchemaVersion: 1,
		NetworkID: record.Latest.Body.NetworkID, IssuerAgentID: record.Latest.Body.IssuerAgentID, Audience: record.Latest.Body.Audience,
		ObjectID: objectID, IntentRevision: record.Latest.Body.Revision, IntentDigest: record.LatestDigest, ReasonCode: reason,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, manager.IdentityKey)
	if err != nil {
		return record, err
	}
	carriers := make([]string, 0, len(record.CarrierActions))
	for carrier := range record.CarrierActions {
		carriers = append(carriers, carrier)
	}
	sort.Strings(carriers)
	record.Status = "withdrawing"
	if err := manager.storeRecord(record, false); err != nil {
		return record, err
	}
	for _, carrier := range carriers {
		if prior, ok := record.WithdrawalActions[carrier]; ok && (prior.State == commerce.ActionTerminal || prior.State == commerce.ActionAccepted) {
			continue
		}
		resolution, withdrawErr := manager.Engine.WithdrawIntent(ctx, carrier, withdrawal, policyRevision, fence)
		if withdrawErr != nil {
			return record, withdrawErr
		}
		if resolution.State != commerce.ActionTerminal && resolution.State != commerce.ActionAccepted {
			return record, errors.New("Carrier withdrawal remains unresolved")
		}
		record.WithdrawalActions[carrier] = resolution
		if err := manager.storeRecord(record, false); err != nil {
			return record, err
		}
	}
	record.Status = "withdrawn"
	record.UpdatedAtUnix = uint64(now.Unix())
	if err := manager.storeRecord(record, false); err != nil {
		return record, err
	}
	return record, nil
}

func (manager *PublicationManager) Records() []PublicationRecord {
	if manager == nil {
		return nil
	}
	result := make([]PublicationRecord, 0, len(manager.doc.Records))
	for _, record := range manager.doc.Records {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ObjectID < result[j].ObjectID })
	return result
}

// ReadPublicationRecords returns an atomic snapshot of the owner journal
// without opening an Economic Action Authority, acquiring a writer lease, or
// loading an Agent signing key.  It is the only path used by read-only operator
// inspection so a disabled publication gate remains inspectable.
func ReadPublicationRecords(directory string) ([]PublicationRecord, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("publication journal directory is invalid")
	}
	path := filepath.Join(directory, "publications.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return []PublicationRecord{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 32<<20 {
		return nil, errors.New("publication journal is not an owner-only bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document publicationJournal
	if json.Unmarshal(raw, &document) != nil || document.Schema != publicationJournalSchema || document.Revision == 0 || document.Records == nil {
		return nil, errors.New("publication journal is invalid")
	}
	result := make([]PublicationRecord, 0, len(document.Records))
	for objectID, record := range document.Records {
		if objectID == "" || record.ObjectID != objectID || record.Latest.Body.ObjectID != objectID || record.LatestDigest == "" {
			return nil, errors.New("publication journal contains a conflicting record")
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ObjectID < result[j].ObjectID })
	return result, nil
}

func (manager *PublicationManager) validateDraft(draft PublicationDraft, inventory InventorySnapshot, revision bool) error {
	now := manager.now().UTC()
	supplyMode, demandMode := false, false
	for _, mode := range draft.Body.Payload.DiscoveryCard.IntentModes {
		supplyMode = supplyMode || mode == commerce.IntentOffer || mode == commerce.IntentSell
		demandMode = demandMode || mode == commerce.IntentRequest || mode == commerce.IntentBuy
	}
	if inventory.Validate(now) != nil || inventory.OwnerID != manager.Engine.OwnerID || inventory.AgentID != manager.Engine.AgentID ||
		draft.Body.IssuerAgentID != manager.Engine.AgentID || draft.Body.CreatedAtUnix == 0 ||
		draft.Body.ExpiresAtUnix <= draft.Body.CreatedAtUnix {
		return errors.New("publication lacks fresh Inventory or pricing evidence")
	}
	if supplyMode == demandMode || demandMode && !manager.Policy.AllowDemand {
		return errors.New("publication direction is ambiguous or outside owner policy")
	}
	if supplyMode && (!canonicalSHA256(draft.Economics.EvidenceDigest) || draft.Economics.AssetNamespace == "" ||
		draft.Economics.AssetIdentifier == "" || draft.Economics.ValueHintRole == "" || draft.Economics.Unit == "" ||
		draft.Economics.ExpiresAtUnix <= uint64(now.Unix())) {
		return errors.New("supply publication lacks fresh pricing evidence")
	}
	ttl := time.Unix(int64(draft.Body.ExpiresAtUnix), 0).Sub(time.Unix(int64(draft.Body.CreatedAtUnix), 0))
	if ttl < manager.Policy.MinimumTTL || ttl > manager.Policy.MaximumTTL {
		return errors.New("publication TTL is outside owner policy")
	}
	if len(manager.Policy.AllowedAudiences) > 0 && !containsSortedOrUnsorted(manager.Policy.AllowedAudiences, draft.Body.Audience) {
		return errors.New("publication audience is outside owner policy")
	}
	if supplyMode {
		priceBound := false
		for _, value := range draft.Body.Payload.DiscoveryCard.ValueHints {
			if value.Role == draft.Economics.ValueHintRole && value.AssetNamespace == draft.Economics.AssetNamespace &&
				value.AssetIdentifier == draft.Economics.AssetIdentifier && value.Unit == draft.Economics.Unit && value.AmountKind == "exact" &&
				value.MinimumDecimal == draft.Economics.RevenueAtomic && value.MaximumDecimal == draft.Economics.RevenueAtomic {
				priceBound = true
			}
		}
		if !priceBound {
			return errors.New("publication price evidence does not bind an exact advertised value hint")
		}
	}
	if supplyMode {
		for _, hint := range draft.Body.Payload.DiscoveryCard.CapabilityHints {
			if hint.Relation == "required" && !inventory.HasCapability(hint.CapabilityNamespace, hint.CapabilityIdentifier, now) {
				return errors.New("publication advertises an unavailable capability")
			}
		}
	}
	for _, preference := range draft.Body.Payload.SettlementPreferences {
		if preference.Required && !inventory.SupportsSettlement(preference.AdapterURI) {
			return errors.New("publication requires an unavailable settlement Adapter")
		}
	}
	var revenue *big.Int
	if supplyMode {
		var okRevenue, okCost bool
		revenue, okRevenue = new(big.Int).SetString(draft.Economics.RevenueAtomic, 10)
		cost, okCost := new(big.Int).SetString(draft.Economics.UnitCostAtomic, 10)
		if !okRevenue || !okCost || revenue.Sign() <= 0 || cost.Sign() < 0 || revenue.Cmp(cost) <= 0 {
			return errors.New("publication economics are invalid or unprofitable")
		}
		if cost.Sign() > 0 {
			margin := new(big.Int).Sub(revenue, cost)
			margin.Mul(margin, big.NewInt(1_000_000)).Quo(margin, cost)
			if margin.Cmp(new(big.Int).SetUint64(uint64(manager.Policy.MinimumMarginPPM))) < 0 {
				return errors.New("publication margin is below owner policy")
			}
		}
	}
	active, recent := uint32(0), uint32(0)
	cutoff := uint64(now.Add(-manager.Policy.Period).Unix())
	for _, record := range manager.doc.Records {
		if record.Status != "withdrawn" {
			active++
		}
	}
	for _, observed := range manager.doc.PublicationTimes {
		if observed >= cutoff {
			recent++
		}
	}
	prior, found := manager.doc.Records[draft.Body.ObjectID]
	draftDigest, digestErr := commerce.IntentBodyDigest(draft.Body)
	if digestErr != nil {
		return digestErr
	}
	if found && prior.LatestDigest == draftDigest {
		if prior.Economics != draft.Economics {
			return errors.New("exact publication retry changed its economic evidence")
		}
		return nil
	}
	if revision {
		if !found || prior.Status == "withdrawn" || draft.Body.Revision != prior.Latest.Body.Revision+1 || draft.Body.PredecessorDigest != prior.LatestDigest ||
			prior.RevisionCount >= manager.Policy.MaximumRevisionsPerObject {
			return errors.New("publication revision lineage or limit is invalid")
		}
		old, _ := new(big.Int).SetString(prior.Economics.RevenueAtomic, 10)
		if supplyMode && old != nil && old.Sign() > 0 {
			change := new(big.Int).Sub(revenue, old)
			change.Abs(change)
			change.Mul(change, big.NewInt(1_000_000)).Quo(change, old)
			if change.Cmp(new(big.Int).SetUint64(uint64(manager.Policy.MaximumPriceChangePPM))) > 0 {
				return errors.New("publication price change exceeds owner policy")
			}
		}
	} else if found || draft.Body.Revision != 1 || draft.Body.PredecessorDigest != "" || active >= manager.Policy.MaximumActive {
		return errors.New("new publication identity or active-publication limit is invalid")
	}
	if recent >= manager.Policy.MaximumPublicationsPerPeriod {
		return errors.New("publication rate limit is exhausted")
	}
	return nil
}

func containsSortedOrUnsorted(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (manager *PublicationManager) storeRecord(record PublicationRecord, countPublication bool) error {
	next := manager.doc
	next.Records = clonePublicationRecords(manager.doc.Records)
	next.Records[record.ObjectID] = record
	next.PublicationTimes = append([]uint64(nil), manager.doc.PublicationTimes...)
	if countPublication {
		next.PublicationTimes = append(next.PublicationTimes, uint64(manager.now().UTC().Unix()))
	}
	if len(next.PublicationTimes) > 16_384 {
		next.PublicationTimes = append([]uint64(nil), next.PublicationTimes[len(next.PublicationTimes)-16_384:]...)
	}
	next.Revision++
	if err := manager.persist(next); err != nil {
		return err
	}
	manager.doc = next
	return nil
}

func clonePublicationRecords(input map[string]PublicationRecord) map[string]PublicationRecord {
	result := make(map[string]PublicationRecord, len(input))
	for key, value := range input {
		value.CarrierActions = cloneResolutions(value.CarrierActions)
		value.WithdrawalActions = cloneResolutions(value.WithdrawalActions)
		result[key] = value
	}
	return result
}

func cloneResolutions(input map[string]commerce.ActionResolution) map[string]commerce.ActionResolution {
	result := make(map[string]commerce.ActionResolution, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func (manager *PublicationManager) persist(document publicationJournal) error {
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > 32<<20 {
		return errors.New("encode publication journal")
	}
	return fileutil.WriteFileAtomic(manager.path, raw, 0o600)
}

func (manager *PublicationManager) load() error {
	info, err := os.Lstat(manager.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 32<<20 {
		return errors.New("publication journal is not an owner-only bounded regular file")
	}
	raw, err := os.ReadFile(manager.path)
	if err != nil {
		return err
	}
	var document publicationJournal
	if json.Unmarshal(raw, &document) != nil || document.Schema != publicationJournalSchema || document.Revision == 0 || document.Records == nil {
		return errors.New("publication journal is invalid")
	}
	manager.doc = document
	return nil
}
