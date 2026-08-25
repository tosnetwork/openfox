package earning

import (
	"context"
	"errors"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type IntentQuery struct {
	Modes          []commerce.IntentMode
	SubjectClasses []commerce.SubjectClass
	TaxonomyPrefix string
	Keywords       []string
	MaximumResults uint32
	Cursor         string
}

type CarrierResult struct {
	Intent     commerce.SignedAgentIntent
	Withdrawal *commerce.SignedAgentIntentWithdrawal
	Cursor     string
	CarrierID  string
}

type Carrier interface {
	ID() string
	Search(context.Context, IntentQuery) ([]CarrierResult, error)
}

type SubscribingCarrier interface {
	Carrier
	Subscribe(context.Context, IntentQuery, time.Duration) ([]CarrierResult, error)
}

// CarrierResolver retrieves exact retained bytes by content digest. Search may
// hide expired revisions, while resolution must retain them long enough for a
// consumer to reconstruct and verify an issuer-signed predecessor chain.
type CarrierResolver interface {
	Resolve(context.Context, string) (CarrierResult, error)
}

type InventorySource interface {
	Snapshot(context.Context) (InventorySnapshot, error)
}

type InventorySourceFunc func(context.Context) (InventorySnapshot, error)

func (function InventorySourceFunc) Snapshot(ctx context.Context) (InventorySnapshot, error) {
	return function(ctx)
}

type EstimateSource interface {
	Estimate(context.Context, commerce.SignedAgentIntent, InventorySnapshot) (EconomicEstimate, error)
}

type DetailedEstimateSource interface {
	EstimateWithContent(context.Context, commerce.SignedAgentIntent, []byte, InventorySnapshot) (EconomicEstimate, error)
}

type Collector struct {
	Carriers  []Carrier
	Authority commerce.IntentAuthorityResolver
	Inventory InventorySource
	Estimator EstimateSource
	Content   IntentContentResolver
	Policy    EconomicPolicy
	Journal   *OpportunityJournal
	Shortlist ShortlistPolicy
	Now       func() time.Time
}

// ShortlistPolicy bounds the expensive T2 detail/model stage independently
// from the Carrier page size. Zero values select conservative defaults. The
// caps are local safety policy; neither Carrier rank nor hostile card text can
// increase them.
type ShortlistPolicy struct {
	Size                uint32
	MaximumPerIssuer    uint32
	MaximumPerSource    uint32
	MaximumPerTaxonomy  uint32
	MaximumPerValueBand uint32
	ExplorationPercent  uint8
}

type observedCandidate struct {
	intent   commerce.SignedAgentIntent
	carriers map[string]bool
	results  map[string]CarrierResult
}

func (collector Collector) Collect(ctx context.Context, query IntentQuery) ([]CandidateAssessment, error) {
	if ctx == nil || len(collector.Carriers) == 0 || len(collector.Carriers) > 32 || collector.Authority == nil || collector.Inventory == nil || collector.Estimator == nil ||
		query.MaximumResults == 0 || query.MaximumResults > 1000 {
		return nil, errors.New("earning collector is incomplete or unbounded")
	}
	now := time.Now().UTC()
	if collector.Now != nil {
		now = collector.Now().UTC()
	}
	inventory, err := collector.Inventory.Snapshot(ctx)
	if err != nil || inventory.Validate(now) != nil {
		return nil, errors.New("fresh consistent Inventory is unavailable")
	}
	byDigest := make(map[string]*observedCandidate)
	withdrawn := make(map[string]bool)
	var failures []error
	for _, carrier := range collector.Carriers {
		if carrier == nil || carrier.ID() == "" {
			continue
		}
		carrierQuery := query
		if collector.Journal != nil {
			cursor, cursorErr := collector.Journal.Cursor(carrier.ID())
			if cursorErr != nil {
				failures = append(failures, cursorErr)
				continue
			}
			carrierQuery.Cursor = cursor
		}
		results, searchErr := carrier.Search(ctx, carrierQuery)
		if searchErr != nil {
			failures = append(failures, searchErr)
			continue
		}
		if len(results) > int(query.MaximumResults) {
			failures = append(failures, errors.New("Carrier exceeded result bound"))
			continue
		}
		if collector.Journal != nil {
			pending, replayErr := collector.Journal.Observations(carrier.ID(), query.MaximumResults)
			if replayErr != nil {
				failures = append(failures, replayErr)
				continue
			}
			results = append(results, pending...)
		}
		for _, result := range results {
			if result.CarrierID != carrier.ID() {
				continue
			}
			if result.Withdrawal != nil {
				if commerce.VerifyIntentWithdrawal(*result.Withdrawal, collector.Authority, now) != nil {
					continue
				}
				withdrawn[result.Withdrawal.Body.IntentDigest] = true
				if collector.Journal != nil && result.Cursor != "" {
					if recordErr := collector.Journal.RecordWithdrawal(result, now); recordErr != nil {
						failures = append(failures, recordErr)
					}
				}
				continue
			}
			if commerce.VerifyIntent(result.Intent, collector.Authority, now) != nil || !matchesQuery(result.Intent.Body.Payload.DiscoveryCard, query) {
				continue
			}
			digest, digestErr := commerce.IntentBodyDigest(result.Intent.Body)
			if digestErr != nil {
				continue
			}
			if collector.Journal != nil && result.Cursor != "" {
				if recordErr := collector.Journal.Record(result, digest, now); recordErr != nil {
					failures = append(failures, recordErr)
					continue
				}
			}
			current := byDigest[digest]
			if current == nil {
				current = &observedCandidate{intent: result.Intent, carriers: map[string]bool{}, results: map[string]CarrierResult{}}
				byDigest[digest] = current
			}
			current.carriers[carrier.ID()] = true
			current.results[carrier.ID()] = result
			// Recover signed predecessors from the same non-authoritative source.
			// Bound depth and reject loops; another Carrier may independently fill
			// gaps when this source has already pruned an older object.
			resolver, canResolve := carrier.(CarrierResolver)
			predecessor := result.Intent.Body.PredecessorDigest
			seen := map[string]bool{digest: true}
			for depth := 0; canResolve && predecessor != "" && depth < 64 && !seen[predecessor]; depth++ {
				seen[predecessor] = true
				prior, resolveErr := resolver.Resolve(ctx, predecessor)
				if resolveErr != nil || prior.CarrierID != carrier.ID() || commerce.VerifyHistoricalIntent(prior.Intent, collector.Authority, now) != nil {
					break
				}
				priorDigest, digestErr := commerce.IntentBodyDigest(prior.Intent.Body)
				if digestErr != nil || priorDigest != predecessor {
					break
				}
				observedPrior := byDigest[priorDigest]
				if observedPrior == nil {
					observedPrior = &observedCandidate{intent: prior.Intent, carriers: map[string]bool{}, results: map[string]CarrierResult{}}
					byDigest[priorDigest] = observedPrior
				}
				observedPrior.carriers[carrier.ID()] = true
				predecessor = prior.Intent.Body.PredecessorDigest
			}
		}
	}
	digests := make([]string, 0, len(byDigest))
	// Resolve revisions locally. A Carrier never supplies a market head: the
	// consumer follows the issuer-signed predecessor chain and refuses forks or
	// gaps. Only the tip is economically evaluated.
	byObject := make(map[string][]string)
	for digest, candidate := range byDigest {
		if withdrawn[digest] || collector.Journal != nil && collector.Journal.IsWithdrawn(digest) {
			continue
		}
		key := candidate.intent.Body.IssuerAgentID + "\x00" + candidate.intent.Body.ObjectID
		byObject[key] = append(byObject[key], digest)
	}
	for _, lineage := range byObject {
		sort.Slice(lineage, func(i, j int) bool {
			left, right := byDigest[lineage[i]].intent.Body, byDigest[lineage[j]].intent.Body
			if left.Revision == right.Revision {
				return lineage[i] < lineage[j]
			}
			return left.Revision < right.Revision
		})
		valid := len(lineage) > 0 && byDigest[lineage[0]].intent.Body.Revision == 1
		for index := 1; valid && index < len(lineage); index++ {
			previous := byDigest[lineage[index-1]].intent.Body
			current := byDigest[lineage[index]].intent.Body
			if current.Revision != previous.Revision+1 || current.PredecessorDigest != lineage[index-1] {
				valid = false
			}
		}
		if valid {
			digests = append(digests, lineage[len(lineage)-1])
		}
	}
	sort.Strings(digests)
	if len(digests) > int(query.MaximumResults) {
		digests = digests[:query.MaximumResults]
	}
	digests = shortlistDigests(digests, byDigest, query, collector.Shortlist)
	assessments := make([]CandidateAssessment, 0, len(digests))
	for _, digest := range digests {
		candidate := byDigest[digest]
		if matchErr := InventoryMatchesIntent(inventory, candidate.intent, now); matchErr != nil {
			collector.markProcessed(digest, candidate)
			continue
		}
		detail := candidate.intent.Body.Payload.DetailDescriptor.InlineContent
		if len(detail) == 0 && collector.Content == nil {
			failures = append(failures, errors.New("external Intent detail has no configured safe resolver"))
			continue
		}
		if collector.Content != nil {
			detail, err = collector.Content.ResolveIntentContent(ctx, candidate.intent.Body.Payload.DetailDescriptor)
			if err != nil {
				failures = append(failures, err)
				continue
			}
		}
		var estimate EconomicEstimate
		var estimateErr error
		if detailed, ok := collector.Estimator.(DetailedEstimateSource); ok {
			estimate, estimateErr = detailed.EstimateWithContent(ctx, candidate.intent, detail, inventory)
		} else if len(candidate.intent.Body.Payload.DetailDescriptor.InlineContent) > 0 {
			estimate, estimateErr = collector.Estimator.Estimate(ctx, candidate.intent, inventory)
		} else {
			estimateErr = errors.New("external Intent detail was retrieved but the estimator cannot consume exact content")
		}
		if estimateErr != nil {
			failures = append(failures, estimateErr)
			continue
		}
		decision, evaluateErr := EvaluateEconomics(estimate, collector.Policy, now)
		if evaluateErr != nil {
			failures = append(failures, evaluateErr)
			continue
		}
		carrierIDs := make([]string, 0, len(candidate.carriers))
		for carrierID := range candidate.carriers {
			carrierIDs = append(carrierIDs, carrierID)
		}
		sort.Strings(carrierIDs)
		assessments = append(assessments, CandidateAssessment{IntentDigest: digest, Intent: candidate.intent, Inventory: inventory,
			Estimate: estimate, Decision: decision, CarrierIDs: carrierIDs})
		if !decision.Eligible {
			collector.markProcessed(digest, candidate)
		}
	}
	if len(assessments) == 0 && len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return assessments, nil
}

type rankedDigest struct {
	digest, issuer, source, taxonomy, valueBand string
	score                                       uint64
}

func shortlistDigests(digests []string, observed map[string]*observedCandidate, query IntentQuery, policy ShortlistPolicy) []string {
	if len(digests) == 0 {
		return nil
	}
	size := policy.Size
	if size == 0 || size > uint32(len(digests)) {
		size = uint32(len(digests))
	}
	perIssuer, perSource, perTaxonomy, perValue := policy.MaximumPerIssuer, policy.MaximumPerSource, policy.MaximumPerTaxonomy, policy.MaximumPerValueBand
	if perIssuer == 0 {
		perIssuer = 3
	}
	if perSource == 0 {
		perSource = size
	}
	if perTaxonomy == 0 {
		perTaxonomy = 12
	}
	if perValue == 0 {
		perValue = size
	}
	if policy.ExplorationPercent > 50 {
		policy.ExplorationPercent = 50
	}
	ranked := make([]rankedDigest, 0, len(digests))
	for _, digest := range digests {
		candidate := observed[digest]
		if candidate == nil {
			continue
		}
		card := candidate.intent.Body.Payload.DiscoveryCard
		taxonomy := "unknown"
		if len(card.TaxonomyPaths) > 0 {
			taxonomy = card.TaxonomyPaths[0]
		}
		valueBand := string(card.ValueState)
		if len(card.ValueHints) > 0 {
			valueBand += ":" + card.ValueHints[0].AssetNamespace + ":" + card.ValueHints[0].AssetIdentifier + ":" + card.ValueHints[0].AmountKind
		}
		sources := make([]string, 0, len(candidate.carriers))
		for source := range candidate.carriers {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		source := "unknown"
		if len(sources) > 0 {
			source = sources[0]
		}
		score := uint64(len(candidate.carriers)) * 1_000
		for _, keyword := range card.Keywords {
			for _, wanted := range query.Keywords {
				if keyword.Text == wanted {
					score += 100
				}
			}
		}
		for _, path := range card.TaxonomyPaths {
			if query.TaxonomyPrefix != "" && len(path) >= len(query.TaxonomyPrefix) && path[:len(query.TaxonomyPrefix)] == query.TaxonomyPrefix {
				score += 50
			}
		}
		if card.ValueState == commerce.ValueSpecified || card.ValueState == commerce.ValueRange {
			score += 25
		}
		ranked = append(ranked, rankedDigest{digest: digest, issuer: candidate.intent.Body.IssuerAgentID, source: source, taxonomy: taxonomy, valueBand: valueBand, score: score})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].digest < ranked[j].digest
	})
	explore := uint32(uint64(size) * uint64(policy.ExplorationPercent) / 100)
	if policy.ExplorationPercent > 0 && explore == 0 {
		explore = 1
	}
	exploitTarget := size - explore
	issuerCount, sourceCount, taxonomyCount, valueCount := map[string]uint32{}, map[string]uint32{}, map[string]uint32{}, map[string]uint32{}
	selected, selectedSet := make([]string, 0, size), map[string]bool{}
	admit := func(item rankedDigest) bool {
		if issuerCount[item.issuer] >= perIssuer || sourceCount[item.source] >= perSource || taxonomyCount[item.taxonomy] >= perTaxonomy || valueCount[item.valueBand] >= perValue {
			return false
		}
		issuerCount[item.issuer]++
		sourceCount[item.source]++
		taxonomyCount[item.taxonomy]++
		valueCount[item.valueBand]++
		selected = append(selected, item.digest)
		selectedSet[item.digest] = true
		return true
	}
	for _, item := range ranked {
		if uint32(len(selected)) >= exploitTarget {
			break
		}
		admit(item)
	}
	// Exploration is deterministic by content digest so restart and takeover do
	// not spend new model budget on an invented sample.
	exploration := append([]rankedDigest(nil), ranked...)
	sort.Slice(exploration, func(i, j int) bool { return exploration[i].digest < exploration[j].digest })
	for _, item := range exploration {
		if uint32(len(selected)) >= size {
			break
		}
		if !selectedSet[item.digest] {
			admit(item)
		}
	}
	return selected
}

func (collector Collector) Acknowledge(assessment CandidateAssessment) error {
	if collector.Journal == nil {
		return nil
	}
	if !canonicalSHA256(assessment.IntentDigest) || len(assessment.CarrierIDs) == 0 {
		return errors.New("opportunity acknowledgement is invalid")
	}
	for _, carrierID := range assessment.CarrierIDs {
		if err := collector.Journal.MarkProcessed(assessment.IntentDigest, carrierID); err != nil {
			return err
		}
	}
	return nil
}

func (collector Collector) markProcessed(digest string, candidate *observedCandidate) {
	if collector.Journal == nil || candidate == nil {
		return
	}
	for carrierID := range candidate.results {
		_ = collector.Journal.MarkProcessed(digest, carrierID)
	}
}

func matchesQuery(card commerce.DiscoveryCard, query IntentQuery) bool {
	if len(query.Modes) > 0 && !intersectsModes(card.IntentModes, query.Modes) || len(query.SubjectClasses) > 0 && !intersectsClasses(card.SubjectClasses, query.SubjectClasses) {
		return false
	}
	if query.TaxonomyPrefix != "" {
		matched := false
		for _, path := range card.TaxonomyPaths {
			if len(path) >= len(query.TaxonomyPrefix) && path[:len(query.TaxonomyPrefix)] == query.TaxonomyPrefix {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, wanted := range query.Keywords {
		matched := false
		for _, keyword := range card.Keywords {
			if keyword.Text == wanted {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func intersectsModes(first, second []commerce.IntentMode) bool {
	for _, left := range first {
		for _, right := range second {
			if left == right {
				return true
			}
		}
	}
	return false
}

func intersectsClasses(first, second []commerce.SubjectClass) bool {
	for _, left := range first {
		for _, right := range second {
			if left == right {
				return true
			}
		}
	}
	return false
}
