package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

func campaignExactJSONObject(raw []byte, required, optional, nullable []string) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("evidence value is not a JSON object")
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	nullableSet := make(map[string]bool, len(nullable))
	for _, key := range nullable {
		nullableSet[key] = true
	}
	for _, key := range required {
		allowed[key] = true
		value, found := object[key]
		if !found {
			return nil, fmt.Errorf("required JSON field %q is absent", key)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !nullableSet[key] {
			return nil, fmt.Errorf("required JSON field %q is null", key)
		}
	}
	for _, key := range optional {
		allowed[key] = true
		if value, found := object[key]; found && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("optional JSON field %q is null", key)
		}
	}
	for key := range object {
		if !allowed[key] {
			return nil, fmt.Errorf("unknown or non-canonical JSON field %q", key)
		}
	}
	return object, nil
}

func validateCampaignValidatorEvidenceJSONShape(raw []byte) error {
	top, err := campaignExactJSONObject(raw, []string{
		"schema", "started_at", "finished_at", "network", "evidence_class", "campaign_run_id",
		"agent_manifest_digest", "pool_address", "pool_code_hash", "pool_config", "validator_selection",
		"reward_evidence", "agent_nominator_rewards", "post_stake_control", "claim_limits", "checks",
		"not_exercised", "events", "failures", "passed",
	}, []string{"network_domain"}, nil)
	if err != nil {
		return err
	}
	var evidenceClass string
	if err = json.Unmarshal(top["evidence_class"], &evidenceClass); err != nil {
		return errors.New("evidence_class is not a string")
	}
	sameGenesis := evidenceClass == "SAME_GENESIS_CAMPAIGN_WALLETS"
	if domain, found := top["network_domain"]; found {
		if _, err = campaignExactJSONObject(domain, []string{
			"network_id", "global_id", "workchain_id", "zero_state_root_hash", "zero_state_file_hash",
		}, nil, nil); err != nil {
			return fmt.Errorf("network_domain: %w", err)
		}
	}
	if _, err = campaignExactJSONObject(top["pool_config"], []string{
		"validator_reward_share_bps", "max_nominators", "min_validator_stake_nanotos",
		"min_nominator_stake_nanotos", "network_minimum_effective_stake_nanotos", "max_stake_factor",
	}, nil, nil); err != nil {
		return fmt.Errorf("pool_config: %w", err)
	}
	if _, err = campaignExactJSONObject(top["validator_selection"], []string{
		"selection_status", "election_id", "validator_public_key", "validator_adnl_id", "selected_adnl_id",
		"selected_weight", "validator_set_utime_since", "validator_set_utime_until", "validator_set_total",
		"validator_set_main", "validator_set_total_weight",
	}, nil, nil); err != nil {
		return fmt.Errorf("validator_selection: %w", err)
	}
	if _, err = campaignExactJSONObject(top["reward_evidence"], []string{
		"stake_amount_sent_nanotos", "effective_stake_nanotos", "reward_active_principal_at_stake_nanotos",
		"pending_principal_nanotos", "total_ledger_principal_nanotos", "non_reward_effective_surplus_nanotos",
		"surplus_earns_network_reward", "elector_returned_credit_nanotos", "gross_election_reward_nanotos",
		"validator_election_reward_nanotos", "nominator_election_reward_nanotos", "election_id",
		"validator_reward_share_bps", "nominator_ledger_reward_nanotos",
		"agent_election_reward_floor_nanotos", "ledger_delta_attribution", "election_reward_attribution",
		"attribution_caveat",
	}, nil, nil); err != nil {
		return fmt.Errorf("reward_evidence: %w", err)
	}
	var rewards []json.RawMessage
	if err = json.Unmarshal(top["agent_nominator_rewards"], &rewards); err != nil || rewards == nil {
		return errors.New("agent_nominator_rewards is not an array")
	}
	for index, rawReward := range rewards {
		optional := []string(nil)
		if sameGenesis {
			optional = []string{"configured_deploy_message_value_nanotos"}
		}
		reward, shapeErr := campaignExactJSONObject(rawReward, []string{
			"agent", "agent_id", "campaign_wallet_label", "campaign_account_address", "delegation_wallet",
			"wallet_funding_nanotos", "wallet_balance_before_deposit_nanotos", "wallet_balance_after_deposit_nanotos",
			"deposit_message_value_nanotos", "deposit_processing_fee_nanotos", "recorded_principal_nanotos",
			"principal_before_recovery_nanotos", "principal_after_recovery_nanotos", "ledger_reward_delta_nanotos",
			"election_reward_floor_nanotos", "attribution_status", "withdrawal_payout",
		}, optional, []string{"withdrawal_payout"})
		if shapeErr != nil {
			return fmt.Errorf("agent_nominator_rewards[%d]: %w", index, shapeErr)
		}
		if sameGenesis {
			if _, found := reward["configured_deploy_message_value_nanotos"]; !found {
				return fmt.Errorf(
					"agent_nominator_rewards[%d]: required Round 5 configured deploy value is absent", index,
				)
			}
		}
		if !bytes.Equal(bytes.TrimSpace(reward["withdrawal_payout"]), []byte("null")) {
			if _, shapeErr = campaignExactJSONObject(reward["withdrawal_payout"], []string{
				"pool_entitlement_nanotos", "wallet_balance_before_nanotos", "wallet_balance_after_nanotos",
				"wallet_credit_nanotos",
			}, nil, nil); shapeErr != nil {
				return fmt.Errorf("agent_nominator_rewards[%d].withdrawal_payout: %w", index, shapeErr)
			}
		}
	}
	if _, err = campaignExactJSONObject(top["post_stake_control"], []string{
		"delegation_wallet", "recorded_principal_nanotos", "principal_before_recovery_nanotos",
		"principal_after_recovery_nanotos", "ledger_reward_delta_nanotos", "expected_reward_nanotos",
	}, nil, nil); err != nil {
		return fmt.Errorf("post_stake_control: %w", err)
	}
	return nil
}
