package config

import "testing"

func TestEarningDefaultsAndSideEffectsFailClosed(t *testing.T) {
	settings := DefaultConfig().Earning
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	if settings.Enabled || !settings.ObserveOnly || settings.MinimumIndependentCarriers != 2 {
		t.Fatalf("unsafe defaults: %+v", settings)
	}
	settings.Gates.Contact = true
	if err := settings.Validate(); err == nil {
		t.Fatal("disabled configuration enabled contact")
	}
}

func TestEnabledEarningRequiresIndependentSecureCarriers(t *testing.T) {
	settings := EarningSettings{Enabled: true, StateDir: "/tmp/openfox-earning", OwnerID: "owner", AgentID: "agent", AuthorityID: "authority",
		MessengerSocket: "/tmp/openfox-messenger.sock",
		MandateDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MinimumIndependentCarriers: 2,
		TrustedIntentIssuerKeys: map[string]string{"agent:issuer": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Gates:                   EarningGateSettings{Contact: true}, Policy: EarningPolicySettings{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "10", MaximumOutgoingPaymentAtomic: "0"},
		Carriers: []EarningCarrierSettings{{ID: "a", Endpoint: "http://127.0.0.1:8081/v1/intents", ReadToken: NewSecureString("one")},
			{ID: "b", Endpoint: "http://localhost:8082/v1/intents", ReadToken: NewSecureString("two")}}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.Carriers = settings.Carriers[:1]
	if err := settings.Validate(); err == nil {
		t.Fatal("single Carrier enabled autonomous contact")
	}
}

func TestSharedEarningAuthorityRequiresCompleteMTLSIdentity(t *testing.T) {
	settings := EarningSettings{Enabled: true, Mode: "observe", ObserveOnly: true, StateDir: "/tmp/openfox-earning",
		OwnerID: "owner", AgentID: "agent", AuthorityID: "authority",
		MandateDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustedIntentIssuerKeys: map[string]string{"agent:issuer": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Policy:                  EarningPolicySettings{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "10"},
		Authority: EarningAuthoritySettings{Mode: "shared", Endpoint: "https://authority.example/v1/economic-authority",
			ServerName: "authority.example", CAFile: "/etc/openfox/authority-ca.pem", ClientCertFile: "/etc/openfox/client.pem",
			ClientKeyFile: "/etc/openfox/client.key", AuthorityPublicKey: "ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			InstanceID: "worker-a", TimeoutMillis: 5000}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.Authority.ClientKeyFile = "relative.key"
	if err := settings.Validate(); err == nil {
		t.Fatal("shared Authority accepted a relative client key path")
	}
}
