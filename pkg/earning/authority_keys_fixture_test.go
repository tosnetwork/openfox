package earning

import (
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// testAuthorityCustody stands in for tosctl custody in logic tests. Its
// signatures are not ML-DSA-44; tests that check real bytes use the helper.
var testAuthorityCustody = &mldsa44test.Fake{}

// testAuthorityKeys returns the owner authority keys held by the fake
// custody under the production controller names.
func testAuthorityKeys() AuthorityKeys {
	return testAuthorityKeysFor(ActionAuthorityController, CustodyAuthorizationController)
}

// testAuthorityKeysFor returns keys of other fake controllers, for tests that
// need a second, distinct owner authority.
func testAuthorityKeysFor(action, custody string) AuthorityKeys {
	return AuthorityKeys{Custody: testAuthorityCustody,
		ActionKeyID: testAuthorityCustody.KeyID(action), ActionPublicKey: testAuthorityCustody.PublicKey(action),
		CustodyKeyID: testAuthorityCustody.KeyID(custody), CustodyPublicKey: testAuthorityCustody.PublicKey(custody)}
}

// testCustodyResolver resolves the fake custody authorization key for one
// exact authority, owner and Agent, as a custody host pins it.
func testCustodyResolver(authorityID, ownerID, agentID string) mldsa44test.CustodyAuthorizationResolver {
	return mldsa44test.CustodyAuthorizationResolver{Verifier: testAuthorityCustody,
		Keys: map[mldsa44test.CustodyPrincipal][]byte{{AuthorityID: authorityID, OwnerID: ownerID, AgentID: agentID}: testAuthorityCustody.PublicKey(CustodyAuthorizationController)}}
}

// testActionAuthorityResolver resolves the fake Action Authority key for one
// authority, as an independent local sink pins it.
func testActionAuthorityResolver(authorityID string) pinnedActionAuthority {
	keys := testAuthorityKeys()
	resolver, err := newPinnedActionAuthority(authorityID, keys.ActionKeyID, keys.ActionPublicKey, testAuthorityCustody)
	if err != nil {
		panic(err)
	}
	return resolver
}
