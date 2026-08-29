// Package authcontext carries claims created by authentication middleware.
// API handlers must never synthesize these claims from request headers.
package authcontext

import (
	"context"
	"crypto/sha256"
)

const LauncherDashboardAudience = "openfox.owner-control.dashboard.v1"

type DashboardClaims struct {
	Audience             string
	ChannelBindingDigest []byte
	MayReadEvidence      bool
}

type dashboardClaimsKey struct{}

func WithDashboardClaims(ctx context.Context, sessionCredential string) context.Context {
	digest := sha256.Sum256(append([]byte("openfox.launcher-dashboard.channel-binding.v1\x00"), []byte(sessionCredential)...))
	claims := DashboardClaims{Audience: LauncherDashboardAudience, ChannelBindingDigest: digest[:], MayReadEvidence: true}
	return context.WithValue(ctx, dashboardClaimsKey{}, claims)
}

func DashboardClaimsFrom(ctx context.Context) (DashboardClaims, bool) {
	claims, ok := ctx.Value(dashboardClaimsKey{}).(DashboardClaims)
	if !ok || claims.Audience != LauncherDashboardAudience || len(claims.ChannelBindingDigest) != sha256.Size {
		return DashboardClaims{}, false
	}
	claims.ChannelBindingDigest = append([]byte(nil), claims.ChannelBindingDigest...)
	return claims, true
}
