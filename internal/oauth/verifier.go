// Package oauth implements bearer OIDC token validation for the HTTP MCP
// frontend (cmd/mcp-broker-http). It delegates to github.com/coreos/go-oidc,
// which discovers the issuer, downloads and caches the JWKS (with key
// rotation), and validates the JWT signature, iss, aud, and exp locally —
// no round-trip per request.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Config configures the OIDC verifier.
type Config struct {
	Issuer         string   // OIDC provider URL (auto-discovery)
	Audience       string   // expected value of the aud claim (this resource server)
	RequiredScopes []string // required scopes (checked by the SDK middleware)
	UserClaim      string   // identity claim; default "sub"
	GroupsClaim    string   // groups/roles claim to propagate; optional
	// MaxTokenAge is the maximum acceptable age of the token since issuance
	// (iat claim). 0 = no limit. Limiting to 1–2 hours reduces the replay risk
	// of leaked tokens within their exp window (M3).
	MaxTokenAge time.Duration
}

// Verifier validates tokens and extracts the user identity and groups.
type Verifier struct {
	verifier    *oidc.IDTokenVerifier
	userClaim   string
	groupsClaim string
	maxTokenAge time.Duration // M3: 0 = no limit
}

// ExtraGroupsKey is the key under which Verify stores the user's groups in
// TokenInfo.Extra, so the frontend can propagate them to the signer.
const ExtraGroupsKey = "groups"

// NewVerifier discovers the issuer and constructs the verifier. JWKS management
// (download, cache, and rotation) is handled by go-oidc.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oauth: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oauth: audience is required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: OIDC discovery: %w", err)
	}
	userClaim := cfg.UserClaim
	if userClaim == "" {
		userClaim = "sub"
	}
	return &Verifier{
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		userClaim:   userClaim,
		groupsClaim: cfg.GroupsClaim,
		maxTokenAge: cfg.MaxTokenAge,
	}, nil
}

// Verify implements auth.TokenVerifier: validates the token and returns its
// TokenInfo. Validation errors are wrapped in auth.ErrInvalidToken so the
// middleware responds with 401.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	idToken, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable claims: %v", auth.ErrInvalidToken, err)
	}

	ti := &auth.TokenInfo{
		Scopes:     scopesFromClaims(claims),
		Expiration: idToken.Expiry,
		UserID:     stringClaim(claims, v.userClaim),
	}
	if ti.UserID == "" {
		// Without a usable identity we cannot audit or apply RBAC.
		return nil, fmt.Errorf("%w: user claim %q absent", auth.ErrInvalidToken, v.userClaim)
	}
	// M3: verify token age (iat) to limit the replay risk.
	if v.maxTokenAge > 0 {
		if iatRaw, ok := claims["iat"].(float64); ok {
			issuedAt := time.Unix(int64(iatRaw), 0)
			age := time.Since(issuedAt)
			if age > v.maxTokenAge {
				return nil, fmt.Errorf("%w: token too old (age=%v, max=%v)",
					auth.ErrInvalidToken, age.Truncate(time.Second), v.maxTokenAge)
			}
		}
	}
	if v.groupsClaim != "" {
		if groups := stringSliceClaim(claims, v.groupsClaim); groups != nil {
			ti.Extra = map[string]any{ExtraGroupsKey: groups}
		}
	}
	return ti, nil
}

// scopesFromClaims extracts scopes from the "scope" claim (space-separated
// string, OAuth2 format) or "scp" (list, used by some providers).
func scopesFromClaims(claims map[string]any) []string {
	if s, ok := claims["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	return stringSliceClaim(claims, "scp")
}

func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// stringSliceClaim returns claim name as []string. Accepts both a JSON array
// and a single string. Returns nil if the claim does not exist.
func stringSliceClaim(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}
