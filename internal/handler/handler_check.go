package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

const (
	xAuthEmailHeader   = "X-Auth-Email"
	xAuthNameHeader    = "X-Auth-Name"
	xAuthPictureHeader = "X-Auth-Picture"
)

// Check performs an authentication check on the given request.
func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get cookie for authentication.
	cookie, err := r.Cookie(accessTokenCookieName)
	if err != nil {
		// Known error.
		if errors.Is(err, http.ErrNoCookie) {
			slog.ErrorContext(ctx, "No cookie in the request")
			httputils.WriteErr(w, errutils.Unauthorized())
			return
		}
		// Unexpected error.
		slog.ErrorContext(ctx, "Failed to get cookie from request", "error", err)
		httputils.WriteErr(w, errutils.InternalServerError())
		return
	}

	// Get token issuer. This is necessary to decide which provider to use to verify the token.
	issuer, err := issuerFromToken(cookie.Value)
	if err != nil {
		slog.ErrorContext(ctx, "error in issuerFromToken call", "error", err)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	// Get the provider to use.
	provider := h.providerByIssuer(issuer)
	if provider == nil {
		slog.ErrorContext(ctx, "no providers for issuer", "issuer", issuer)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	// Decode token for verification and claims.
	claims, err := provider.DecodeToken(ctx, cookie.Value)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to decode token", "error", err)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	headers := map[string]string{
		xAuthEmailHeader:   claims.Email,
		xAuthNameHeader:    claims.GivenName + " " + claims.FamilyName,
		xAuthPictureHeader: claims.Picture,
	}

	httputils.Write(w, http.StatusOK, headers, nil)
}

// issuerFromToken decodes the base64 encoded payload of the token and returns the value of the "iss" claim.
func issuerFromToken(token string) (string, error) {
	// Split the token to parse the payload.
	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) != 3 {
		return "", fmt.Errorf("token expected to have 3 parts but had %d", len(tokenSplit))
	}

	// Decode the payload of the token.
	// This is necessary because we need the token issuer in order to decide which provider to use to validate it.
	payloadBase64 := tokenSplit[1]
	payload, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Unmarshal claims to struct to finally get the "iss" value.
	var claims oauth.Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal token claims: %w", err)
	}

	return claims.Iss, nil
}
