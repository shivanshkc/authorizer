package handler

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
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

	// Split the token to parse the payload.
	tokenSplit := strings.Split(cookie.Value, ".")
	if len(tokenSplit) != 3 {
		slog.ErrorContext(ctx, "token does not contain 3 parts", "parts", tokenSplit, "token", cookie.Value)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	// Decode the payload of the token.
	// This is necessary because we need the token issuer in order to decide which provider to use to validate it.
	payloadBase64 := tokenSplit[1]
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to decode token payload", "error", err)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	// TODO: Get the issuer from the payload and decide on the provider.
	_ = payload

	// Decode token for verification and claims.
	//
	// TODO: Decode on which provider to use based on token issuer.
	claims, err := h.googleProvider.DecodeToken(ctx, cookie.Value)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to decode token", "error", err)
		httputils.WriteErr(w, errutils.Unauthorized())
		return
	}

	headers := map[string]string{
		"X-Auth-Email":   claims.Email,
		"X-Auth-Name":    claims.GivenName + " " + claims.FamilyName,
		"X-Auth-Picture": claims.PictureURL,
	}

	httputils.Write(w, http.StatusOK, headers, nil)
}
