package handler

import (
	"errors"
	"log/slog"
	"net/http"

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
