package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/pkg/oauth"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// GetUser serves the specified user's information if the authorization token is correct.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Email of the user to be fetched.
	targetUserEmail := mux.Vars(r)["email"]

	// Obtain the token.
	token := r.Header.Get("Authorization")
	if token == "" {
		slog.ErrorContext(ctx, "no access token in request")
		httputils.WriteErr(w, errutils.Unauthorized().WithReasonStr("access token absent"))
		return
	}

	// Identify which provider does this token belong to.
	providerName, err := oauth.ProviderFromToken(token)
	if err != nil {
		slog.ErrorContext(ctx, "failed to identify the token's provider", "err", err)
		// Handle known errors.
		if errors.Is(err, oauth.ErrUnknownProvider) || errors.Is(err, oauth.ErrCannotDeduceProvider) {
			httputils.WriteErr(w, errutils.Unauthorized().WithReasonStr("access token invalid"))
			return
		}
		// Unexpected error.
		httputils.WriteErr(w, err)
		return
	}

	// Validate token.
	if _, err := h.Providers[providerName].ValidateToken(ctx, token); err != nil {
		slog.ErrorContext(ctx, "failed to validate token", "err", err)
		httputils.WriteErr(w, err)
		return
	}

	// Get user details from DB.
	userDoc, err := h.UserDB.GetUser(ctx, targetUserEmail)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user from DB", "err", err)
		httputils.WriteErr(w, err)
		return
	}

	// Success.
	httputils.Write(w, http.StatusOK, nil, userDoc)
}
