package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// errInvalidState is used when the OAuth flow fails due to an invalid state parameter in the callback API.
// The user is redirected and this error is attached to the URL as a query parameter.
var errInvalidState = errors.New("invalid oauth state")

// Callback handles the provider's OAuth callback.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: Add validations.

	// Obtain params from the request.
	providerName := mux.Vars(r)["provider"]
	errAuth, code, state := r.URL.Query().Get("error"),
		r.URL.Query().Get("code"),
		r.URL.Query().Get("state")

	// Attempt to decode state.
	oState, err := decodeState(state)
	if err != nil {
		slog.ErrorContext(ctx, "failed to decode state, this should never happen", "error", err)
		// Since the state is invalid, the actual clientCallbackURL is unknown,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errInvalidState, h.config.AllowedRedirectURLs[0])
		return
	}

	// If the state ID is found in the local map, it guarantees that the request is genuine.
	// Otherwise, it could be that the provider took too long to callback and the state ID got expired and cleaned up
	// from the map or, it could be that it is a malicious request and someone is trying to impersonate the provider.
	if _, present := h.stateIDs.LoadAndDelete(oState.ID); !present {
		slog.ErrorContext(ctx, "state ID not found in the local map, failing request", "stateID", oState.ID)
		errorRedirect(w, errInvalidState, oState.ClientCallbackURL)
		return
	}

	// If this error is not empty, then the OAuth flow has failed from the provider's side.
	if errAuth != "" {
		slog.ErrorContext(ctx, "provider called back with error", "error", errAuth)
		errorRedirect(w, errors.New(errAuth), oState.ClientCallbackURL)
		return
	}

	// Get the required provider.
	provider := h.getProvider(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "callback from unknown provider, this should never happen", "provider", providerName)
		errorRedirect(w, errutils.InternalServerError(), oState.ClientCallbackURL)
		return
	}

	// Convert the code sent by the provider to an access token.
	token, err := provider.TokenFromCode(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "error in TokenFromCode call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), oState.ClientCallbackURL)
		return
	}

	// Decode token to obtain claims. This also verifies the token.
	claims, err := provider.DecodeToken(ctx, token)
	if err != nil {
		slog.ErrorContext(ctx, "error in DecodeToken call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), oState.ClientCallbackURL)
		return
	}

	_ = claims
	// TODO: Redirect with correct encoding, cookies and security headers.

	// Success redirect URL.
	// We don't need to verify the token in this flow since it is coming directly from the provider.
	redirectURL := fmt.Sprintf("%s?token=%s&provider=%s", oState.ClientCallbackURL, token, providerName)
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(w, http.StatusFound, headers, nil)
}

// errorRedirect redirects the caller (by writing 302 and the Location header to the response) and attaches
// the given error information as a query parameter.
func errorRedirect(w http.ResponseWriter, err error, targetURL string) {
	redirectURL := fmt.Sprintf("%s?error=%s", targetURL, url.QueryEscape(err.Error()))
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(w, http.StatusFound, headers, nil)
}
