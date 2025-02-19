package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// accessTokenCookieName is the name of the cookie that holds the access token (or the ID token).
const accessTokenCookieName = "session"

// Callback handles the provider's OAuth callback.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Obtain params from the request.
	providerName := mux.Vars(r)["provider"]
	errAuth, code, state := r.URL.Query().Get("error"),
		r.URL.Query().Get("code"),
		r.URL.Query().Get("state")

	// State parameter validation.
	if err := validateState(state); err != nil {
		slog.ErrorContext(ctx, "invalid state", "value", state, "error", err)
		// Since the state is invalid, the actual clientCallbackURL is unknown,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errInvalidState, h.config.AllowedRedirectURLs[0])
		return
	}

	// Attempt to decode state. This is done before any other validations because we need the Client Callback URL to
	// redirect to, even in case of errors.
	oState, err := decodeState(state)
	if err != nil {
		slog.ErrorContext(ctx, "failed to decode state, this should never happen", "error", err)
		// Since the state is invalid, the actual clientCallbackURL is unknown,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errMalformedState, h.config.AllowedRedirectURLs[0])
		return
	}

	// If the state ID is found in the State ID Map, it guarantees that the request is genuine.
	// Otherwise, it could be that the provider took too long to callback and the state ID got expired and cleaned up
	// from the map or, it could be that it is a malicious request and someone is trying to impersonate the provider.
	if _, present := h.stateIDMap.LoadAndDelete(oState.ID); !present {
		slog.ErrorContext(ctx, "state ID not found in the State ID Map, failing request", "stateID", oState.ID)
		errorRedirect(w, errInvalidState, oState.ClientCallbackURL)
		return
	}

	// Provider name validation.
	if err := validateProvider(providerName); err != nil {
		slog.ErrorContext(ctx, "invalid provider in callback", "value", providerName, "error", err)
		errorRedirect(w, errutils.InternalServerError(), oState.ClientCallbackURL)
		return
	}

	// Authorization code validation.
	if err := validateAuthCode(code); err != nil {
		slog.ErrorContext(ctx, "invalid code in callback", "value", code, "error", err)
		errorRedirect(w, errutils.InternalServerError(), oState.ClientCallbackURL)
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
		slog.ErrorContext(ctx, "callback from unknown provider", "provider", providerName)
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

	// TODO: Use the claims to insert/update user in the DB.

	// Set the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:   accessTokenCookieName,
		Value:  token,
		Path:   "/",
		Domain: httputils.TrimProtocol(h.config.Application.BaseURL),
		// The cookie expires at the same time as the token.
		MaxAge: int(time.Until(claims.ExpiresAt).Seconds()),
		// Use secure mode when the application is running over HTTPS.
		Secure:   strings.HasPrefix(h.config.Application.BaseURL, "https://"),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Success redirect URL.
	redirectURL := fmt.Sprintf("%s?provider=%s", oState.ClientCallbackURL, providerName)
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
