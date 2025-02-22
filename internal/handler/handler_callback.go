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
	state, errAuth, code := r.URL.Query().Get("state"),
		r.URL.Query().Get("error"),
		r.URL.Query().Get("code")

	// State parameter validation.
	if err := validateState(state); err != nil {
		slog.ErrorContext(ctx, "invalid state", "value", state, "error", err)
		// Since the state is invalid, the actual clientCallbackURL is unknown,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errInvalidState, h.config.AllowedRedirectURLs[0])
		return
	}

	// If the state value is found in the State Info Map, it guarantees that the request is genuine.
	// Otherwise, it could be that the provider took too long to callback and the state got expired and cleaned up
	// from the map, or it could be that it is a malicious request and someone is trying to impersonate the provider.
	sInfoAny, present := h.stateInfoMap.LoadAndDelete(state)
	if !present {
		slog.ErrorContext(ctx, "state not found in the State Info Map, failing request", "state", state)
		// Since the state is expired, the Client Callback URL is gone,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errutils.RequestTimeout(), h.config.AllowedRedirectURLs[0])
		return
	}

	// Assert to the stateInfo type to access fields.
	sInfo, ok := sInfoAny.(stateInfo)
	if !ok {
		slog.ErrorContext(ctx, "failed to assert to stateInfo type", "stateInfo", sInfoAny)
		errorRedirect(w, errutils.RequestTimeout(), h.config.AllowedRedirectURLs[0])
		return
	}

	// Provider name validation.
	if err := validateProvider(providerName); err != nil {
		slog.ErrorContext(ctx, "invalid provider in callback", "value", providerName, "error", err)
		errorRedirect(w, errutils.InternalServerError(), sInfo.ClientCallbackURL)
		return
	}

	// Authorization code validation.
	if err := validateAuthCode(code); err != nil {
		slog.ErrorContext(ctx, "invalid code in callback", "value", code, "error", err)
		errorRedirect(w, errutils.InternalServerError(), sInfo.ClientCallbackURL)
		return
	}

	// If this error is not empty, then the OAuth flow has failed from the provider's side.
	if errAuth != "" {
		slog.ErrorContext(ctx, "provider called back with error", "error", errAuth)
		errorRedirect(w, errors.New(errAuth), sInfo.ClientCallbackURL)
		return
	}

	// Get the required provider.
	provider := h.providerByName(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "callback from unknown provider", "provider", providerName)
		errorRedirect(w, errutils.InternalServerError(), sInfo.ClientCallbackURL)
		return
	}

	// Convert the code sent by the provider to an access token.
	token, err := provider.TokenFromCode(ctx, code, sInfo.CodeVerifier)
	if err != nil {
		slog.ErrorContext(ctx, "error in TokenFromCode call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), sInfo.ClientCallbackURL)
		return
	}

	// Decode token to obtain claims. This also verifies the token.
	claims, err := provider.DecodeToken(ctx, token)
	if err != nil {
		slog.ErrorContext(ctx, "error in DecodeToken call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), sInfo.ClientCallbackURL)
		return
	}

	// TODO: Use the claims to insert/update user in the DB.

	// Set the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:  accessTokenCookieName,
		Value: token,
		Path:  "/",
		// This will be required if Authorizer needs to be used with multiple subdomains.
		Domain: "",
		// The cookie expires at the same time as the token.
		MaxAge: int(time.Until(claims.Exp).Seconds()),
		// Use secure mode when the application is running over HTTPS.
		Secure:   strings.HasPrefix(h.config.Application.BaseURL, "https://"),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Success redirect URL.
	redirectURL := fmt.Sprintf("%s?provider=%s", sInfo.ClientCallbackURL, providerName)
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
