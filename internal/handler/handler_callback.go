package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/repository"
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
	stateKey, errAuth, code := r.URL.Query().Get("state"),
		r.URL.Query().Get("error"),
		r.URL.Query().Get("code")

	// State key validation.
	if err := validateState(stateKey); err != nil {
		slog.ErrorContext(ctx, "invalid state from provider", "value", stateKey, "error", err)
		// Since the state key is invalid, the state map can not be accessed, and so the redirect URL is unknown.
		// Therefore, we have to fall back to the first allowed redirect URL.
		errorRedirect(w, errInvalidState, h.config.AllowedRedirectURLs[0])
		return
	}

	// If the state value is found in the state map, it guarantees that it is not a CSRF attack.
	// Otherwise, it could be that the provider took too long to callback and the state key got expired and cleaned up
	// from the map, or it could be that it is a malicious request and someone is trying to impersonate the provider.
	sValueAny, present := h.stateMap.LoadAndDelete(stateKey)
	if !present {
		slog.ErrorContext(ctx, "state key not found in the map, failing request", "stateKey", stateKey)
		// Since the state key is expired, the redirect URL is gone,
		// and so we fall back to the first allowed redirect URL.
		errorRedirect(w, errutils.RequestTimeout(), h.config.AllowedRedirectURLs[0])
		return
	}

	// Assert to the stateValue type to access fields.
	sValue, ok := sValueAny.(stateValue)
	if !ok {
		slog.ErrorContext(ctx, "failed to assert to stateValue type", "stateValue", sValueAny)
		errorRedirect(w, errutils.InternalServerError(), h.config.AllowedRedirectURLs[0])
		return
	}

	// Provider name validation.
	if err := validateProvider(providerName); err != nil {
		slog.ErrorContext(ctx, "invalid provider in callback", "value", providerName, "error", err)
		errorRedirect(w, errutils.InternalServerError(), sValue.ClientCallbackURL)
		return
	}

	// Authorization code validation.
	if err := validateAuthCode(code); err != nil {
		slog.ErrorContext(ctx, "invalid code in callback", "value", code, "error", err)
		errorRedirect(w, errutils.InternalServerError(), sValue.ClientCallbackURL)
		return
	}

	// If this error is not empty, then the OAuth flow has failed from the provider's side.
	if errAuth != "" {
		slog.ErrorContext(ctx, "provider called back with error", "error", errAuth)
		errorRedirect(w, errors.New(errAuth), sValue.ClientCallbackURL)
		return
	}

	// Get the required provider.
	provider := h.providerByName(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "callback from unknown provider", "provider", providerName)
		errorRedirect(w, errutils.InternalServerError(), sValue.ClientCallbackURL)
		return
	}

	// Convert the code sent by the provider to an access token.
	token, err := provider.TokenFromCode(ctx, code, sValue.CodeVerifier)
	if err != nil {
		slog.ErrorContext(ctx, "error in TokenFromCode call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), sValue.ClientCallbackURL)
		return
	}

	// Decode token to obtain claims. This also verifies the token.
	claims, err := provider.DecodeToken(ctx, token)
	if err != nil {
		slog.ErrorContext(ctx, "error in DecodeToken call", "error", err)
		errorRedirect(w, errutils.InternalServerError(), sValue.ClientCallbackURL)
		return
	}

	// Upsert user in the database asynchronously.
	go func() {
		// Do not use the request's context for this operation.
		ctx := context.Background()
		// The user record to store.
		user := repository.User{
			Email:      claims.Email,
			GivenName:  claims.GivenName,
			FamilyName: claims.FamilyName,
			PictureURL: claims.Picture,
		}

		// Database call.
		if err := h.repo.UpsertUser(ctx, user); err != nil {
			slog.ErrorContext(ctx, "error in UpsertUser call", "error", err)
		}
	}()

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
	redirectURL := fmt.Sprintf("%s?provider=%s", sValue.ClientCallbackURL, providerName)
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
