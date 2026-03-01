package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shivanshkc/authorizer/internal/repository"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/oauth"

	"github.com/gorilla/mux"
)

// accessTokenCookieName is the name of the cookie that holds the access token (or the ID token).
const accessTokenCookieName = "session"

// Callback handles the provider's OAuth callback.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// Obtain params from the request.
	providerName := mux.Vars(r)["provider"]
	stateKey, errAuth, code := q.Get("state"), q.Get("error"), q.Get("code")

	// Validate the stateKey and obtain the corresponding stateValue.
	sValue, err := loadAndDeleteStateValue(ctx, stateKey, h.stateMap)
	if err != nil {
		// Since the state key is invalid, the state map can not be accessed, and so the redirect URL is unknown.
		// Therefore, we have to fall back to the first allowed redirect URL.
		errorRedirect(w, err.Error(), h.config.AllowedRedirectURLs[0])
		return
	}

	// Validate remaining inputs.
	if err := validateCallbackInputs(ctx, providerName, code, errAuth); err != nil {
		errorRedirect(w, err.Error(), sValue.ClientCallbackURL)
		return
	}

	// Convert the oauth code to ID token, and then subsequently to claims, for the given provider.
	claims, token, err := h.obtainAndDecodeToken(ctx, providerName, code, sValue.CodeVerifier)
	if err != nil {
		errorRedirect(w, err.Error(), sValue.ClientCallbackURL)
		return
	}

	// Upsert user in the database asynchronously.
	go buildAndUpsertUser(claims, h.repo)

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
func errorRedirect(w http.ResponseWriter, err string, targetURL string) {
	redirectURL := fmt.Sprintf("%s?error=%s", targetURL, url.QueryEscape(err))
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(w, http.StatusFound, headers, nil)
}

// loadAndDeleteStateValue accepts an unvalidated stateKey (coming right from the API caller) and the stateMap.
//
// It validates the stateKey, then fetches its corresponding stateValue from the stateMap.
// If found, the stateValue is asserted to the correct type and returned.
//
// The returned error is safe to send to the client. More specifc details about the error are logged.
func loadAndDeleteStateValue(ctx context.Context, stateKey string, stateMap *sync.Map) (stateValue, error) {
	// State key validation.
	if err := validateState(stateKey); err != nil {
		slog.ErrorContext(ctx, "invalid state from provider", "value", stateKey, "error", err)
		return stateValue{}, errInvalidState
	}

	// If the state value is found in the state map, it guarantees that it is not a CSRF attack.
	// Otherwise, it could be that the provider took too long to callback and the state key got expired and cleaned up
	// from the map, or it could be that it is a malicious request and someone is trying to impersonate the provider.
	sValueAny, present := stateMap.LoadAndDelete(stateKey)
	if !present {
		slog.ErrorContext(ctx, "state key not found in the map, failing request", "stateKey", stateKey)
		return stateValue{}, errutils.RequestTimeout()
	}

	// Assert to the stateValue type to access fields.
	sValue, ok := sValueAny.(stateValue)
	if !ok {
		slog.ErrorContext(ctx, "failed to assert to stateValue type", "stateValue", sValueAny)
		return stateValue{}, errutils.InternalServerError()
	}

	return sValue, nil
}

// validateCallbackInputs validates all inputs received by the callback API.
//
// The returned error is safe to send to the client. More specifc details about the error are logged.
func validateCallbackInputs(ctx context.Context, providerName, code, errAuth string) error {
	// Provider name validation.
	if err := validateProvider(providerName); err != nil {
		slog.ErrorContext(ctx, "invalid provider in callback", "value", providerName, "error", err)
		return errutils.InternalServerError()
	}

	// Authorization code validation.
	if err := validateAuthCode(code); err != nil {
		slog.ErrorContext(ctx, "invalid code in callback", "value", code, "error", err)
		return errutils.InternalServerError()
	}

	// If this error is not empty, then the OAuth flow has failed from the provider's side.
	if errAuth != "" {
		slog.ErrorContext(ctx, "provider called back with error", "error", errAuth)
		return errors.New(errAuth)
	}

	return nil
}

// obtainAndDecodeToken fetches the correct provider implementation for the give name, uses the implementation to
// convert the "code" and "codeVerifier" to the ID token, then safely decodes the ID token to get claims.
//
// The returned error is safe to send to the client. More specific details about the error are logged.
func (h *Handler) obtainAndDecodeToken(
	ctx context.Context, providerName, code, codeVerifier string,
) (oauth.Claims, string, error) {
	// Get the required provider.
	provider := h.providerByName(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "callback from unknown provider", "provider", providerName)
		return oauth.Claims{}, "", errutils.InternalServerError()
	}

	// Convert the code sent by the provider to an access token.
	token, err := provider.TokenFromCode(ctx, code, codeVerifier)
	if err != nil {
		slog.ErrorContext(ctx, "error in TokenFromCode call", "error", err)
		return oauth.Claims{}, "", errutils.InternalServerError()
	}

	// Decode token to obtain claims. This also verifies the token.
	claims, err := provider.DecodeToken(ctx, token)
	if err != nil {
		slog.ErrorContext(ctx, "error in DecodeToken call", "error", err)
		return oauth.Claims{}, "", errutils.InternalServerError()
	}

	return claims, token, nil
}

// buildAndUpsertUser build the user from the given claims and upserts it into the database.
func buildAndUpsertUser(claims oauth.Claims, repo repository.Repository) {
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
	if err := repo.UpsertUser(ctx, user); err != nil {
		slog.ErrorContext(ctx, "error in UpsertUser call", "error", err)
	}
}
