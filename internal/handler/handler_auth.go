package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// stateExpiry is the max allowed time for a provider to invoke the callback API.
// If the provider is too late, the state value will be removed from the memory and the flow will fail.
//
// This is a var and not a const so it can be modified for testing purposes.
var stateExpiry = time.Minute

var (
	errUnknownRedirectURL  = errutils.BadRequest().WithReasonStr("redirect_url is not allowed")
	errUnsupportedProvider = errutils.BadRequest().WithReasonStr("provider is not supported")
)

// Auth starts the OAuth flow by redirecting the caller to the specified provider's authentication page.
func (h *Handler) Auth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Provider is a path parameter and so it will always be present.
	providerName := mux.Vars(r)["provider"]
	// Once authentication is done, the flow will end on this URL.
	clientCallbackURL := r.URL.Query().Get("redirect_url")

	// Provider name validation.
	if err := validateProvider(providerName); err != nil {
		slog.ErrorContext(ctx, "invalid provider", "value", providerName, "error", err)
		httputils.WriteErr(w, errutils.BadRequest().WithReasonErr(err))
		return
	}

	// Client callback URL validation.
	if err := validateClientCallbackURL(clientCallbackURL); err != nil {
		slog.ErrorContext(ctx, "invalid client callback URL", "value", clientCallbackURL, "error", err)
		httputils.WriteErr(w, errutils.BadRequest().WithReasonErr(err))
		return
	}

	// Client callback URL  must be one of the allowed ones.
	if !slices.Contains(h.config.AllowedRedirectURLs, clientCallbackURL) {
		slog.ErrorContext(ctx, "request contains unknown redirect_url")
		httputils.WriteErr(w, errUnknownRedirectURL)
		return
	}

	// Select provider as per the given name.
	provider := h.providerByName(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "provider is not implemented", "provider", providerName)
		httputils.WriteErr(w, errUnsupportedProvider)
		return
	}

	// Generate the "state" parameter for CSRF protection.
	state := uuid.NewString()
	// Generate code verifier and challenge for PKCE (Proof Key for Code Exchange).
	codeVerifier, codeChallenge := getPKCE()
	// Persist contextual info. This will be required upon callback.
	h.stateInfoMap.Store(state, stateInfo{
		CodeVerifier:      codeVerifier,
		ClientCallbackURL: clientCallbackURL,
	})

	// Expire the state after some time.
	go func() {
		// Don't use the HTTP request's context here.
		ctx := context.Background()
		// Allow the provider some time to invoke the callback API before timing out the flow.
		time.Sleep(stateExpiry)

		// Expire state with apt logs.
		slog.InfoContext(ctx, "expiring state", "state", state)
		if _, present := h.stateInfoMap.LoadAndDelete(state); !present {
			slog.InfoContext(ctx, "state utilized before expiry", "state", state)
			return
		}
		slog.WarnContext(ctx, "state expired", "state", state)
	}()

	// Get the Auth URL of the provider.
	authURL := provider.GetAuthURL(ctx, state, codeChallenge)
	// Response headers.
	headers := map[string]string{"Location": authURL}
	// Redirect.
	httputils.Write(w, http.StatusFound, headers, nil)
}

// stateInfo holds all contextual info for an OAuth flow.
type stateInfo struct {
	// CodeVerifier is for PKCE (Proof Key for Code Exchange).
	CodeVerifier string
	// ClientCallbackURL is the URL where the OAuth flow is supposed to end.
	ClientCallbackURL string
}

// getPKCE returns the code verifier and the code challenge for PKCE (Proof Key for Code Exchange).
func getPKCE() (string, string) {
	codeVerifier := fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String())
	codeVerifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeVerifierHash[:])
	return codeVerifier, codeChallenge
}
