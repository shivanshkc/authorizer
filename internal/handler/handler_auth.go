package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// stateIDExpiry is the max allowed time for a provider to invoke the callback API.
// If the provider is too late, the state ID will be expired and the flow will fail.
//
// This is a var and not a const so it can be modified for testing purposes.
var stateIDExpiry = time.Minute

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
	provider := h.getProvider(providerName)
	if provider == nil {
		slog.ErrorContext(ctx, "provider is not implemented", "provider", providerName)
		httputils.WriteErr(w, errUnsupportedProvider)
		return
	}

	// Create and persist the state ID for better CSRF protection.
	stateID := uuid.NewString()
	h.stateIDMap.Store(stateID, struct{}{})

	// Expire the state ID after some time.
	go func() {
		// Don't use the HTTP request's context here.
		ctx := context.Background()
		// Allow the provider some time to invoke the callback API before timing out the flow.
		time.Sleep(stateIDExpiry)

		// Expire state ID will apt logs.
		slog.InfoContext(ctx, "expiring state ID", "stateID", stateID)
		if _, present := h.stateIDMap.LoadAndDelete(stateID); !present {
			slog.InfoContext(ctx, "state ID utilized before expiry", "stateID", stateID)
			return
		}
		slog.WarnContext(ctx, "state ID expired", "stateID", stateID)
	}()

	// Obtain the OAuth "state" parameter.
	state := encodeState(stateID, clientCallbackURL)
	// Get the Auth URL of the provider.
	authURL := provider.GetAuthURL(ctx, state)

	// Response headers.
	// TODO: Add a common middleware for these headers.
	headers := map[string]string{
		"Location": authURL,
		// The following headers make sure that the browser is not allowed to render the page
		// in a <frame>, <iframe>, <embed> or <object> tag.
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	// Redirect.
	httputils.Write(w, http.StatusFound, headers, nil)
}

// oAuthState is encoded and used as the "state" parameter during the OAuth flow.
type oAuthState struct {
	// ID makes the state unique
	ID                string
	ClientCallbackURL string
}

// encodeState combines the given clientCallbackURL with a salt to create a unique state string.
func encodeState(id, clientCallbackURL string) string {
	s, _ := json.Marshal(oAuthState{ClientCallbackURL: clientCallbackURL, ID: id})
	return base64.StdEncoding.EncodeToString(s)
}

// decodeState decodes the given state to retrieve the originally encoded params (clientCallbackURL).
func decodeState(state string) (oAuthState, error) {
	// Base64 decode the state.
	structBytes, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return oAuthState{}, fmt.Errorf("failed to base64 decode state: %w", err)
	}

	var oState oAuthState
	if err := json.Unmarshal(structBytes, &oState); err != nil {
		return oAuthState{}, fmt.Errorf("error in json.Unmarshal call: %w", err)
	}

	return oState, nil
}
