package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

var (
	errMissingRedirectURL    = errutils.BadRequest().WithReasonStr("redirect_url is missing")
	errUnknownRedirectURL    = errutils.BadRequest().WithReasonStr("redirect_url is not allowed")
	errUnsupportedProvider   = errutils.BadRequest().WithReasonStr("provider is not supported")
	errUnimplementedProvider = errutils.BadRequest().WithReasonStr("provider is not implemented")
)

// Redirect the caller to the specified provider's authentication page.
func (h *Handler) Redirect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Provider is a path parameter and so it will always be present.
	providerName := mux.Vars(r)["provider"]
	// Once authentication is done, the flow will end on this URL.
	clientCallbackURL := r.URL.Query().Get("redirect_url")

	// Client callback URL must be present.
	if clientCallbackURL == "" {
		slog.ErrorContext(ctx, "request has no redirect_url")
		httputils.WriteErr(w, errMissingRedirectURL)
		return
	}

	// client callback URI must be one of the allowed ones.
	if !slices.Contains(h.config.AllowedRedirectURLs, clientCallbackURL) {
		slog.ErrorContext(ctx, "request contains unknown redirect_url")
		httputils.WriteErr(w, errUnknownRedirectURL)
		return
	}

	// Select provider as per the given name.
	var provider oauth.Provider
	switch providerName {
	case h.googleProvider.Name():
		provider = h.googleProvider
	case h.discordProvider.Name():
		slog.ErrorContext(ctx, "provider is not implemented", "provider", providerName)
		httputils.WriteErr(w, errUnimplementedProvider)
		return
	default:
		slog.ErrorContext(ctx, "request contains unsupported provider", "provider", providerName)
		httputils.WriteErr(w, errUnsupportedProvider)
		return
	}

	// Obtain the OAuth "state" parameter.
	state := encodeState(clientCallbackURL)
	// Get the redirect URL.
	redirectURL := provider.GetRedirectURL(ctx, state)
	// Redirect the caller.
	httputils.Write(w, http.StatusFound, map[string]string{"Location": redirectURL}, nil)
}

// oAuthState is encoded and used as the "state" parameter during the OAuth flow.
type oAuthState struct {
	// salt keeps the state unique.
	Salt              string
	ClientCallbackURL string
}

// encodeState combines the given clientCallbackURL with a salt to create a unique state string.
func encodeState(clientCallbackURL string) string {
	s, _ := json.Marshal(oAuthState{ClientCallbackURL: clientCallbackURL, Salt: uuid.New().String()})
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
