package handlers

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// errMissingRedirectURI is returned when the request contains no redirect URI.
var errMissingRedirectURI = errutils.BadRequest().WithReasonStr("redirect_uri is missing")

// errUnsupportedProvider is returned when the request specifies an unsupported oauth provider.
var errUnsupportedProvider = errutils.BadRequest().WithReasonStr("provider is not supported")

// Redirect takes the user to the provider's authentication page.
func (h Handler) Redirect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Provider is a path parameter, and so, it will always be present.
	providerName := mux.Vars(r)["provider"]

	// Once authentication is done, the flow will end on this URL.
	clientCallbackURI := r.URL.Query().Get("redirect_uri")
	if clientCallbackURI == "" {
		slog.ErrorContext(ctx, "request has no redirect_uri")
		httputils.WriteErr(w, errMissingRedirectURI)
		return
	}

	// Obtain the required provider.
	provider, exists := h.Providers[providerName]
	if !exists {
		slog.ErrorContext(ctx, "request contains unsupported provider", "provider", providerName)
		httputils.WriteErr(w, errUnsupportedProvider)
		return
	}

	// Encode the client callback URI to base64 as it needs to be query-param compatible.
	state := base64.StdEncoding.EncodeToString([]byte(clientCallbackURI))

	// Get the redirect URI.
	redirectURI := provider.GetRedirectURL(r.Context(), state)
	// Redirect the caller.
	httputils.Write(w, http.StatusFound, map[string]string{"Location": redirectURI}, nil)
}
