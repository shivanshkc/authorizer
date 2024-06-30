package handlers

import (
	"net/http"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/utils/errutils"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

// AuthRedirectHandler handles the OAuth redirection calls.
func AuthRedirectHandler(writer http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// The provider to use for auth.
	provider := mux.Vars(req)["provider"]
	// The final redirect URI after successful authentication.
	clientRedirectURI := req.URL.Query().Get("redirect_uri")
	if clientRedirectURI == "" {
		httputils.WriteErr(writer, errutils.BadRequest().WithReasonStr("redirect_uri is required"))
		return
	}

	// Redirection.
	providerRedirectURI, err := core.GetProviderRedirectURI(ctx, provider, clientRedirectURI)
	if err != nil {
		httputils.WriteErr(writer, err)
		return
	}

	// Location header is required for redirection in the browser.
	headers := map[string]string{"Location": providerRedirectURI}
	// Write response.
	httputils.Write(writer, http.StatusFound, headers, nil)
}
