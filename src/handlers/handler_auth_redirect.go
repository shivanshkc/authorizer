package handlers

import (
	"net/http"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

// AuthRedirectHandler handles the OAuth redirection calls.
func AuthRedirectHandler(writer http.ResponseWriter, req *http.Request) {
	// Get provider from the request route params.
	provider := mux.Vars(req)["provider"]

	// Redirection.
	if err := core.OAuthRedirect(req.Context(), provider, writer); err != nil {
		httputils.WriteErr(writer, err)
	}
}
