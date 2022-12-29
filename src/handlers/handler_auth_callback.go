package handlers

import (
	"net/http"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

// AuthCallbackHandler handles the OAuth callbacks.
func AuthCallbackHandler(writer http.ResponseWriter, req *http.Request) {
	// Obtain params from the request.
	provider, code := mux.Vars(req)["provider"], req.URL.Query().Get("code")

	// Core call.
	if err := core.OAuthCallback(req.Context(), provider, code, writer); err != nil {
		httputils.WriteErr(writer, err)
	}
}
