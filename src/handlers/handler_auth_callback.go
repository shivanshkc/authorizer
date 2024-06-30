package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/logger"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

// AuthCallbackHandler handles the OAuth callbacks.
func AuthCallbackHandler(writer http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Obtain params from the request.
	provider := mux.Vars(req)["provider"]
	code, state := req.URL.Query().Get("code"), req.URL.Query().Get("state")

	// Decode the state parameter to obtain the client redirect URI.
	decoded, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		logger.Error(ctx, "failed to decode state: %v", err)
		return
	}

	// Core call.
	if err := core.OAuthCallback(ctx, provider, code, string(decoded), writer); err != nil {
		httputils.WriteErr(writer, err)
	}
}
