package handlers

import (
	"net/http"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

// GetUserHandler handles the Get-User calls.
func GetUserHandler(writer http.ResponseWriter, req *http.Request) {
	// Obtain user ID from the path params.
	userID := mux.Vars(req)["user_id"]

	// Fetch user's document.
	userDoc, err := core.GetUser(req.Context(), userID)
	if err != nil {
		httputils.WriteErr(writer, err)
		return
	}

	// Success.
	httputils.Write(writer, http.StatusOK, nil, userDoc)
}
