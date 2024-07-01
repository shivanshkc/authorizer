package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// errBadUserID is the returned error for an invalid user ID.
var errBadUserID = errutils.BadRequest().WithReasonStr("invalid user ID")

// GetUser serves the specified user's info.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// ID is a path parameter, so it will always be present.
	userIDStr := mux.Vars(r)["id"]

	// Parse the User ID.
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		slog.ErrorContext(ctx, "invalid user id", "id", userIDStr)
		httputils.WriteErr(w, errBadUserID)
		return
	}

	// Fetch the details.
	userDoc, err := h.UserDB.GetUser(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error in GetUser call", "err", err)
		httputils.WriteErr(w, err)
		return
	}

	// Success.
	httputils.Write(w, http.StatusOK, nil, userDoc)
}
