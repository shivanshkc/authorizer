package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/database"
	"github.com/shivanshkc/authorizer/pkg/oauth"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// Callback handles the provider's callback and then finally redirects back to the client's callback URI.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Obtain params from the request.
	providerName := mux.Vars(r)["provider"]
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")

	// Decode the state parameter to obtain the client redirect URI.
	ccuBytes, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		slog.ErrorContext(ctx, "failed to decode state", "err", err)
		// Since we have nothing to redirect to, the flow ends here.
		return
	}

	// The flow will end on this URI.
	clientCallbackURI := string(ccuBytes)

	// Obtain the required provider.
	provider, exists := h.Providers[providerName]
	if !exists {
		slog.ErrorContext(ctx, "request contains unsupported provider, HOW?", "provider", providerName)
		errorRedirect(w, errutils.InternalServerError(), clientCallbackURI)
		return
	}

	// Convert the code to access token.
	accessToken, err := provider.TokenFromCode(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "failed to convert provider code to token", "err", err)
		errorRedirect(w, fmt.Errorf("failed to convert code to token: %w", err), clientCallbackURI)
		return
	}

	// Save the logged-in user's info in the database.
	go fetchAndSaveUser(context.Background(), provider, accessToken, h.UserDB)

	// Success redirect URL.
	// We don't need to verify the token in this flow since it is coming directly from the provider.
	redirectURL := fmt.Sprintf("%s?id_token=%s&provider=%s", clientCallbackURI, accessToken, providerName)
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(w, http.StatusFound, headers, nil)
}

// fetchAndSaveUser fetches the user's data from the given provider using the given access token and sets it in the db.
func fetchAndSaveUser(ctx context.Context, provider oauth.Provider, token string, userDB *database.UserDB) {
	// Obtain user's information from the token.
	claims, err := provider.ValidateToken(ctx, token)
	if err != nil {
		slog.ErrorContext(ctx, "failed to validate token", "err", err)
		return
	}

	userDoc := database.UserDoc{
		Email:       claims.Email,
		FirstName:   claims.GivenName,
		LastName:    claims.FamilyName,
		PictureLink: claims.PictureLink,
	}

	// Persist user's document in the database for later usage.
	if err := userDB.SetUser(ctx, userDoc); err != nil {
		slog.ErrorContext(ctx, "failed to set user in the database", "err", err)
	}
}

// errorRedirect redirects the client in case of an error.
func errorRedirect(w http.ResponseWriter, err error, uri string) {
	redirectURL := fmt.Sprintf("%s?error=%s", uri, err.Error())
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(w, http.StatusFound, headers, nil)
}
