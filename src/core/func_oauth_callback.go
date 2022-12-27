package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/shivanshkc/authorizer/src/utils/httputils"
)

// OAuthCallback handles the callback received from the provider.
func OAuthCallback(ctx context.Context, provider string, code string, writer http.ResponseWriter) error {
	// Obtain the required provider from the map.
	oAuthProvider, exists := ProviderMap[provider]
	if !exists {
		errorRedirect(writer, ErrProviderNotFound, http.StatusNotFound)
		return nil
	}

	// Convert OAuth code to identity token.
	token, err := oAuthProvider.Code2Token(ctx, code)
	if err != nil {
		errorRedirect(writer, err, http.StatusInternalServerError)
		return nil
	}

	// Obtain user's information from the token.
	userInfo, err := oAuthProvider.Token2UserInfo(ctx, token)
	if err != nil {
		errorRedirect(writer, err, http.StatusInternalServerError)
		return nil
	}

	// Persist user's document in the database for later usage.
	// For now, this call is allowed to fail. So, we ignore the error.
	go func() {
		// User ID is nothing but the SHA of their email.
		userInfo.ID = sha256Hex(userInfo.Email)
		_ = UserDB.InsertUser(ctx, userInfo)
	}()

	// Success redirect URL.
	redirectURL := fmt.Sprintf("%s?id_token=%s&provider=%s", ClientCallbackURL, token, provider)
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(writer, http.StatusFound, headers, nil)

	return nil
}

// errorRedirect redirects the client in case of an error.
func errorRedirect(writer http.ResponseWriter, err error, status int) {
	redirectURL := fmt.Sprintf("%s?error=%s", ClientCallbackURL, err.Error())
	headers := map[string]string{"Location": redirectURL}
	httputils.Write(writer, status, headers, nil)
}

// sha256Hex provides the hex encoded SHA256 of the input.
func sha256Hex(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
