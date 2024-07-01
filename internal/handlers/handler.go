package handlers

import (
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// Handler encapsulates all API handler functions.
type Handler struct {
	Providers map[string]oauth.Provider
}
