package handler

import (
	"net/http"
	"slices"
	"sync"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// Handler encapsulates all REST handlers.
type Handler struct {
	config config.Config

	// stateMap maps state keys to state values.
	// Its role is to defend against CSRF attacks as well as persist an OAuth flow's contextual info.
	stateMap *sync.Map

	googleProvider  oauth.Provider
	discordProvider oauth.Provider
}

// NewHandler creates a new Handler instance.
func NewHandler(config config.Config, google, discord oauth.Provider) *Handler {
	return &Handler{
		config:          config,
		stateMap:        &sync.Map{},
		googleProvider:  google,
		discordProvider: discord,
	}
}

// NotFound handler can be used to serve any unrecognized routes.
func (h *Handler) NotFound(w http.ResponseWriter, r *http.Request) {
	httputils.WriteErr(w, errutils.NotFound())
}

// Health returns 200 if everything is running fine.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	info := map[string]string{}
	httputils.Write(w, http.StatusOK, nil, info)
}

// providerByName returns the provider for the given name.
func (h *Handler) providerByName(providerName string) oauth.Provider {
	switch providerName {
	case h.googleProvider.Name():
		return h.googleProvider
	// More cases would come here as more providers are implemented.
	default:
		return nil
	}
}

// providerByIssuer returns the provider for the given token issuer.
func (h *Handler) providerByIssuer(issuer string) oauth.Provider {
	if slices.Contains(h.googleProvider.Issuers(), issuer) {
		return h.googleProvider
	}
	// More cases would come here as more providers are implemented.
	return nil
}
