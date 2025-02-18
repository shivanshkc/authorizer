package handler

import (
	"net/http"
	"sync"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// Handler encapsulates all REST handlers.
type Handler struct {
	config   config.Config
	stateIDs *sync.Map

	googleProvider  oauth.Provider
	discordProvider oauth.Provider
}

// NewHandler creates a new Handler instance.
func NewHandler(config config.Config, google, discord oauth.Provider) *Handler {
	return &Handler{
		config:          config,
		stateIDs:        &sync.Map{},
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

// getProvider returns the provider for the given name.
func (h *Handler) getProvider(providerName string) oauth.Provider {
	switch providerName {
	case h.googleProvider.Name():
		return h.googleProvider
	// More cases would come here as more providers are implemented.
	default:
		return nil
	}
}
