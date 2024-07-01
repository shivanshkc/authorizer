package main

import (
	"os"

	"github.com/shivanshkc/authorizer/internal/handlers"
	"github.com/shivanshkc/authorizer/internal/http"
	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/logger"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func main() {
	// Initialize basic dependencies.
	conf := config.Load()
	logger.Init(os.Stdout, conf.Logger.Level, conf.Logger.Pretty)

	// Instantiate all OAuth providers.
	googleProvider := oauth.NewGoogleProvider(conf)

	// Instantiate the API handlers.
	handler := &handlers.Handler{
		Providers: map[string]oauth.Provider{
			googleProvider.Name(): googleProvider,
			// More providers here...
		},
	}

	// Initialize the HTTP server.
	server := &http.Server{
		Config:     conf,
		Middleware: http.Middleware{},
		Handler:    handler,
	}

	// This internally calls ListenAndServe.
	// This is a blocking call and will panic if the server is unable to start.
	server.Start()
}
