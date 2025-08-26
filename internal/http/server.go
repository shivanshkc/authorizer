package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/handler"
	"github.com/shivanshkc/authorizer/internal/middleware"
)

// Server is the HTTP server of this application.
type Server struct {
	Config     config.Config
	Middleware middleware.Middleware
	Handler    *handler.Handler

	httpServer *http.Server
}

// Start sets up all the dependencies and routes on the server, and calls ListenAndServe on it.
func (s *Server) Start() error {
	addr := s.Config.HTTPServer.Addr

	// Create the HTTP server.
	s.httpServer = &http.Server{Addr: addr, ReadHeaderTimeout: time.Minute, Handler: s.handler()}

	slog.Info("Starting HTTP server", "name", s.Config.Application.Name, "addr", s.Config.HTTPServer.Addr)
	// Start the HTTP server.
	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("error in ListenAndServe call: %w", err)
	}

	return nil
}

// Shutdown initiates a graceful shutdown of the HTTP server.
//
// It does not return any errors, only logs them.
func (s *Server) Shutdown(ctx context.Context) {
	// In case the application initiates a shutdown before the server is even initialized.
	// This may be because of a sudden SIGINT (ctrl+c).
	if s.httpServer == nil {
		slog.Info("HTTP server found nil")
		return
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		slog.Error("Error in Shutdown call", "err", err)
	} else {
		slog.Info("HTTP server shutdown successful")
	}
}

// registerRoutes attaches middleware and REST methods to the server.
func (s *Server) handler() http.Handler {
	router := mux.NewRouter()

	// Attach middleware.
	router.Use(s.Middleware.Recovery)
	router.Use(s.Middleware.CORS)
	router.Use(s.Middleware.AccessLogger)
	router.Use(s.Middleware.Security)

	// Heath check route.
	router.HandleFunc("/api", s.Handler.Health).Methods(http.MethodGet)
	router.HandleFunc("/api/health", s.Handler.Health).Methods(http.MethodGet)

	// Endpoint to check if a request is authenticated.
	router.HandleFunc("/api/check", s.Handler.Check).Methods(http.MethodGet)
	// Endpoint to initiate the OAuth flow.
	router.HandleFunc("/api/auth/{provider}", s.Handler.Auth).Methods(http.MethodGet)
	// Callback endpoint for a provider.
	router.HandleFunc("/api/auth/{provider}/callback", s.Handler.Callback).Methods(http.MethodGet)

	// All remaining routes result in 404.
	router.PathPrefix("/").HandlerFunc(s.Handler.NotFound)

	return router
}
