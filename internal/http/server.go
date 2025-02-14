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
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// Server is the HTTP server of this application.
type Server struct {
	Config     config.Config
	Middleware Middleware
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
func (s *Server) Shutdown() {
	if err := s.httpServer.Shutdown(context.Background()); err != nil {
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

	// Sample REST method.
	router.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		httputils.Write(w, http.StatusNoContent, nil, nil)
	}).Methods(http.MethodGet)

	// More API routes here...

	// Handle 404.
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputils.WriteErr(w, errutils.NotFound())
	})

	return router
}
