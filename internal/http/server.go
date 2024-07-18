package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/gorilla/mux"

	"github.com/shivanshkc/authorizer/internal/handlers"
	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
	"github.com/shivanshkc/authorizer/pkg/utils/signals"
)

// Server is the HTTP server of this application.
type Server struct {
	Config     config.Config
	Middleware Middleware
	Handler    *handlers.Handler
	httpServer *http.Server
}

// Start sets up all the dependencies and routes on the server, and calls ListenAndServe on it.
func (s *Server) Start() {
	// Create the HTTP server.
	s.httpServer = &http.Server{
		Addr:              s.Config.HTTPServer.Addr,
		ReadHeaderTimeout: time.Minute,
		Handler:           s.getHandler(),
	}

	// Gracefully shut down upon interruption.
	signals.OnSignal(func(_ os.Signal) {
		slog.Info("interruption detected, gracefully shutting down the server")
		// Graceful shutdown.
		if err := s.httpServer.Shutdown(context.Background()); err != nil {
			slog.Error("failed to gracefully shutdown the server", "err", err)
		}
	})

	slog.Info("starting http server", "name", s.Config.Application.Name, "addr", s.Config.HTTPServer.Addr)
	// Start the HTTP server.
	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("error in ListenAndServe call", "err", err)
		panic(err)
	}
}

// registerRoutes attaches middleware and REST methods to the server.
func (s *Server) getHandler() http.Handler {
	router := mux.NewRouter()

	// Attach middleware.
	router.Use(s.Middleware.Recovery)
	router.Use(s.Middleware.CORS)
	router.Use(s.Middleware.AccessLogger)

	// Redirect route.
	router.HandleFunc("/api/auth/{provider}", s.Handler.Redirect).Methods(http.MethodGet)
	// Callback route.
	router.HandleFunc("/api/auth/{provider}/callback", s.Handler.Callback).Methods(http.MethodGet)

	// Endpoint to fetch the logged-in user's own information.
	// It can also be used to check the validity of an ID token.
	router.HandleFunc("/api/user", s.Handler.GetSelf).Methods(http.MethodGet, http.MethodHead)
	// Endpoint to fetch any user's data.
	router.HandleFunc("/api/user/{email}", s.Handler.GetUser).Methods(http.MethodGet)

	// Enable profiling if configured.
	if s.Config.Application.PProf {
		s.addProfilingRoutes(router)
	}

	// Handle 404.
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputils.WriteErr(w, errutils.NotFound())
	})

	return router
}

// addProfilingRoutes adds all the pprof routes to the router.
func (s *Server) addProfilingRoutes(router *mux.Router) {
	// Enable block profiling.
	runtime.SetBlockProfileRate(1)
	// Enable mutex profiling.
	runtime.SetMutexProfileFraction(1)

	// Manually add support for paths linked to by index page at /debug/pprof
	router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/debug/pprof/block", pprof.Handler("block"))

	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	router.HandleFunc("/debug/pprof", pprof.Index)

	slog.Info("pprof endpoints available at: /debug/pprof")
}
