package main

import (
	"context"
	"net/http"
	"time"

	"github.com/shivanshkc/authorizer/src/configs"
	"github.com/shivanshkc/authorizer/src/logger"
	"github.com/shivanshkc/authorizer/src/middlewares"
	"github.com/shivanshkc/authorizer/src/utils/httputils"

	"github.com/gorilla/mux"
)

func main() {
	// Prerequisites.
	ctx, conf := context.Background(), configs.Get()

	// Creating the HTTP server.
	server := &http.Server{
		Addr:              conf.HTTPServer.Addr,
		Handler:           handler(),
		ReadHeaderTimeout: time.Minute,
	}

	// Logging HTTP server details.
	logger.Info(ctx, "%s http server starting at: %s", conf.Application.Name, conf.HTTPServer.Addr)

	// Starting the HTTP server.
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal(ctx, "failed to start the http server: %+v", err)
	}
}

// handler is responsible to handle all incoming HTTP traffic.
func handler() http.Handler {
	router := mux.NewRouter()

	// Attaching global middlewares.
	router.Use(middlewares.Recovery)
	router.Use(middlewares.AccessLogger)
	router.Use(middlewares.CORS)

	// REST API.
	router.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		httputils.Write(w, http.StatusOK, nil, nil)
	}).Methods(http.MethodGet)

	return router
}
