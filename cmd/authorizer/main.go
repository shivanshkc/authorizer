package main

import (
	"log/slog"
	"os"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/http"
	"github.com/shivanshkc/authorizer/internal/logger"
	"github.com/shivanshkc/authorizer/pkg/signals"
)

func main() {
	// Initialize basic dependencies.
	conf := config.Load()
	logger.Init(os.Stdout, conf.Logger.Level, conf.Logger.Pretty)

	// Initialize the HTTP server.
	server := &http.Server{Config: conf, Middleware: http.Middleware{}}

	// Handle interruptions like SIGINT.
	signals.OnSignal(func(_ os.Signal) {
		slog.Info("Interruption detected, attempting graceful shutdown...")
		// Execute all interruption handling here, like HTTP server shutdown, database connection closing etc.
		server.Shutdown()
	})

	// Block until all actions are executed.
	defer signals.Wait()

	// This internally calls ListenAndServe.
	// This is a blocking call and will panic if the server is unable to start.
	if err := server.Start(); err != nil {
		panic("error in server.Start call: " + err.Error())
	}
}
