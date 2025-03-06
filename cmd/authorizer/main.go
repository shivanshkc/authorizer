package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/handler"
	"github.com/shivanshkc/authorizer/internal/http"
	"github.com/shivanshkc/authorizer/internal/logger"
	"github.com/shivanshkc/authorizer/internal/middleware"
	"github.com/shivanshkc/authorizer/internal/repository"
	"github.com/shivanshkc/authorizer/pkg/oauth"
	"github.com/shivanshkc/authorizer/pkg/signals"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// googleScopes for OAuth with Google.
const googleScopes = "https://www.googleapis.com/auth/userinfo.email " +
	"https://www.googleapis.com/auth/userinfo.profile"

func main() {
	// All signals.Xxx calls are for interruption (SIGINT, SIGTERM) handling.
	// Wait blocks until all actions (registered by signals.OnSignal) have executed.
	defer signals.Wait()
	// Manually trigger cleanup whenever main exits.
	// This MUST run before signals.Wait and so it is deferred after it.
	defer signals.Manual()

	// Root application context.
	ctx, ctxCancel := context.WithCancel(context.Background())
	// Cancel root context upon interruption or exit.
	signals.OnSignal(func(signal os.Signal) { ctxCancel(); slog.Info("Root context canceled") })

	// Initialize basic dependencies.
	conf := config.Load()
	logger.Init(os.Stdout, conf.Logger.Level, conf.Logger.Pretty)

	// Connect to database.
	database, err := sql.Open("pgx", fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable",
		conf.Database.Username, conf.Database.Password, conf.Database.Addr, conf.Database.Database))
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	// Close database upon interruption or exit.
	signals.OnSignal(func(signal os.Signal) { _ = database.Close(); slog.Info("Database connection closed") })

	// Instantiate the OAuth client for Google.
	gCallback := fmt.Sprintf("%s/api/auth/google/callback", conf.Application.BaseURL)
	gProvider, err := oauth.NewGoogle(ctx, conf.Google.ClientID, conf.Google.ClientSecret, gCallback, googleScopes)
	if err != nil {
		panic("failed to initialize google provider: " + err.Error())
	}

	// Initialize the HTTP server.
	server := &http.Server{
		Config:     conf,
		Middleware: middleware.Middleware{},
		Handler:    handler.NewHandler(conf, gProvider, nil, repository.NewRepository(database)),
	}

	// Shutdown server upon interruption or exit.
	signals.OnSignal(func(_ os.Signal) { server.Shutdown() })

	// This internally calls ListenAndServe.
	// This is a blocking call and will panic if the server is unable to start.
	if err := server.Start(); err != nil {
		panic("error in server.Start call: " + err.Error())
	}
}
