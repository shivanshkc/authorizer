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
	// Root application context.
	ctx, ctxCancel := context.WithCancel(context.Background())

	// Initialize basic dependencies.
	conf := config.Load()
	logger.Init(os.Stdout, conf.Logger.Level, conf.Logger.Pretty)

	// Connect to database.
	database, err := sql.Open("pgx", fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable",
		conf.Database.Username, conf.Database.Password, conf.Database.Addr, conf.Database.Database))
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

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

	// Handle interruptions like SIGINT.
	signals.OnSignal(func(_ os.Signal) {
		slog.Info("Interruption detected, attempting graceful shutdown...")
		// Execute all interruption handling here, like HTTP server shutdown, database connection closing etc.
		ctxCancel()
		_ = database.Close()
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
