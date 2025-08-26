package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/handler"
	"github.com/shivanshkc/authorizer/internal/http"
	"github.com/shivanshkc/authorizer/internal/logger"
	"github.com/shivanshkc/authorizer/internal/middleware"
	"github.com/shivanshkc/authorizer/internal/repository"
	"github.com/shivanshkc/authorizer/pkg/oauth"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// googleScopes for OAuth with Google.
const googleScopes = "https://www.googleapis.com/auth/userinfo.email " +
	"https://www.googleapis.com/auth/userinfo.profile"

func main() {
	// Root application context.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize basic dependencies.
	conf := config.Load()
	logger.Init(os.Stdout, conf.Logger.Level, conf.Logger.Pretty)

	// Setup the database.
	database, err := connectDatabaseAndRunMigrations(ctx, conf)
	if err != nil {
		panic("failed to connect database and run migrations: " + err.Error())
	}

	// Instantiate the OAuth client for Google.
	gCallback := fmt.Sprintf("%s/api/auth/google/callback", conf.Application.BaseURL)
	gProvider, err := oauth.NewGoogle(ctx, conf.Google.ClientID, conf.Google.ClientSecret, gCallback, googleScopes)
	if err != nil {
		cleanup(database, nil)
		panic("failed to initialize google provider: " + err.Error())
	}

	// Initialize the HTTP server.
	handlers := handler.NewHandler(conf, gProvider, nil, repository.NewRepository(database))
	server := &http.Server{Config: conf, Middleware: middleware.Middleware{}, Handler: handlers}

	// Start the server and unblock the main thread if it returns.
	go func() {
		if err := server.Start(); err != nil {
			slog.Error("Error in server.Start call:", "error", err)
		}
		cancel()
	}()

	<-ctx.Done()
	cleanup(database, server)
}

func connectDatabaseAndRunMigrations(ctx context.Context, conf config.Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable", conf.Database.Username,
		conf.Database.Password, conf.Database.Addr, conf.Database.Database)

	// Connect to database.
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// Verify connection.
	if err := database.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.InfoContext(ctx, "Successfully connected to the database", "addr", conf.Database.Addr)

	// Create a client to execute migrations.
	migrationClient, err := migrate.New("file://db/migrations", dsn)
	if err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("failed to create migration client: %w", err)
	}

	defer func() { _, _ = migrationClient.Close() }()

	// Run migrations.
	if err := migrationClient.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.InfoContext(ctx, "No migrations to run")
			return database, nil
		}
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	slog.InfoContext(ctx, "Successfully completed database migrations")
	return database, nil
}

func cleanup(database *sql.DB, server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if database != nil {
		_ = database.Close()
	}

	if server != nil {
		server.Shutdown(ctx)
	}
}
