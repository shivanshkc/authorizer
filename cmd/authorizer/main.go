package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/shivanshkc/authorizer/internal/database"
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

	// Connect with the database.
	mongoClient, err := connectDB(conf)
	if err != nil {
		slog.Error("failed to connect with database")
		panic(err)
	}

	// Create the database object and indices.
	userDB := database.NewUserDB(conf, mongoClient)
	if err := userDB.CreateIndices(context.Background()); err != nil {
		slog.Error("failed to create indices in the database")
		panic(err)
	}

	// Instantiate all OAuth providers.
	googleProvider := oauth.NewGoogleProvider(conf)

	// Instantiate the API handlers.
	handler := &handlers.Handler{
		UserDB:    userDB,
		Providers: map[string]oauth.Provider{googleProvider.Name(): googleProvider},
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

// connectDB uses the given config to connect with MongoDB and returns the client.
func connectDB(conf config.Config) (*mongo.Client, error) {
	// Connect.
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(conf.Mongo.Addr))
	if err != nil {
		return nil, fmt.Errorf("failed to connect with database: %w", err)
	}

	// Ping to check connection.
	if err := client.Ping(context.Background(), readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("Connected with database")
	return client, nil
}
