package mongodb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shivanshkc/authorizer/src/configs"
	"github.com/shivanshkc/authorizer/src/logger"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	clientOnce      = &sync.Once{}
	clientSingleton *mongo.Client
)

// getClient returns the MongoDB client singleton.
func getClient() *mongo.Client {
	// We initialize the client only once.
	clientOnce.Do(func() {
		// Prerequisites.
		ctx := context.Background()

		logger.Info(ctx, "attempting connection with mongodb")
		clientSingleton = getClientOnce()
		logger.Info(ctx, "connected with mongodb")
	})

	return clientSingleton
}

// getClientOnce is a pure function (except for configs) to generate a MongoDB client.
func getClientOnce() *mongo.Client {
	conf := configs.Get()
	connectOpts := options.Client().ApplyURI(conf.Mongo.Addr)

	// Creating the client object.
	client, err := mongo.NewClient(connectOpts)
	if err != nil {
		panic(fmt.Errorf("failed to create mongodb client: %w", err))
	}

	// Creating timeout context for the "Connect" call.
	timeoutDuration := time.Duration(conf.Mongo.OperationTimeoutSec) * time.Second
	connectCtx, connectCancelFunc := context.WithTimeout(context.Background(), timeoutDuration)
	// Cancelling context upon function return.
	defer connectCancelFunc()

	// Attempting connection with MongoDB.
	if err := client.Connect(connectCtx); err != nil {
		panic(fmt.Errorf("failed to connect to mongodb: %w", err))
	}

	// Creating timeout context for the "Ping" call.
	pingCtx, pingCancelFunc := context.WithTimeout(context.Background(), timeoutDuration)
	defer pingCancelFunc()

	// Pinging the DB to make sure the connection is okay.
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		panic(fmt.Errorf("failed to ping mongodb: %w", err))
	}

	return client
}
