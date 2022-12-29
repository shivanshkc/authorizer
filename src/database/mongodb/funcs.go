package mongodb

import (
	"context"
	"time"

	"github.com/shivanshkc/authorizer/src/configs"

	"go.mongodb.org/mongo-driver/mongo"
)

const (
	// usersCollName is the name of the collection that holds user records.
	usersCollName = "users"
)

// GetUsersColl provides the collection that holds user documents.
func GetUsersColl() *mongo.Collection {
	conf := configs.Get()
	return getClient().Database(conf.Mongo.DatabaseName).Collection(usersCollName)
}

// GetTimeoutContext provides the timeout context for database operations.
func GetTimeoutContext(parent context.Context) (context.Context, context.CancelFunc) {
	conf := configs.Get()
	timeoutDuration := time.Duration(conf.Mongo.OperationTimeoutSec) * time.Second
	// Create and returning context.
	return context.WithTimeout(parent, timeoutDuration)
}
