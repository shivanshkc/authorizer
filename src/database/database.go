package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/database/mongodb"
	"github.com/shivanshkc/authorizer/src/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// UserDB implements core.UserDatabase using mongodb.
type UserDB struct{}

// NewUserDB is the constructor for UserDB.
func NewUserDB() core.UserDatabase {
	// Initiate database connection at startup.
	_ = mongodb.GetUsersColl()
	// Create new instance and return.
	return &UserDB{}
}

func (u *UserDB) SetUser(ctx context.Context, userDoc *core.UserDoc) error {
	// Prerequisites.
	filter := bson.M{"_id": userDoc.ID}
	update := bson.M{"$set": userDoc}
	opts := options.Update().SetUpsert(true)

	// Get timeout context for the database call.
	dbCtx, cancelFunc := mongodb.GetTimeoutContext(ctx)
	defer cancelFunc()

	// Database call.
	if _, err := mongodb.GetUsersColl().UpdateOne(dbCtx, filter, update, opts); err != nil {
		// Unexpected error.
		err = fmt.Errorf("error in UpdateOne call: %w", err)
		logger.Error(ctx, err.Error())
		return err
	}

	return nil
}

func (u *UserDB) GetUser(ctx context.Context, userID string) (*core.UserDoc, error) {
	// Get timeout context for the database call.
	dbCtx, cancelFunc := mongodb.GetTimeoutContext(ctx)
	defer cancelFunc()

	// Database call.
	result := mongodb.GetUsersColl().FindOne(dbCtx, bson.M{"_id": userID})
	if result.Err() != nil {
		// Handle recognized errors.
		if errors.Is(result.Err(), mongo.ErrNoDocuments) {
			return nil, core.ErrUserNotFound
		}

		// Unexpected error.
		err := fmt.Errorf("error in FindOne call: %w", result.Err())
		logger.Error(ctx, err.Error())
		return nil, err
	}

	// Decode the result into a user document.
	userDoc := &core.UserDoc{}
	if err := result.Decode(userDoc); err != nil {
		// Unexpected error.
		err = fmt.Errorf("error in Decode call: %w", err)
		logger.Error(ctx, err.Error())
		return nil, err
	}

	return userDoc, nil
}
