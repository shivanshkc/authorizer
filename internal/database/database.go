package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
)

// usersCollectionName is the name of the collection that holds user records.
const usersCollectionName = "users"

// UserDoc is the schema of a user's info in the database.
type UserDoc struct {
	ID primitive.ObjectID `json:"_id" bson:"_id"`

	Email       string `json:"email" bson:"email"`
	FirstName   string `json:"first_name" bson:"first_name"`
	LastName    string `json:"last_name" bson:"last_name"`
	PictureLink string `json:"picture_link" bson:"picture_link"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// UserDB encapsulates all user collection methods.
type UserDB struct {
	client     *mongo.Client
	collection *mongo.Collection
}

// NewUserDB returns a new *UserDB instance.
func NewUserDB(conf config.Config, client *mongo.Client) *UserDB {
	collection := client.Database(conf.Mongo.DatabaseName).Collection(usersCollectionName)
	return &UserDB{client: client, collection: collection}
}

func (u *UserDB) SetUser(ctx context.Context, userDoc UserDoc) error {
	// This defines the entire update operation for both insertion and update cases.
	update := bson.M{
		// If the document is being inserted
		"$setOnInsert": bson.M{
			"email":      userDoc.Email,
			"created_at": time.Now(),
		},
		// If the document is only being updated (email and created_at will not be changed)
		"$set": bson.M{
			"first_name":   userDoc.FirstName,
			"last_name":    userDoc.LastName,
			"picture_link": userDoc.PictureLink,
			"updated_at":   time.Now(), // Only change "updated_at", not "created_at"
		},
	}

	// Allow upsert.
	opts := options.Update().SetUpsert(true)
	// Run query.
	result, err := u.collection.UpdateOne(ctx, bson.M{"email": userDoc.Email}, update, opts)
	if err != nil {
		return fmt.Errorf("error in UpdateOne call: %w", err)
	}

	if result.MatchedCount > 0 {
		slog.InfoContext(ctx, "user document updated", "email", userDoc.Email)
	} else if result.UpsertedCount > 0 {
		slog.InfoContext(ctx, "user document inserted", "email", userDoc.Email)
	}

	return nil
}

// GetUser gets a user from the database.
func (u *UserDB) GetUser(ctx context.Context, userID primitive.ObjectID) (UserDoc, error) {
	// Run query.
	result := u.collection.FindOne(ctx, bson.M{"_id": userID})
	if err := result.Err(); err != nil {
		// Handle 404.
		if errors.Is(err, mongo.ErrNoDocuments) {
			return UserDoc{}, errutils.NotFound()
		}
		// Unexpected error.
		return UserDoc{}, fmt.Errorf("error in FindOne call: %w", err)
	}

	// Decode result.
	var userDoc UserDoc
	if err := result.Decode(&userDoc); err != nil {
		return UserDoc{}, fmt.Errorf("failed to decode user doc: %w", err)
	}

	return userDoc, nil
}

// CreateIndices creates all required database indices.
func (u *UserDB) CreateIndices(ctx context.Context) error {
	// Define.
	indexModel := mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}}

	// Create.
	if _, err := u.collection.Indexes().CreateOne(ctx, indexModel); err != nil {
		return fmt.Errorf("failed to create indiex: %w", err)
	}

	return nil
}
