package database

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserDoc is the schema of a user's info in the database.
type UserDoc struct {
	ID          primitive.ObjectID `json:"_id" bson:"_id"`
	Email       string             `json:"email" bson:"email"`
	FirstName   string             `json:"first_name" bson:"first_name"`
	LastName    string             `json:"last_name" bson:"last_name"`
	PictureLink string             `json:"picture_link" bson:"picture_link"`
}

// UserDB encapsulates all user collection methods.
type UserDB struct {
	Client *mongo.Client //nolint:unused // Will be used soon.
}

// SetUser sets the given userDoc in the database.
func (u *UserDB) SetUser(ctx context.Context, userDoc UserDoc) error {
	return nil
}

// GetUser gets a user from the database.
func (u *UserDB) GetUser(ctx context.Context, userID primitive.ObjectID) (UserDoc, error) {
	return UserDoc{}, nil
}
