package database

import (
	"go.mongodb.org/mongo-driver/mongo"
)

// UserDB encapsulates all user collection methods.
type UserDB struct {
	client *mongo.Client //nolint:unused // Will be used soon.
}

// UserDoc is the schema of a user's info in the database.
type UserDoc struct {
	ID          string `json:"_id" bson:"_id"`
	Email       string `json:"email" bson:"email"`
	FirstName   string `json:"first_name" bson:"first_name"`
	LastName    string `json:"last_name" bson:"last_name"`
	PictureLink string `json:"picture_link" bson:"picture_link"`
}
