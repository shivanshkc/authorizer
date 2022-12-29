package core

import (
	"errors"
)

var (
	// ErrProviderNotFound is returned when the required provider is not supported.
	ErrProviderNotFound = errors.New("provider not found")
	// ErrUserNotFound is returned when the required user document is not present in the database.
	ErrUserNotFound = errors.New("user not found")
)

// UserDoc is the schema of the user document as saved in the database.
type UserDoc struct {
	ID          string `json:"_id" bson:"_id"`
	Email       string `json:"email" bson:"email"`
	FirstName   string `json:"first_name" bson:"first_name"`
	LastName    string `json:"last_name" bson:"last_name"`
	PictureLink string `json:"picture_link" bson:"picture_link"`
}
