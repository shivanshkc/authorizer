package core

import (
	"context"
	"errors"
	"fmt"
)

// GetUser fetches the provided user's document from the database.
func GetUser(ctx context.Context, userID string) (*UserDoc, error) {
	// Fetch user's document from the database.
	userDoc, err := UserDB.GetUser(ctx, userID)
	if err != nil {
		// Handle recognized errors.
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		// Unexpected error.
		return nil, fmt.Errorf("error in UserDB.GetUser call: %w", err)
	}

	return userDoc, nil
}
