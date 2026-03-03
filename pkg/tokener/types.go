package tokener

import (
	"context"
	"time"
)

// Repository encapsulates methods required store and manage refresh tokens in the database.
//
// Each refresh token entry is assumed to have 4 fields: tokenHash, expiresAt, revoked, userID.
type Repository interface {
	// Insert should insert a new (refresh) token entry in the database.
	// The new entry should have the given "userID" and "expiresAt".
	// The "revoked" field of the entry should be set to false.
	Insert(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error

	// Refresh should execute the following logic.
	//
	// Fetch the entry with the given "oldTokenHash".
	// If the entry is revoked or expired, revoke all tokens for the user.
	// Otherwise, mark the entry as revoked, and insert a new entry with "newTokenHash" for the user.
	Refresh(ctx context.Context, oldTokenHash, newTokenHash string, expiresAt time.Time) error

	// Revoke should mark the entry with the given "tokenHash" as revoked.
	Revoke(ctx context.Context, tokenHash string) error
}

// Claims is the info that can be put inside the access token.
type Claims struct {
	Iss string `json:"iss"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Sub string `json:"sub"`

	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
}
