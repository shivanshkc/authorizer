package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// User represents a single user in the database.
type User struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	PictureURL string `json:"picture_url"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// Repository encapsulates all operations available on the database.
type Repository interface {
	UpsertUser(ctx context.Context, user User) error
}

// repository implements Repository.
type repository struct {
	database *sql.DB
}

// NewRepository returns a new implementation of Repository.
func NewRepository(database *sql.DB) Repository {
	return &repository{database: database}
}

func (r *repository) UpsertUser(ctx context.Context, user User) error {
	// Form and execute query.
	query, args := upsertUserQuery(user)
	result, err := r.database.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("error in query execution: %w", err)
	}

	// Parameters for logging.
	id, _ := result.LastInsertId()
	af, _ := result.RowsAffected()

	slog.InfoContext(ctx, "user upserted successfully", "id", id, "rows-affected", af)
	return nil
}
