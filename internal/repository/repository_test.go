package repository

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err, "Failed to create mock DB")
	// Close upon return.
	defer func() { _ = db.Close() }()

	// Test repo creation.
	repo := NewRepository(db)
	require.NotNil(t, repo, "Repository is nil")
}

func TestUpsertUser(t *testing.T) {
	// Common mock params for testing.
	mUser := User{Email: "test@hey.com", GivenName: "John", FamilyName: "Doe", PictureURL: "https://hey.com/pic.jpg"}
	mQuery, mArgs := upsertUserQuery(mUser)
	mQuery = regexp.QuoteMeta(mQuery)

	for _, tc := range []struct {
		name        string
		mockFunc    func(mock sqlmock.Sqlmock)
		errExpected bool
	}{
		{
			name: "Successful insert, no errors.",
			mockFunc: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(mQuery).
					WithArgs(mArgs[0], mArgs[1], mArgs[2], mArgs[3]).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			errExpected: false,
		},
		{
			name: "Successful update, no errors.",
			mockFunc: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(mQuery).
					WithArgs(mArgs[0], mArgs[1], mArgs[2], mArgs[3]).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			errExpected: false,
		},
		{
			name: "Database returns error, error expected.",
			mockFunc: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(mQuery).
					WithArgs(mArgs[0], mArgs[1], mArgs[2], mArgs[3]).
					WillReturnError(sql.ErrConnDone)
			},
			errExpected: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create a new mock database for each test.
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "Failed to create mock DB")
			// Close upon return.
			defer func() { _ = db.Close() }()

			// Set up the mock expectations.
			tc.mockFunc(mock)
			// Create a new repository with the mock DB.
			repo := NewRepository(db)

			// Execute the test.
			err = repo.UpsertUser(context.Background(), mUser)

			// Check the results.
			if tc.errExpected {
				require.Error(t, err, "UpsertUser should have returned an error")
			} else {
				require.NoError(t, err, "UpsertUser should not have returned an error")
			}

			// Ensure all expectations were met.
			err = mock.ExpectationsWereMet()
			require.NoError(t, err, "Expectations were not met")
		})
	}
}
