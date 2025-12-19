package authentication

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// RefreshRepository is the interface for persistance operations related to refresh tokens
type RefreshRepository interface {

	// RefreshExists checks if a refresh token exists in persistence by blind index
	RefreshExists(refreshIndex string) (bool, error)

	// FindUserRefresh finds a user refresh token by refresh token blind index
	FindUserRefresh(refreshIndex string) (*types.UserRefresh, error)

	// InsertUserRefresh inserts a new user refresh token record into persistence
	InsertUserRefresh(refresh types.UserRefresh) error

	// UpdateUserRefresh updates an existing user refresh token record in persistence
	// by blind index
	UpdateUserRefresh(refresh types.UserRefresh) error

	// DeleteUserRefresh deletes a user refresh token record from persistence by blind index
	DeleteUserRefresh(refreshIndex string) error
}

// NewRefreshRepository creates a new implementation of the RefreshRepository interface
// returning a pointer to the concrete implementation
func NewRefreshRepository(db *sql.DB) RefreshRepository {

	return &refreshRepository{
		db: db,
	}
}

var _ RefreshRepository = (*refreshRepository)(nil)

// refreshRepository is the concrete implementation of the RefreshRepository interface
type refreshRepository struct {
	db *sql.DB
}

// RefreshExists checks if a refresh token exists in persistence by blind index
func (r *refreshRepository) RefreshExists(refreshIndex string) (bool, error) {

	qry := `
		SELECT EXISTS (
			SELECT 1 
			FROM refresh 
			WHERE refresh_index = ?
		)`

	return data.SelectExists(r.db, qry, refreshIndex)
}

// FindUserRefresh finds a user refresh token by refresh token blind index
func (r *refreshRepository) FindUserRefresh(refreshIndex string) (*types.UserRefresh, error) {

	qry := `
		SELECT 
			uuid, 
			refresh_index,
			client_id, 
			refresh_token, 
			username,
			username_index,
			scopes,
			created_at,
			revoked
		FROM refresh 
		WHERE refresh_index = ?`

	refresh, err := data.SelectOneRecord[types.UserRefresh](r.db, qry, refreshIndex)
	if err != nil {
		return nil, err
	}

	return &refresh, nil
}

// InsertUserRefresh inserts a new user refresh token record into persistence
func (r *refreshRepository) InsertUserRefresh(refresh types.UserRefresh) error {

	qry := `
		INSERT INTO refresh (
			uuid, 
			refresh_index, 
			client_id, 
			refresh_token, 
			username, 
			username_index, 
			scopes, 
			created_at, 
			revoked
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, refresh); err != nil {
		return err
	}

	return nil
}

// UpdateUserRefresh updates an existing user refresh token record in persistence
// by blind index
func (r *refreshRepository) UpdateUserRefresh(refresh types.UserRefresh) error {

	// not all fields are allowed to be updated
	// AT THIS TIME ONLY 'revoked' CAN BE UPDATED
	qry := `
		UPDATE refresh SET
			revoked = ?
		WHERE refresh_index = ?`

	if err := data.UpdateRecord(r.db, qry, refresh.Revoked, refresh.RefreshIndex); err != nil {
		return err
	}

	return nil
}
			

// DeleteUserRefresh deletes a user refresh token record from persistence by blind index
func (r *refreshRepository) DeleteUserRefresh(refreshIndex string) error {

	qry := `
		DELETE FROM refresh 
		WHERE refresh_index = ?`

	if err := data.DeleteRecord(r.db, qry, refreshIndex); err != nil {
		return err
	}

	return nil
}
