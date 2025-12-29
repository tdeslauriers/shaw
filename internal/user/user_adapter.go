package user

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	api "github.com/tdeslauriers/shaw/pkg/api/user"
)

// UserRepository defines the user repository interface for user data operations.
type UserRepository interface {

	// FindUserBySlug retrieves a user profile by their slug index.
	FindUserBySlug(index string) (*api.Profile, error)

	// FindAllUsers retrieves all user profiles.
	FindAllUsers() ([]api.Profile, error)

	// UpdateUser updates a user profile in the database identified by their index.
	UpdateUser(user *api.Profile, index string) error

	// DeleteAccountScopeXref deletes the xref record between an account and a scope.
	DeleteAccountScopeXref(accountId string, scopeId string) error

	// InsertAccountScopeXref inserts a new xref record between an account and a scope.
	InsertAccountScopeXref(xref AccountScopeXref) error
}

// NewUserRepository creates a new implementation of the user repository interface, returning
// a pointer to the concrete implementation.
func NewUserRepository(sql *sql.DB) UserRepository {

	return &userRepository{
		sql: sql,
	}
}

var _ UserRepository = (*userRepository)(nil)

// userRepository is the concrete implementation of the user repository interface.
type userRepository struct {
	sql *sql.DB
}

// GetUserByIndex retrieves a user by their slug index from the database.
func (r *userRepository) FindUserBySlug(index string) (*api.Profile, error) {

	qry := `
		SELECT 
			uuid, 
			username, 
			firstname, 
			lastname,
			birth_date,
			slug,
			created_at, 
			enabled,
			account_expired,
			account_locked 
		FROM account 
		WHERE slug_index = ?`
	profile, err := data.SelectOneRecord[api.Profile](r.sql, qry, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user with provided index not found")
		}
		return nil, fmt.Errorf("failed to retrieve user by index %s from database: %v", index, err)
	}

	return &profile, nil
}

// FindAllUsers retrieves all user profiles from the database.
func (r *userRepository) FindAllUsers() ([]api.Profile, error) {

	qry := `
		SELECT
			uuid,
			username,
			firstname,
			lastname,
			birth_date,
			slug,
			created_at,
			enabled,
			account_expired,
			account_locked
		FROM account`
	profiles, err := data.SelectRecords[api.Profile](r.sql, qry)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve all users from database: %v", err)
	}

	return profiles, nil
}

// UpdateUser updates a user profile in the database.
func (r *userRepository) UpdateUser(user *api.Profile, index string) error {

	// only the following fields are allowed to be updated
	qry := `
			UPDATE account SET 
				firstname = ?,
				lastname = ?,
				birth_date = ?,
				enabled = ?,
				account_locked = ?,
				account_expired = ?
			WHERE user_index = ?`
	if err := data.UpdateRecord(
		r.sql,
		qry,
		user.Firstname,
		user.Lastname,
		user.BirthDate,
		user.Enabled,
		user.AccountLocked,
		user.AccountExpired,
		index,
	); err != nil {
		return fmt.Errorf("failed to update user profile in database: %v", err)
	}

	return nil
}

// DeleteAccountScopeXref deletes the xref record between an account and a scope.
func (r *userRepository) DeleteAccountScopeXref(accountId string, scopeId string) error {

	qry := `
		DELETE 
		FROM account_scope 
		WHERE account_uuid = ? AND scope_uuid = ?`
	if err := data.DeleteRecord(r.sql, qry, accountId, scopeId); err != nil {
		return err
	}

	return nil
}

// InsertAccountScopeXref inserts a new xref record between an account and a scope.
func (r *userRepository) InsertAccountScopeXref(xref AccountScopeXref) error {

	qry := `
		INSERT INTO account_scope (
			id, 
			account_uuid, 
			scope_uuid, 
			created_at
		)
		VALUES (?, ?, ?, ?)`
	if err := data.InsertRecord(data.Execer(r.sql), qry, xref); err != nil {
		return err
	}

	return nil
}
