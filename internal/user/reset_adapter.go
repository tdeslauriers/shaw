package user

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// ResetRepository defines the reset repository interface for password reset operations.
type ResetRepository interface {

	// FindPasswordHistory retrieves the password history for a user by their username index.
	FindPasswordHistory(userIndex string) ([]UserPasswordHistory, error)

	// UpdatePassword updates the user's password in the account table of database.
	UpdatePassword(hash string, userIndex string) error

	// InsertPasswordHistory inserts a new password record into the password history table.
	InsertPasswordHistory(history PasswordHistory) error
}

// NewResetRepository creates a new implementation of the reset repository interface, returning
// a pointer to the concrete implementation.
func NewResetRepository(sql *sql.DB) ResetRepository {

	return &resetRepository{
		sql: sql,
	}
}

var _ ResetRepository = (*resetRepository)(nil)

// resetRepository is the concrete implementation of the reset repository interface.
type resetRepository struct {
	sql *sql.DB
}

// FindPasswordHistory retrieves the password history for a user by their username index from the database.
func (r *resetRepository) FindPasswordHistory(userIndex string) ([]UserPasswordHistory, error) {

	qry := `
		SELECT
			a.uuid AS user_uuid,
			a.username,
			a.password AS current_password,
			a.enabled,
			a.account_expired,
			a.account_locked,
			ph.uuid AS password_history_uuid,
			ph.password AS history_password,
			ph.updated
		FROM account a
		LEFT OUTER JOIN password_history ph ON a.uuid = ph.account_uuid
		WHERE a.user_index = ?`
	history, err := data.SelectRecords[UserPasswordHistory](r.sql, qry, userIndex)
	if err != nil {

		return nil, err
	}

	return history, nil
}

// UpdatePassword updates the user's password in the account table of database.
func (r *resetRepository) UpdatePassword(hash string, userIndex string) error {

	qry := `
		UPDATE account 
		SET password = ? 
		WHERE user_index = ?`
	if err := data.UpdateRecord(r.sql, qry, hash, userIndex); err != nil {
		return err
	}

	return nil
}

// InsertPasswordHistory inserts a new password record into the password history table.
func (r *resetRepository) InsertPasswordHistory(history PasswordHistory) error {

	qry := `
		INSERT INTO password_history (
			uuid, 
			password, 
			updated, 
			account_uuid
		) VALUES (?, ?, ?, ?)`
	if err := data.InsertRecord(r.sql, qry, history); err != nil {
		return err
	}

	return nil
}
