package register

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/shaw/internal/user"
)

// RegisterRepository handles database operations for user registration
type RegisterRepsoitory interface {

	// FindUserExists checks if a user already exists in the database by looking up
	// there username by index.
	FindUserExists(userIndex string) (bool, error)

	// FindClientById finds a in the database by looking up there client id.
	FindClientById(clientId string) (*IdentityClient, error)

	// InsertUserAccount inserts a new user account into the database.
	InsertUserAccount(account user.UserAccount) error

	// InsertPasswordHistory inserts a new password history record into the database.
	InsertPasswordHistory(history user.PasswordHistory) error

	// InsertAccountScopeXref inserts a new xref record between an account and a scope.
	InsertAccountScopeXref(xref user.AccountScopeXref) error

	// InsertAccountClientXref inserts a new xref record between an account and a client.
	InsertAccountClientXref(xref AccountClientXref) error
}

// NewRegisterRepository creates a new RegisterRepository interface by returning
// a pointer to a new concrete implementation.
func NewRegisterRepository(db *sql.DB) RegisterRepsoitory {

	return &registerRepository{
		db: db,
	}
}

var _ RegisterRepsoitory = (*registerRepository)(nil)

// registerRepository is the concrete implementation of the RegisterRepository interface
type registerRepository struct {
	db *sql.DB
}

// FindUserExists checks if a user already exists in the database by looking up
// there username by index.
func (r *registerRepository) FindUserExists(userIndex string) (bool, error) {

	qry := `
		SELECT EXISTS(
			SELECT 1
			FROM account 
			WHERE user_index = ?
		) AS record_exists`

	return data.SelectExists(r.db, qry, userIndex)
}

// FindClientById finds a in the database by looking up
// there client id.
func (r *registerRepository) FindClientById(clientId string) (*IdentityClient, error) {

	qry := `
		SELECT 
			uuid, 
			client_id, 
			client_name, 
			description, 
			created_at, 
			enabled, 
			client_expired, 
			client_locked 
		FROM client
		WHERE client_id = ?`

	iamClient, err := data.SelectOneRecord[IdentityClient](r.db, qry, clientId)
	if err != nil {
		return nil, err
	}

	return &iamClient, nil
}

// InsertUserAccount inserts a new user account into the database.
func (r *registerRepository) InsertUserAccount(account user.UserAccount) error {

	qry := `
		INSERT INTO account (
			uuid,
			username, 
			user_index, 
			password, 
			firstname, 
			lastname, 
			birth_date, 
			slug, 
			slug_index, 
			created_at, 
			enabled, 
			account_expired, 
			account_locked
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, account); err != nil {
		return err
	}

	return nil
}

// InsertPasswordHistory inserts a new password history record into the database.
func (r *registerRepository) InsertPasswordHistory(history user.PasswordHistory) error {

	qry := `
		INSERT INTO password_history (
			uuid, 
			password, 
			updated, 
			account_uuid
		) VALUES (?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, history); err != nil {
		return err
	}

	return nil
}

// InsertAccountScopeXref inserts a new xref record between an account and a scope.
func (r *registerRepository) InsertAccountScopeXref(xref user.AccountScopeXref) error {

	qry := `
		INSERT INTO account_scope (
			id, 
			account_uuid, 
			scope_uuid, 
			created_at
		)
		VALUES (?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, xref); err != nil {
		return err
	}

	return nil
}

// InsertAccountClientXref inserts a new xref record between an account and a client.
func (r *registerRepository) InsertAccountClientXref(xref AccountClientXref) error {

	qry := `
		INSERT INTO account_client (
			id, 
			account_uuid, 
			client_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, xref); err != nil {
		return err
	}

	return nil
}
