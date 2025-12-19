package authentication

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	apiUser "github.com/tdeslauriers/shaw/pkg/api/user"
)

// AuthRepository is the interface for persistance operations related to authentication
type AuthRepository interface {

	// FindUserAccount finds a user account by username blind index
	FindUserAccount(userIndex string) (*apiUser.UserAccount, error)
}

// NewAuthRepository creates a new implementation of the AuthRepository interface
// returning a pointer to the concrete implementation
func NewAuthRepository(db *sql.DB) AuthRepository {

	return &authRepository{
		db: db,
	}
}

var _ AuthRepository = (*authRepository)(nil)

// authRepository is the concrete implementation of the AuthRepository interface
type authRepository struct {
	db *sql.DB
}

// FindUserAccount finds a user account by username blind index
func (r *authRepository) FindUserAccount(userIndex string) (*apiUser.UserAccount, error) {

	qry := `
		SELECT 
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
		FROM account
		WHERE user_index = ?`

	u, err := data.SelectOneRecord[apiUser.UserAccount](r.db, qry, userIndex)
	if err != nil {
		return nil, err
	}

	return &u, nil
}
