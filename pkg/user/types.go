package user

import "github.com/tdeslauriers/carapace/pkg/data"

const (
	// 401
	ErrUserNotFound = "user not found"
	ErrUserDisabled = "user account is disabled"
	ErrUserExpired  = "user account is expired"
	ErrUserLocked   = "user account is locked"

	// 500
	ErrDecryptUsername = "failed to decrypt username"
	ErrDecryptFirstname = "failed to decrypt firstname"
	ErrDecryptLastname  = "failed to decrypt lastname"
	ErrDecryptBirthDate = "failed to decrypt birth date"

)

// User is a model struct that represents a user in the accounts table of the db.
// note: it omits the password field for security reasons.
type User struct {
	Id             string          `json:"id" db:"uuid"`
	Username       string          `json:"username" db:"username"`
	Firstname      string          `json:"firstname" db:"firstname"`
	Lastname       string          `json:"lastname" db:"lastname"`
	BirthDate      string          `json:"birth_date" db:"birth_date"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
}
