package user

import "github.com/tdeslauriers/carapace/pkg/data"

const (
	// 401
	ErrUserNotFound    = "user not found"
	ErrUserDisabled    = "user account is disabled"
	ErrUserExpired     = "user account is expired"
	ErrUserLocked      = "user account is locked"
	ErrInvalidPassword = "failed to validate current password"

	// 422
	ErrInvalidUserData        = "invalid or not well formed user data"
	ErrPasswordUsedPreviously = "password has been used previously"
	ErrNewConfirmPwMismatch   = "new password and confirmation password do not match"

	// 500
	ErrDecryptUsername  = "failed to decrypt username"
	ErrDecryptFirstname = "failed to decrypt firstname"
	ErrDecryptLastname  = "failed to decrypt lastname"
	ErrDecryptBirthDate = "failed to decrypt birth date"
	ErrDecryptSlug      = "failed to decrypt slug"

	ErrEncryptFirstname = "failed to encrypt firstname"
	ErrEncryptLastname  = "failed to encrypt lastname"
	ErrEncryptBirthDate = "failed to encrypt birth date"

	ErrGenerateUserIndex = "failed to generate user index"
	ErrGenerateSlugIndex = "failed to generate slug index"
)

// PasswordHistory is a model struct that represents a password history record in the password_history table.
type PasswordHistory struct {
	Id        string `json:"id" db:"uuid"`
	Password  string `json:"password" db:"password"`
	Updated   string `json:"updated" db:"updated"`
	AccountId string `json:"account_uuid" db:"account_uuid"`
}

// UserAccount is a model struct that represents a user account record in the account table
// and the password history table joined on the account_uuid.
type UserPasswordHistory struct {
	// account table
	AccountId       string `json:"user_uuid" db:"user_uuid"`
	Username        string `db:"username" json:"username"`
	CurrentPassword string `db:"current_password" json:"current_password,omitempty"`
	Enabled         bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired  bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked   bool   `db:"account_locked" json:"account_locked,omitempty"`

	// password_history table
	PasswordHisotryId string          `json:"password_history_id" db:"password_history_uuid"`
	HistoryPassword   string          `json:"history_password" db:"history_password"`
	Updated           data.CustomTime `json:"updated" db:"updated"`
}
