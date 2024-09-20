package authentication

import "github.com/tdeslauriers/carapace/pkg/data"

const (

	// 401
	ErrInvalidUsernamePassword = "invalid username or password"
	ErrUserExipred             = "account is expired"
	ErrUserLocked              = "account is locked"
	ErrUserDisabled            = "account is disabled"

	ErrRefreshNotFound = "refresh token not found"

	// 500
	ErrGenerateIndex = "failed to generate blind index"

	ErrEncryptClientId = "failed to encrypt client id"
	ErrEncryptRefresh  = "failed to encrypt refresh token"
	ErrEncryptUsername = "failed to encrypt username"

	ErrDecryptClientId = "failed to decrypt client id"
	ErrDecryptRefresh  = "failed to decrypt refresh token"
	ErrDecryptUsername = "failed to decrypt username"
)

// AccountScope is a model for account_scope xref table
type AccountScope struct {
	Id          int             `json:"id" db:"id"`
	AccountUuid string          `json:"account_uuid" db:"account_uuid"`
	ScopeUuid   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt   data.CustomTime `json:"created_at" db:"created_at"`
}
