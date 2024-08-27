package authentication

import "github.com/tdeslauriers/carapace/pkg/data"

const (
	ErrGenerateIndex           = "failed to generate blind index"
	ErrInvalidUsernamePassword = "invalid username or password"
	ErrUserExipred             = "account is expired"
	ErrUserLocked              = "account is locked"
	ErrUserDisabled            = "account is disabled"
)

// AccountScope is a model for account_scope xref table
type AccountScope struct {
	Id          int             `json:"id" db:"id"`
	AccountUuid string          `json:"account_uuid" db:"account_uuid"`
	ScopeUuid   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt   data.CustomTime `json:"created_at" db:"created_at"`
}
