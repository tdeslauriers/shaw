package scope

import "github.com/tdeslauriers/carapace/pkg/data"

const (
	// 500
	ErrGenerateIndex = "failed to generate blind index"
)

// AccountScopeXref is a model for account_scope xref table
type AccountScopeXref struct {
	Id          int             `json:"id" db:"id"`
	AccountUuid string          `json:"account_uuid" db:"account_uuid"`
	ScopeUuid   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt   data.CustomTime `json:"created_at" db:"created_at"`
}
