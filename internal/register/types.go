package register

import (
	"github.com/tdeslauriers/carapace/pkg/data"
)

// IdentityClient is a struct for identity client data, NOT the same as S2S client data:
// ie, https://deslauriers.com instead of the s2s shaw service
type IdentityClient struct {
	Uuid          string          `db:"uuid" json:"uuid"`
	ClientId      string          `db:"client_id" json:"client_id"`
	ClientName    string          `db:"client_name" json:"client_name"`
	Description   string          `db:"description" json:"description"`
	CreatedAt     data.CustomTime `db:"created_at" json:"created_at"`
	Enabled       bool            `db:"enabled" json:"enabled"`
	ClientExpired bool            `db:"client_expired" json:"client_expired"`
	ClientLocked  bool            `db:"client_locked" json:"client_locked"`
}

// AccountClientXref is a model struct xref table joining user accounts and identity clients tables.
type AccountClientXref struct {
	Id        int    `db:"id" json:"id"`
	AccountId string `db:"account_uuid" json:"account_uuid"`
	ClientId  string `db:"client_uuid" json:"client_uuid"`
	CreatedAt string `db:"created_at" json:"created_at"`
}
