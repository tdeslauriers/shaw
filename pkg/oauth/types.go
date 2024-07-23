package oauth

import "github.com/tdeslauriers/carapace/pkg/data"

// Client is a model for client table in the identity service db
type Client struct {
	ClientId      string          `json:"client_id" db:"uuid"`
	CLientName    string          `json:"client_name" db:"client_name"`
	Description   string          `json:"description" db:"description"`
	CreatedAt     data.CustomTime `json:"created_at" db:"created_at"`
	Enabled       bool            `json:"enabled" db:"enabled"`
	ClientExpired bool            `json:"client_expired" db:"client_expired"`
	ClientLocked  bool            `json:"client_locked" db:"client_locked"`
}

// Redirect is a model for redirect table
type Redirect struct {
	Id          string `json:"uuid" db:"uuid"`
	RedirectUrl string `json:"redirect_url" db:"redirect_url"`
	Enabled     bool   `json:"enabled" db:"enabled"`
	ClientId    string `json:"client_uiid" db:"client_uuid"`
}

// ClientRedirect exists for output of validateRedirect sql query result
// NOT a db table
type ClientRedirect struct {
	Id              string `json:"uuid" db:"uuid"`
	ClientId        string `json:"client_id" db:"client_id"`
	ClientEnabled   bool   `json:"client_enabled" db:"client_enabled"`
	ClientExpired   bool   `json:"client_expired" db:"client_expired"`
	ClientLocked    bool   `json:"client_locked" db:"client_locked"`
	RedirectUrl     string `json:"redirect_url" db:"redirect_url"`
	RedirectEnabled bool   `json:"redirect_enabled" db:"redirect_enabled"`
}

// AccountClient is an object to hold the results of a join query between account, account_client (xref), and client
type AccountClient struct {
	AccountUuid    string `json:"account_uuid" db:"account_uuid"`
	UserIndex      string `json:"user_index" db:"user_index"`
	AccountEnabled bool   `json:"enabled" db:"account_enabled"`
	AccountExpired bool   `json:"account_expired" db:"account_expired"`
	AccountLocked  bool   `json:"account_locked" db:"account_locked"`
	ClientUuid     string `json:"client_uuid" db:"client_uuid"`
	ClientId       string `json:"client_id" db:"client_id"`
	ClientEnabled  bool   `json:"client_enabled" db:"client_enabled"`
	ClientExpired  bool   `json:"client_expired" db:"client_expired"`
	ClientLocked   bool   `json:"client_locked" db:"client_locked"`
}

// AuthCode is a model for authcode table
type AuthCode struct {
	Id            string `json:"uuid" db:"uuid"`
	AuthCodeIndex string `json:"authcode_index" db:"authcode_index"`
	Authcode      string `json:"authcode" db:"authcode"`
	ClientId      string `json:"client_uuid" db:"client_uuid"`
	RedirectUrl   string `json:"redirect_url" db:"redirect_url"`
	Scopes        string `json:"scopes" db:"scopes"`
	CreatedAt     string `json:"created_at" db:"created_at"`
	Claimed       bool   `json:"claimed" db:"claimed"`
	Revoked       bool   `json:"revoked" db:"revoked"`
}

// AuthcodeAccount is a model for authcode_account xref table
type AuthcodeAccount struct {
	// Id omitted for insert
	AuthcodeUuid string `json:"authcode_uuid" db:"authcode_uuid"`
	AccountUuid  string `json:"account_uuid" db:"account_uuid"`
	CreatedAt    string `json:"created_at" db:"created_at"`
}


