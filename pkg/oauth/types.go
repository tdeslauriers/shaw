package oauth

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (

	// 400
	ErrValidateAuthCode = "failed to validate auth code data"

	// 401
	ErrIndexNotFound = "auth code does not exist"

	ErrInvalidGrantType = "invalid grant type"

	ErrAuthcodeExpired = "auth code expired"
	ErrAuthcodeRevoked = "auth code revoked"
	ErrAuthcodeClaimed = "auth code has been claimed already"

	ErrUserDisabled       = "user has been disabled"
	ErrUserAccountLocked  = "user account is locked"
	ErrUserAccountExpired = "user account is expired"

	ErrMismatchAuthcode = "submitted auth code does not match stored auth code"
	ErrMismatchClientid = "submitted client id does not match stored client id"
	ErrMismatchRedirect = "submitted redirect url does not match stored redirect url"

	// 500
	ErrGenAuthCodeIndex  = "failed to generate auth code index"
	ErrFailedLookupIndex = "failed to look up auth code record" // sql error/problem => NOT zero results

	ErrFailedDecrypt      = "failed to decrypt oauth data"
	ErrDecryptUsername    = "failed to decrypt username"
	ErrDecryptFirstname   = "failed to decrypt first name"
	ErrDecryptLastname    = "failed to decrypt last name"
	ErrDecryptBirthdate   = "failed to decrypt birthdate"
	ErrDecryptAuthcode    = "failed to decrypt authcode"
	ErrDecryptNonce       = "failed to decrypt nonce"
	ErrDecryptClientid    = "failed to decrypt client id"
	ErrDecryptRedirecturl = "failed to decrypt redirect url"
	ErrDecryptScopes      = "failed to decrypt scopes"
)

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
	Nonce         string `json:"nonce" db:"nonce"`
	ClientId      string `json:"client_uuid" db:"client_uuid"`
	RedirectUrl   string `json:"redirect_url" db:"redirect_url"`
	Scopes        string `json:"scopes" db:"scopes"`
	CreatedAt     string `json:"created_at" db:"created_at"`
	Claimed       bool   `json:"claimed" db:"claimed"`
	Revoked       bool   `json:"revoked" db:"revoked"`
}

// AuthcodeAccount is a model for authcode_account xref table
type AuthcodeAccount struct {
	Id           int    `json:"id" db:"id"`
	AuthcodeUuid string `json:"authcode_uuid" db:"authcode_uuid"`
	AccountUuid  string `json:"account_uuid" db:"account_uuid"`
	CreatedAt    string `json:"created_at" db:"created_at"`
}

// OauthUserData is a model for oauth user data returned by db query of authcode values
// Note: it omits identifiers, primary keys, indexes, etc. because unnecessary for application prurposes
type OauthUserData struct {
	// account table
	Username       string `json:"username" db:"username"`
	Firstname      string `json:"firstname" db:"firstname"`
	Lastname       string `json:"lastname" db:"lastname"`
	BirthDate      string `json:"birth_date" db:"birth_date"`
	Enabled        bool   `json:"enabled" db:"enabled"`
	AccountExpired bool   `json:"account_expired" db:"account_expired"`
	AccountLocked  bool   `json:"account_locked" db:"account_locked"`

	// authcode table
	Authcode          string          `json:"authcode" db:"authcode"`
	Nonce             string          `json:"nonce" db:"nonce"`
	ClientId          string          `json:"client_id" db:"client_uuid"`
	RedirectUrl       string          `json:"redirect_url" db:"redirect_url"`
	Scopes            string          `json:"scopes" db:"scopes"`
	AuthcodeCreatedAt data.CustomTime `json:"created_at" db:"created_at"`
	AuthcodeClaimed   bool            `json:"claimed" db:"claimed"`
	AuthcodeRevoked   bool            `json:"revoked" db:"revoked"`
}

// GrantType is a string type that represents the type of grant being requested from the authroization server,
// eg., authorization_code, refresh_token, client_credentials, or password
type GrantType string

const (
	AuthorizationCode GrantType = "authorization_code"
	RefreshToken      GrantType = "refresh_token"
	ClientCredentials GrantType = "client_credentials"
	Password          GrantType = "password"
)

// AccessTokenCmd is a struct to hold incoming access token values
// that are forwaded to the callback endpoint gateway to the authroization server
// as part of the oauth2 authorization code flow.
type AccessTokenCmd struct {
	Grant       GrantType `json:"grant_type"`
	AuthCode    string    `json:"auth_code"`
	ClientId    string    `json:"client_id"`
	RedirectUrl string    `json:"redirect_url"`
}

// ValidateCmd conducts light-weight validation of incoming access token values
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *AccessTokenCmd) ValidateCmd() error {
	if validate.TooShort(string(cmd.Grant), 4) || validate.TooLong(string(cmd.Grant), 32) {
		return fmt.Errorf("invalid grant type: must be between %d and %d characters", 4, 32)
	}

	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.RedirectUrl, 6) || validate.TooLong(cmd.RedirectUrl, 2048) {
		return fmt.Errorf("invalid redirect url: must be between %d and %d characters", 16, 2048)
	}

	return nil
}
