package oauth

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	apiUser "github.com/tdeslauriers/shaw/pkg/api/user"
)

// OAuthRepository defines the interface for OAuth data operations.
type OAuthRepository interface {

	// FindClientRedirect retrieves a client and its redirect information by client ID and redirect URI.
	FindClientRedirect(clientId, redirectUri string) (*ClientRedirect, error)

	// FindAccountClient retrieves account and client information by user index and client ID.
	FindAccountClient(userIndex, clientId string) (*AccountClient, error)

	// FindUserAccount retrieves a user account by their index.
	FindUserAccount(index string) (*apiUser.UserAccount, error)

	// FindOauthUserData retrieves OAuth user data by authcode from the account and authcode tables.
	FindOauthUserData(authCodeIndex string) (*OauthUserData, error)

	// InsertAuthcode inserts an authcode record into the database.
	InsertAuthcode(authcode AuthCode) error

	// InsertAuthcodeAccountXref inserts a new authcode-account cross-reference record into the database.
	InsertAuthcodeAccountXref(xref AuthcodeAccount) error
}

// NewOAuthRepository creates a new implementation of the OAuth repository interface, returning
// a pointer to the concrete implementation.
func NewOAuthRepository(db *sql.DB) OAuthRepository {

	return &oauthRepository{
		db: db,
	}
}

var _ OAuthRepository = (*oauthRepository)(nil)

// oauthRepository is the concrete implementation of the OAuth repository interface.
type oauthRepository struct {
	db *sql.DB
}

// FindClientRedirect gets the client table and redirect table data for a given id amd redirect uri.
func (r *oauthRepository) FindClientRedirect(clientId, redirectUri string) (*ClientRedirect, error) {

	qry := `
		SELECT
			c.uuid,
			c.client_id,
			c.enabled AS client_enabled,
			c.client_expired AS client_expired, 
			c.client_locked AS client_locked,
			r.redirect_url,
			r.enabled AS redirect_enabled
		FROM client c
			LEFT OUTER JOIN redirect r ON c.uuid = r.client_uuid
		WHERE c.client_id = ? AND r.redirect_url = ?`

	cr, err := data.SelectOneRecord[ClientRedirect](r.db, qry, clientId, redirectUri)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

// FindAccountClient retrieves data from the account and client tables for a given
// account username index and client id.
func (r *oauthRepository) FindAccountClient(userIndex, clientId string) (*AccountClient, error) {

	qry := `
		SELECT
			a.uuid AS account_uuid,
			a.user_index,
			a.enabled as account_enabled,
			a.account_expired,
			a.account_locked,
			c.uuid AS client_uuid,
			c.client_id,
			c.enabled AS client_enabled,
			c.client_expired,
			c.client_locked
		FROM account a
			LEFT OUTER JOIN account_client ac ON a.uuid = ac.account_uuid
			LEFT OUTER JOIN client c ON ac.client_uuid = c.uuid
		WHERE a.user_index = ? 
			AND c.client_id = ?`

	ac, err := data.SelectOneRecord[AccountClient](r.db, qry, userIndex, clientId)
	if err != nil {
		return nil, err
	}

	return &ac, nil
}

// FindUserAccount retrieves a user account by their index from the database.
func (r *oauthRepository) FindUserAccount(index string) (*apiUser.UserAccount, error) {

	qry := `
		SELECT uuid, 
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

	acct, err := data.SelectOneRecord[apiUser.UserAccount](r.db, qry, index)
	if err != nil {
		return nil, err
	}

	return &acct, nil
}

// FindOauthUserData retrieves OAuth user data by authcode from the account and
// authcode tables in the database.
func (r *oauthRepository) FindOauthUserData(authCodeIndex string) (*OauthUserData, error) {

	qry := `
		SELECT 
			a.username, 
			a.firstname,
			a.lastname,
			a.birth_date,
			a.enabled,
			a.account_expired,
			a.account_locked,
			ac.authcode,
			ac.nonce,
			ac.client_uuid,
			ac.redirect_url,
			ac.scopes,
			ac.created_at,
			ac.claimed, 
			ac.revoked
		FROM authcode ac 
			LEFT OUTER JOIN authcode_account aac ON ac.uuid = aac.authcode_uuid
			LEFT OUTER JOIN account a ON aac.account_uuid = a.uuid
		WHERE ac.authcode_index = ?`

	data, err := data.SelectOneRecord[OauthUserData](r.db, qry, authCodeIndex)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// InsertAuthcode inserts an authcode record into the database.
func (r *oauthRepository) InsertAuthcode(authcode AuthCode) error {

	qry := `
		INSERT into authcode (
			uuid, 
			authcode_index, 
			authcode, nonce, 
			client_uuid, 
			redirect_url, 
			scopes, created_at, 
			claimed, 
			revoked
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, authcode); err != nil {
		return err
	}

	return nil
}

// InsertAuthcodeAccountXref inserts a new authcode-account cross-reference record into the database.
func (r *oauthRepository) InsertAuthcodeAccountXref(xref AuthcodeAccount) error {

	qry := `
		INSERT into authcode_account (
			id, 
			authcode_uuid, 
			account_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	if err := data.InsertRecord(r.db, qry, xref); err != nil {
		return err
	}

	return nil
}
