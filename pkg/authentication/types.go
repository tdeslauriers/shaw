package authentication

import "github.com/tdeslauriers/carapace/pkg/data"

type Client struct {
	ClientId      string          `json:"client_id" db:"uuid"`
	CLientName    string          `json:"client_name" db:"client_name"`
	Description   string          `json:"description" db:"description"`
	CreatedAt     data.CustomTime `json:"created_at" db:"created_at"`
	Enabled       bool            `json:"enabled" db:"enabled"`
	ClientExpired bool            `json:"client_expired" db:"client_expired"`
	ClientLocked  bool            `json:"client_locked" db:"client_locked"`
}

type Redirect struct {
	Id          string `json:"uuid" db:"uuid"`
	RedirectUrl string `json:"redirect_url" db:"redirect_url"`
	Enabled     bool   `json:"enabled" db:"enabled"`
	ClientId    string `json:"client_uiid" db:"client_uuid"`
}

type ClientRedirect struct {
	ClientId        string `json:"client_id" db:"client_id"`
	ClientEnabled   bool   `json:"client_enabled" db:"client_enabled"`
	ClientExpired   bool   `json:"client_expired" db:"client_expired"`
	ClientLocked    bool   `json:"client_locked" db:"client_locked"`
	RedirectUrl     string `json:"redirect_url" db:"redirect_url"`
	RedirectEnabled bool   `json:"redirect_enabled" db:"redirect_enabled"`
}

func validateRedirect(clientId, redirect string) error {

	// TODO: url unencode

	// TODO: remove any query params

	qry := `
		SELECT
			c.uuid AS client_id,
			c.enabled AS client_enabled,
			c.client_expired AS client_expired, 
			c.client_locked AS client_locked,
			r.redirect_url,
			r.enabled AS redirect_enabled
		FROM client c
			LEFT OUTER JOIN redirect r ON c.uuid = r.client_uuid
		WHERE c.uuid = ? AND r.redirect_url = ?`

	// TODO: query db

	// TODO: check result isnt empty

	// TODO: check if client, redirect is enabled, not expired, not locked

	return nil

}
