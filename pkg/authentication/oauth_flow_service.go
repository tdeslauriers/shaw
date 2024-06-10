package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
)

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

// exists for output of validateRedirect sql query result
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

// AccountClient is a join table between account, account_client (xref), and client
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

type OuathFlowService interface {
	IsValidRedirect(clientid, url string) (bool, error)
	IsValidClient(clientid, username string) (bool, error)
	GenerateAuthCode(clientId, username string) (string, error)
}

func NewOauthFlowService(db data.SqlRepository, i data.Indexer) OuathFlowService {
	return &oauthFlowService{
		db:      db,
		indexer: i,
	}
}

var _ OuathFlowService = (*oauthFlowService)(nil)

type oauthFlowService struct {
	db      data.SqlRepository
	indexer data.Indexer
}

// isVaildRedirect validates the client and redirect url exist, are linked, and are enabled/not expired/not locked
func (svc *oauthFlowService) IsValidRedirect(clientId, redirect string) (bool, error) {

	// remove any query params from redirect url
	parsed, err := url.Parse(redirect)
	if err != nil {
		return false, fmt.Errorf("failed to parse redirect url: %v", err)
	}

	url := url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   parsed.Path,
	}

	// query db for client and redirect
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

	var result ClientRedirect
	if err := svc.db.SelectRecord(qry, &result, clientId, url.String()); err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("client/redirect pair not found")
		} else {
			return false, fmt.Errorf("failed to retrieve client/redirect pair: %v", err)
		}
	}

	// check if client, redirect is enabled, not expired, not locked
	if !result.ClientEnabled {
		return false, errors.New("client disabled")
	}

	if result.ClientExpired {
		return false, errors.New("client expired")
	}

	if result.ClientLocked {
		return false, errors.New("client locked")
	}

	if !result.RedirectEnabled {
		return false, errors.New("redirect disabled")
	}

	return true, nil
}

func (svc *oauthFlowService) IsValidClient(clientId, username string) (bool, error) {

	// re-generate user index
	index, err := svc.indexer.ObtainBlindIndex(username)
	if err != nil {
		return false, fmt.Errorf("failed to generate user index: %v", err)
	}

	// query db for client and user index association
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

	var result AccountClient
	if err := svc.db.SelectRecord(qry, &result, index, clientId); err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("user (%s) / client (%s) association not found", username, clientId)
		} else {
			return false, fmt.Errorf("failed to retrieve user (%s) / client (%s) pair: %v", username, clientId, err)
		}
	}

	// check user account is enabled, not expired, not locked
	if !result.AccountEnabled {
		return false, errors.New("user account disabled")
	}

	if result.AccountExpired {
		return false, errors.New("user account expired")
	}

	if result.AccountLocked {
		return false, errors.New("user account locked")
	}

	// check client is enabled, not expired, not locked
	if !result.ClientEnabled {
		return false, errors.New("client disabled")
	}

	if result.ClientExpired {
		return false, errors.New("client expired")
	}

	if result.ClientLocked {
		return false, errors.New("client locked")
	}

	// if all checks pass, return true
	return true, nil
}

func (svc *oauthFlowService) GenerateAuthCode(clientId, username string) (string, error) {

	authCode, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code: %v", err)
	}

	// TODO lookup user index

	// TODO: build auth code record

	go func() {
		// TODO: persist auth code to db
	}()

	return authCode.String(), nil
}
