package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"shaw/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
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

// authcode_account xref table
type AuthcodeAccount struct {
	// Id omitted for insert
	AuthcodeUuid string `json:"authcode_uuid" db:"authcode_uuid"`
	AccountUuid  string `json:"account_uuid" db:"account_uuid"`
	CreatedAt    string `json:"created_at" db:"created_at"`
}

// account_scope xref table
type AccountScope struct {
	Id          string          `json:"id" db:"id"`
	AccountUuid string          `json:"account_uuid" db:"account_uuid"`
	ScopeUuid   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt   data.CustomTime `json:"created_at" db:"created_at"`
}

type OuathFlowService interface {
	IsValidRedirect(clientid, url string) (bool, error)
	IsValidClient(clientid, username string) (bool, error)
	GenerateAuthCode(username, client, redirect string) (string, error)
}

func NewOauthFlowService(sql data.SqlRepository, ciph data.Cryptor, indexer data.Indexer, s2s session.S2sTokenProvider, caller connect.S2sCaller) OuathFlowService {
	return &oauthFlowService{
		db:               sql,
		cipher:           ciph,
		indexer:          indexer,
		s2sTokenProvider: s2s,
		s2sCaller:        caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentOauthFlow)),
	}
}

var _ OuathFlowService = (*oauthFlowService)(nil)

type oauthFlowService struct {
	db               data.SqlRepository
	cipher           data.Cryptor
	indexer          data.Indexer
	s2sTokenProvider session.S2sTokenProvider
	s2sCaller        connect.S2sCaller

	logger *slog.Logger
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

// GenerateAuthCode generates an auth code for and persists it to the db along with the user's scopes, the client, and the redirect url,
// associating it with the user so that it can be used to mint a token on callback from the client
func (svc *oauthFlowService) GenerateAuthCode(username, clientId, redirect string) (string, error) {

	// get user's scopes and all scopes
	var wg sync.WaitGroup
	var userScopes []AccountScope
	var scopes []session.Scope

	wg.Add(2)
	go svc.getUserScopes(username, &wg, &userScopes)
	go svc.getAllScopes(&wg, &scopes)
	wg.Wait()

	// return error either call returns no scopes
	if len(userScopes) < 1 {
		return "", fmt.Errorf("no scopes found for user %s", username)
	}
	if len(scopes) < 1 {
		return "", errors.New("no scopes returned from s2s scopes endpoint")
	}

	idSet := make(map[string]struct{})
	for _, scope := range userScopes {
		idSet[scope.ScopeUuid] = struct{}{}
	}

	// filter out scopes that user does not have
	var filtered []session.Scope
	for _, scope := range scopes {
		if _, exists := idSet[scope.Uuid]; exists && scope.Active {
			filtered = append(filtered, scope)
		}
	}

	// build scopes string
	var builder strings.Builder
	for i, scope := range filtered {
		builder.WriteString(scope.Scope)
		if i < len(filtered)-1 {
			builder.WriteString(" ")
		}
	}

	// build auth code record
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code id: %v", err)
	}

	authCode, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code: %v", err)
	}
	encryptedAuthcode, err := svc.cipher.EncryptServiceData(authCode.String())
	if err != nil {
		return "", fmt.Errorf("failed to encrypt auth code: %v", err)
	}

	authcodeIndex, err := svc.indexer.ObtainBlindIndex(authCode.String())
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code index: %v", err)
	}

	encryptedClientId, err := svc.cipher.EncryptServiceData(clientId)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt client id: %v", err)
	}

	encryptedRedirect, err := svc.cipher.EncryptServiceData(redirect)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt redirect url: %v", err)
	}

	encryptedScopes, err := svc.cipher.EncryptServiceData(builder.String())
	if err != nil {
		return "", fmt.Errorf("failed to encrypt generaed scopes string: %v", err)
	}

	createdAt := time.Now()

	code := AuthCode{
		Id:            id.String(),
		AuthCodeIndex: authcodeIndex,
		Authcode:      encryptedAuthcode,
		ClientId:      encryptedClientId,
		RedirectUrl:   encryptedRedirect,
		Scopes:        encryptedScopes,
		CreatedAt:     createdAt.Format("2006-01-02 15:04:05"),
		Claimed:       false,
		Revoked:       false,
	}

	xref := AuthcodeAccount{
		AuthcodeUuid: code.Id,
		AccountUuid:  userScopes[0].AccountUuid,
		CreatedAt:    createdAt.Format("2006-01-02 15:04:05"),
	}

	go func() {
		// persist auth code to db
		qry := `INSERT into authcode (uuid, authcode_index, authcode, client_uuid, redirect_url, scopes, created_at, claimed, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
		if err := svc.db.InsertRecord(qry, code); err != nil {
			svc.logger.Error(fmt.Sprintf("failed to insert authcode record for %s", username), "err", err.Error())
			return
		}

		// persist account authcode xref to db
		qry = `INSERT into authcode_account (authcode_uuid, account_uuid, created_at) VALUES (?, ?, ?)`
		if err := svc.db.InsertRecord(qry, xref); err != nil {
			svc.logger.Error(fmt.Sprintf("failed to insert authcode_account xref record %s", username), "err", err.Error())
			return
		}
	}()

	return authCode.String(), nil
}

// get individual user's scopes uuids from account_scope table
func (svc *oauthFlowService) getUserScopes(username string, wg *sync.WaitGroup, acctScopes *[]AccountScope) {

	defer wg.Done()

	// user index
	index, err := svc.indexer.ObtainBlindIndex(username)
	if err != nil {
		svc.logger.Error(fmt.Sprintf("failed to generate user index for username %s", username), "err", err.Error())
	}

	qry := `
		SELECT
			as.id,
			as.account_uuid,
			as.scope_uuid,
			as.created_at
		FROM account_scope as
			LEFT OUTER JOIN account a ON as.account_uuid = a.uuid
		WHERE a.user_index = ?`

	var scopes []AccountScope
	if err := svc.db.SelectRecords(qry, &scopes, index); err != nil {
		if err == sql.ErrNoRows {
			svc.logger.Error(fmt.Sprintf("no scopes found for user %s", username), "err", err.Error())
			return
		} else {
			svc.logger.Error(fmt.Sprintf("failed to retrieve scopes for user %s", username), "err", err.Error())
			return
		}
	}

	*acctScopes = scopes
}

// get scopes data from s2s scopes endpoint
func (svc *oauthFlowService) getAllScopes(wg *sync.WaitGroup, scopes *[]session.Scope) {

	defer wg.Done()

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := svc.s2sTokenProvider.GetServiceToken(util.S2sServiceName)
	if err != nil {
		svc.logger.Error("failed to get s2s token: %v", err)
		return
	}

	// call scopes endpoint
	var s2sScopes []session.Scope
	if err := svc.s2sCaller.GetServiceData("/scopes", s2stoken, "", &s2sScopes); err != nil {
		svc.logger.Error("failed to get scopes data from s2s scopes endpoint", "err", err.Error())
		return
	}

	*scopes = s2sScopes
}
