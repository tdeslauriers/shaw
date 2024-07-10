package oauth

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
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

type Service interface {
	// IsVaildRedirect validates the client and redirect url exist, are linked, and are enabled/not expired/not locked
	IsValidRedirect(clientid, url string) (bool, error)

	// IsValidClient validates the client and user are linked, enabled, not expired, not locked
	IsValidClient(clientid, username string) (bool, error)

	// GenerateAuthCode generates an auth code for and persists it to the db along with the user's scopes, the client, and the redirect url,
	// associating it with the user so that it can be used to mint a token on callback from the client
	GenerateAuthCode(username, client, redirect string) (string, error)
}

func NewService(db data.SqlRepository, c data.Cryptor, i data.Indexer, p provider.S2sTokenProvider, caller connect.S2sCaller) Service {
	return &service{
		db:               db,
		cipher:           c,
		indexer:          i,
		s2sTokenProvider: p,
		s2sCaller:        caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentOauthFlow)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db               data.SqlRepository
	cipher           data.Cryptor
	indexer          data.Indexer
	s2sTokenProvider provider.S2sTokenProvider
	s2sCaller        connect.S2sCaller

	logger *slog.Logger
}

// IsValidRedirect implements the OauthFlowService interface
func (s *service) IsValidRedirect(clientId, redirect string) (bool, error) {

	// remove any query params from redirect url
	parsed, err := url.Parse(redirect)
	if err != nil {
		return false, fmt.Errorf("failed to parse redirect url: %v", err)
	}

	snipped := &url.URL{
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
	if err := s.db.SelectRecord(qry, &result, clientId, snipped.String()); err != nil {
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

// IsValidClient implements the OauthFlowService interface
func (s *service) IsValidClient(clientId, username string) (bool, error) {

	// re-generate user index
	index, err := s.indexer.ObtainBlindIndex(username)
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
	if err := s.db.SelectRecord(qry, &result, index, clientId); err != nil {
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

// GenerateAuthCode implements the OauthFlowService interface
func (s *service) GenerateAuthCode(username, clientId, redirect string) (string, error) {

	// get user's scopes and all scopes
	var wg sync.WaitGroup
	var userScopes []AccountScope
	var scopes []types.Scope

	wg.Add(2)
	go s.getUserScopes(username, &wg, &userScopes)
	go s.getAllScopes(&wg, &scopes)
	wg.Wait()

	// return error either call returns no scopes
	if len(userScopes) < 1 {
		return "", fmt.Errorf("no scopes found for user (%s)", username)
	}
	if len(scopes) < 1 {
		return "", errors.New("no scopes returned from s2s scopes endpoint")
	}

	idSet := make(map[string]struct{})
	for _, scope := range userScopes {
		idSet[scope.ScopeUuid] = struct{}{}
	}

	// filter out scopes that user does not have
	var filtered []types.Scope
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
	encryptedAuthcode, err := s.cipher.EncryptServiceData(authCode.String())
	if err != nil {
		return "", fmt.Errorf("failed to encrypt auth code: %v", err)
	}

	authcodeIndex, err := s.indexer.ObtainBlindIndex(authCode.String())
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code index: %v", err)
	}

	encryptedClientId, err := s.cipher.EncryptServiceData(clientId)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt client id: %v", err)
	}

	encryptedRedirect, err := s.cipher.EncryptServiceData(redirect)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt redirect url: %v", err)
	}

	encryptedScopes, err := s.cipher.EncryptServiceData(builder.String())
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
		if err := s.db.InsertRecord(qry, code); err != nil {
			s.logger.Error(fmt.Sprintf("failed to insert authcode record for %s", username), "err", err.Error())
			return
		}

		// persist account authcode xref to db
		qry = `INSERT into authcode_account (authcode_uuid, account_uuid, created_at) VALUES (?, ?, ?)`
		if err := s.db.InsertRecord(qry, xref); err != nil {
			s.logger.Error(fmt.Sprintf("failed to insert authcode_account xref record %s", username), "err", err.Error())
			return
		}
	}()

	return authCode.String(), nil
}

// get individual user's scopes uuids from account_scope table
func (s *service) getUserScopes(username string, wg *sync.WaitGroup, acctScopes *[]AccountScope) {

	defer wg.Done()

	// user index
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to generate user index for username %s", username), "err", err.Error())
	}

	qry := `
		SELECT
			asp.id,
			asp.account_uuid,
			asp.scope_uuid,
			asp.created_at
		FROM account_scope asp
			LEFT OUTER JOIN account a ON asp.account_uuid = a.uuid
		WHERE a.user_index = ?`

	var scopes []AccountScope
	if err := s.db.SelectRecords(qry, &scopes, index); err != nil {
		if err == sql.ErrNoRows {
			s.logger.Error(fmt.Sprintf("no scopes found for user %s", username), "err", err.Error())
			return
		} else {
			s.logger.Error(fmt.Sprintf("failed to retrieve scopes for user %s", username), "err", err.Error())
			return
		}
	}

	*acctScopes = scopes
}

// get scopes data from s2s scopes endpoint
func (s *service) getAllScopes(wg *sync.WaitGroup, scopes *[]types.Scope) {

	defer wg.Done()

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.s2sTokenProvider.GetServiceToken(util.S2sServiceName)
	if err != nil {
		s.logger.Error("failed to get s2s token: %v", "err", err.Error())
		return
	}

	// call scopes endpoint
	var s2sScopes []types.Scope
	if err := s.s2sCaller.GetServiceData("/scopes", s2stoken, "", &s2sScopes); err != nil {
		s.logger.Error("failed to get scopes data from s2s scopes endpoint", "err", err.Error())
		return
	}

	*scopes = s2sScopes
}
