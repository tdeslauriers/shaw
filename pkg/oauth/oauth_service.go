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
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

type Service interface {
	// IsVaildRedirect validates the client and redirect url exist, are linked, and are enabled/not expired/not locked
	IsValidRedirect(clientid, url string) (bool, error)

	// IsValidClient validates the client and user are linked, enabled, not expired, not locked
	IsValidClient(clientid, username string) (bool, error)

	// GenerateAuthCode generates an auth code for and persists it to the db along with the user's scopes, the client, and the redirect url,
	// associating it with the user so that it can be used to mint a token on callback from the client
	GenerateAuthCode(username, client, redirect string, scopes []types.Scope) (string, error)

	// RetrieveUserData retrieves the user data associated with the auth code, if it exists and is valid.
	// If any of the data provided in the AccessTokenCmd is invalid, an error is returned.
	RetrieveUserData(cmd types.AccessTokenCmd) (*OauthUserData, error)
}

func NewService(db data.SqlRepository, c data.Cryptor, i data.Indexer) Service {
	return &service{
		db:      db,
		cipher:  c,
		indexer: i,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentOauthFlow)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db      data.SqlRepository
	cipher  data.Cryptor
	indexer data.Indexer

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
		return false, fmt.Errorf("failed to generate user index for %s: %v", username, err)
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
func (s *service) GenerateAuthCode(username, clientId, redirect string, scopes []types.Scope) (string, error) {

	// check for empty fields: redundant check, but good practice
	if username == "" || clientId == "" || redirect == "" || len(scopes) == 0 {
		switch {
		case username == "":
			return "", errors.New("failed to generate auth code: username is empty")
		case clientId == "":
			return "", errors.New("failed to generate auth code: client id is empty")
		case redirect == "":
			return "", errors.New("failed to generate auth code: redirect url is empty")
		case len(scopes) == 0:
			return "", errors.New("failed to generate auth code: scopes are empty")
		}
	}

	var (
		wg                sync.WaitGroup
		userId            string
		authCodeId        uuid.UUID
		authCode          uuid.UUID
		authCodeIndex     string
		encryptedAuthCode string
		encryptedClientId string
		encryptedRedirect string
		encryptedScopes   string
	)
	errChan := make(chan error, 6)

	// get user uuid from account table
	wg.Add(1)
	go func(username string, id *string, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		userIndex, err := s.indexer.ObtainBlindIndex(username)
		if err != nil {
			errs <- fmt.Errorf("failed to generate user index for %s: %v", username, err)
			return
		}

		qry := `SELECT uuid FROM account WHERE user_index = ?`
		if err := s.db.SelectRecord(qry, &id, userIndex); err != nil {
			errs <- fmt.Errorf("failed to retrieve user uuid for %s: %v", username, err)
		}
	}(username, &userId, errChan, &wg)

	// build auth code record
	// generate auth code id
	wg.Add(1)
	go func(authCodeId *uuid.UUID, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		id, err := uuid.NewRandom()
		if err != nil {
			errs <- fmt.Errorf("failed to generate auth code id: %v", err)
			return
		}
		*authCodeId = id
	}(&authCodeId, errChan, &wg)

	// generate auth code, blind index, and encrypt auth code for persistence
	wg.Add(1)
	go func(authCode *uuid.UUID, authCodeIndex, encryptedAuthCode *string, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		code, err := uuid.NewRandom()
		if err != nil {
			errs <- fmt.Errorf("failed to generate auth code: %v", err)
			return
		}
		*authCode = code

		index, err := s.indexer.ObtainBlindIndex(code.String())
		if err != nil {
			errs <- fmt.Errorf("failed to generate auth code index: %v", err)
			return
		}
		*authCodeIndex = index

		encrypted, err := s.cipher.EncryptServiceData(authCode.String())
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt auth code: %v", err)
			return
		}
		*encryptedAuthCode = encrypted
	}(&authCode, &authCodeIndex, &encryptedAuthCode, errChan, &wg)

	// encrypt client id
	wg.Add(1)
	go func(clientId string, encryptedClientId *string, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(clientId)
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt client id: %v", err)
			return
		}
		*encryptedClientId = encrypted
	}(clientId, &encryptedClientId, errChan, &wg)

	// encrypt redirect url
	wg.Add(1)
	go func(redirect string, encryptedRedirect *string, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(redirect)
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt redirect url: %v", err)
			return
		}
		*encryptedRedirect = encrypted
	}(redirect, &encryptedRedirect, errChan, &wg)

	// encrypt scopes
	wg.Add(1)
	go func(scopes []types.Scope, encryptedScopes *string, errs chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// build scopes string
		var builder strings.Builder
		for i, scope := range scopes {
			builder.WriteString(scope.Scope)
			if i < len(scopes)-1 {
				builder.WriteString(" ")
			}
		}

		encrypted, err := s.cipher.EncryptServiceData(builder.String())
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt generaed scopes string: %v", err)
			return
		}
		*encryptedScopes = encrypted
	}(scopes, &encryptedScopes, errChan, &wg)

	// wait for all value generation goroutines to finish
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// consolidate and return any errors
	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return "", fmt.Errorf("failed to generate auth code: %v", builder.String())
	}

	// create auth code and authcode-account xref records for persistance
	createdAt := time.Now()

	code := AuthCode{
		Id:            authCodeId.String(),
		AuthCodeIndex: authCodeIndex,
		Authcode:      encryptedAuthCode,
		ClientId:      encryptedClientId,
		RedirectUrl:   encryptedRedirect,
		Scopes:        encryptedScopes,
		CreatedAt:     createdAt.Format("2006-01-02 15:04:05"),
		Claimed:       false,
		Revoked:       false,
	}

	xref := AuthcodeAccount{
		AuthcodeUuid: code.Id,
		AccountUuid:  userId,
		CreatedAt:    createdAt.Format("2006-01-02 15:04:05"),
	}

	var wgPersist sync.WaitGroup
	var errPersistChan = make(chan error, 2)

	// persist auth code to db
	wgPersist.Add(1)
	go func(code AuthCode, errs chan error, wg *sync.WaitGroup) {
		defer wgPersist.Done()

		qry := `INSERT into authcode (uuid, authcode_index, authcode, client_uuid, redirect_url, scopes, created_at, claimed, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
		if err := s.db.InsertRecord(qry, code); err != nil {
			errPersistChan <- fmt.Errorf("failed to insert authcode record for %s into db: %v", username, err)
			return
		}
	}(code, errPersistChan, &wgPersist)

	// persist account authcode xref to db
	wgPersist.Add(1)
	go func(xref AuthcodeAccount, errs chan error, wg *sync.WaitGroup) {
		defer wgPersist.Done()

		qry := `INSERT into authcode_account (authcode_uuid, account_uuid, created_at) VALUES (?, ?, ?)`
		if err := s.db.InsertRecord(qry, xref); err != nil {
			errPersistChan <- fmt.Errorf("failed to insert authcode_account xref record for %s into db: %v", username, err)
			return
		}
	}(xref, errPersistChan, &wgPersist)

	// wait for persistence activities to finish
	go func() {
		wgPersist.Wait()
		close(errPersistChan)
	}()

	// consolidate and return any errors
	if len(errPersistChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range errPersistChan {
			builder.WriteString(e.Error())
			if count < len(errPersistChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return "", fmt.Errorf("failed to generate auth code: %v", builder.String())
	}

	return authCode.String(), nil
}

func (s *service) RetrieveUserData(cmd types.AccessTokenCmd) (*OauthUserData, error) {

	// check for empty fields: redundant check, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		return nil, fmt.Errorf("%s: %v", ErrValidateAuthCode, err)
	}

	// recreate auth code index
	index, err := s.indexer.ObtainBlindIndex(cmd.AuthCode)
	if err != nil {
		return nil, fmt.Errorf("%s for auth code xxxxxx-%s: %v", ErrGenAuthCodeIndex, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// pulling back all data for the auth code/account so any errors
	// can be directly referenced vs a restrictive query
	qry := `SELECT 
				a.username, 
				a.firstname,
				a.lastname,
				a.birthdate,
				a.enabled,
				a.account_expired,
				a.account_locked,
				ac.client_id,
				ac.redirect_url,
				ac.scopes,
				ac.claimed, 
				ac.revoked
			FROM authcode ac 
				LEFT OUTER JOIN authcode_account aac ON ac.uuid = aac.authcode_uuid
				LEFT OUTER JOIN account a ON aac.account_uuid = a.uuid
			WHERE ac.authcode_index = ?`

	var user OauthUserData
	if err := s.db.SelectRecord(qry, &user, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %v", ErrIndexNotFound, err)
		} else {
			return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrFailedLookupIndex, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
		}
	}

	// perform expiry, enabled, etc., checks before decryption
	// check authcode expiry
	now := time.Now().UTC()
	if user.AuthcodeCreatedAt.Add(5 * time.Minute).Before(now) {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeExpired, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check if auth code has already been claimed
	if user.AuthcodeClaimed {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeClaimed, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check if authcode revoked
	if user.AuthcodeRevoked {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeRevoked, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check if user is disabled: redundant, authcode should never have been generated
	if !user.Enabled {
		return nil, fmt.Errorf("%s (%s): %v", ErrUserDisabled, user.Username, err)
	}

	// check if user account expired
	if user.AccountExpired {
		return nil, fmt.Errorf("%s (%s): %v", ErrUserAccountExpired, user.Username, err)
	}

	// check if user account locked
	if user.AccountLocked {
		return nil, fmt.Errorf("%s (%s): %v", ErrUserAccountLocked, user.Username, err)
	}

	// TODO: decrypt data, perform checks, and return user data

	return &OauthUserData{}, nil
}
