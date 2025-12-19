package oauth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	ran "github.com/tdeslauriers/ran/pkg/api/scopes"
	"github.com/tdeslauriers/shaw/internal/util"
	"github.com/tdeslauriers/shaw/pkg/api/oauth"
)

func NewService(db *sql.DB, i data.Indexer, c data.Cryptor) Service {
	return &service{
		db:      NewOAuthRepository(db),
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageOauth)).
			With(slog.String(util.ComponentKey, util.ComponentOauthFlow)),
	}
}

// Service is the interface for the oauth service functionality like validating clients and redirect urls, generating auth codes, and retrieving user data associated with an auth code.
type Service interface {
	// IsVaildRedirect validates the client and redirect url exist, are linked, and are enabled/not expired/not locked
	IsValidRedirect(clientid, url string) (bool, error)

	// IsValidClient validates the client and user are linked, enabled, not expired, not locked
	IsValidClient(clientid, username string) (bool, error)

	// GenerateAuthCode generates an auth code for and persists it to the db along with the user's scopes, nonce, the client, and the redirect url,
	// associating it with the user so that it can be used to mint an access token and Id token on callback from the client
	GenerateAuthCode(username, nonce, client, redirect string, scopes []ran.Scope) (string, error)

	// RetrieveUserData retrieves the user data associated with the auth code, if it exists and is valid.
	// If any of the data provided in the AccessTokenCmd is invalid, an error is returned.
	RetrieveUserData(cmd oauth.AccessTokenCmd) (*OauthUserData, error)
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the OauthService interface
type service struct {
	db      OAuthRepository
	indexer data.Indexer
	cryptor data.Cryptor

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
	result, err := s.db.FindClientRedirect(clientId, snipped.String())
	if err != nil {
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
	result, err := s.db.FindAccountClient(index, clientId)
	if err != nil {
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
func (s *service) GenerateAuthCode(username, nonce, clientId, redirect string, scopes []ran.Scope) (string, error) {

	// check for empty fields: redundant check, but good practice
	if username == "" || nonce == "" || clientId == "" || redirect == "" || len(scopes) == 0 {
		switch {
		case username == "":
			return "", errors.New("failed to generate auth code: username is empty")
		case nonce == "":
			return "", errors.New("failed to generate auth code: nonce is empty")
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
		encryptedNonce    string
		encryptedClientId string
		encryptedRedirect string
		encryptedScopes   string
	)
	errChan := make(chan error, 7)

	// get user uuid from account table
	wg.Add(1)
	go func(
		username string,
		id *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		userIndex, err := s.indexer.ObtainBlindIndex(username)
		if err != nil {
			errs <- fmt.Errorf("failed to generate user index for %s: %v", username, err)
			return
		}

		// only need the user uuid
		user, err := s.db.FindUserAccount(userIndex)
		if err != nil {
			errs <- fmt.Errorf("failed to retrieve user uuid for %s: %v", username, err)
		}

		*id = user.Uuid
	}(
		username,
		&userId,
		errChan,
		&wg,
	)

	// build auth code record
	// generate auth code primary key/id
	wg.Add(1)
	go func(
		authCodeId *uuid.UUID,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		id, err := uuid.NewRandom()
		if err != nil {
			errs <- fmt.Errorf("failed to generate auth code id: %v", err)
			return
		}
		*authCodeId = id
	}(
		&authCodeId,
		errChan,
		&wg,
	)

	// generate auth code, blind index, and encrypt auth code for persistence
	wg.Add(1)
	go func(
		authCode *uuid.UUID,
		authCodeIndex *string,
		encryptedAuthCode *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

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

		encrypted, err := s.cryptor.EncryptServiceData([]byte(authCode.String()))
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt auth code: %v", err)
			return
		}
		*encryptedAuthCode = encrypted
	}(
		&authCode,
		&authCodeIndex,
		&encryptedAuthCode,
		errChan,
		&wg,
	)

	// encrypt nonce
	wg.Add(1)
	go func(
		nonce string,
		encryptedNonce *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(nonce))
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt nonce: %v", err)
			return
		}
		*encryptedNonce = encrypted
	}(
		nonce,
		&encryptedNonce,
		errChan,
		&wg,
	)

	// encrypt client id
	wg.Add(1)
	go func(
		clientId string,
		encryptedClientId *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(clientId))
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt client id: %v", err)
			return
		}
		*encryptedClientId = encrypted
	}(
		clientId,
		&encryptedClientId,
		errChan,
		&wg,
	)

	// encrypt redirect url
	wg.Add(1)
	go func(
		redirect string,
		encryptedRedirect *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(redirect))
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt redirect url: %v", err)
			return
		}
		*encryptedRedirect = encrypted
	}(
		redirect,
		&encryptedRedirect,
		errChan,
		&wg,
	)

	// encrypt scopes
	wg.Add(1)
	go func(
		scopes []ran.Scope,
		encryptedScopes *string,
		errs chan error,
		wg *sync.WaitGroup,
	) {

		defer wg.Done()

		// build scopes string
		var builder strings.Builder
		for i, scope := range scopes {
			builder.WriteString(scope.Scope)
			if i < len(scopes)-1 {
				builder.WriteString(" ")
			}
		}

		encrypted, err := s.cryptor.EncryptServiceData([]byte(builder.String()))
		if err != nil {
			errs <- fmt.Errorf("failed to encrypt generaed scopes string: %v", err)
			return
		}
		*encryptedScopes = encrypted
	}(
		scopes,
		&encryptedScopes,
		errChan,
		&wg,
	)

	// wait for all value generation goroutines to finish

	wg.Wait()
	close(errChan)

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
	createdAt := time.Now().UTC()

	code := AuthCode{
		Id:            authCodeId.String(),
		AuthCodeIndex: authCodeIndex,
		Authcode:      encryptedAuthCode,
		Nonce:         encryptedNonce,
		ClientId:      encryptedClientId,
		RedirectUrl:   encryptedRedirect,
		Scopes:        encryptedScopes,
		CreatedAt:     createdAt.Format("2006-01-02 15:04:05"),
		Claimed:       false,
		Revoked:       false,
	}

	if err := s.db.InsertAuthcode(code); err != nil {
		return "", fmt.Errorf("failed to insert authcode record for %s into db: %v", username, err)
	}

	xref := AuthcodeAccount{
		AuthcodeUuid: code.Id,
		AccountUuid:  userId,
		CreatedAt:    createdAt.Format("2006-01-02 15:04:05"),
	}

	// cannot use concurrency because of foreign key constraints parent table uuids.
	if err := s.db.InsertAuthcodeAccountXref(xref); err != nil {
		return "", fmt.Errorf("failed to insert authcode_account xref record for %s into db: %v", username, err)
	}

	return authCode.String(), nil
}

func (s *service) RetrieveUserData(cmd oauth.AccessTokenCmd) (*OauthUserData, error) {

	// check for empty fields: redundant check, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		return nil, fmt.Errorf("%s: %v", ErrValidateAuthCode, err)
	}

	// authorization code grant type is the only supported grant type within this service
	if cmd.Grant != oauth.AuthorizationCode {
		return nil, fmt.Errorf("%s for auth code xxxxxx-%s: %s", ErrInvalidGrantType, cmd.AuthCode[len(cmd.AuthCode)-6:], cmd.Grant)
	}

	// recreate auth code index
	index, err := s.indexer.ObtainBlindIndex(cmd.AuthCode)
	if err != nil {
		return nil, fmt.Errorf("%s for auth code xxxxxx-%s: %v", ErrGenAuthCodeIndex, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// pulling back all data for the auth code/account so any errors
	// can be directly referenced vs a restrictive query
	user, err := s.db.FindOauthUserData(index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %v", ErrIndexNotFound, err)
		} else {
			return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrFailedLookupIndex, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
		}
	}

	// perform expiry, revoked, enabled, etc., checks before decryption
	// check if authcode revoked
	if user.AuthcodeRevoked {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeRevoked, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check if auth code has already been claimed
	if user.AuthcodeClaimed {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeClaimed, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check authcode expiry
	now := time.Now().UTC()
	if user.AuthcodeCreatedAt.Add(5 * time.Minute).Before(now) {
		return nil, fmt.Errorf("%s (xxxxxx-%s): %v", ErrAuthcodeExpired, cmd.AuthCode[len(cmd.AuthCode)-6:], err)
	}

	// check if user is disabled
	// redundant, authcode should never have been generated
	if !user.Enabled {
		return nil, fmt.Errorf("authcode xxxxxx-%s: %s", cmd.AuthCode[len(cmd.AuthCode)-6:], ErrUserDisabled)
	}

	// check if user account locked
	// redundant, authcode should never have been generated
	if user.AccountLocked {
		return nil, fmt.Errorf("authcode xxxxxx-%s: %s", cmd.AuthCode[len(cmd.AuthCode)-6:], ErrUserAccountLocked)
	}

	// check if user account expired
	// redundant, authcode should never have been generated
	if user.AccountExpired {
		return nil, fmt.Errorf("authcode xxxxxx-%s: %s", cmd.AuthCode[len(cmd.AuthCode)-6:], ErrUserAccountExpired)
	}

	// decrypt data
	var (
		wg sync.WaitGroup

		decryptedUsername    []byte
		decryptedFirstname   []byte
		decryptedLastname    []byte
		decryptedBirthdate   []byte
		decryptedAuthcode    []byte
		decryptedNonce       []byte
		decryptedClientId    []byte
		decryptedRedirectUrl []byte
		decryptedScopes      []byte

		errChan = make(chan error, 9)
	)

	wg.Add(1)
	go s.decrypt(
		user.Username,
		ErrDecryptUsername,
		&decryptedUsername,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.Firstname,
		ErrDecryptFirstname,
		&decryptedFirstname,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.Lastname,
		ErrDecryptLastname,
		&decryptedLastname,
		errChan,
		&wg,
	)

	if user.BirthDate != "" {
		wg.Add(1)
		go s.decrypt(
			user.BirthDate,
			ErrDecryptBirthdate,
			&decryptedBirthdate,
			errChan,
			&wg,
		)
	}

	wg.Add(1)
	go s.decrypt(
		user.Authcode,
		ErrDecryptAuthcode,
		&decryptedAuthcode,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.Nonce,
		ErrDecryptNonce,
		&decryptedNonce,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.ClientId,
		ErrDecryptClientid,
		&decryptedClientId,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.RedirectUrl,
		ErrDecryptRedirecturl,
		&decryptedRedirectUrl,
		errChan,
		&wg,
	)

	wg.Add(1)
	go s.decrypt(
		user.Scopes,
		ErrDecryptScopes,
		&decryptedScopes,
		errChan,
		&wg,
	)

	// wait for all decryption goroutines to finish
	wg.Wait()
	close(errChan)

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
		return nil, fmt.Errorf("%s for auth code (xxxxxx-%s): %v", ErrFailedDecrypt, cmd.AuthCode[len(cmd.AuthCode)-6:], builder.String())
	}

	// validate cmd data against decrypted data
	// authcode mismatch should not happen since auth code generates the lookup index
	if cmd.AuthCode != string(decryptedAuthcode) {
		return nil, fmt.Errorf("%s for auth code (xxxxxx-%s)", ErrMismatchAuthcode, cmd.AuthCode[len(cmd.AuthCode)-6:])
	}

	// check client id submitted matches decrypted client id
	if cmd.ClientId != string(decryptedClientId) {
		return nil, fmt.Errorf("%s for auth code (xxxxxx-%s)", ErrMismatchClientid, cmd.AuthCode[len(cmd.AuthCode)-6:])
	}

	// check redirect url submitted matches decrypted redirect url
	if cmd.RedirectUrl != string(decryptedRedirectUrl) {
		return nil, fmt.Errorf("%s for auth code (xxxxxx-%s)", ErrMismatchRedirect, cmd.AuthCode[len(cmd.AuthCode)-6:])
	}

	// build and return user data
	return &OauthUserData{
		Username:       string(decryptedUsername),
		Firstname:      string(decryptedFirstname),
		Lastname:       string(decryptedLastname),
		BirthDate:      string(decryptedBirthdate),
		Enabled:        user.Enabled,
		AccountExpired: user.AccountExpired,
		AccountLocked:  user.AccountLocked,

		Authcode:          string(decryptedAuthcode),
		Nonce:             string(decryptedNonce),
		ClientId:          string(decryptedClientId),
		RedirectUrl:       string(decryptedRedirectUrl),
		Scopes:            string(decryptedScopes),
		AuthcodeCreatedAt: user.AuthcodeCreatedAt,
		AuthcodeClaimed:   user.AuthcodeClaimed,
		AuthcodeRevoked:   user.AuthcodeRevoked,
	}, nil
}

// decrypt is a helper function to absract the decryption process for the user data fields
func (s *service) decrypt(encrypted, errMsg string, clear *[]byte, ch chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	decrypted, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*clear = decrypted
}
