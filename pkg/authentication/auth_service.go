package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"

	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration time.Duration = 15 // minutes
	RefreshDuration     time.Duration = 12 // hours
	IdTokenDuration     time.Duration = 60 // minutes
)

type Service interface {
	types.UserAuthService
	AuthErrService
}

// NewService creates an implementation of the user authentication service in the carapace session package.
func NewService(db data.SqlRepository, s jwt.Signer, i data.Indexer, c data.Cryptor, p provider.S2sTokenProvider, call connect.S2sCaller) Service {
	return &userAuthService{
		db:               db,
		mint:             s,
		indexer:          i,
		cryptor:          c,
		s2sTokenProvider: p,
		s2sCaller:        call,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

// AuthErrService is an interface for handling errors returned by the service methods and sending the appropriate error response to the client.
type AuthErrService interface {
	// HandleAuthErr handles errors returned by the service methods and sends the appropriate error response to the client.
	HandleServiceErr(err error, w http.ResponseWriter)
}

var _ Service = (*userAuthService)(nil)

type userAuthService struct {
	db               data.SqlRepository
	mint             jwt.Signer
	indexer          data.Indexer
	cryptor          data.Cryptor
	s2sTokenProvider provider.S2sTokenProvider
	s2sCaller        connect.S2sCaller

	logger *slog.Logger
}

// ValidateCredentials validates the user credentials for user authentication service
func (s *userAuthService) ValidateCredentials(username, password string) error {

	if len(username) < 5 || len(password) > 255 {
		return errors.New(ErrInvalidUsernamePassword)
	}

	if len(password) < 16 || len(password) > 64 {
		return errors.New(ErrInvalidUsernamePassword)
	}

	// create index for db lookup
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error(fmt.Sprintf("%s for user %s lookup", ErrGenerateIndex, username), "err", err.Error())
		return err
	}

	var user types.UserAccount
	qry := `
		SELECT 
			uuid,
			user_key,
			username,
			user_index,
			password,
			firstname,
			lastname,
			birth_date,
			created_at,
			enabled,
			account_expired,
			account_locked
		FROM account
		WHERE user_index = ?`
	if err := s.db.SelectRecord(qry, &user, userIndex); err != nil {
		s.logger.Error(fmt.Sprintf("failed to retrieve user record for %s", username), "err", err.Error())
		return errors.New(ErrInvalidUsernamePassword)
	}

	// validate password
	pw := []byte(password)
	hash := []byte(user.Password)
	if err := bcrypt.CompareHashAndPassword(hash, pw); err != nil {
		s.logger.Error("failed to validate user password", "err", err.Error())
		return errors.New(ErrInvalidUsernamePassword)
	}

	if !user.Enabled {
		s.logger.Error(fmt.Sprintf("user account %s is disabled", username))
		return fmt.Errorf("user %s account is disabled", username)
	}

	if user.AccountLocked {
		s.logger.Error(fmt.Sprintf("user account %s is locked", username))
		return fmt.Errorf("user %s account is locked", username)
	}

	if user.AccountExpired {
		s.logger.Error(fmt.Sprintf("user account %s is expired", username))
		return fmt.Errorf("user %s account is expired", username)
	}

	return nil
}

// GetUserScopes gets the user scopes for user authentication service so that an authcode record can be created.
// Note: service is not used in this implementation because a user's scopes are not service specific (yet).
func (s *userAuthService) GetScopes(username, service string) ([]types.Scope, error) {

	// get user's allScopes and all allScopes
	var (
		wg         sync.WaitGroup
		userScopes []AccountScope
		allScopes  []types.Scope
	)

	wg.Add(2)
	go s.lookupUserScopes(username, &wg, &userScopes)
	go s.getAllScopes(&wg, &allScopes)
	wg.Wait()

	// return error either call returns no scopes
	if len(userScopes) < 1 {
		return nil, fmt.Errorf("no scopes found for user (%s)", username)
	}
	if len(allScopes) < 1 {
		return nil, errors.New("no scopes returned from s2s scopes endpoint")
	}

	idSet := make(map[string]struct{})
	for _, scope := range userScopes {
		idSet[scope.ScopeUuid] = struct{}{}
	}

	// filter out scopes that user does not have
	var filtered []types.Scope
	for _, scope := range allScopes {
		if _, exists := idSet[scope.Uuid]; exists && scope.Active {
			filtered = append(filtered, scope)
		}
	}

	return filtered, nil
}

// lookupUserScopes gets individual user's scopes uuids from account_scope table.
// Note: returns uuids only.  Needs additional functionality to get the actual scope records
// from the scope table in the s2s service.
func (s *userAuthService) lookupUserScopes(username string, wg *sync.WaitGroup, acctScopes *[]AccountScope) {

	defer wg.Done()

	// user index
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error(fmt.Sprintf("%s for username %s", ErrGenerateIndex, username), "err", err.Error())
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

// getAllScopes gets scopes data objects/records from s2s scopes endpoint
func (s *userAuthService) getAllScopes(wg *sync.WaitGroup, scopes *[]types.Scope) {

	defer wg.Done()

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.s2sTokenProvider.GetServiceToken(util.ServiceNameS2s)
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

// MintToken mints the users access token token for user authentication service.
// It assumes that the user's credentials have been validated.
func (s *userAuthService) MintToken(claims jwt.Claims) (*jwt.Token, error) {

	// jwt header
	header := jwt.Header{
		Alg: "HS256",
		Typ: jwt.TokenType,
	}

	jot := jwt.Token{
		Header: header,
		Claims: claims,
	}

	// sign jwt token
	if err := s.mint.Mint(&jot); err != nil {
		return nil, fmt.Errorf("failed to sign token jwt: %v", err)
	}

	return &jot, nil
}

// Concrete implementations of the refresh token for user authentication service.

// GetRefreshToken retreives a refresh token by recreating the blind index, selecting, and then decrypting the record.
func (s *userAuthService) GetRefreshToken(refreshToken string) (*types.UserRefresh, error) {

	// TDOO: implement get refresh token
	return nil, nil
}

// PersistRefresh persists the refresh token for user authentication service.
// It encrypts the refresh token and creates the primary key and blind index before persisting it.
func (s *userAuthService) PersistRefresh(r types.UserRefresh) error {

	var (
		wgRecord          sync.WaitGroup
		id                uuid.UUID
		refreshIndex      string
		encryptedClientId string
		encryptedRefresh  string
		encryptedUsername string
		usernameIndex     string
	)
	errChan := make(chan error, 6)

	// create primary key
	wgRecord.Add(1)
	go func(id *uuid.UUID, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to generate uuid for refresh token: %v", err)
			return
		}
		*id = i
	}(&id, errChan, &wgRecord)

	// create blind index
	wgRecord.Add(1)
	go func(index *string, refresh string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		ndx, err := s.indexer.ObtainBlindIndex(refresh)
		if err != nil {
			ch <- fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refresh[len(refresh)-6:], err)
			return
		}
		*index = ndx
	}(&refreshIndex, r.RefreshToken, errChan, &wgRecord)

	// encrypt client id
	wgRecord.Add(1)
	go func(clientId string, encryptedClientId *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(clientId)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt client id %s: %v", clientId, err)
			return
		}
		*encryptedClientId = encrypted
	}(r.ClientId, &encryptedClientId, errChan, &wgRecord)

	// create encrypt refresh token
	wgRecord.Add(1)
	go func(refreshToken string, encryptedRefresh *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(refreshToken)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt refresh token xxxxxx-%s: %v", refreshToken[len(refreshToken)-6:], err)
			return
		}
		*encryptedRefresh = encrypted
	}(r.RefreshToken, &encryptedRefresh, errChan, &wgRecord)

	// encrypt username
	wgRecord.Add(1)
	go func(username string, encryptedUsername *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(username)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt username %s: %v", username, err)
			return
		}
		*encryptedUsername = encrypted
	}(r.Username, &encryptedUsername, errChan, &wgRecord)

	// create username index
	wgRecord.Add(1)
	go func(username string, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		ndx, err := s.indexer.ObtainBlindIndex(username)
		if err != nil {
			ch <- fmt.Errorf("%s for username %s: %v", ErrGenerateIndex, username, err)
			return
		}
		*index = ndx
	}(r.Username, &usernameIndex, errChan, &wgRecord)

	// wait for all go routines to finish
	wgRecord.Wait()
	close(errChan)

	// consolidate errors
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
		return fmt.Errorf("failed to persist refresh token: %s", builder.String())
	}

	// update refresh struct
	r.Uuid = id.String()
	r.RefreshIndex = refreshIndex
	r.ClientId = encryptedClientId
	r.RefreshToken = encryptedRefresh
	r.Username = encryptedUsername
	r.UsernameIndex = usernameIndex

	// insert record
	qry := `INSERT INTO refresh (uuid, refresh_index, client_id, refresh_token, username, username_index, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, r); err != nil {
		return fmt.Errorf("failed to insert refresh token record: %v", err)
	}

	return nil
}

// DestroyRefresh removes the refresh token from the persistence store.
func (s *userAuthService) DestroyRefresh(refreshToken string) error {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	// create blind index
	index, err := s.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	if exists, err := s.db.SelectExists(qry, index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist", refreshToken[len(refreshToken)-6:])
	}

	// delete record
	qry = `DELETE FROM refresh WHERE refresh_index = ?`
	if err := s.db.DeleteRecord(qry, index); err != nil {
		return fmt.Errorf("failed to delete refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	return nil
}

// RevokeRefresh revokes the user refresh token by updating the record in the persistence store.
func (s *userAuthService) RevokeRefresh(refreshToken string) error {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return errors.New("invalid refresh token")
	}

	// create blind index
	index, err := s.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	if exists, err := s.db.SelectExists(qry, index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist", refreshToken[len(refreshToken)-6:])
	}

	// update record to revoked
	qry = `UPDATE refresh SET revoked = ? WHERE refresh_index = ?`
	if err := s.db.UpdateRecord(qry, true, index); err != nil {
		return fmt.Errorf("failed to revoke refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	return nil
}

func (s *userAuthService) HandleServiceErr(err error, w http.ResponseWriter) {
	switch {

	// 401
	case strings.Contains(err.Error(), ErrInvalidUsernamePassword):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrInvalidUsernamePassword,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserDisabled):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserDisabled),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserLocked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserLocked),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserExipred):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserExipred),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "not found"):
	case strings.Contains(err.Error(), "does not exist"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    "not found",
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "invalid refresh token"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid refresh token",
		}
		e.SendJsonErr(w)
		return
	default:
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

}
