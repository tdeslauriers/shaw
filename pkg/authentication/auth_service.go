package authentication

import (
	"errors"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"shaw/pkg/scope"
	"time"

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
	types.AuthService
	types.RefreshService[types.UserRefresh]
	AuthErrService
}

// NewService creates an implementation of the user authentication service in the carapace session package.
func NewService(db data.SqlRepository, s jwt.Signer, i data.Indexer, c data.Cryptor, p provider.S2sTokenProvider, call connect.S2sCaller) Service {
	return &service{
		AuthService:    NewAuthService(db, s, i, p, call),
		RefreshService: NewRefreshService(db, i, c),
		AuthErrService: NewAuthErrService(),
	}
}

var _ Service = (*service)(nil)

type service struct {
	types.AuthService
	types.RefreshService[types.UserRefresh]
	AuthErrService
}

// NewAuthService creates an implementation of the user authentication service in the carapace session package.
func NewAuthService(db data.SqlRepository, s jwt.Signer, i data.Indexer, p provider.S2sTokenProvider, call connect.S2sCaller) types.AuthService {
	return &authService{
		db:      db,
		mint:    s,
		indexer: i,
		scopes:  scope.NewScopesService(db, i, p, call),

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ types.AuthService = (*authService)(nil)

// authService is a concrete implementation of the user authentication service in the carapace session package.
type authService struct {
	db      data.SqlRepository
	mint    jwt.Signer
	indexer data.Indexer
	scopes  scope.ScopesService

	logger *slog.Logger
}

// ValidateCredentials validates the user credentials for user authentication service
func (s *authService) ValidateCredentials(username, password string) error {

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
func (s *authService) GetScopes(username, service string) ([]types.Scope, error) {

	// get user's scopes
	return s.scopes.GetUserScopes(username, service)
}

// MintToken mints the users access token token for user authentication service.
// It assumes that the user's credentials have been validated.
func (s *authService) MintToken(claims jwt.Claims) (*jwt.Token, error) {

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
