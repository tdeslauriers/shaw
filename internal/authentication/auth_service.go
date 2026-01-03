package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
	"github.com/tdeslauriers/shaw/internal/creds"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/scope"

	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration time.Duration = 15 // minutes
	RefreshDuration     time.Duration = 12 // hours
	IdTokenDuration     time.Duration = 60 // minutes
)

// AuthService is an interface for authentication services that validates credentials,
// gets user scopes, and mints authorization tokens
type AuthService interface {
	// ValidateCredentials validates credentials provided by client, whether s2s or user
	ValidateCredentials(id, secret string) error

	// GetScopes gets scopes specific to a service for a given identifier.
	// 'user' parameter can be a username or a client id.
	GetScopes(ctx context.Context, user, service string) ([]scopes.Scope, error)

	// MintToken builds and signs a jwt token for a given claims struct.
	// It does not validate or perform checks on these values, it assumes they are valid.
	MintToken(claims jwt.Claims) (*jwt.Token, error)
}

// NewAuthService creates an implementation of the user authentication service in the carapace session package.
func NewAuthService(
	db *sql.DB,
	s jwt.Signer,
	i data.Indexer,
	p provider.S2sTokenProvider,
	s2s *connect.S2sCaller,
) AuthService {

	return &authService{
		db:      NewAuthRepository(db),
		mint:    s,
		indexer: i,
		creds:   creds.NewService(),
		scopes:  scope.NewScopesService(db, i, p, s2s),

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ AuthService = (*authService)(nil)

// authService is a concrete implementation of the user authentication service in the carapace session package.
type authService struct {
	db      AuthRepository
	mint    jwt.Signer
	indexer data.Indexer
	creds   creds.Service
	scopes  scope.ScopesService

	logger *slog.Logger
}

// ValidateCredentials validates the user credentials for user authentication service
func (s *authService) ValidateCredentials(username, password string) error {

	if len(username) < 5 || len(password) > 255 {
		s.logger.Error(fmt.Sprintf("username %s is either either too short or too long", username),
			"err", fmt.Sprintf("expected between 5 adn 255; username length: %d", len(username)))
		return errors.New(ErrInvalidUsernamePassword)
	}

	if len(password) < 16 || len(password) > 64 {
		s.logger.Error(fmt.Sprintf("password for user %s is either too short or too long", username),
			"err", fmt.Sprintf("expected between 16 and 64; password length: %d", len(password)))
		return errors.New(ErrInvalidUsernamePassword)
	}

	// create index for db lookup
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error(fmt.Sprintf("%s for user %s lookup", ErrGenerateIndex, username), "err", err.Error())
		return errors.New(ErrInvalidUsernamePassword)
	}

	// find user account in persistence
	user, err := s.db.FindUserAccount(userIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			s.logger.Error(fmt.Sprintf("user not found: %s", username), "err", err.Error())
			return errors.New(ErrInvalidUsernamePassword)
		} else {
			s.logger.Error(fmt.Sprintf("failed to query user account for user %s", username), "err", err.Error())
			return fmt.Errorf("failed to query user account for user %s: %v", username, err)
		}
	}

	if !user.Enabled {
		return fmt.Errorf("user %s account is disabled", username)
	}

	if user.AccountLocked {
		return fmt.Errorf("user %s account is locked", username)
	}

	if user.AccountExpired {
		return fmt.Errorf("user %s account is expired", username)
	}

	// validate password
	// check if user is using legacy bcrypt password
	// if not, use argon2id verification
	// if legacy, use bcrypt verification and silently convert to argon2id hash
	if !user.Legacy {
		// argon2id verification
		// user is using argon2id password
		valid, err := s.creds.VerifyPassword(password, user.Password)
		if err != nil {
			// with will be for formatting errors or decoding errors
			s.logger.Error("failed to validate user password", "err", err.Error())
			return errors.New(ErrInvalidUsernamePassword)
		}

		if !valid {
			// invalid password
			s.logger.Error("invalid user password")
			return errors.New(ErrInvalidUsernamePassword)
		}
		return nil
	} else {

		// bcrypt verification
		pw := []byte(password)
		hash := []byte(user.Password)
		if err := bcrypt.CompareHashAndPassword(hash, pw); err != nil {
			s.logger.Error("failed to validate user password", "err", err.Error())
			return errors.New(ErrInvalidUsernamePassword)
		}

		// silently convert to argon2id hash
		go func(pw, ind string) {

			newHash, err := s.creds.HashPassword(pw)
			if err != nil {
				// log only, do not return error to user
				s.logger.Error("failed to silently convert user password to argon2id hash", "err", err.Error())
				return
			}

			// save over the old bcrypt hash with new argon2id hash and set legacy to false
			if err := s.db.UpdateLegacyPassword(false, newHash, ind); err != nil {
				// log only, do not return error to user
				s.logger.Error("failed to update user password to argon2id hash", "err", err.Error())
				return
			}

			s.logger.Info(fmt.Sprintf("silently converted user %s password to argon2id hash", username))
		}(password, userIndex)

		return nil
	}
}

// GetUserScopes gets the user scopes for user authentication service so that an authcode record can be created.
// Note: service is not used in this implementation because a user's scopes are not service specific (yet).
func (s *authService) GetScopes(ctx context.Context, username, service string) ([]scopes.Scope, error) {

	// get user's scopes
	return s.scopes.GetUserScopes(ctx, username, service)
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
