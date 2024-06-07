package authentication

import (
	"errors"
	"fmt"
	"log/slog"
	"shaw/internal/util"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
	"golang.org/x/crypto/bcrypt"
)

// NewUserAuthService creates an implementation of the user authentication service in the carapace session package.
func NewUserAuthService(sql data.SqlRepository, mint jwt.JwtSigner, indexer data.Indexer, cryptor data.Cryptor) session.UserAuthService {
	return &userAuthService{
		sql:     sql,
		mint:    mint,
		indexer: indexer,
		cryptor: cryptor,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ session.UserAuthService = (*userAuthService)(nil)

type userAuthService struct {
	sql     data.SqlRepository
	mint    jwt.JwtSigner
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// ValidateCredentials validates the user credentials for user authentication service
func (s *userAuthService) ValidateCredentials(username, password string) error {

	// create index for db lookup
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error("failed to obtain blind index for user lookup", "err", err.Error())
		return err
	}

	var user session.UserAccountData
	qry := `
		SELECT 
			uuid,
			username,
			user_index,
			password,
			firstname,
			lastname,
			birthdate,
			created_at,
			enabled,
			account_expired,
			account_locked
		FROM account
		WHERE user_index = ?`
	if err := s.sql.SelectRecord(qry, &user, userIndex); err != nil {
		s.logger.Error(fmt.Sprintf("failed to retrieve user record for %s", username), "err", err.Error())
		return errors.New("invalid username or password")
	}

	// validate password
	pw := []byte(password)
	hash := []byte(user.Password)
	if err := bcrypt.CompareHashAndPassword(hash, pw); err != nil {
		s.logger.Error("failed to validate user password", "err", err.Error())
		return errors.New("invalid username or password")
	}

	if !user.Enabled {
		s.logger.Error(fmt.Sprintf("user account %s is disabled", username))
		return fmt.Errorf("user account %s is disabled", username)
	}

	if user.AccountLocked {
		s.logger.Error(fmt.Sprintf("user account %s is locked", username))
		return fmt.Errorf("user account %s is locked", username)
	}

	if user.AccountExpired {
		s.logger.Error(fmt.Sprintf("user account %s is expired", username))
		return fmt.Errorf("user account %s is expired", username)
	}

	return nil
}

// GetUserScopes gets the user scopes for user authentication service so that a token can be minted
func (s *userAuthService) GetUserScopes(uuid, service string) ([]session.Scope, error) {

	// TDOO: implement get user scopes
	return nil, nil
}

// MintAuthToken mints the users access token token for user authentication service.
// It assumes that the user's credentials have been validated.
func (s *userAuthService) MintAuthzToken(subject, service string) (*jwt.JwtToken, error) {

	// TDOO: implement mint authz token
	return nil, nil
}

// GetRefreshToken retreives a refresh token by recreating the blind index, selecting, and then decrypting the record.
func (s *userAuthService) GetRefreshToken(refreshToken string) (*session.UserRefresh, error) {

	// TDOO: implement get refresh token
	return nil, nil
}

// PersistRefresh persists the refresh token for user authentication service.
// It encrypts the refresh token and creates the blind index before persisting it.
func (s *userAuthService) PersistRefresh(r session.UserRefresh) error {

	// TDOO: implement persist refresh
	return nil
}
