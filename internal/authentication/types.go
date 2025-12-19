package authentication

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

const (

	// 401
	ErrInvalidUsernamePassword = "invalid username or password"
	ErrUserExipred             = "account is expired"
	ErrUserLocked              = "account is locked"
	ErrUserDisabled            = "account is disabled"

	ErrRefreshNotFound = "refresh token not found"

	// 500
	ErrGenerateIndex = "failed to generate blind index"

	ErrEncryptClientId = "failed to encrypt client id"
	ErrEncryptRefresh  = "failed to encrypt refresh token"
	ErrEncryptUsername = "failed to encrypt username"
	ErrEncryptScopes   = "failed to encrypt scopes"

	ErrDecryptClientId = "failed to decrypt client id"
	ErrDecryptRefresh  = "failed to decrypt refresh token"
	ErrDecryptUsername = "failed to decrypt username"
	ErrDecryptScopes   = "failed to decrypt scopes"
)

type Service interface {
	AuthService
	types.RefreshService[types.UserRefresh]
	AuthErrService
}

// NewService creates an implementation of the user authentication service in the carapace session package.
func NewService(
	db *sql.DB,
	s jwt.Signer,
	i data.Indexer,
	c data.Cryptor,
	p provider.S2sTokenProvider,
	s2s *connect.S2sCaller,
) Service {

	return &service{
		AuthService:    NewAuthService(db, s, i, p, s2s),
		RefreshService: NewRefreshService(db, i, c),
		AuthErrService: NewAuthErrService(),
	}
}

var _ Service = (*service)(nil)

type service struct {
	AuthService
	types.RefreshService[types.UserRefresh]
	AuthErrService
}
