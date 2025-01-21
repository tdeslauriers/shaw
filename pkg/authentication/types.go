package authentication

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
