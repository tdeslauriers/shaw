package user

const (
	// 401
	ErrUserNotFound = "user not found"
	ErrUserDisabled = "user account is disabled"
	ErrUserExpired  = "user account is expired"
	ErrUserLocked   = "user account is locked"

	// 422
	ErrInvalidUserData = "invalid or not well formed user data"

	// 500
	ErrDecryptUsername  = "failed to decrypt username"
	ErrDecryptFirstname = "failed to decrypt firstname"
	ErrDecryptLastname  = "failed to decrypt lastname"
	ErrDecryptBirthDate = "failed to decrypt birth date"
	ErrDecryptSlug      = "failed to decrypt slug"

	ErrEncryptFirstname = "failed to encrypt firstname"
	ErrEncryptLastname  = "failed to encrypt lastname"
	ErrEncryptBirthDate = "failed to encrypt birth date"

	ErrGenerateUserIndex = "failed to generate user index"
	ErrGenerateSlugIndex = "failed to generate slug index"
)
