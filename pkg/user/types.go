package user

const (
	// 401
	ErrUserNotFound = "user not found"
	ErrUserDisabled = "user account is disabled"
	ErrUserExpired  = "user account is expired"
	ErrUserLocked   = "user account is locked"

	// 500
	ErrDecryptUsername  = "failed to decrypt username"
	ErrDecryptFirstname = "failed to decrypt firstname"
	ErrDecryptLastname  = "failed to decrypt lastname"
	ErrDecryptBirthDate = "failed to decrypt birth date"
)
