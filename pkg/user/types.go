package user

import (
	"fmt"
	"shaw/pkg/scope"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	// 401
	ErrUserNotFound    = "user not found"
	ErrUsersNotFound   = "user records not found"
	ErrUserDisabled    = "user account is disabled"
	ErrUserExpired     = "user account is expired"
	ErrUserLocked      = "user account is locked"
	ErrInvalidPassword = "failed to validate current password"

	// 422
	ErrInvalidUserData        = "invalid or not well formed user data"
	ErrPasswordUsedPreviously = "password has been used previously"
	ErrNewConfirmPwMismatch   = "new password and confirmation password do not match"

	// 500
	ErrDecryptUsername  = "failed to decrypt username"
	ErrDecryptFirstname = "failed to decrypt firstname"
	ErrDecryptLastname  = "failed to decrypt lastname"
	ErrDecryptBirthDate = "failed to decrypt birth date"
	ErrDecryptSlug      = "failed to decrypt slug"

	ErrEncryptFirstname = "failed to encrypt firstname"
	ErrEncryptLastname  = "failed to encrypt lastname"
	ErrEncryptBirthDate = "failed to encrypt birth date"

	ErrGenUserIndex = "failed to generate user index"
	ErrGenSlugIndex = "failed to generate slug index"
)

// service scopes required
var (
	getProfileAllowed    = []string{"r:shaw:profile:*"}
	updateProfileAllowed = []string{"w:shaw:profile:*"}
)

// Handler interface for user profile request handling
type Handler interface {
	ProfileHandler
	ResetHandler
	UserHandler
}

// NewHandler creates a new Handler interface by returning a pointer to a new concrete implementation of the Handler interface
func NewHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) Handler {
	return &handler{
		ProfileHandler: NewProfileHandler(s, s2s, iam),
		ResetHandler:   NewResetHandler(s, s2s, iam),
		UserHandler:    NewUserHandler(s, s2s, iam),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	ProfileHandler
	ResetHandler
	UserHandler
}

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type Service interface {
	UserService
	ResetService
	UserErrService
}

// NewService creates a new Service interface by returning a pointer to a new concrete implementation
// of the underlying UserService, ResetService, and UserErrService interfaces.
func NewService(db data.SqlRepository, i data.Indexer, c data.Cryptor, p provider.S2sTokenProvider, call connect.S2sCaller) Service {
	return &service{
		UserService:    NewUserService(db, i, c, scope.NewScopesService(db, i, p, call)),
		ResetService:   NewResetService(db, i),
		UserErrService: NewUserErrService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
// and is composed of the UserService, ResetService, and UserErrService interfaces.
type service struct {
	UserService
	ResetService
	UserErrService
}

// PasswordHistory is a model struct that represents a password history record in the password_history table.
type PasswordHistory struct {
	Id        string `json:"id" db:"uuid"`
	Password  string `json:"password" db:"password"`
	Updated   string `json:"updated" db:"updated"`
	AccountId string `json:"account_uuid" db:"account_uuid"`
}

// UserAccount is a model struct that represents a user account record in the account table
// and the password history table joined on the account_uuid.
type UserPasswordHistory struct {
	// account table
	AccountId       string `json:"user_uuid" db:"user_uuid"`
	Username        string `db:"username" json:"username"`
	CurrentPassword string `db:"current_password" json:"current_password,omitempty"`
	Enabled         bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired  bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked   bool   `db:"account_locked" json:"account_locked,omitempty"`

	// password_history table
	PasswordHisotryId string          `json:"password_history_id" db:"password_history_uuid"`
	HistoryPassword   string          `json:"history_password" db:"history_password"`
	Updated           data.CustomTime `json:"updated" db:"updated"`
}

// Profile is a model struct that represents an account record in the database user table.
// It does not include the password field, or scopes.
type Profile struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	Username       string          `json:"username" db:"username"`
	Firstname      string          `json:"firstname" db:"firstname"`
	Lastname       string          `json:"lastname" db:"lastname"`
	BirthDate      string          `json:"birth_date,omitempty" db:"birth_date"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
}

func (u *Profile) ValidateCmd() error {

	// validate Id:  Only checks if it is a uuid, not if it is the correct uuid
	// Note: for operations this model is used in, id is often dropped or not the lookup key,
	// check for nil or empty string if needed
	if u.Id != "" && !validate.IsValidUuid(u.Id) {
		return fmt.Errorf("invalid or not well formatted user id")
	}

	// Username is immutable at this time.
	// TODO: make funcitonality to change username
	// only lightweight validation to make sure it isnt too long
	// Note: may not be present in all operations, check for nil or empty string if needed
	if u.Username != "" {
		if len(u.Username) < validate.EmailMin || len(u.Username) > validate.EmailMax {
			return fmt.Errorf("invalid username: must be greater than %d and less than %d characters long", validate.EmailMin, validate.EmailMax)
		}
	}

	// validate Firstname
	if err := validate.IsValidName(u.Firstname); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	// validate Lastname
	if err := validate.IsValidName(u.Lastname); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	// validate Birthdate
	if err := validate.IsValidBirthday(u.BirthDate); err != nil {
		return fmt.Errorf("invalid birthdate: %v", err)
	}

	// validate slug is well formatted if present
	// Note: only checks if it is a uuid, not if it is the correct uuid
	// Slug may or may not be present depending on the operation,
	// if it is supposed to be present, and is not, that will need to be checked elsewhere
	if u.Slug != "" && !validate.IsValidUuid(u.Slug) {
		fmt.Printf("VALIDATE")
		return fmt.Errorf("invalid or not well formatted slug")
	}

	// CreatedAt is a timestamp, no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	return nil
}
