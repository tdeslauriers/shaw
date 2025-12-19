package user

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
	"github.com/tdeslauriers/shaw/internal/scope"
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
	ErrInvalidScopeSlug       = "invalid scope slug submitted"
	ErrScopeSlugDoesNotExist  = "scope slug does not exist"

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

// scopes required to read and write user profile user endpoints
var (
	getProfileAllowed    = []string{"r:shaw:profile:*"}
	updateProfileAllowed = []string{"w:shaw:profile:*"}
)

// scopes required to read and write user endpoints
var (
	s2sGetUserAllowed = []string{"r:shaw:s2s:users:*"}

	s2sGetGroupsAllowed = []string{"r:shaw:s2s:users:groups:*"}

	getUserAllowed    = []string{"r:shaw:users:*"}
	updateUserAllowed = []string{"w:shaw:users:*"}

	getGroupsAllowed = []string{"r:shaw:users:groups:*"}
)

// Handler interface for user profile request handling
type Handler interface {
	GroupsHandler
	ProfileHandler
	ResetHandler
	ScopesHandler
	UserHandler
}

// NewHandler creates a new Handler interface by returning a pointer to a new concrete implementation of the Handler interface
func NewHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) Handler {
	return &handler{
		GroupsHandler:  NewGroupsHandler(s, s2s, iam),
		ProfileHandler: NewProfileHandler(s, s2s, iam),
		ResetHandler:   NewResetHandler(s, s2s, iam),
		ScopesHandler:  NewScopesHandler(s, s2s, iam),
		UserHandler:    NewUserHandler(s, s2s, iam),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	GroupsHandler
	ProfileHandler
	ResetHandler
	ScopesHandler
	UserHandler
}

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type Service interface {
	UserService
	GroupService
	ResetService
}

// NewService creates a new Service interface by returning a pointer to a new concrete implementation
// of the underlying UserService, ResetService, and UserErrService interfaces.
func NewService(db *sql.DB, i data.Indexer, c data.Cryptor, p provider.S2sTokenProvider, call *connect.S2sCaller) Service {
	return &service{
		UserService:  NewUserService(db, i, c, scope.NewScopesService(db, i, p, call)),
		GroupService: NewGroupService(db, i, c, scope.NewScopesService(db, i, p, call)),
		ResetService: NewResetService(db, i),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
// and is composed of the UserService, ResetService, and UserErrService interfaces.
type service struct {
	UserService
	GroupService
	ResetService
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

// User is a model struct that represents a user in the accounts table of the identity service db.
// note: it omits the password field for security reasons.
type User struct {
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
	Scopes         []scopes.Scope  `json:"scopes,omitempty"` // will not always be present; call specific/depenedent
}

func (u *User) ValidateCmd() error {

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
		return fmt.Errorf("invalid or not well formatted slug")
	}

	// CreatedAt is a timestamp, no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	return nil
}

// UserScopesCmd is a model for the user scopes cmd recieved by the user handler
type UserScopesCmd struct {
	UserSlug   string   `json:"user_slug" db:"user_slug"`
	ScopeSlugs []string `json:"scope_slugs" db:"scope_slugs"`
}

// ValidateCmd validates the UserScopesCmd
func (cmd *UserScopesCmd) ValidateCmd() error {

	// validate UserSlug
	if cmd.UserSlug == "" {
		return fmt.Errorf("user slug is required")
	}

	if !validate.IsValidUuid(cmd.UserSlug) {
		return fmt.Errorf("invalid user slug")
	}

	if len(cmd.ScopeSlugs) > 0 {
		for _, slug := range cmd.ScopeSlugs {
			if !validate.IsValidUuid(slug) {
				return fmt.Errorf("invalid scope slug submitted: all slugs must be valid uuids")
			}
		}
	}

	return nil
}

// AccountScopeXref is a model struct that represents a record in the account_scope_xref table.
type AccountScopeXref struct {
	Id        int             `db:"id" json:"id"`
	AccountId string          `json:"account_uuid" db:"account_uuid"`
	ScopeId   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt data.CustomTime `json:"created_at" db:"created_at"`
}

// UserAccount is a model struct for user account table data.
type UserAccount struct {
	Uuid           string `db:"uuid" json:"uuid,omitempty"`
	Username       string `db:"username" json:"username"`
	UserIndex      string `db:"user_index" json:"user_index,omitempty"`
	Password       string `db:"password" json:"password,omitempty"`
	Firstname      string `db:"firstname" json:"firstname"`
	Lastname       string `db:"lastname" json:"lastname"`
	Birthdate      string `db:"birth_date" json:"birth_date,omitempty"` // string because field encrypted in db
	Slug           string `db:"slug" json:"slug,omitempty"`
	SlugIndex      string `db:"slug_index" json:"slug_index,omitempty"`
	CreatedAt      string `db:"created_at" json:"created_at"`
	Enabled        bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked,omitempty"`
}
