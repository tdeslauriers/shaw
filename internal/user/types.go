package user

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
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
	Legacy    bool   `json:"legacy" db:"legacy"`
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
	CurrentLegacy   bool   `db:"current_legacy" json:"current_legacy,omitempty"`
	Enabled         bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired  bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked   bool   `db:"account_locked" json:"account_locked,omitempty"`

	// password_history table
	PasswordHisotryId string          `json:"password_history_id" db:"password_history_uuid"`
	HistoryPassword   string          `json:"history_password" db:"history_password"`
	HistoryLegacy     bool            `json:"history_legacy" db:"history_legacy"`
	Updated           data.CustomTime `json:"updated" db:"updated"`
}

// AccountScopeXref is a model struct that represents a record in the account_scope_xref table.
type AccountScopeXref struct {
	Id        int             `db:"id" json:"id"`
	AccountId string          `json:"account_uuid" db:"account_uuid"`
	ScopeId   string          `json:"scope_uuid" db:"scope_uuid"`
	CreatedAt data.CustomTime `json:"created_at" db:"created_at"`
}
