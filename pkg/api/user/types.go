package user

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

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

// UserAccount is a model struct for user account table data.
type UserAccount struct {
	Uuid           string `db:"uuid" json:"uuid,omitempty"`
	Username       string `db:"username" json:"username"`
	UserIndex      string `db:"user_index" json:"user_index,omitempty"`
	Password       string `db:"password" json:"password,omitempty"`
	Legacy         bool   `db:"legacy" json:"legacy,omitempty"` // indicates if account is using legacy bcrypt password vs argon2id
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
