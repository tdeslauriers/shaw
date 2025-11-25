package login

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// UserLoginCmd is a struct for a user login request endpoint to consume.
type UserLoginCmd struct {
	Username string `json:"username"`
	Password string `json:"password"`

	ResponseType string `json:"response_type"`
	State        string `json:"state,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	Redirect     string `json:"redirect,omitempty"`

	Session string `json:"session,omitempty"`
	Csrf    string `json:"csrf,omitempty"`
}

// ValidateCmd performs very limited checks login cmd fields.
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *UserLoginCmd) ValidateCmd() error {

	// field input restrictions
	if validate.TooShort(cmd.Username, validate.EmailMin) || validate.TooLong(cmd.Username, validate.EmailMax) {
		return fmt.Errorf("invalid username: must be between %d and %d characters", validate.EmailMin, validate.EmailMax)
	}

	if validate.TooShort(cmd.Password, validate.PasswordMin) || validate.TooLong(cmd.Password, validate.PasswordMax) {
		return fmt.Errorf("invalid password: must be between %d and %d characters", validate.PasswordMin, validate.PasswordMax)
	}

	if validate.TooShort(cmd.ResponseType, 4) || validate.TooLong(cmd.ResponseType, 8) {
		return fmt.Errorf("invalid response type: must be between %d and %d characters", 4, 8)
	}

	if validate.TooShort(cmd.State, 16) || validate.TooLong(cmd.State, 256) {
		return fmt.Errorf("invalid state: must be between %d and %d characters", 16, 256)
	}

	if validate.TooShort(cmd.Nonce, 16) || validate.TooLong(cmd.Nonce, 64) {
		return fmt.Errorf("invalid nonce: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 66) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.Redirect, 6) || validate.TooLong(cmd.Redirect, 2048) {
		return fmt.Errorf("invalid redirect: must be between %d and %d characters", 16, 2048)
	}

	return nil
}
