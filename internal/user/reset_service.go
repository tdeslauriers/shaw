package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/shaw/internal/creds"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"golang.org/x/crypto/bcrypt"
)

// ResetService is the interface for the reset service functionality like updating the users password in the database.
type ResetService interface {

	// ResetPassword updates the users password in the database.
	// Note: this will check if the user exists, is valid, and if the current password is correct
	ResetPassword(ctx context.Context, username string, cmd profile.ResetCmd) error
}

// NewResetService creates a new ResetService interface by returning a pointer to a new concrete implementation
func NewResetService(db *sql.DB, i data.Indexer) ResetService {
	return &resetService{
		db:     NewResetRepository(db),
		index:  i,
		hasher: creds.NewService(),

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentReset)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is the concrete implementation of the ResetService interface.
type resetService struct {
	db     ResetRepository
	index  data.Indexer
	hasher creds.Service

	logger *slog.Logger
}

// ResetPassword is the concrete implementation of the method which updates the users password in the database.
func (s *resetService) ResetPassword(ctx context.Context, username string, cmd profile.ResetCmd) error {

	// create local logger with telemetry from context
	log := s.logger

	// get tlemetry from context
	if tel, ok := ctx.Value(connect.TelemetryKey).(*connect.Telemetry); ok && tel != nil {
		log = log.With(tel.TelemetryFields()...)
	} else {
		log.Warn("no telemetry found in context for reset password request")
	}

	// lightweight input validation of username
	if len(username) < validate.EmailMin || len(username) > validate.EmailMax {
		return fmt.Errorf("invalid username: must be between %d and %d characters", validate.EmailMin, validate.EmailMax)
	}

	// validate current password: lightweight input validation > proper validation below
	if len(cmd.CurrentPassword) < validate.PasswordMin || len(cmd.CurrentPassword) > validate.PasswordMax {
		return fmt.Errorf("invalid current password: must be between %d and %d characters", validate.PasswordMin, validate.PasswordMax)
	}

	// validate new password is well formed and complies with complexity requirements
	if err := validate.IsValidPassword(cmd.NewPassword); err != nil {
		return fmt.Errorf("invalid new password: fails complexity requirements: %v", err)
	}

	// validate password == confirmation: redundant, but necessary for data integrity and good practice
	if cmd.NewPassword != cmd.ConfirmPassword {
		return fmt.Errorf("invalid: new password and confirmation password do not match")
	}

	// generate user index
	index, err := s.index.ObtainBlindIndex(username)
	if err != nil {
		return fmt.Errorf("failed to generate user index for %s: %v", username, err)
	}

	// get historical passwords for user from database
	history, err := s.db.FindPasswordHistory(index)
	if err != nil {
		return fmt.Errorf("failed to retrieve password history for user %s: %v", username, err)
	}

	// check that records exist to evaluate.
	// this should not be possible.
	if len(history) < 1 {
		return fmt.Errorf("no password history records found for user")
	}

	// check if user is enabled, not locked, and not expired before hashing operations
	if !history[0].Enabled {
		return fmt.Errorf("user account is disabled")
	}

	if history[0].AccountLocked {
		return fmt.Errorf("user account is locked")
	}

	if history[0].AccountExpired {
		return fmt.Errorf("user account is expired")
	}

	// validate current password
	// need to check if legacy hashing is used
	// if not legacy, use argon2id hashing, otherwise, use bcrypt
	if !history[0].CurrentLegacy {

		// non-legacy hashing: argon2id
		exists, err := s.hasher.VerifyPassword(cmd.CurrentPassword, history[0].CurrentPassword)
		if err != nil {
			// this means there was an error during verification, ie, coding or decoding, not a mismatch
			s.logger.Error(fmt.Sprintf("error verifying current password with argon2id hashing for user %s", username),
				"err", err.Error())
			return errors.New("failed to validate current password for user")
		}
		if !exists {
			s.logger.Error(fmt.Sprintf("incorrect current password provided for user %s using argon2id hashing", username))
			return fmt.Errorf("incorrect current password")
		}
	} else {

		// legacy hashing: bcrypt
		current := []byte(cmd.CurrentPassword)
		currentHash := []byte(history[0].CurrentPassword)
		if err := bcrypt.CompareHashAndPassword(currentHash, current); err != nil {
			s.logger.Error(fmt.Sprintf("incorrect current password provided for user %s using legacy bcrypt hashing", username),
				"err", err.Error())
			return errors.New("incorrect current password")
		}
	}

	// validate new password is not the same as any previous password
	// NOTE: password history could contain both legacy and non-legacy passwords, so need
	// to check legacy field for each accordingly
	for _, h := range history {

		if !h.HistoryLegacy {

			// non-legacy argon2id hashing
			exists, err := s.hasher.VerifyPassword(cmd.NewPassword, h.HistoryPassword)
			if err != nil {
				// this means there was an error during verification, ie, coding or decoding, not a mismatch
				return errors.New("failed to validate new password for user")
			}

			// this means there was a match => password has already been used.
			if exists {
				return fmt.Errorf("invalid: user's new password has been used previously: %s", h.Updated.Format("2006-01-02 15:04:05"))
			}
		} else {

			// legacy bcrypt hashing
			// If no error, then a match => password has already been used.
			if err := bcrypt.CompareHashAndPassword([]byte(h.HistoryPassword), []byte(cmd.NewPassword)); err == nil {
				return fmt.Errorf("invalid: user's new password has been used previously: %s", h.Updated.Format("2006-01-02 15:04:05"))
			}
		}
	}

	// hash new password in argon2id
	newHash, err := s.hasher.HashPassword(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password for user %s: %w", username, err)
	}

	// update password in persistent storage
	if err := s.db.UpdatePassword(newHash, false, index); err != nil {
		return fmt.Errorf("failed to update user %s's password in db: %w", username, err)
	}

	// insert new password history record into password_history table
	// dont wait for success, return immediately
	go func() {

		id, err := uuid.NewRandom()
		if err != nil {
			log.Error(fmt.Sprintf("failed to generate uuid for user %s's new password history record", username),
				"err", err.Error())
			return
		}

		record := PasswordHistory{
			Id:        id.String(),
			Password:  string(newHash),
			Legacy:    false, // new password always non-legacy hashing -> argon2id
			Updated:   time.Now().UTC().Format("2006-01-02 15:04:05"),
			AccountId: history[0].AccountId,
		}

		if err := s.db.InsertPasswordHistory(record); err != nil {
			log.Error(fmt.Sprintf("failed to insert new password history record for user %s", username),
				"err", err.Error())
			return
		}

		log.Info(fmt.Sprintf("successfully updated user %s's password history", username))
	}()

	return nil
}
