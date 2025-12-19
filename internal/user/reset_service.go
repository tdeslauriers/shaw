package user

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/validate"
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
		db:    NewResetRepository(db),
		index: i,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentReset)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is the concrete implementation of the ResetService interface.
type resetService struct {
	db    ResetRepository
	index data.Indexer

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
	current := []byte(cmd.CurrentPassword)
	currentHash := []byte(history[0].CurrentPassword)
	if err := bcrypt.CompareHashAndPassword(currentHash, current); err != nil {
		return fmt.Errorf("failed to validate current password for user: %w", err)
	}

	// hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(cmd.NewPassword), 13)
	if err != nil {
		return fmt.Errorf("failed to hash new password for user: %w", err)
	}

	// validate new password is not the same as any previous password
	for _, h := range history {
		// If no error, then a match => password has already been used.
		if err := bcrypt.CompareHashAndPassword([]byte(h.HistoryPassword), []byte(cmd.NewPassword)); err == nil {
			return fmt.Errorf("invalid: user's new password has been used previously: %s", h.Updated.Format("2006-01-02 15:04:05"))
		}
	}

	// update password in persistent storage
	if err := s.db.UpdatePassword(string(newHash), index); err != nil {
		return fmt.Errorf("failed to update user %s's password: %v", username, err)
	}

	// insert new password history record into password_history table
	// dont wait for success, return immediately
	go func() {

		id, err := uuid.NewRandom()
		if err != nil {
			log.Error("failed to generate uuid for user's new password history record", "err", err.Error())
			return
		}

		record := PasswordHistory{
			Id:        id.String(),
			Password:  string(newHash),
			Updated:   time.Now().UTC().Format("2006-01-02 15:04:05"),
			AccountId: history[0].AccountId,
		}

		if err := s.db.InsertPasswordHistory(record); err != nil {
			log.Error("failed to insert new password history record for user",
				"err", err.Error())
			return
		}

		log.Info("successfully updated user's password history")
	}()

	return nil
}
