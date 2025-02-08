package user

import (
	"database/sql"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"golang.org/x/crypto/bcrypt"
)

// ResetService is the interface for the reset service functionality like updating the users password in the database.
type ResetService interface {

	// ResetPassword updates the users password in the database.
	// Note: this will check if the user exists, is valid, and if the current password is correct
	ResetPassword(username string, cmd profile.ResetCmd) error
}

// NewResetService creates a new ResetService interface by returning a pointer to a new concrete implementation
func NewResetService(db data.SqlRepository, i data.Indexer) ResetService {
	return &resetService{
		db:    db,
		index: i,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentReset)).
			With(slog.String(util.ServiceKey, util.ServiceName)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is the concrete implementation of the ResetService interface.
type resetService struct {
	db    data.SqlRepository
	index data.Indexer

	logger *slog.Logger
}

// ResetPassword is the concrete implementation of the method which updates the users password in the database.
func (s *resetService) ResetPassword(username string, cmd profile.ResetCmd) error {

	// lightweight input validation of username
	if len(username) < validate.EmailMin || len(username) > validate.EmailMax {
		return fmt.Errorf("%s: username must be between %d and %d characters", ErrInvalidUserData, validate.EmailMin, validate.EmailMax)
	}

	// validate current password: lightweight input validation > proper validation below
	if len(cmd.CurrentPassword) < validate.PasswordMin || len(cmd.CurrentPassword) > validate.PasswordMax {
		return fmt.Errorf("%s: current password must be between %d and %d characters", ErrInvalidUserData, validate.PasswordMin, validate.PasswordMax)
	}

	// validate new password is well formed and complies with complexity requirements
	if err := validate.IsValidPassword(cmd.NewPassword); err != nil {
		return fmt.Errorf("new password fails complexity requirements: %v", err)
	}

	// validate password == confirmation: redundant, but necessary for data integrity and good practice
	if cmd.NewPassword != cmd.ConfirmPassword {
		return fmt.Errorf("%s", ErrNewConfirmPwMismatch)
	}

	// generate user index
	index, err := s.index.ObtainBlindIndex(username)
	if err != nil {
		return fmt.Errorf("%s for %s: %v", ErrGenUserIndex, username, err)
	}

	var history []UserPasswordHistory
	qry := `SELECT
	a.uuid AS user_uuid,
	a.username,
	a.password AS current_password,
	a.enabled,
	a.account_expired,
	a.account_locked,
	ph.uuid AS password_history_uuid,
	ph.password AS history_password,
	ph.updated
	FROM account a
	LEFT OUTER JOIN password_history ph ON a.uuid = ph.account_uuid
	WHERE a.user_index = ?`
	if err := s.db.SelectRecords(qry, &history, index); err != nil {
		if err == sql.ErrNoRows {
			// this should never happen: pulled from token
			s.logger.Error(fmt.Sprintf("user %s not found", username))
			return fmt.Errorf("%s: %s", ErrUserNotFound, username)
		}
		s.logger.Error(fmt.Sprintf("password reset failed: failed to retrieve user %s data", username), "err", err.Error())
		return fmt.Errorf("failed to retrieve user %s data: %v", username, err)
	}

	// check that records exist to evaluate.
	// this should not be possible.
	if len(history) < 1 {
		s.logger.Error(fmt.Sprintf("password reset failed: no password history records found for user: %s", username))
		return fmt.Errorf("no password history records found for user: %s", username)
	}

	// check if user is enabled, not locked, and not expired before hashing operations
	if !history[0].Enabled {

		return fmt.Errorf("%s: %s", ErrUserDisabled, username)
	}

	if history[0].AccountLocked {
		return fmt.Errorf("%s: %s", ErrUserLocked, username)
	}

	if history[0].AccountExpired {
		return fmt.Errorf("%s: %s", ErrUserExpired, username)
	}

	// validate current password
	current := []byte(cmd.CurrentPassword)
	currentHash := []byte(history[0].CurrentPassword)
	if err := bcrypt.CompareHashAndPassword(currentHash, current); err != nil {
		return fmt.Errorf("%s for user %s", ErrInvalidPassword, username)
	}

	// hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(cmd.NewPassword), 13)
	if err != nil {
		s.logger.Error(fmt.Sprintf("password reset failed: failed to hash new password for user %s", username), "err", err.Error())
		return fmt.Errorf("failed to hash new password")
	}

	// validate new password is not the same as any previous password
	for _, h := range history {
		// If no error, then a match => password has already been used.
		if err := bcrypt.CompareHashAndPassword([]byte(h.HistoryPassword), []byte(cmd.NewPassword)); err == nil {
			s.logger.Error(fmt.Sprintf("password reset failed: user %s's new %s: %s", username, ErrPasswordUsedPreviously, h.Updated.Format("2006-01-02 15:04:05")))
			return fmt.Errorf("%s: %s", ErrPasswordUsedPreviously, h.Updated.Format("2006-01-02 15:04:05"))
		}
	}

	// update password in account table
	qry = `UPDATE account SET password = ? WHERE user_index = ?`
	if err := s.db.UpdateRecord(qry, string(newHash), index); err != nil {
		s.logger.Error(fmt.Sprintf("password reset failed: failed to update user %s's password", username), "err", err.Error())
		return fmt.Errorf("failed to update user %s's password", username)
	}
	s.logger.Info(fmt.Sprintf("successfully updated user %s's password in account record", username))

	// insert new password history record into password_history table
	// dont wait for success, return immediately
	go func() {

		id, err := uuid.NewRandom()
		if err != nil {
			s.logger.Error(fmt.Sprintf("password reset failed: failed to generate uuid for user %s's new password history record", username), "err", err.Error())
			return
		}

		record := PasswordHistory{
			Id:        id.String(),
			Password:  string(newHash),
			Updated:   time.Now().UTC().Format("2006-01-02 15:04:05"),
			AccountId: history[0].AccountId,
		}

		qry = `INSERT INTO password_history (uuid, password, updated, account_uuid) VALUES (?, ?, ?, ?)`
		if err := s.db.InsertRecord(qry, record); err != nil {
			s.logger.Error(fmt.Sprintf("password reset failed: failed to insert new password history record for user %s", username), "err", err.Error())
			return
		}
		s.logger.Info(fmt.Sprintf("successfully updated user %s's password history", username))
	}()

	return nil
}
