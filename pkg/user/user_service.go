package user

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	UserService
	UserErrService
}

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type UserService interface {

	// GetUserByUsername retrieves user data by username from the database.
	GetByUsername(username string) (*profile.User, error)

	// Update updates the user data in the database.
	Update(user *profile.User) error

	// IsActive checks if the user is active.
	IsActive(u *profile.User) (bool, error)

	// ResetPassword updates the users password in the database.
	// Note: this will check if the user exists, is valid, and if the current password is correct
	ResetPassword(username string, cmd profile.ResetCmd) error
}

type UserErrService interface {
	// HandleServiceErr handles errors that occur during user service operations.
	HandleServiceErr(err error, w http.ResponseWriter)
}

func NewService(db data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		db:    db,
		index: i,
		crypt: c,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the user Service interface.
type service struct {
	db    data.SqlRepository
	index data.Indexer
	crypt data.Cryptor

	logger *slog.Logger
}

// GetUserByUsername retrieves user data by username from the database.
func (s *service) GetByUsername(username string) (*profile.User, error) {

	// lightweight input validation
	if len(username) < 5 || len(username) > 255 {
		return nil, errors.New("invalid username")
	}

	// obtain user index
	index, err := s.index.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// retrieve user record
	qry := `SELECT 
				uuid, 
				username, 
				firstname, 
				lastname,
				birth_date,
				slug,
				created_at, 
				enabled,
				account_expired,
				account_locked 
			FROM account 
			WHERE user_index = ?`
	var user profile.User
	if err := s.db.SelectRecord(qry, &user, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrUserNotFound)
		}
		return nil, fmt.Errorf("failed to retrieve user %s data: %v", username, err)
	}

	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 3)

		decryptedUsername  string
		decryptedFirstname string
		decryptedLastname  string
		decryptBirthDate   string
		decryptedSlug      string
	)

	// decrypt user data
	wg.Add(4)
	go s.decrypt(user.Username, ErrDecryptUsername, &decryptedUsername, errChan, &wg)
	go s.decrypt(user.Firstname, ErrDecryptFirstname, &decryptedFirstname, errChan, &wg)
	go s.decrypt(user.Lastname, ErrDecryptLastname, &decryptedLastname, errChan, &wg)
	go s.decrypt(user.Slug, ErrDecryptSlug, &decryptedSlug, errChan, &wg)

	if user.BirthDate != "" {
		wg.Add(1)
		go s.decrypt(user.BirthDate, ErrDecryptBirthDate, &decryptBirthDate, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for decryption errors
	errCount := len(errChan)
	if errCount > 0 {
		var builder strings.Builder
		counter := 0
		for err := range errChan {
			builder.WriteString(fmt.Sprintf("%d. %v\n", counter, err))
			if counter < errCount-1 {
				builder.WriteString("; ")
			}
			counter++
		}
		return nil, fmt.Errorf("failed to decrypt user data: %s", builder.String())
	}

	// update user data with decrypted values
	user.Username = decryptedUsername
	user.Firstname = decryptedFirstname
	user.Lastname = decryptedLastname
	user.BirthDate = decryptBirthDate
	user.Slug = decryptedSlug

	return &user, nil
}

// decrypt is a helper method that abstracts away the decryption process for encrypted strings.
func (s *service) decrypt(encrypted, errMsg string, plaintext *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	decrypted, err := s.crypt.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*plaintext = decrypted
}

// Update updates the user data in the database.
func (s *service) Update(user *profile.User) error {

	// validate user data before updating
	// redundant, but necessary for data integrity and good practice
	if err := user.ValidateCmd(); err != nil {
		return fmt.Errorf("invalid user data: %v", err)
	}

	// encrypt user data
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 4)

		index        string // user index
		encFirstname string
		encLastname  string
		encBirthDate string
	)

	// obtain user index
	wg.Add(1)
	go func(username string, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		idx, err := s.index.ObtainBlindIndex(username)
		if err != nil {
			ch <- fmt.Errorf("%s for %s: %v", ErrGenerateUserIndex, username, err)
			return
		}

		*index = idx
	}(user.Username, &index, errChan, &wg)

	// encrypt user data for persistence
	wg.Add(2)
	go s.encrypt(user.Firstname, ErrEncryptFirstname, &encFirstname, errChan, &wg)
	go s.encrypt(user.Lastname, ErrEncryptLastname, &encLastname, errChan, &wg)

	if user.BirthDate != "" {
		wg.Add(1)
		go s.encrypt(user.BirthDate, ErrEncryptBirthDate, &encBirthDate, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for encryption errors and consolidate
	errCount := len(errChan)
	if errCount > 0 {
		var builder strings.Builder
		counter := 0
		for err := range errChan {
			builder.WriteString(fmt.Sprintf("%d. %v\n", counter, err))
			if counter < errCount-1 {
				builder.WriteString("; ")
			}
			counter++
		}
		return fmt.Errorf("failed to encrypt user data: %s", builder.String())
	}

	// update user data
	qry := `UPDATE account
			SET firstname = ?,
				lastname = ?,
				birth_date = ?,
				enabled = ?,
				account_locked = ?,
				account_expired = ?
			WHERE user_index = ?`
	if err := s.db.UpdateRecord(qry, encFirstname, encLastname, encBirthDate, user.Enabled, user.AccountLocked, user.AccountExpired, index); err != nil {
		return fmt.Errorf("failed to update user %s data: %v", user.Username, err)
	}

	return nil
}

// encrypt is a helper function that abstracts the service encryption process for plaintext strings.
func (s *service) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	ciphertext, err := s.crypt.EncryptServiceData(plaintext)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = ciphertext
}

// IsActive checks if the user is active.
func (s *service) IsActive(u *profile.User) (bool, error) {

	if !u.Enabled {
		return false, fmt.Errorf("%s: %s", ErrUserDisabled, u.Username)
	}

	if u.AccountLocked {
		return false, fmt.Errorf("%s: %s", ErrUserLocked, u.Username)
	}

	if u.AccountExpired {
		return false, fmt.Errorf("%s: %s", ErrUserExpired, u.Username)
	}

	return true, nil
}

// ResetPassword is the concrete implementation of the method which updates the users password in the database.
func (s *service) ResetPassword(username string, cmd profile.ResetCmd) error {

	// lightweight input validation of username
	if len(username) < validate.EmailMin || len(username) > validate.EmailMax {
		return fmt.Errorf("%s - username must be between %d and %d characters", ErrInvalidUserData, validate.EmailMin, validate.EmailMax)
	}

	// validate password: rundundant, but necessary for data integrity and good practice
	if err := validate.IsValidPassword(cmd.NewPassword); err != nil {
		return fmt.Errorf("%s - user %s's new password must not well formed: %v", ErrInvalidUserData, username, err)
	}

	// validate password == confirmation: redundant, but necessary for data integrity and good practice
	if cmd.NewPassword != cmd.ConfirmPassword {
		return fmt.Errorf("%s - user %s's new password and confirmation password do not match", ErrInvalidUserData, username)
	}

	// generate user index
	index, err := s.index.ObtainBlindIndex(username)
	if err != nil {
		return fmt.Errorf("%s for %s: %v", ErrGenerateUserIndex, username, err)
	}

	var history []UserPasswordHistory
	qry := `SELECT
				a.uuid AS user_uuid,
				a.username,
				a.passowrd AS current_password,
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
			return fmt.Errorf("%s: %s", ErrUserNotFound, username)
		}
		return fmt.Errorf("failed to retrieve user %s data: %v", username, err)
	}

	// check that records exist to evaluate.
	// this should not be possible.
	if len(history) < 1 {
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
		s.logger.Error(fmt.Sprintf("failed to validate user %s's current password", username), "err", err.Error())
		return fmt.Errorf("failed to validate current password for user %s", username)
	}

	// hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(cmd.NewPassword), 13)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to hash new password for user %s", username), "err", err.Error())
		return fmt.Errorf("failed to hash new password")
	}

	// validate new password is not the same as any previous password
	for _, h := range history {
		if string(newHash) == h.HistoryPassword {
			s.logger.Error(fmt.Sprintf("user %s's new password has been used previously: %s", username, h.Updated.Format("2006-01-02 15:04:05")))
			return fmt.Errorf("this password has been used previously: %s", h.Updated.Format("2006-01-02 15:04:05"))
		}
	}

	// update password in account table

	qry = `UPDATE account SET password = ? WHERE user_index = ?`
	if err := s.db.UpdateRecord(qry, string(newHash), index); err != nil {
		s.logger.Error(fmt.Sprintf("failed to update user %s's password", username), "err", err.Error())
		return fmt.Errorf("failed to update user %s's password", username)
	}
	s.logger.Info(fmt.Sprintf("successfully updated user %s's password", username))

	// insert new password history record into password_history table
	// cannot user concurrency because need to be sure account table password is updated before history record is inserted
	id, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to generate uuid for user %s's new password history record", username), "err", err.Error())
		return fmt.Errorf("failed to generate uuid for user %s's new password history record", username)
	}

	record := PasswordHistory{
		Id:        id.String(),
		Password:  string(newHash),
		Updated:   time.Now().UTC().Format("2006-01-02 15:04:05"),
		AccountId: history[0].AccountId,
	}

	qry = `INSERT INTO password_history (uuid, password, updated, account_uuid) VALUES (?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, record); err != nil {
		s.logger.Error(fmt.Sprintf("failed to insert new password history record for user %s", username), "err", err.Error())
		return fmt.Errorf("failed to insert new password history record for user %s", username)
	}
	s.logger.Info(fmt.Sprintf("successfully updated user %s's password history", username))

	return nil
}

// HandleServiceErr handles errors that occur during user service operations and sends a json error response.
func (s *service) HandleServiceErr(err error, w http.ResponseWriter) {
	switch {
	case strings.Contains(err.Error(), ErrUserNotFound):
	case strings.Contains(err.Error(), ErrUserDisabled):
	case strings.Contains(err.Error(), ErrUserLocked):
	case strings.Contains(err.Error(), ErrUserExpired):
	case strings.Contains(err.Error(), "failed to validate current password"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrInvalidUserData):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
