package user

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"shaw/pkg/scope"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
)

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type UserService interface {

	// GetProfile retrieves user data by username from the database.
	// Note: this will not return the user's scopes
	GetProfile(username string) (*Profile, error)

	// GetUsers retrieves all user data from the database.
	GetUsers() ([]Profile, error)

	// GetUser retrieves user data (including user's scopes) by username from the database.
	GetUser(username string) (*profile.User, error)

	// Update updates the user data in the database.
	Update(user *Profile) error

	// IsActive checks if the user is active.
	IsActive(u *Profile) (bool, error)
}

// NewUserService creates a new UserService interface by returning a pointer to a new concrete implementation
func NewUserService(db data.SqlRepository, i data.Indexer, c data.Cryptor, s scope.ScopesService) UserService {
	return &userService{
		db:     db,
		index:  i,
		crypt:  c,
		scopes: s,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentUser)).
			With(slog.String(util.ServiceKey, util.ServiceName)),
	}
}

// userService is the concrete implementation of the UserService interface.
type userService struct {
	db     data.SqlRepository
	index  data.Indexer
	crypt  data.Cryptor
	scopes scope.ScopesService

	logger *slog.Logger
}

// GetProfile is the concrete implementation of the method which retrieves a user's profile data by username from the database.
func (s *userService) GetProfile(username string) (*Profile, error) {
	return s.getByUsername(username)
}

// GetUsers retrieves all user data from the database.
func (s *userService) GetUsers() ([]Profile, error) {

	var users []Profile
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
			FROM account`
	if err := s.db.SelectRecords(qry, &users); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrUsersNotFound)
		}
		return nil, fmt.Errorf("failed to retrieve user records: %v", err)
	}

	// decrypt user data
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, len(users))
	)

	for i := range users {
		wg.Add(1)
		go func(i int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			if err := s.decryptProfile(&users[i]); err != nil {
				ch <- fmt.Errorf("failed to decrypt user %s data: %v", users[i].Username, err)
			}

		}(i, errChan, &wg)
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

	return users, nil

}

// GetUser retrieves user data (including user's sscopes) by username from the database.
func (s *userService) GetUser(username string) (*profile.User, error) {

	// get profile data
	usr, err := s.getByUsername(username)
	if err != nil {

		return nil, err
	}

	// get scopes
	// service left empty for now because not service specific
	scopes, err := s.scopes.GetUserScopes(username, "")
	if err != nil {
		return nil, err
	}

	return &profile.User{
		Username:       usr.Username,
		Firstname:      usr.Firstname,
		Lastname:       usr.Lastname,
		BirthDate:      usr.BirthDate,
		Slug:           usr.Slug,
		CreatedAt:      usr.CreatedAt,
		Enabled:        usr.Enabled,
		AccountLocked:  usr.AccountLocked,
		AccountExpired: usr.AccountExpired,
		Scopes:         scopes,
	}, nil
}

func (s *userService) getByUsername(username string) (*Profile, error) {

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
	var user Profile
	if err := s.db.SelectRecord(qry, &user, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrUserNotFound)
		}
		return nil, fmt.Errorf("failed to retrieve user %s data: %v", username, err)
	}

	if err := s.decryptProfile(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Update updates the user data in the database.
func (s *userService) Update(user *Profile) error {

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
			ch <- fmt.Errorf("%s for %s: %v", ErrGenUserIndex, username, err)
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

// IsActive checks if the user is active.
func (s *userService) IsActive(u *Profile) (bool, error) {

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

// decryptProfile is a helper function that abstracts the decryption process for user profile data.
func (s *userService) decryptProfile(user *Profile) error {

	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 5)

		decryptedUsername  string
		decryptedFirstname string
		decryptedLastname  string
		decryptedBirthDate string
		decryptedSlug      string
	)

	// decrypt user data
	wg.Add(4)
	go s.decrypt(user.Username, ErrDecryptUsername, &decryptedUsername, errChan, &wg)
	go s.decrypt(user.Firstname, ErrDecryptFirstname, &decryptedFirstname, errChan, &wg)
	go s.decrypt(user.Lastname, ErrDecryptLastname, &decryptedLastname, errChan, &wg)
	go s.decrypt(user.Slug, ErrDecryptSlug, &decryptedSlug, errChan, &wg)

	// only decrypt birth date if it exists
	if len(user.BirthDate) > 0 {
		wg.Add(1)
		go s.decrypt(user.BirthDate, ErrDecryptBirthDate, &decryptedBirthDate, errChan, &wg)
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
		return fmt.Errorf("failed to decrypt user data: %s", builder.String())
	}

	// update user data with decrypted values
	user.Username = decryptedUsername
	user.Firstname = decryptedFirstname
	user.Lastname = decryptedLastname
	user.BirthDate = decryptedBirthDate
	user.Slug = decryptedSlug

	return nil
}

// decrypt is a helper method that abstracts away the decryption process for encrypted strings.
func (s *userService) decrypt(encrypted, errMsg string, plaintext *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	decrypted, err := s.crypt.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*plaintext = decrypted
}

// encrypt is a helper function that abstracts the service encryption process for plaintext strings.
func (s *userService) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	ciphertext, err := s.crypt.EncryptServiceData(plaintext)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = ciphertext
}
