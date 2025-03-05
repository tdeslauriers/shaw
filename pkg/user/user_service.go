package user

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"log/slog"
	"shaw/internal/util"
	"shaw/pkg/scope"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type UserService interface {

	// GetProfile retrieves user data by username from peristence.
	// Note: this will not return the user's scopes
	GetProfile(username string) (*Profile, error)

	// GetUsers retrieves all user data from persistence.
	GetUsers() ([]Profile, error)

	// GetUser retrieves user data (including user's scopes) by slug from persistence.
	GetUser(slug string) (*profile.User, error)

	// Update updates the user data in in persistence.
	Update(user *Profile) error

	// UpdateScopes updates the user's scopes assigned scopes given a command of scope slugs.
	UpdateScopes(user *profile.User, cmd []string) error

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

// GetUser retrieves user data (including user's scopes) by slug from the database.
func (s *userService) GetUser(slug string) (*profile.User, error) {

	// get profile data
	u, err := s.getBySlug(slug)
	if err != nil {
		return nil, err
	}

	// get scopes
	// service left empty for now because not service specific
	scopes, err := s.scopes.GetUserScopes(u.Username, "")
	if err != nil {
		return nil, err
	}

	return &profile.User{
		Id:             u.Id,
		Username:       u.Username,
		Firstname:      u.Firstname,
		Lastname:       u.Lastname,
		BirthDate:      u.BirthDate,
		Slug:           u.Slug,
		CreatedAt:      u.CreatedAt,
		Enabled:        u.Enabled,
		AccountLocked:  u.AccountLocked,
		AccountExpired: u.AccountExpired,
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
			return nil, fmt.Errorf("%s in db for username: %s", ErrUserNotFound, username)
		}
		return nil, fmt.Errorf("failed to retrieve user %s data: %v", username, err)
	}

	if err := s.decryptProfile(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *userService) getBySlug(slug string) (*Profile, error) {

	// lightweight validatino of slug
	if len(slug) < 16 || len(slug) > 64 {
		return nil, errors.New("invalid user slug")
	}

	// obtain slug index
	slugIndex, err := s.index.ObtainBlindIndex(slug)
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
			WHERE slug_index = ?`
	var user Profile
	if err := s.db.SelectRecord(qry, &user, slugIndex); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s in db for slug: %s", ErrUserNotFound, slug)
		}
		return nil, fmt.Errorf("failed to retrieve user slug %s data: %v", slug, err)
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
	go s.encrypt([]byte(user.Firstname), ErrEncryptFirstname, &encFirstname, errChan, &wg)
	go s.encrypt([]byte(user.Lastname), ErrEncryptLastname, &encLastname, errChan, &wg)

	if user.BirthDate != "" {
		wg.Add(1)
		go s.encrypt([]byte(user.BirthDate), ErrEncryptBirthDate, &encBirthDate, errChan, &wg)
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

// UpdateScopes is a concrete implementation of the interface method which updates the
// user's assigned scopes given a command of scope slugs.
func (s *userService) UpdateScopes(user *profile.User, cmd []string) error {

	// validate the cmd scopes
	for _, slug := range cmd {
		if !validate.IsValidUuid(slug) {
			return fmt.Errorf("%s: %s", ErrInvalidScopeSlug, slug)
		}
	}

	// call scopes service to get all scopes.
	allScopes, err := s.scopes.GetAll()
	if err != nil {
		return fmt.Errorf("failed to update scopes: %v", err)
	}

	// validate that all scopes slugs submitted are valid scopes
	// and build updated list of scopes from cmd slugs
	// so uuids can be used for db xref records
	updated := make([]types.Scope, 0, len(cmd))
	if len(cmd) > 0 {
		for _, slug := range cmd {
			var exists bool
			for _, scope := range allScopes {
				if slug == scope.Slug {
					exists = true
					updated = append(updated, scope)
					break
				}
			}
			if !exists {
				return fmt.Errorf("%s: %s", ErrScopeSlugDoesNotExist, slug)
			}
		}
	}

	// identify the user's scopes to revome, if any
	var (
		toRemove  = make(map[string]bool)
		isRemoved bool
	)

	for _, scope := range user.Scopes {
		isRemoved = true
		// if cmd is empty, remove all scopes
		for _, s := range updated {
			if scope.Slug == s.Slug {
				isRemoved = false
				break
			}
		}
		if isRemoved {
			toRemove[scope.Uuid] = true
		}
	}

	// identify the scopes to add, if any
	var (
		toAdd   = make(map[string]bool)
		isAdded bool
	)

	for _, scope := range updated {
		isAdded = true
		// if user has no scopes, add all
		for _, s := range user.Scopes {
			if scope.Slug == s.Slug {
				isAdded = false
				break
			}
		}
		if isAdded {
			toAdd[scope.Uuid] = true
		}
	}

	// update user's scopes if necessary
	if len(toRemove) > 0 || len(toAdd) > 0 {

		var (
			wg      sync.WaitGroup
			errChan = make(chan error, len(toRemove)+len(toAdd))
		)

		// remove user's scopes
		if len(toRemove) > 0 {
			for uuid := range toRemove {
				wg.Add(1)
				go func(id string, ch chan error, wg *sync.WaitGroup) {
					defer wg.Done()

					query := `
						DELETE 
						FROM account_scope 
						WHERE account_uuid = ? AND scope_uuid = ?`
					if err := s.db.DeleteRecord(query, user.Id, id); err != nil {
						ch <- fmt.Errorf("failed to remove scope %s from user %s: %v", id, user.Username, err)
					}

					s.logger.Info(fmt.Sprintf("removed scope %s from user %s", id, user.Username))
				}(uuid, errChan, &wg)
			}
		}

		// add user's scopes
		if len(toAdd) > 0 {
			for uuid := range toAdd {
				wg.Add(1)
				go func(id string, ch chan error, wg *sync.WaitGroup) {
					defer wg.Done()

					xref := AccountScopeXref{
						AccountId: user.Id,
						ScopeId:   id,
						CreatedAt: data.CustomTime{Time: time.Now().UTC()},
					}

					query := `
						INSERT 
						INTO account_scope (account_uuid, scope_uuid, created_at)
						VALUES (?, ?, ?)`
					if err := s.db.InsertRecord(query, xref); err != nil {
						ch <- fmt.Errorf("failed to add scope %s to user %s: %v", id, user.Username, err)
					}

					s.logger.Info(fmt.Sprintf("added scope %s to user %s", id, user.Username))
				}(uuid, errChan, &wg)
			}
		}

		// wait for all updates to complete
		wg.Wait()
		close(errChan)

		// check for errors
		errCount := len(errChan)
		if errCount > 0 {
			var sb strings.Builder
			counter := 0
			for err := range errChan {
				sb.WriteString(fmt.Sprintf("%d. %v\n", counter, err))
				if counter < errCount-1 {
					sb.WriteString("; ")
				}
				counter++
			}
			return fmt.Errorf("failed to update user scopes: %s", sb.String())
		}
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

		decryptedUsername  []byte
		decryptedFirstname []byte
		decryptedLastname  []byte
		decryptedBirthDate []byte
		decryptedSlug      []byte
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
	user.Username = string(decryptedUsername)
	user.Firstname = string(decryptedFirstname)
	user.Lastname = string(decryptedLastname)
	user.BirthDate = string(decryptedBirthDate)
	user.Slug = string(decryptedSlug)

	return nil
}

// decrypt is a helper method that abstracts away the decryption process for encrypted strings.
func (s *userService) decrypt(encrypted, errMsg string, clear *[]byte, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	decrypted, err := s.crypt.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*clear = decrypted
}

// encrypt is a helper function that abstracts the service encryption process for plaintext strings.
func (s *userService) encrypt(clear []byte, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	ciphertext, err := s.crypt.EncryptServiceData(clear)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = ciphertext
}
