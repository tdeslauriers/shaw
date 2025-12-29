package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/scope"
	api "github.com/tdeslauriers/shaw/pkg/api/user"
)

// Service is the interface for the user service functionality like retrieving user data by username from the db.
type UserService interface {

	// GetProfile retrieves user data by username from peristence.
	// Note: this will not return the user's scopes
	GetProfile(username string) (*api.Profile, error)

	// GetUsers retrieves all user data from persistence.
	GetUsers() ([]api.Profile, error)

	// GetUser retrieves user data (including user's scopes) by slug from persistence.
	GetUser(ctx context.Context, slug string) (*api.User, error)

	// Update updates the user data in in persistence.
	Update(user *api.Profile) error

	// UpdateScopes updates the user's scopes assigned scopes given a command of scope slugs.
	UpdateScopes(ctx context.Context, user *api.User, cmd []string) error

	// IsActive checks if the user is active.
	IsActive(u *api.Profile) (bool, error)
}

// NewUserService creates a new UserService interface by returning a pointer to a new concrete implementation
func NewUserService(
	db *sql.DB,
	i data.Indexer,
	c data.Cryptor,
	s scope.ScopesService,
) UserService {

	return &userService{
		db:     NewUserRepository(db),
		index:  i,
		crypt:  c,
		scopes: s,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentUser)).
			With(slog.String(util.PackageKey, util.PackageUser)),
	}
}

// userService is the concrete implementation of the UserService interface.
type userService struct {
	db     UserRepository
	index  data.Indexer
	crypt  data.Cryptor
	scopes scope.ScopesService

	logger *slog.Logger
}

// GetProfile is the concrete implementation of the method which retrieves a user's profile data by username from the database.
func (s *userService) GetProfile(username string) (*api.Profile, error) {
	return s.getByUsername(username)
}

// GetUsers retrieves all user data from the database.
func (s *userService) GetUsers() ([]api.Profile, error) {

	// retrieve all users from persistence
	users, err := s.db.FindAllUsers()
	if err != nil {
		return nil, err
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
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt user records: %v", errors.Join(errs...))
	}

	return users, nil
}

// GetUser retrieves user data (including user's scopes) by slug from the database.
func (s *userService) GetUser(ctx context.Context, slug string) (*api.User, error) {

	// get profile data
	u, err := s.getBySlug(slug)
	if err != nil {
		return nil, err
	}

	// get scopes
	// service left empty for now because not service specific
	scopes, err := s.scopes.GetUserScopes(ctx, u.Username, "")
	if err != nil {
		return nil, err
	}

	return &api.User{
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

func (s *userService) getByUsername(username string) (*api.Profile, error) {

	// lightweight input validation
	if len(username) < 5 || len(username) > 255 {
		return nil, errors.New("invalid username")
	}

	// obtain user index
	index, err := s.index.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// retrieve user record from persistence
	user, err := s.db.FindUserBySlug(index)
	if err != nil {
		return nil, err
	}

	// decrypt user data
	if err := s.decryptProfile(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) getBySlug(slug string) (*api.Profile, error) {

	// lightweight validatino of slug
	if len(slug) < 16 || len(slug) > 64 {
		return nil, errors.New("invalid user slug")
	}

	// obtain slug index
	slugIndex, err := s.index.ObtainBlindIndex(slug)
	if err != nil {
		return nil, err
	}

	// retrieve user account record from persistence
	user, err := s.db.FindUserBySlug(slugIndex)
	if err != nil {
		return nil, err
	}

	// decrypt user data
	if err := s.decryptProfile(user); err != nil {
		return nil, err
	}

	return user, nil
}

// Update updates the user data in the database.
func (s *userService) Update(user *api.Profile) error {

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
	go s.encrypt(
		[]byte(user.Firstname),
		ErrEncryptFirstname,
		&encFirstname,
		errChan,
		&wg,
	)
	go s.encrypt(
		[]byte(user.Lastname),
		ErrEncryptLastname,
		&encLastname,
		errChan,
		&wg,
	)

	if user.BirthDate != "" {
		wg.Add(1)
		go s.encrypt(
			[]byte(user.BirthDate),
			ErrEncryptBirthDate,
			&encBirthDate,
			errChan,
			&wg,
		)
	}

	wg.Wait()
	close(errChan)

	// check for encryption errors and consolidate
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return fmt.Errorf("failed to encrypt user data for user %s update: %v", user.Username, errors.Join(errs...))
	}

	// update user data
	if err := s.db.UpdateUser(
		&api.Profile{
			Firstname:      encFirstname,
			Lastname:       encLastname,
			BirthDate:      encBirthDate,
			Enabled:        user.Enabled,
			AccountLocked:  user.AccountLocked,
			AccountExpired: user.AccountExpired,
		},
		index,
	); err != nil {
		return err
	}

	return nil
}

// UpdateScopes is a concrete implementation of the interface method which updates the
// user's assigned scopes given a command of scope slugs.
func (s *userService) UpdateScopes(ctx context.Context, user *api.User, cmd []string) error {

	// validate the cmd scopes
	for _, slug := range cmd {
		if !validate.IsValidUuid(slug) {
			return fmt.Errorf("%s: %s", ErrInvalidScopeSlug, slug)
		}
	}

	// call scopes service to get all scopes.
	allScopes, err := s.scopes.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to update scopes: %v", err)
	}

	// validate that all scopes slugs submitted are valid scopes
	// and build updated list of scopes from cmd slugs
	// so uuids can be used for db xref records
	updated := make([]scopes.Scope, 0, len(cmd))
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

					if err := s.db.DeleteAccountScopeXref(user.Id, id); err != nil {
						ch <- fmt.Errorf("failed to remove account %s - %s scope xref: %v", user.Id, id, err)
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
						Id:        0, // auto-increment
						AccountId: user.Id,
						ScopeId:   id,
						CreatedAt: data.CustomTime{Time: time.Now().UTC()},
					}

					if err := s.db.InsertAccountScopeXref(xref); err != nil {
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
func (s *userService) IsActive(u *api.Profile) (bool, error) {

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
func (s *userService) decryptProfile(user *api.Profile) error {

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
