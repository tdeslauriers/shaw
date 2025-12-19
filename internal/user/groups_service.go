package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/scope"
	api "github.com/tdeslauriers/shaw/pkg/api/user"
)

// GroupService interface handles services related to groups of users
type GroupService interface {

	// GetUsersWithScopes returns a list of users who have one of a slice of scopes
	GetUsersWithScopes(ctx context.Context, scopes []string) ([]api.Profile, error)
}

// NewGroupService creates a new GroupService interface by returning a pointer to a new concrete implementation of the GroupService interface
func NewGroupService(sql *sql.DB, i data.Indexer, c data.Cryptor, s scope.ScopesService) GroupService {
	return &groupService{
		db:      NewGroupsRepository(sql),
		indexer: i,
		cryptor: c,
		scopes:  s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ GroupService = (*groupService)(nil)

// groupService struct is the concrete implementation of the GroupService interface
type groupService struct {
	db      GroupsRepository
	indexer data.Indexer
	cryptor data.Cryptor
	scopes  scope.ScopesService

	logger *slog.Logger
}

// sliceToVariatic is a helper function for the args ...interface{} parameter in the SelectRecords method
// it converts a slice of any type to a slice of interface{}
func sliceToVariatic[T any](in []T) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// GetUsersWithScopes is the concrete implementation of the interface function
// that returns a list of users who have one of a slice of scopes
func (s *groupService) GetUsersWithScopes(ctx context.Context, scopes []string) ([]api.Profile, error) {

	// check that scopes not empty
	if len(scopes) < 1 {
		return nil, fmt.Errorf("no scopes provided")
	}

	// get all scopes from s2s identity service
	allScopes, err := s.scopes.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all scopes from s2s service: %v", err)
	}

	valid := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if len(s) == 0 || len(s) > 100 {
			return nil, fmt.Errorf("invalid scope: %s", s)
		}

		var exists bool
		for _, a := range allScopes {
			if a.Scope == s {
				exists = true
				// get the uuids for xref table
				valid = append(valid, a.Uuid)
				break
			}
		}

		if !exists {
			return nil, fmt.Errorf("invalid scope: %s", s)
		}
	}

	// get users from database
	records, err := s.db.FindUsersWithScopes(valid)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with scopes from database: %v", err)
	}

	// no users found
	if len(records) < 1 {
		return nil, errors.New("no users found for provided scopes")
	}

	// de-dupelicate records
	unique := make(map[string]api.Profile, len(records))
	for _, r := range records {
		unique[r.Id] = r
	}

	// convert map to slice of users
	// decrypt user data
	users := make([]api.Profile, 0, len(unique))
	for _, u := range unique {

		// decrypt user data
		if err := s.decryptProfile(&u); err != nil {
			return nil, err
		}

		users = append(users, u)
	}

	return users, nil
}

// decryptProfile is a helper function that abstracts the decryption process for user profile data.
func (s *groupService) decryptProfile(user *api.Profile) error {

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
	go s.decrypt(
		user.Username,
		ErrDecryptUsername,
		&decryptedUsername,
		errChan,
		&wg,
	)
	go s.decrypt(
		user.Firstname,
		ErrDecryptFirstname,
		&decryptedFirstname,
		errChan,
		&wg,
	)
	go s.decrypt(
		user.Lastname,
		ErrDecryptLastname,
		&decryptedLastname,
		errChan,
		&wg,
	)
	go s.decrypt(
		user.Slug,
		ErrDecryptSlug,
		&decryptedSlug,
		errChan,
		&wg,
	)

	// only decrypt birth date if it exists
	if len(user.BirthDate) > 0 {
		wg.Add(1)
		go s.decrypt(
			user.BirthDate,
			ErrDecryptBirthDate,
			&decryptedBirthDate,
			errChan,
			&wg,
		)
	}

	wg.Wait()
	close(errChan)

	// check for decryption errors
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return fmt.Errorf("failed to decrypt user profile data for user %s: %v", user.Username, errors.Join(errs...))
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
func (s *groupService) decrypt(encrypted, errMsg string, clear *[]byte, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	decrypted, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*clear = decrypted
}
