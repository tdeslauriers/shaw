package user

import (
	"database/sql"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"shaw/pkg/scope"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// GroupService interface handles services related to groups of users
type GroupService interface {

	// GetUsersWithScopes returns a list of users who have one of a slice of scopes
	GetUsersWithScopes(scopes []string) ([]Profile, error)
}

// NewGroupService creates a new GroupService interface by returning a pointer to a new concrete implementation of the GroupService interface
func NewGroupService(db data.SqlRepository, i data.Indexer, c data.Cryptor, s scope.ScopesService) GroupService {
	return &groupService{
		db:      db,
		indexer: i,
		cryptor: c,
		scopes:  s,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceName)).
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ GroupService = (*groupService)(nil)

// groupService struct is the concrete implementation of the GroupService interface
type groupService struct {
	db      data.SqlRepository
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
func (s *groupService) GetUsersWithScopes(scopes []string) ([]Profile, error) {

	// check that scopes not empty
	if len(scopes) < 1 {
		return nil, fmt.Errorf("no scopes provided")
	}

	// get all scopes from s2s identity service
	allScopes, err := s.scopes.GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to get all scopes from s2s service: %v", err)
	}

	valid := make([]types.Scope, 0, len(scopes))
	for _, s := range scopes {
		if len(s) == 0 || len(s) > 100 {
			return nil, fmt.Errorf("invalid scope: %s", s)
		}

		var exists bool
		for _, a := range allScopes {
			if a.Scope == s {
				exists = true
				valid = append(valid, a)
				break
			}
		}

		if !exists {
			return nil, fmt.Errorf("invalid scope: %s", s)
		}
	}

	// get users from database
	// build query
	var query strings.Builder
	query.WriteString(`
					SELECT
				a.uuid,
				a.username,
				a.firstname,
				a.lastname,
				a.birth_date,
				a.slug,
				a.created_at,
				a.enabled,
				a.account_expired,
				a.account_locked
			FROM account a 
				LEFT OUTER JOIN account_scope as on a.uuid = as.account_uuid
			WHERE `)
	for i, _ := range valid {
		query.WriteString(`as.scope = ?`)
		if i < len(valid)-1 {
			query.WriteString(" OR ")
		}
	}
	query.WriteString(`ORDER BY lastname, firstname ASC`)

	// needs to be this type
	var records []Profile
	if err := s.db.SelectRecords(query.String(), &records, sliceToVariatic(valid)...); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("users not found: %v", err)
		}
		return nil, fmt.Errorf("failed to execute sql query: %v", err)
	}

	// de-dupelicate records
	unique := make(map[string]Profile, len(records))
	for _, r := range records {
		unique[r.Id] = r
	}

	// convert map to slice of users
	// decrypt user data
	users := make([]Profile, 0, len(unique))
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
func (s *groupService) decryptProfile(user *Profile) error {

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
func (s *groupService) decrypt(encrypted, errMsg string, clear *[]byte, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	decrypted, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*clear = decrypted
}
