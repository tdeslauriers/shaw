package register

import (
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
	"golang.org/x/crypto/bcrypt"
)

var defaultScopes []string = []string{"r:silhouette:profile:*", "e:silhouette:profile:*", "r:junk:*"}

type RegistrationService interface {
	Register(session.UserRegisterCmd) error
}

func NewRegistrationService(sql data.SqlRepository, ciph data.Cryptor, indexer data.Indexer, s2s session.S2sTokenProvider, caller connect.S2sCaller) RegistrationService {
	return &registrationService{
		db:        sql,
		cipher:    ciph,
		indexer:   indexer,
		s2sToken:  s2s,
		s2sCaller: caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationService = (*registrationService)(nil)

type registrationService struct {
	db        data.SqlRepository
	cipher    data.Cryptor
	indexer   data.Indexer
	s2sToken  session.S2sTokenProvider
	s2sCaller connect.S2sCaller

	logger *slog.Logger
}

// assumes fields have passed input validation
func (r *registrationService) Register(cmd session.UserRegisterCmd) error {

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		return fmt.Errorf("failed to create username blind index: %v", err)
	}

	// check if user already exists
	query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
	exists, err := r.db.SelectExists(query, index)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %v", err)
	}
	if exists {
		return fmt.Errorf("username unavailable")
	}

	// build user record / encrypt user data
	id, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to create uuid for user registration request: %v", err)
	}

	username, err := r.cipher.EncyptServiceData(cmd.Username)
	if err != nil {
		return fmt.Errorf("failed to field level encrypt user registration username/email: %v", err)
	}

	// bcrypt hash password
	password, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
	if err != nil {
		r.logger.Error("failed to generate bcrypt password hash", "err", err.Error())
		return fmt.Errorf("failed to create user record")
	}

	first, err := r.cipher.EncyptServiceData(cmd.Firstname)
	if err != nil {
		return fmt.Errorf("failed to field level encrypt user registration firstname: %v", err)
	}

	last, err := r.cipher.EncyptServiceData(cmd.Lastname)
	if err != nil {
		return fmt.Errorf("failed to field level encrypt user registration lastname: %v", err)
	}

	dob, err := r.cipher.EncyptServiceData(cmd.Birthdate)
	if err != nil {
		return fmt.Errorf("failed to field level encrypt user registration dob: %v", err)
	}

	createdAt := time.Now()

	user := session.UserAccountData{
		Uuid:           id.String(),
		Username:       username,
		UserIndex:      index,
		Password:       string(password),
		Firstname:      first,
		Lastname:       last,
		Birthdate:      dob,
		CreatedAt:      createdAt.Format("2006-01-02 15:04:05"),
		Enabled:        true, // this will change to false when email verification built
		AccountExpired: false,
		AccountLocked:  false,
	}

	// insert user into database
	query = "INSERT INTO account (uuid, username, user_index, password, firstname, lastname, birth_date, created_at, enabled, account_expired, account_locked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	if err := r.db.InsertRecord(query, user); err != nil {
		return fmt.Errorf("failed to enter registration record into account table in db: %v", err)
	}

	// add profile, blog service scopes r, w
	// get s2s ran token to retreive scopes
	s2stoken, err := r.s2sToken.GetServiceToken("ran")
	if err != nil {
		return fmt.Errorf("failed to get ran service token to retreive scopes: %v", err)
	}

	// call scopes endpoint
	var scopes []session.Scope
	if err := r.s2sCaller.GetServiceData("/scopes", s2stoken, "", &scopes); err != nil {
		return fmt.Errorf("failed to get scopes data: %v", err)
	}

	if len(scopes) < 1 {
		return fmt.Errorf("no scopes returned from scopes endpoint")
	}

	// filter defaults
	defaults := filterScopes(scopes, defaultScopes)

	// insert xrefs
	var wg sync.WaitGroup
	for _, scope := range defaults {

		wg.Add(1)
		go func(scope session.Scope) {
			defer wg.Done()

			xref := session.AccountScopeXref{
				Id:          0,           // auto increment
				AccountUuid: id.String(), // user id from above
				ScopeUuid:   scope.Uuid,
				CreatedAt:   createdAt.Format("2006-01-02 15:04:05"),
			}

			query := "INSERT INTO account_scope (id, account_uuid, scope_uuid, created_at) VALUES (?, ?, ?, ?)"
			if err := r.db.InsertRecord(query, xref); err != nil {
				r.logger.Error(fmt.Sprintf("failed to create xref record for %s - %s", cmd.Username, scope.Name), "err", err.Error())
				return
			}

		}(scope)
	}

	wg.Wait()

	return nil
}

func filterScopes(scopes []session.Scope, defaults []string) []session.Scope {

	scopeMap := make(map[string]struct{})
	for _, d := range defaults {
		scopeMap[d] = struct{}{}
	}

	var filtered []session.Scope
	for _, s := range scopes {
		if _, exists := scopeMap[s.Scope]; exists {
			filtered = append(filtered, s)
		}
	}

	return filtered
}
