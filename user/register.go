package user

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/session"
	"golang.org/x/crypto/bcrypt"
)

var defaultScopes []string = []string{"r:silhouette:profile:*", "e:silhouette:profile:*", "r:junk:*"}

type RegistrationService interface {
	Register(session.UserRegisterCmd) error
}

type MariaAuthRegistrationService struct {
	Dao       data.SqlRepository
	Cipher    data.Cryptor
	Indexer   data.Indexer
	S2sToken  session.S2STokenProvider
	S2sCaller connect.S2SCaller
}

func NewAuthRegistrationService(sql data.SqlRepository, ciph data.Cryptor, i data.Indexer, s2s session.S2STokenProvider, caller connect.S2SCaller) *MariaAuthRegistrationService {
	return &MariaAuthRegistrationService{
		Dao:       sql,
		Cipher:    ciph,
		Indexer:   i,
		S2sToken:  s2s,
		S2sCaller: caller,
	}
}

// assumes fields have passed input validation
func (r *MariaAuthRegistrationService) Register(cmd session.UserRegisterCmd) error {

	// create blind index
	index, err := r.Indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		log.Printf("unable to create username blind index: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	// check if user already exists
	query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
	exists, err := r.Dao.SelectExists(query, index)
	if err != nil {
		log.Printf("unable to check if user exists: %v", err)
		return fmt.Errorf("unable to create user record")
	}
	if exists {
		return fmt.Errorf("username unavailable")
	}

	// build user record / encrypt user data
	id, err := uuid.NewRandom()
	if err != nil {
		log.Printf("unable to create uuid for user registration request: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	username, err := r.Cipher.EncyptServiceData(cmd.Username)
	if err != nil {
		log.Printf("unable to field level encrypt user registration username/email: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	// bcrypt hash password
	password, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
	if err != nil {
		log.Printf("unable to generate bcrypt password hash: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	first, err := r.Cipher.EncyptServiceData(cmd.Firstname)
	if err != nil {
		log.Printf("unable to field level encrypt user registration firstname: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	last, err := r.Cipher.EncyptServiceData(cmd.Lastname)
	if err != nil {
		log.Printf("unable to field level encrypt user registration lastname: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	dob, err := r.Cipher.EncyptServiceData(cmd.Birthdate)
	if err != nil {
		log.Printf("unable to field level encrypt user registration dob: %v", err)
		return fmt.Errorf("unable to create user record")
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
	if err := r.Dao.InsertRecord(query, user); err != nil {
		log.Printf("unable to enter registration record into account table in db: %v", err)
		return fmt.Errorf("unable to persist user registration to db")
	}

	// add profile, blog service scopes r, w
	// get token
	s2stoken, err := r.S2sToken.GetServiceToken()
	if err != nil {
		log.Printf("unable to obtain service token: %v", err)
		return fmt.Errorf("unable to set scopes for new user")
	}

	// call scopes endpoint
	var scopes []session.Scope
	if err := r.S2sCaller.GetServiceData("/scopes", s2stoken, "", scopes); err != nil {
		log.Printf("unable to get scopes data: %v", err)
		return fmt.Errorf("unable to set scopes for new user")
	}

	if len(scopes) < 1 {
		log.Printf("no scopes returned from scopes endpoint")
		return fmt.Errorf("unable to set scopes for new user")
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
			if err := r.Dao.InsertRecord(query, xref); err != nil {
				log.Printf("unable to create xref record for %s - %s: %v", cmd.Username, scope.Name, err)
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
