package register

import (
	"errors"
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

type Service interface {
	// Register registers a new user account and creates appropriate xrefs for default scopes and client(s)
	Register(session.UserRegisterCmd) error
}

func NewService(sql data.SqlRepository, ciph data.Cryptor, indexer data.Indexer, s2s session.S2sTokenProvider, caller connect.S2sCaller) Service {
	return &service{
		db:        sql,
		cipher:    ciph,
		indexer:   indexer,
		s2sToken:  s2s,
		s2sCaller: caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db        data.SqlRepository
	cipher    data.Cryptor
	indexer   data.Indexer
	s2sToken  session.S2sTokenProvider
	s2sCaller connect.S2sCaller

	logger *slog.Logger
}

const (
	// BuildUserErrMsg is a genearlized error message returned a failed process in the Register method of the RegistationService interface.
	// For example, a failure to create an user index or encrypt field level data.
	// Intent is for consuming handler to check for this message and return a 500 status code.
	BuildUserErrMsg = "failed to build/persist user record"
	// UsernameUnavailableErrMsg is a error message returned when a user attempts to register with a username that already exists in the database.
	// Intent is for consuming handler to check for this message and return a 409 status code.
	UsernameUnavailableErrMsg = "username unavailable"
)

// Register implements the RegistrationService interface
func (r *service) Register(cmd session.UserRegisterCmd) error {

	// validate registration fields
	// redundant check because checked in handler, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		r.logger.Error("failed to validate user registration fields", "err", err.Error())
		return errors.New(err.Error())
	}

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		r.logger.Error("failed to create username index", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// check if user already exists
	query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
	exists, err := r.db.SelectExists(query, index)
	if err != nil {
		r.logger.Error("failed db call to check if user exists", "err", err.Error())
		return fmt.Errorf("failed call to check if user exists")
	}
	if exists {
		r.logger.Error(fmt.Sprintf("username %s already exists", cmd.Username))
		return errors.New(UsernameUnavailableErrMsg)
	}

	// build user record / encrypt user data
	id, err := uuid.NewRandom()
	if err != nil {
		r.logger.Error("failed to create uuid for user registration request", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	username, err := r.cipher.EncryptServiceData(cmd.Username)
	if err != nil {
		r.logger.Error("failed to field level encrypt user registration username/email", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// bcrypt hash password
	password, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
	if err != nil {
		r.logger.Error("failed to generate bcrypt password hash", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	first, err := r.cipher.EncryptServiceData(cmd.Firstname)
	if err != nil {
		r.logger.Error("failed to field level encrypt user registration firstname", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	last, err := r.cipher.EncryptServiceData(cmd.Lastname)
	if err != nil {
		r.logger.Error("failed to field level encrypt user registration lastname", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	dob, err := r.cipher.EncryptServiceData(cmd.Birthdate)
	if err != nil {
		r.logger.Error("failed to field level encrypt user registration dob", "err", err.Error())
		return errors.New(BuildUserErrMsg)
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
		r.logger.Error(fmt.Sprintf("failed to insert (%s) user record into account table in db", username), "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}
	r.logger.Info(fmt.Sprintf("user %s successfully saved in account table", cmd.Username))

	// add profile, blog service scopes r, w
	// get s2s service endpoint token to retreive scopes
	s2stoken, err := r.s2sToken.GetServiceToken(util.S2sServiceName)
	if err != nil {
		r.logger.Error("failed to get s2s token to retreive scopes", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// call scopes endpoint
	var scopes []session.Scope
	if err := r.s2sCaller.GetServiceData("/scopes", s2stoken, "", &scopes); err != nil {
		r.logger.Error("failed to get scopes data", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	if len(scopes) < 1 {
		r.logger.Error("no scopes returned from scopes endpoint")
		return errors.New(BuildUserErrMsg)
	}

	// filter defaults
	defaults := filterScopes(scopes, defaultScopes)

	// insert xrefs
	var wg sync.WaitGroup
	xrefChan := make(chan error)
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
				xrefChan <- err
				return
			}
			r.logger.Info(fmt.Sprintf("user %s successfully assigned default scope %s", cmd.Username, scope.Name))

		}(scope)
	}

	// Associate user with client
	wg.Add(1)
	go func() {
		defer wg.Done()

		// lookup client uuid for xref
		var client session.IdentityClient
		query := "SELECT uuid, client_id, client_name, description, created_at, enabled, client_expired, client_locked FROM client WHERE client_id = ?"
		if err := r.db.SelectRecord(query, &client, cmd.ClientId); err != nil {
			r.logger.Error(fmt.Sprintf("failed to lookup client uuid for client id %s", cmd.ClientId), "err", err.Error())
			xrefChan <- err
			return
		}

		xref := session.UserAccountClientXref{
			Id:        0,           // auto increment
			AccountId: id.String(), // user id from above
			ClientId:  client.Uuid, // Note: client.Uuid is the identity client record's uuid, not the client_id
			CreatedAt: createdAt.Format("2006-01-02 15:04:05"),
		}

		query = "INSERT INTO account_client (id, account_uuid, client_uuid, created_at) VALUES (?, ?, ?, ?)"
		if err := r.db.InsertRecord(query, xref); err != nil {
			r.logger.Error(fmt.Sprintf("failed to associate user %s with client %s", cmd.Username, ""), "err", err.Error())
			xrefChan <- err
			return
		}
		r.logger.Info(fmt.Sprintf("user %s successfully associated with client %s", cmd.Username, ""))
	}()

	go func() {
		wg.Wait()
		close(xrefChan)
	}()

	// return err of xref associations failed
	if len(xrefChan) > 0 {
		return errors.New(BuildUserErrMsg)
	}

	r.logger.Info(fmt.Sprintf("successfully assigned and saved all default scopes to user %s", cmd.Username))

	return nil
}

func filterScopes(scopes []session.Scope, defaults []string) []session.Scope {

	scopeMap := make(map[string]struct{})
	for _, def := range defaults {
		scopeMap[def] = struct{}{}
	}

	var filtered []session.Scope
	for _, s := range scopes {
		if _, exists := scopeMap[s.Scope]; exists {
			filtered = append(filtered, s)
		}
	}

	return filtered
}
