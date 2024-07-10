package register

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"

	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"

	"golang.org/x/crypto/bcrypt"
)

var defaultScopes []string = []string{"r:silhouette:profile:*", "e:silhouette:profile:*", "r:junk:*"}

type Service interface {
	// Register registers a new user account and creates appropriate xrefs for default scopes and client(s)
	Register(types.UserRegisterCmd) error
}

func NewService(db data.SqlRepository, c data.Cryptor, i data.Indexer, p provider.S2sTokenProvider, caller connect.S2sCaller) Service {
	return &service{
		db:        db,
		cipher:    c,
		indexer:   i,
		s2sToken:  p,
		s2sCaller: caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db        data.SqlRepository
	cipher    data.Cryptor
	indexer   data.Indexer
	s2sToken  provider.S2sTokenProvider
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

	// FieldLevelEncryptErrMsg is a error message returned when a field level encryption operation fails.
	// Intent is for consuming handler to check for this message and return a 500 status code.
	FieldLevelEncryptErrMsg = "failed to field level encrypt "
)

// Register implements the RegistrationService interface
func (s *service) Register(cmd types.UserRegisterCmd) error {

	// validate registration fields
	// redundant check because checked in handler, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		s.logger.Error("failed to validate user registration fields", "err", err.Error())
		return errors.New(err.Error())
	}

	// create blind user index
	index, err := s.indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		s.logger.Error("failed to create username index", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// lookup user name and client id first
	// if user name exists, or client name does not exist, return error
	var wgCheck sync.WaitGroup
	clientChan := make(chan types.IdentityClient, 1)
	checkErrChan := make(chan error, 2)

	// check if user exists
	wgCheck.Add(1)
	go func() {
		defer wgCheck.Done()

		query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
		exists, err := s.db.SelectExists(query, index)
		if err != nil {
			s.logger.Error("failed db call to check if user exists", "err", err.Error())
			checkErrChan <- fmt.Errorf("failed db lookup to check if user exists")
		}
		if exists {
			s.logger.Error(fmt.Sprintf("username %s already exists", cmd.Username))
			checkErrChan <- errors.New(UsernameUnavailableErrMsg)
		}
	}()

	// check if client exists
	wgCheck.Add(1)
	go func() {
		defer wgCheck.Done()

		var client types.IdentityClient
		query := "SELECT uuid, client_id, client_name, description, created_at, enabled, client_expired, client_locked FROM client WHERE client_id = ?"
		if err := s.db.SelectRecord(query, &client, cmd.ClientId); err != nil {
			if err == sql.ErrNoRows {
				s.logger.Error(fmt.Sprintf("client id xxxxxx-%s not found", cmd.ClientId[len(cmd.ClientId)-6:]), "err", err.Error())
				checkErrChan <- errors.New(BuildUserErrMsg)
			} else {
				s.logger.Error(fmt.Sprintf("failed to lookup client record for client id %s", cmd.ClientId[len(cmd.ClientId)-6:]), "err", err.Error())
				checkErrChan <- errors.New(BuildUserErrMsg)
			}
		}
	}()

	go func() {
		wgCheck.Wait()
		close(clientChan)
		close(checkErrChan)
	}()

	// return err if either check fails
	if len(checkErrChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range checkErrChan {
			builder.WriteString(e.Error())
			if len(checkErrChan) > 1 && count < len(checkErrChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	// handle crypto/encryption operations on user data concurrently
	var wgBuild sync.WaitGroup
	idChan := make(chan uuid.UUID, 1)
	usernameChan := make(chan string, 1)
	passwordChan := make(chan string, 1)
	firstnameChan := make(chan string, 1)
	lastnameChan := make(chan string, 1)
	dobChan := make(chan string, 1)

	buildErrChan := make(chan error, 1)

	// build user record / encrypt user data for persistance
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		id, err := uuid.NewRandom()
		if err != nil {
			s.logger.Error(fmt.Sprintf("failed to create uuid for username/email %s", cmd.Username), "err", err.Error())
			buildErrChan <- errors.New(BuildUserErrMsg)
		}
		idChan <- id
	}()

	// encrypt username
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		username, err := s.cipher.EncryptServiceData(cmd.Username)
		if err != nil {
			msg := fmt.Sprintf("%s username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			buildErrChan <- errors.New(msg)
		}
		usernameChan <- username
	}()

	// bcrypt hash password
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		password, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
		if err != nil {
			msg := fmt.Sprintf("failed to generate bcrypt password hash for username/email (%s)", cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			buildErrChan <- errors.New(msg)
		}
		passwordChan <- string(password)
	}()

	// encrypt firstname
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		first, err := s.cipher.EncryptServiceData(cmd.Firstname)
		if err != nil {
			msg := fmt.Sprintf("%s first name for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			buildErrChan <- errors.New(msg)
		}
		firstnameChan <- first

	}()

	// encrypt lastname
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		last, err := s.cipher.EncryptServiceData(cmd.Lastname)
		if err != nil {
			msg := fmt.Sprintf("%s lastname for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			buildErrChan <- errors.New(msg)
		}
		lastnameChan <- last
	}()

	// encrypt dob
	wgBuild.Add(1)
	go func() {
		defer wgBuild.Done()

		dob, err := s.cipher.EncryptServiceData(cmd.Birthdate)
		if err != nil {
			msg := fmt.Sprintf("%s dob for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			buildErrChan <- errors.New(msg)
		}
		dobChan <- dob
	}()

	go func() {
		wgBuild.Wait()
		close(idChan)
		close(usernameChan)
		close(passwordChan)
		close(firstnameChan)
		close(lastnameChan)
		close(dobChan)
		close(buildErrChan)
	}()

	// if any build errors, aggregate and return
	if len(buildErrChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range buildErrChan {
			builder.WriteString(e.Error())
			if len(buildErrChan) > 1 && count < len(buildErrChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	// get uuid and encrypted values from channels
	id := <-idChan
	username := <-usernameChan
	password := <-passwordChan
	first := <-firstnameChan
	last := <-lastnameChan
	dob := <-dobChan

	createdAt := time.Now()

	user := types.UserAccount{
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
	query := "INSERT INTO account (uuid, username, user_index, password, firstname, lastname, birth_date, created_at, enabled, account_expired, account_locked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	if err := s.db.InsertRecord(query, user); err != nil {
		s.logger.Error(fmt.Sprintf("failed to insert (%s) user record into account table in db", username), "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}
	s.logger.Info(fmt.Sprintf("user %s successfully saved in account table", cmd.Username))

	// wait for user to be saved, otherwise no need to continue.
	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.s2sToken.GetServiceToken(util.S2sServiceName)
	if err != nil {
		s.logger.Error("failed to get s2s token to retreive scopes", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// call scopes endpoint
	var scopes []types.Scope
	if err := s.s2sCaller.GetServiceData("/scopes", s2stoken, "", &scopes); err != nil {
		s.logger.Error("failed to get scopes data", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	if len(scopes) < 1 {
		s.logger.Error("no scopes returned from scopes endpoint")
		return errors.New(BuildUserErrMsg)
	}

	// filter for default scopes
	defaults := filterScopes(scopes, defaultScopes)

	// insert xrefs
	var wgXref sync.WaitGroup
	xrefErrChan := make(chan error)
	for _, scope := range defaults {

		wgXref.Add(1)
		go func(scope types.Scope) {
			defer wgXref.Done()

			xref := types.AccountScopeXref{
				Id:          0,           // auto increment
				AccountUuid: id.String(), // user id from above
				ScopeUuid:   scope.Uuid,
				CreatedAt:   createdAt.Format("2006-01-02 15:04:05"),
			}

			query := "INSERT INTO account_scope (id, account_uuid, scope_uuid, created_at) VALUES (?, ?, ?, ?)"
			if err := s.db.InsertRecord(query, xref); err != nil {
				xrefErrChan <- fmt.Errorf("failed to create/persist xref record for %s - %s: %v", cmd.Username, scope.Name, err)
				return
			}

			s.logger.Info(fmt.Sprintf("user %s successfully assigned default scope %s", cmd.Username, scope.Name))
		}(scope)
	}

	// Associate user with client
	wgXref.Add(1)
	go func() {
		defer wgXref.Done()

		c := <-clientChan

		xref := types.UserAccountClientXref{
			Id:        0,           // auto increment
			AccountId: id.String(), // user id from above
			ClientId:  c.Uuid,      // Note: client.Uuid is the identity client record's uuid, not the client_id
			CreatedAt: createdAt.Format("2006-01-02 15:04:05"),
		}

		query = "INSERT INTO account_client (id, account_uuid, client_uuid, created_at) VALUES (?, ?, ?, ?)"
		if err := s.db.InsertRecord(query, xref); err != nil {
			xrefErrChan <- fmt.Errorf("failed to associate user %s with client %s: %v", cmd.Username, c.ClientName, err)
			return
		}

		s.logger.Info(fmt.Sprintf("user %s successfully associated with client %s", cmd.Username, ""))
	}()

	go func() {
		wgXref.Wait()
		close(xrefErrChan)
	}()

	// return err if xref associations failed
	if len(xrefErrChan) > 0 {
		for err := range xrefErrChan {
			s.logger.Error(err.Error())
		}
		return errors.New(BuildUserErrMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully assigned and saved all default scopes and clients to user %s", cmd.Username))
	s.logger.Info(fmt.Sprintf("user %s successfully registered", cmd.Username))

	return nil
}

func filterScopes(scopes []types.Scope, defaults []string) []types.Scope {

	scopeMap := make(map[string]struct{})
	for _, def := range defaults {
		scopeMap[def] = struct{}{}
	}

	var filtered []types.Scope
	for _, s := range scopes {
		if _, exists := scopeMap[s.Scope]; exists {
			filtered = append(filtered, s)
		}
	}

	return filtered
}
