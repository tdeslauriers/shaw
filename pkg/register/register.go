package register

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"shaw/internal/util"
	"shaw/pkg/user"
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

var defaultScopes []string = []string{"r:shaw:profile:*", "w:shaw:profile:*", "r:silhouette:profile:*", "w:silhouette:profile:*", "r:junk:*"}

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

	// check client id
	if len(cmd.ClientId) != 36 {
		s.logger.Error("invalid client id", "err", fmt.Sprintf("client id %s is not a valid uuid", cmd.ClientId))
		return errors.New("invalid client id")
	}

	// create blind user userIndex
	userIndex, err := s.indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		s.logger.Error("failed to create username index", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// lookup user name and client id first
	// if user name exists, or client name does not exist, return error
	var wgCheck sync.WaitGroup
	checkErrChan := make(chan error, 2)

	// client lookup for client id used in xref creation
	var client types.IdentityClient

	// check if user exists
	wgCheck.Add(1)
	go func(idx string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
		exists, err := s.db.SelectExists(query, idx)
		if err != nil {
			s.logger.Error("failed db call to check if user exists", "err", err.Error())
			ch <- fmt.Errorf("failed db lookup to check if user exists")
		}
		if exists {
			s.logger.Error(fmt.Sprintf("username %s already exists", cmd.Username))
			ch <- errors.New(UsernameUnavailableErrMsg)
		}
	}(userIndex, checkErrChan, &wgCheck)

	// check if client exists
	wgCheck.Add(1)
	go func(c *types.IdentityClient, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		query := "SELECT uuid, client_id, client_name, description, created_at, enabled, client_expired, client_locked FROM client WHERE client_id = ?"
		if err := s.db.SelectRecord(query, c, cmd.ClientId); err != nil {
			if err == sql.ErrNoRows {
				s.logger.Error(fmt.Sprintf("client id xxxxxx-%s not found", cmd.ClientId[len(cmd.ClientId)-6:]), "err", err.Error())
				ch <- errors.New(BuildUserErrMsg)
			} else {
				s.logger.Error(fmt.Sprintf("failed to lookup client record for client id %s", cmd.ClientId[len(cmd.ClientId)-6:]), "err", err.Error())
				ch <- errors.New(BuildUserErrMsg)
			}
		}

		if !c.Enabled {
			s.logger.Error(fmt.Sprintf("client id xxxxxx-%s is disabled", cmd.ClientId[len(cmd.ClientId)-6:]))
			ch <- errors.New("registration failed because client is disabled")
		}

		if c.ClientExpired {
			s.logger.Error(fmt.Sprintf("client id xxxxxx-%s is expired", cmd.ClientId[len(cmd.ClientId)-6:]))
			ch <- errors.New("registration failed because client is expired")
		}

		if c.ClientLocked {
			s.logger.Error(fmt.Sprintf("client id xxxxxx-%s is locked", cmd.ClientId[len(cmd.ClientId)-6:]))
			ch <- errors.New("registration failed because client is locked")
		}

	}(&client, checkErrChan, &wgCheck)

	// wait for checks to complete
	wgCheck.Wait()
	close(checkErrChan)

	// return err if either check fails
	errCount := len(checkErrChan)
	if errCount > 0 {
		var builder strings.Builder
		count := 0
		for e := range checkErrChan {
			builder.WriteString(e.Error())
			if errCount > 1 && count < errCount-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	// handle crypto/encryption operations on user data concurrently
	var (
		wgBuild   sync.WaitGroup
		id        string
		username  string
		password  string
		firstname string
		lastname  string
		dob       string
		slug      string
		slugIndex string

		buildErrChan = make(chan error, 10)
	)

	// build user record / encrypt user data for persistance
	wgBuild.Add(1)
	go func(id *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			msg := fmt.Sprintf("failed to create uuid for username/email %s", cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*id = i.String()
	}(&id, buildErrChan, &wgBuild)

	// build user slug and slug index
	wgBuild.Add(1)
	go func(slug, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// create user slug value
		sg, err := uuid.NewRandom()
		if err != nil {
			msg := fmt.Sprintf("failed to create user slug for username/email %s: %v", cmd.Username, err)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		sgIndex, err := s.indexer.ObtainBlindIndex(sg.String())
		if err != nil {
			msg := fmt.Sprintf("failed to create slug index for username/email %s", cmd.Username)
			ch <- errors.New(msg)
		}

		encrypted, err := s.cipher.EncryptServiceData(sg.String())
		if err != nil {
			msg := fmt.Sprintf("%s user slug for username/email %s: %v", FieldLevelEncryptErrMsg, cmd.Username, err)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*slug = encrypted
		*index = sgIndex
	}(&slug, &slugIndex, buildErrChan, &wgBuild)

	// encrypt username
	wgBuild.Add(1)
	go func(user *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(cmd.Username)
		if err != nil {
			msg := fmt.Sprintf("%s username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*user = encrypted
	}(&username, buildErrChan, &wgBuild)

	// bcrypt hash password
	wgBuild.Add(1)
	go func(pw *string, ch chan error, wg *sync.WaitGroup) {
		defer wgBuild.Done()

		hashed, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
		if err != nil {
			msg := fmt.Sprintf("failed to generate bcrypt password hash for username/email (%s)", cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*pw = string(hashed)
	}(&password, buildErrChan, &wgBuild)

	// encrypt firstname
	wgBuild.Add(1)
	go func(first *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(cmd.Firstname)
		if err != nil {
			msg := fmt.Sprintf("%s first name for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*first = encrypted
	}(&firstname, buildErrChan, &wgBuild)

	// encrypt lastname
	wgBuild.Add(1)
	go func(last *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(cmd.Lastname)
		if err != nil {
			msg := fmt.Sprintf("%s lastname for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*last = encrypted
	}(&lastname, buildErrChan, &wgBuild)

	// encrypt dob
	wgBuild.Add(1)
	go func(dob *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData(cmd.Birthdate)
		if err != nil {
			msg := fmt.Sprintf("%s dob for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			s.logger.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*dob = encrypted
	}(&dob, buildErrChan, &wgBuild)

	// wait for all build operations to complete
	wgBuild.Wait()
	close(buildErrChan)

	// if any build errors, aggregate and return
	errCount = len(buildErrChan)
	if errCount > 0 {
		var builder strings.Builder
		count := 0
		for e := range buildErrChan {
			builder.WriteString(e.Error())
			if errCount > 1 && count < errCount-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	createdAt := time.Now().UTC()

	account := types.UserAccount{
		Uuid:           id,
		Username:       username, // encrypted username
		UserIndex:      userIndex,
		Password:       password,  // encrypted password
		Firstname:      firstname, // encrypted firstname
		Lastname:       lastname,  // encrypted lastname
		Birthdate:      dob,       // encrypted dob
		Slug:           slug,      // encrypted slug
		SlugIndex:      slugIndex,
		CreatedAt:      createdAt.Format("2006-01-02 15:04:05"),
		Enabled:        true, // this will change to false when email verification built
		AccountExpired: false,
		AccountLocked:  false,
	}

	var (
		wgPersist      sync.WaitGroup
		persistErrChan = make(chan error, 2)
	)

	wgPersist.Add(1)
	go func(a types.UserAccount, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()
		// insert user into database
		query := "INSERT INTO account (uuid, username, user_index, password, firstname, lastname, birth_date, slug, slug_index, created_at, enabled, account_expired, account_locked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
		if err := s.db.InsertRecord(query, a); err != nil {
			s.logger.Error(fmt.Sprintf("failed to insert (%s) user record into account table in db", cmd.Username), "err", err.Error())
			ch <- errors.New(BuildUserErrMsg)
			return
		}
		s.logger.Info(fmt.Sprintf("user %s successfully saved in account table", cmd.Username))
	}(account, persistErrChan, &wgPersist)

	// persist password to password history table
	wgPersist.Add(1)
	go func(a types.UserAccount, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		pwId, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to create uuid for password history record for registering user %s", cmd.Username)
			return
		}

		history := user.PasswordHistory{
			Id:        pwId.String(),
			Password:  a.Password,
			Updated:   a.CreatedAt,
			AccountId: a.Uuid,
		}

		query := "INSERT INTO password_history (uuid, password, updated, account_uuid) VALUES (?, ?, ?, ?)"
		if err := s.db.InsertRecord(query, history); err != nil {
			ch <- fmt.Errorf("failed to insert password history record for registering user %s", cmd.Username)
			return
		}
		s.logger.Info(fmt.Sprintf("password history record successfully saved for registering user %s", cmd.Username))
	}(account, persistErrChan, &wgPersist)

	// wait for user to be saved, otherwise no need to continue.
	wgPersist.Wait()
	close(persistErrChan)

	// consolidate and return err if user account failed to save
	errCount = len(persistErrChan)
	if errCount > 0 {
		var builder strings.Builder
		count := 0
		for e := range persistErrChan {
			builder.WriteString(e.Error())
			if count < errCount-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.s2sToken.GetServiceToken(util.ServiceNameS2s)
	if err != nil {
		s.logger.Error("failed to get s2s token to retreive scopes", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// call scopes endpoint
	var scopes []types.Scope
	if err := s.s2sCaller.GetServiceData("/service/scopes", s2stoken, "", &scopes); err != nil {
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
	var (
		wgXref      sync.WaitGroup
		xrefErrChan = make(chan error)
	)
	for _, scope := range defaults {

		wgXref.Add(1)
		go func(id, created string, scope types.Scope, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			xref := types.AccountScopeXref{
				Id:          0,  // auto increment
				AccountUuid: id, // user id from above
				ScopeUuid:   scope.Uuid,
				CreatedAt:   created,
			}

			query := "INSERT INTO account_scope (id, account_uuid, scope_uuid, created_at) VALUES (?, ?, ?, ?)"
			if err := s.db.InsertRecord(query, xref); err != nil {
				ch <- fmt.Errorf("failed to create/persist xref record for %s - %s: %v", cmd.Username, scope.Name, err)
				return
			}

			s.logger.Info(fmt.Sprintf("user %s successfully assigned default scope %s", cmd.Username, scope.Name))
		}(id, createdAt.Format("2006-01-02 15:04:05"), scope, xrefErrChan, &wgXref)
	}

	// Associate user with client
	wgXref.Add(1)
	go func(id, created string, c types.IdentityClient, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		xref := types.UserAccountClientXref{
			Id:        0,      // auto increment
			AccountId: id,     // user id from above
			ClientId:  c.Uuid, // Note: client.Uuid is the identity client record's uuid, not the client_id
			CreatedAt: created,
		}

		query := "INSERT INTO account_client (id, account_uuid, client_uuid, created_at) VALUES (?, ?, ?, ?)"
		if err := s.db.InsertRecord(query, xref); err != nil {
			ch <- fmt.Errorf("failed to associate user %s with client %s: %v", cmd.Username, c.ClientName, err)
			return
		}

		s.logger.Info(fmt.Sprintf("user %s successfully associated with client %s", cmd.Username, ""))
	}(id, createdAt.Format("2006-01-02 15:04:05"), client, xrefErrChan, &wgXref)

	// wait for all xref operations to complete
	wgXref.Wait()
	close(xrefErrChan)

	// return err if xref associations failed
	errCount = len(xrefErrChan)
	if errCount > 0 {
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
