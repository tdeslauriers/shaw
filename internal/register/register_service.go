package register

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	ran "github.com/tdeslauriers/ran/pkg/api/scopes"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/user"
	apiReg "github.com/tdeslauriers/shaw/pkg/api/register"
	apiUser "github.com/tdeslauriers/shaw/pkg/api/user"

	"golang.org/x/crypto/bcrypt"
)

var defaultScopes []string = []string{"r:shaw:profile:*", "w:shaw:profile:*", "r:silhouette:profile:*", "w:silhouette:profile:*", "r:junk:*"}

type Service interface {
	// Register registers a new user account and creates appropriate xrefs for default scopes and client(s)
	Register(ctx context.Context, cmd apiReg.UserRegisterCmd) error
}

func NewService(
	db *sql.DB,
	c data.Cryptor,
	i data.Indexer,
	p provider.S2sTokenProvider,
	s2s *connect.S2sCaller,
) Service {

	return &service{
		db:      NewRegisterRepository(db),
		cipher:  c,
		indexer: i,
		tkn:     p,
		s2s:     s2s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageRegister)).
			With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db      RegisterRepsoitory
	cipher  data.Cryptor
	indexer data.Indexer
	tkn     provider.S2sTokenProvider
	s2s     *connect.S2sCaller

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
func (s *service) Register(ctx context.Context, cmd apiReg.UserRegisterCmd) error {

	// create local logger for this function with telemetry fields
	log := s.logger

	// get telemetry from context if exists
	if tel, ok := ctx.Value(connect.TelemetryKey).(*connect.Telemetry); ok && tel != nil {
		log = log.With(tel.TelemetryFields()...)
	} else {
		log.Warn("no telemetry found in context for registration service")
	}

	// check client id
	if len(cmd.ClientId) != 36 {
		log.Error("invalid client id", "err", fmt.Sprintf("client id %s is not a valid uuid", cmd.ClientId))
		return errors.New("invalid client id")
	}

	// create blind user userIndex
	userIndex, err := s.indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		log.Error("failed to create username index", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// lookup user name and client id first
	// if user name exists, or client name does not exist, return error
	var (
		wgCheck      sync.WaitGroup
		checkErrChan = make(chan error, 2)

		// client lookup for client id used in xref creation
		client IdentityClient
	)

	// check if user exists
	wgCheck.Add(1)
	go func(idx string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		exists, err := s.db.FindUserExists(idx)
		if err != nil {
			log.Error("failed db call to check if user exists", "err", err.Error())
			ch <- fmt.Errorf("failed db lookup to check if user exists")
		}
		if exists {
			log.Error(fmt.Sprintf("username %s already exists", cmd.Username))
			ch <- errors.New(UsernameUnavailableErrMsg)
		}
	}(userIndex, checkErrChan, &wgCheck)

	// check if client exists
	wgCheck.Add(1)
	go func(c *IdentityClient, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		iamClient, err := s.db.FindClientById(cmd.ClientId)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Error(fmt.Sprintf("client id %s not found", cmd.ClientId), "err", err.Error())
				ch <- errors.New(BuildUserErrMsg)
			} else {
				log.Error(fmt.Sprintf("failed to lookup client record for client id %s", cmd.ClientId), "err", err.Error())
				ch <- errors.New(BuildUserErrMsg)
			}
			return
		}

		// set client to value retrieved from db
		*c = *iamClient

		if !iamClient.Enabled {
			log.Error(fmt.Sprintf("client id %s is disabled", cmd.ClientId))
			ch <- errors.New("registration failed because client is disabled")
		}

		if iamClient.ClientExpired {
			log.Error(fmt.Sprintf("client id %s is expired", cmd.ClientId))
			ch <- errors.New("registration failed because client is expired")
		}

		if iamClient.ClientLocked {
			log.Error(fmt.Sprintf("client id xxxxxx-%s is locked", cmd.ClientId[len(cmd.ClientId)-6:]))
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
			log.Error(msg, "err", err.Error())
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
			log.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		sgIndex, err := s.indexer.ObtainBlindIndex(sg.String())
		if err != nil {
			msg := fmt.Sprintf("failed to create slug index for username/email %s", cmd.Username)
			ch <- errors.New(msg)
		}

		encrypted, err := s.cipher.EncryptServiceData([]byte(sg.String()))
		if err != nil {
			msg := fmt.Sprintf("%s user slug for username/email %s: %v", FieldLevelEncryptErrMsg, cmd.Username, err)
			log.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*slug = encrypted
		*index = sgIndex
	}(&slug, &slugIndex, buildErrChan, &wgBuild)

	// encrypt username
	wgBuild.Add(1)
	go func(user *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData([]byte(cmd.Username))
		if err != nil {
			msg := fmt.Sprintf("%s username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			log.Error(msg, "err", err.Error())
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
			log.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*pw = string(hashed)
	}(&password, buildErrChan, &wgBuild)

	// encrypt firstname
	wgBuild.Add(1)
	go func(first *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData([]byte(cmd.Firstname))
		if err != nil {
			msg := fmt.Sprintf("%s first name for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			log.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*first = encrypted
	}(&firstname, buildErrChan, &wgBuild)

	// encrypt lastname
	wgBuild.Add(1)
	go func(last *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData([]byte(cmd.Lastname))
		if err != nil {
			msg := fmt.Sprintf("%s lastname for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			log.Error(msg, "err", err.Error())
			ch <- errors.New(msg)
		}

		*last = encrypted
	}(&lastname, buildErrChan, &wgBuild)

	// encrypt dob
	wgBuild.Add(1)
	go func(dob *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cipher.EncryptServiceData([]byte(cmd.Birthdate))
		if err != nil {
			msg := fmt.Sprintf("%s dob for username/email (%s)", FieldLevelEncryptErrMsg, cmd.Username)
			log.Error(msg, "err", err.Error())
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

	account := apiUser.UserAccount{
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
	go func(a apiUser.UserAccount, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// insert user into database
		if err := s.db.InsertUserAccount(a); err != nil {
			log.Error(fmt.Sprintf("failed to insert (%s) user record into account table in db", cmd.Username), "err", err.Error())
			ch <- errors.New(BuildUserErrMsg)
			return
		}

		log.Info(fmt.Sprintf("user %s successfully saved in account table", cmd.Username))
	}(account, persistErrChan, &wgPersist)

	// persist password to password history table
	wgPersist.Add(1)
	go func(a apiUser.UserAccount, ch chan error, wg *sync.WaitGroup) {
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

		if err := s.db.InsertPasswordHistory(history); err != nil {
			ch <- fmt.Errorf("failed to insert password history record for registering user %s", cmd.Username)
			return
		}
		log.Info(fmt.Sprintf("password history record successfully saved for registering user %s", cmd.Username))
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
	s2stoken, err := s.tkn.GetServiceToken(ctx, util.ServiceNameS2s)
	if err != nil {
		log.Error("failed to get s2s token to retreive scopes", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	// call scopes endpoint
	scopes, err := connect.GetServiceData[[]ran.Scope](
		ctx,
		s.s2s,
		"/s2s/scopes",
		s2stoken,
		"",
	)
	if err != nil {
		log.Error("failed to get scopes data from s2s scopes endpoint", "err", err.Error())
		return errors.New(BuildUserErrMsg)
	}

	if len(scopes) < 1 {
		log.Error("no scopes returned from scopes endpoint")
		return errors.New(BuildUserErrMsg)
	} else {
		log.Info(fmt.Sprintf("successfully retrieved %d scopes from s2s scopes endpoint", len(scopes)))
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
		go func(id string, created time.Time, scope ran.Scope, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			xref := user.AccountScopeXref{
				Id:        0,  // auto increment
				AccountId: id, // user id from above
				ScopeId:   scope.Uuid,
				CreatedAt: data.CustomTime{Time: created},
			}

			if err := s.db.InsertAccountScopeXref(xref); err != nil {
				ch <- fmt.Errorf("failed to create/persist xref record for %s - %s: %v", cmd.Username, scope.Name, err)
				return
			}

			log.Info(fmt.Sprintf("user %s successfully assigned default scope %s", cmd.Username, scope.Name))
		}(id, createdAt, scope, xrefErrChan, &wgXref)
	}

	// Associate user with client
	wgXref.Add(1)
	go func(id, created string, c IdentityClient, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		xref := AccountClientXref{
			Id:        0,      // auto increment
			AccountId: id,     // user id from above
			ClientId:  c.Uuid, // Note: client.Uuid is the identity client record's uuid, not the client_id
			CreatedAt: created,
		}

		if err := s.db.InsertAccountClientXref(xref); err != nil {
			ch <- fmt.Errorf("failed to associate user %s with client %s: %v", cmd.Username, c.ClientName, err)
			return
		}

		log.Info(fmt.Sprintf("user %s successfully associated with client %s", cmd.Username, ""))
	}(id, createdAt.Format("2006-01-02 15:04:05"), client, xrefErrChan, &wgXref)

	// wait for all xref operations to complete
	wgXref.Wait()
	close(xrefErrChan)

	// return err if xref associations failed
	if len(xrefErrChan) > 0 {
		for err := range xrefErrChan {
			log.Error(err.Error())
		}
		return errors.New(BuildUserErrMsg)
	}

	log.Info(fmt.Sprintf("successfully assigned and saved all default scopes and clients to user %s", cmd.Username))
	log.Info(fmt.Sprintf("user %s successfully registered", cmd.Username))

	return nil
}

func filterScopes(scopes []ran.Scope, defaults []string) []ran.Scope {

	scopeMap := make(map[string]struct{})
	for _, def := range defaults {
		scopeMap[def] = struct{}{}
	}

	var filtered []ran.Scope
	for _, s := range scopes {
		if _, exists := scopeMap[s.Scope]; exists {
			filtered = append(filtered, s)
		}
	}

	return filtered
}
