package user

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/session"
	"golang.org/x/crypto/bcrypt"
)

type RegistrationService interface {
	Register(session.UserRegisterCmd) error
}

type MariaAuthRegistrationService struct {
	Dao     data.SqlRepository
	Cipher  data.Cryptor
	Indexer data.Indexer
	S2s     session.S2STokenProvider
}

func NewAuthRegistrationService(sql data.SqlRepository, ciph data.Cryptor, i data.Indexer, s2s session.S2STokenProvider) *MariaAuthRegistrationService {
	return &MariaAuthRegistrationService{
		Dao:     sql,
		Cipher:  ciph,
		Indexer: i,
		S2s:     s2s,
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
		log.Printf("unable to enter registeration record into account table in db: %v", err)
		return fmt.Errorf("unable to perst user registration to db")
	}

	// add profile service scopes r, w
	// get token
	r.S2s.GetServiceToken()

	return nil
}
