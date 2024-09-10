package register

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

var (
	RegistrationUuid       = "1234"
	RegistrationUserKey    = "4567"
	RegistrationUsername   = "darth.vader@empire.com"
	RegistrationUserIndex  = "TK427"
	RegistrationPassword   = "YouDontPower0fTheDarkSide!"
	RegistrationFirstname  = "Darth"
	RegistrationLastname   = "Vader"
	ReigstrationBirthdate  = "1977-05-25"
	RegisterCreatedAt      = "2021-01-01"
	RegisterEnabled        = true
	RegisterAccountExpired = false
	RegisterAccountLocked  = false

	RegistrationClientId = "8d0b917a-6e0c-4600-b0fc-09739d6bd42b"

	UsernameExists = "sheev.palpatine@empire.com"
)

// mocks the indexer
type mockRegisterIndexer struct{}

func (i *mockRegisterIndexer) ObtainBlindIndex(username string) (string, error) {
	return RegistrationUserIndex, nil
}

// mock register service sql repository
type mockRegisterSqlRepository struct{}

func (dao *mockRegisterSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}
func (dao *mockRegisterSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	if args[0] == RegistrationClientId {
		*record.(*types.IdentityClient) = types.IdentityClient{
			Uuid:          "8d0b917a-6e0c-4600-b0fc-09739d6bd42b",
			Enabled:       true,
			ClientLocked:  false,
			ClientExpired: false,
		}
	}

	if args[0] == "invalid--6e0c-4600-b0fc-09739d6bd42b" {
		*record.(*types.IdentityClient) = types.IdentityClient{
			Uuid:          "8d0b917a-6e0c-4600-b0fc-09739d6bd42b",
			Enabled:       false,
			ClientLocked:  false,
			ClientExpired: false,
		}
	}
	return nil
}
func (dao *mockRegisterSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	if args[0] == UsernameExists {
		return false, errors.New("username unavailable")
	}
	return false, nil
}
func (dao *mockRegisterSqlRepository) InsertRecord(query string, record interface{}) error {

	if userAccount, ok := record.(*types.UserAccount); ok {
		if userAccount.Username == "account.insert@fail.com" {
			return errors.New("failed to insert")
		}
	}

	return nil
}

func (dao *mockRegisterSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	return nil
}
func (dao *mockRegisterSqlRepository) DeleteRecord(query string, args ...interface{}) error {
	return nil
}
func (dao *mockRegisterSqlRepository) Close() error { return nil }

// mock registration service cryptor
type mockRegisterCryptor struct{}

func (c *mockRegisterCryptor) EncryptServiceData(plaintext string) (string, error) {
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}
func (c *mockRegisterCryptor) DecryptServiceData(string) (string, error) { return "", nil }

// mock s2s token provider
type mockRegisterS2sTokenProvider struct{}

func (s2s *mockRegisterS2sTokenProvider) GetServiceToken(serviceName string) (string, error) {
	return fmt.Sprintf("valid-%s-service-token", serviceName), nil
}

// mock registration service call to s2s to get scopes
type mockRegisterS2sCaller struct{}

func (c *mockRegisterS2sCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {

	*data.(*[]types.Scope) = []types.Scope{
		{
			Uuid:        "1234",
			ServiceName: "silhouette",
			Scope:       "r:silhouette:profile:*",
			Name:        "read profile",
			Description: "read profile",
			CreatedAt:   "2021-01-01",
			Active:      true,
		},
		{
			Uuid:        "5678",
			ServiceName: "silhouette",
			Scope:       "e:silhouette:profile:*",
			Name:        "edit profile",
			Description: "edit profile",
			CreatedAt:   "2021-01-01",
			Active:      true,
		},
		{
			Uuid:        "9012",
			ServiceName: "junk",
			Scope:       "r:junk:*",
			Name:        "read blog",
			Description: "read blog",
			CreatedAt:   "2021-01-01",
			Active:      true,
		},
	}

	return nil
}
func (c *mockRegisterS2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {
	return nil
}

func (c *mockRegisterS2sCaller) RespondUpstreamError(err error, w http.ResponseWriter) {}

func TestRegister(t *testing.T) {

	testCases := []struct {
		name     string
		user     types.UserRegisterCmd
		expected error
	}{
		{
			name: "valid registration",
			user: types.UserRegisterCmd{
				Username:  RegistrationUsername,
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: nil,
		},
		{
			name: "empty username",
			user: types.UserRegisterCmd{
				Username:  "",
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: fmt.Errorf("invalid username: email must be between %d and %d characters in length", validate.EmailMin, validate.EmailMax),
		},
		{
			name: "invalid username",
			user: types.UserRegisterCmd{
				Username:  "invalid-username",
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: errors.New("invalid username: email address must be valid format, eg., name@domain.com"),
		},
		{
			name: "empty password",
			user: types.UserRegisterCmd{
				Username:  RegistrationUsername,
				Password:  "",
				Confirm:   "",
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: fmt.Errorf("invalid password: password should be between %d and %d characters in length", validate.PasswordMin, validate.PasswordMax),
		},
		{
			name: "invalid password",
			user: types.UserRegisterCmd{
				Username:  RegistrationUsername,
				Password:  "invalid-password",
				Confirm:   "invalid-password",
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: errors.New("invalid password: password must include at least 1 uppercase letter"),
		},
		{
			name: "invalid client id",
			user: types.UserRegisterCmd{
				Username:  RegistrationUsername,
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  "invalid-client-id",
			},
			expected: errors.New("invalid client id"),
		},
		{
			name: "username already exists",
			user: types.UserRegisterCmd{
				Username:  UsernameExists,
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: errors.New("username unavailable"),
		},
		{
			name: "client disabled",
			user: types.UserRegisterCmd{
				Username:  RegistrationUsername,
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  "invalid--6e0c-4600-b0fc-09739d6bd42b",
			},
			expected: errors.New("client is disabled"),
		},
		{
			name: "failed account insert",
			user: types.UserRegisterCmd{
				Username:  "account.insert@fail.com",
				Password:  RegistrationPassword,
				Confirm:   RegistrationPassword,
				Firstname: RegistrationFirstname,
				Lastname:  RegistrationLastname,
				Birthdate: ReigstrationBirthdate,
				ClientId:  RegistrationClientId,
			},
			expected: nil,
		},
	}

	registerService := NewService(&mockRegisterSqlRepository{}, &mockRegisterCryptor{}, &mockRegisterIndexer{}, &mockRegisterS2sTokenProvider{}, &mockRegisterS2sCaller{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := registerService.Register(tc.user)
			if err != nil && !strings.Contains(err.Error(), tc.expected.Error()) {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}
}
