package register

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

var (
	RegistrationUuid       = "1234"
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
	return nil
}
func (dao *mockRegisterSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	if args[0] == UsernameExists {
		return false, errors.New("username unavailable")
	}
	return false, nil
}
func (dao *mockRegisterSqlRepository) InsertRecord(query string, record interface{}) error {
	// no need to mock db insert call, only return nil err
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
			},
			expected: errors.New("invalid password: password must include at least 1 uppercase letter"),
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
			},
			expected: errors.New("username unavailable"),
		},
	}

	registerService := NewService(&mockRegisterSqlRepository{}, &mockRegisterCryptor{}, &mockRegisterIndexer{}, &mockRegisterS2sTokenProvider{}, &mockRegisterS2sCaller{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := registerService.Register(tc.user)
			if err != nil && err.Error() != tc.expected.Error() {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}
}
