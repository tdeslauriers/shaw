package authentication

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session"
	"golang.org/x/crypto/bcrypt"
)

const (
	RealUsername = "darth.vader@empire.com"
	RealPassword = "YouDontPowerofTheDarkSide"

	UserIndex          = "Deathstar"
	IncorrectUserIndex = "incorrect-user-index"

	BcryptCost = 13
)

type mockAuthIndexer struct{}

func (idx *mockAuthIndexer) ObtainBlindIndex(input string) (string, error) {

	if input != RealUsername {
		return IncorrectUserIndex, nil
	} else {
		return UserIndex, nil
	}
}

type mockAuthSqlRepository struct{}

func (dao *mockAuthSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockAuthSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	if args[0] != UserIndex {
		return fmt.Errorf(fmt.Sprintf("failed to retrieve user record for %s", args[0]))
	} else {

		hash, _ := bcrypt.GenerateFromPassword([]byte(RealPassword), BcryptCost)

		*record.(*session.UserAccountData) = session.UserAccountData{
			Uuid:           "1234",
			Username:       RealUsername,
			UserIndex:      UserIndex,
			Password:       string(hash),
			Firstname:      "Darth",
			Lastname:       "Vader",
			Birthdate:      "1977-05-25",
			CreatedAt:      "2021-01-01",
			Enabled:        true,
			AccountExpired: false,
			AccountLocked:  false,
		}

	}
	return nil
}
func (dao *mockAuthSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockAuthSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockAuthSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) Close() error                                         { return nil }

func TestValidateCredentials(t *testing.T) {

	testCases := []struct {
		name     string
		username string
		password string
		expected error
	}{
		{
			name:     "valid credentials",
			username: RealUsername,
			password: RealPassword,
			expected: nil,
		},
		{
			name:     "invalid username",
			username: "anikan.skywalker@jedi.com",
			password: RealPassword,
			expected: errors.New("invalid username or password"),
		},
		{
			name:     "empty username",
			username: "",
			password: RealPassword,
			expected: errors.New("invalid username or password"),
		},
		{
			name:     "invalid password",
			username: RealUsername,
			password: "NowThisIsPodRacing!",
			expected: errors.New("invalid username or password"),
		},
		{
			name:     "empty password",
			username: RealUsername,
			password: "",
			expected: errors.New("invalid username or password"),
		},
	}

	authservice := NewService(&mockAuthSqlRepository{}, nil, &mockAuthIndexer{}, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := authservice.ValidateCredentials(tc.username, tc.password)
			if err != nil && err.Error() != tc.expected.Error() {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}

}
