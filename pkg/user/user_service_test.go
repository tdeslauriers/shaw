package user

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/profile"
)

const (
	ValidUsername  = "darth.vader@empire.com"
	ValidFirstname = "Darth"
	ValidLastname  = "Vader"
	ValidDob       = "1977-05-25"
)

func TestGetByUsername(t *testing.T) {

	// test cases
	testCases := []struct {
		name         string
		username     string
		expectedUser *profile.User
		expectedErr  error
	}{
		{
			name:     "success - valid username",
			username: "darth.vader@empire.com",
			expectedUser: &profile.User{
				Id:        "uuid-1",
				Username:  "darth.vader@empire.com",
				Firstname: "Darth",
				Lastname:  "Vader",
				BirthDate: "1977-05-25",
			},
			expectedErr: nil,
		},
		{
			name:         "failure - invalid username",
			username:     "luke",
			expectedUser: nil,
			expectedErr:  errors.New("invalid username"),
		},
		{
			name:         "failure - user not found",
			username:     "record-does-not-exist",
			expectedUser: nil,
			expectedErr:  errors.New(ErrUserNotFound),
		},
		{
			name:         "failure - failed to decrypt firstname",
			username:     "luke.skywalker@rebels.com",
			expectedUser: nil,
			expectedErr:  errors.New(ErrDecryptFirstname),
		},
	}

	svc := NewService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockUserCryptor{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.GetByUsername(tc.username)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

// mock implementations

// mock repository
type mockUserSqlRepository struct{}

func (m *mockUserSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {
	switch r := record.(type) {
	case *profile.User:
		switch args[0] {
		case "index-" + ValidUsername:
			r.Id = "uuid-1"
			r.Username = "encrypted-" + ValidUsername
			r.Firstname = "encrypted-" + ValidFirstname
			r.Lastname = "encrypted-" + ValidLastname
			r.BirthDate = "encrypted-" + ValidDob
			return nil
		case "index-" + "luke.skywalker@rebels.com":
			r.Id = "uuid-1"
			r.Username = "encrypted-" + ValidUsername
			r.Firstname = "failed-to-decrypt-firstname"
			r.Lastname = "encrypted-" + ValidLastname
			r.BirthDate = "encrypted-" + ValidDob
			return nil
		default:
			return sql.ErrNoRows
		}
	default:
		return sql.ErrNoRows
	}
}

func (m *mockUserSqlRepository) SelectRecords(query string, dest interface{}, args ...interface{}) error {
	return nil
}

func (m *mockUserSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	return nil
}

func (m *mockUserSqlRepository) InsertRecord(query string, record interface{}) error {
	return nil
}

func (m *mockUserSqlRepository) DeleteRecord(query string, args ...interface{}) error {
	return nil
}

func (dao *mockUserSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	if args[0] == "index-"+"record-does-not-exist" {
		return false, nil
	}
	return true, nil
}

func (dao *mockUserSqlRepository) Close() error { return nil }

// mock indexer
type mockUserIndexer struct{}

func (m *mockUserIndexer) ObtainBlindIndex(input string) (string, error) {
	return "index-" + input, nil
}

type mockUserCryptor struct{}

// mock cryptor
func (m *mockUserCryptor) EncryptServiceData(data string) (string, error) {
	return "encrypted-" + data, nil
}

func (m *mockUserCryptor) DecryptServiceData(data string) (string, error) {
	if strings.Contains(data, "failed-to-decrypt-username") {
		return "", errors.New(ErrDecryptFirstname)
	}
	return data[10:] + data, nil
}
