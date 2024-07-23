package authentication

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session/types"
	"golang.org/x/crypto/bcrypt"
)

const (
	RealUsername = "darth.vader@empire.com"
	RealPassword = "YouDontPowerofTheDarkSide"

	InvalidUsername = "anakin.skywalker@rebels.com"

	DisabledUser = "disabled-user"
	LockedUser   = "locked-user"
	ExpiredUser  = "expired-user"

	UserIndex          = "index-" + RealUsername
	IncorrectUserIndex = "incorrect-user-index"

	BcryptCost = 13
)

type mockAuthIndexer struct{}

func (idx *mockAuthIndexer) ObtainBlindIndex(input string) (string, error) {
	if input == IncorrectUserIndex {
		return "", fmt.Errorf("failed to obtain blind index for user lookup")
	}

	return "index-" + input, nil
}

type mockAuthSqlRepository struct{}

func (dao *mockAuthSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	switch r := records.(type) {
	case *[]AccountScope:
		if args[0] == UserIndex {

			*records.(*[]AccountScope) = []AccountScope{
				{
					Id:          1,
					AccountUuid: "1234",
					ScopeUuid:   "scope-one-uuid",
				},
				{
					Id:          2,
					AccountUuid: "1234",
					ScopeUuid:   "scope-two-uuid",
				},
			}
		}
		if args[0] == "index-"+InvalidUsername {
			return errors.New("no scopes found for user")
		}
		// empty username
		if args[0] == "index-" {
			return errors.New("no scopes found for user")
		}
		return nil
	default:
		return fmt.Errorf("unexpected record type: %T", r)
	}

}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockAuthSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	switch r := record.(type) {
	case *types.UserAccount:
		switch args[0] {
		case UserIndex:
			hash, _ := bcrypt.GenerateFromPassword([]byte(RealPassword), BcryptCost)
			*record.(*types.UserAccount) = types.UserAccount{
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

		case "index-" + DisabledUser:
			hash, _ := bcrypt.GenerateFromPassword([]byte(RealPassword), BcryptCost)
			*record.(*types.UserAccount) = types.UserAccount{
				Uuid:           "1234",
				Username:       DisabledUser,
				UserIndex:      "index-" + DisabledUser,
				Password:       string(hash),
				Firstname:      "Darth",
				Lastname:       "Vader",
				Birthdate:      "1977-05-25",
				CreatedAt:      "2021-01-01",
				Enabled:        false,
				AccountExpired: false,
				AccountLocked:  false,
			}
		case "index-" + LockedUser:
			hash, _ := bcrypt.GenerateFromPassword([]byte(RealPassword), BcryptCost)
			*record.(*types.UserAccount) = types.UserAccount{
				Uuid:           "1234",
				Username:       LockedUser,
				UserIndex:      "index-" + LockedUser,
				Password:       string(hash),
				Firstname:      "Darth",
				Lastname:       "Vader",
				Birthdate:      "1977-05-25",
				CreatedAt:      "2021-01-01",
				Enabled:        true,
				AccountExpired: false,
				AccountLocked:  true,
			}
		case "index-" + ExpiredUser:
			hash, _ := bcrypt.GenerateFromPassword([]byte(RealPassword), BcryptCost)
			*record.(*types.UserAccount) = types.UserAccount{
				Uuid:           "1234",
				Username:       ExpiredUser,
				UserIndex:      "index-" + ExpiredUser,
				Password:       string(hash),
				Firstname:      "Darth",
				Lastname:       "Vader",
				Birthdate:      "1977-05-25",
				CreatedAt:      "2021-01-01",
				Enabled:        true,
				AccountExpired: true,
				AccountLocked:  false,
			}
		default:
			return fmt.Errorf("unexpected user index: %s", args[0])
		}

		return nil
	default:
		return fmt.Errorf("unexpected record type: %T", r)
	}
}
func (dao *mockAuthSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockAuthSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockAuthSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) Close() error                                         { return nil }

type mockS2sTokenProvider struct{}

func (tp *mockS2sTokenProvider) GetServiceToken(service string) (string, error) {
	return "mock-service-token", nil
}

type mockS2sCaller struct{}

func (c *mockS2sCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {
	switch d := data.(type) {
	case *[]types.Scope:
		*data.(*[]types.Scope) = []types.Scope{
			{
				Uuid:        "scope-one-uuid",
				ServiceName: "service-one",
				Scope:       "r:service-one:*",
				Name:        "Read Blog",
				Description: "read the blog",
				Active:      true,
			},
			{
				Uuid:        "scope-two-uuid",
				ServiceName: "service-two",
				Scope:       "r:service-two:*",
				Name:        "Read Profile",
				Description: "read the profile",
				Active:      true,
			},
			{
				Uuid:        "scope-three-uuid",
				ServiceName: "service-three",
				Scope:       "r:service-three:*",
				Name:        "Read Gallery",
				Description: "view the gallery",
				Active:      true,
			},
			{
				Uuid:        "scope-four-uuid",
				ServiceName: "service-four",
				Scope:       "r:service-four:*",
				Name:        "Read Allowance",
				Description: "view allowance",
				Active:      true,
			},
		}
	default:
		return fmt.Errorf("unexpected data type: %T", d)
	}
	return nil
}
func (c *mockS2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {
	return nil
}
func (c *mockS2sCaller) RespondUpstreamError(err error, w http.ResponseWriter) {}

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
			name:     "incorrect user index",
			username: IncorrectUserIndex,
			password: RealPassword,
			expected: errors.New("failed to obtain blind index for user lookup"),
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
		{
			name:     "user disabled",
			username: DisabledUser,
			password: RealPassword,
			expected: errors.New("is disabled"),
		},
		{
			name:     "account locked",
			username: LockedUser,
			password: RealPassword,
			expected: errors.New("is locked"),
		},
		{
			name:     "account expired",
			username: ExpiredUser,
			password: RealPassword,
			expected: errors.New("is expired"),
		},
	}

	authservice := NewService(&mockAuthSqlRepository{}, nil, &mockAuthIndexer{}, nil, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := authservice.ValidateCredentials(tc.username, tc.password)
			if err != nil && !strings.Contains(err.Error(), tc.expected.Error()) {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}

}

func TestGetScopes(t *testing.T) {

	testCases := []struct {
		name        string
		username    string
		scopes      []types.Scope
		expectedErr error
	}{
		{
			name:     "valid scopes",
			username: RealUsername,
			scopes: []types.Scope{
				{
					Uuid:        "scope-one-uuid",
					ServiceName: "service-one",
					Scope:       "r:service-one:*",
					Name:        "Read Blog",
					Description: "read the blog",
					Active:      true,
				},
				{
					Uuid:        "scope-two-uuid",
					ServiceName: "service-two",
					Scope:       "r:service-two:*",
					Name:        "Read Profile",
					Description: "read the profile",
					Active:      true,
				},
			},
			expectedErr: nil,
		},
		{
			name:        "failed index",
			username:    IncorrectUserIndex,
			scopes:      nil,
			expectedErr: errors.New("no scopes found for user"),
		},
		{
			name:        "invalid username",
			username:    InvalidUsername,
			scopes:      nil,
			expectedErr: errors.New("no scopes found for user"),
		},
		{
			name:        "empty username",
			username:    "",
			scopes:      nil,
			expectedErr: errors.New("no scopes found for user"),
		},
	}

	authService := NewService(&mockAuthSqlRepository{}, nil, &mockAuthIndexer{}, nil, &mockS2sTokenProvider{}, &mockS2sCaller{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scopes, err := authService.GetScopes(tc.username, "")
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
			if len(scopes) != len(tc.scopes) {
				t.Errorf("expected %d scopes, got %d", len(tc.scopes), len(scopes))
			}
		})
	}
}
