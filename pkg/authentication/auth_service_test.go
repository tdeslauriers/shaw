package authentication

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"shaw/internal/util"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
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

var (
	RealScopes = "r:service-one:*,r:service-two:*"
)

type mockAuthIndexer struct{}

func (idx *mockAuthIndexer) ObtainBlindIndex(input string) (string, error) {
	if input == IncorrectUserIndex {
		return "", fmt.Errorf("failed to obtain blind index for user lookup")
	}

	return "index-" + input, nil
}

type mockCryptor struct{}

func (c *mockCryptor) EncryptServiceData(data string) (string, error) {
	if data == "failed to encrypt" {
		return "", errors.New("failed to encrypt")
	}

	return "encrypted+" + data, nil
}

func (c *mockCryptor) DecryptServiceData(data string) (string, error) {
	if data == "failed to decrypt" {
		return "", errors.New("failed to decrypt")
	}

	return strings.TrimPrefix(data, "encrypted-"), nil
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
func (dao *mockAuthSqlRepository) InsertRecord(query string, record interface{}) error {
	// mock failed insert
	if record.(types.UserRefresh).RefreshToken == "failed to persist" {
		return errors.New("failed to insert")
	}
	return nil
}
func (dao *mockAuthSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) Close() error                                         { return nil }

type mockS2sTokenProvider struct{}

func (tp *mockS2sTokenProvider) GetServiceToken(service string) (string, error) {
	return "mock-service-token", nil
}

type mockSigner struct{}

func (s *mockSigner) Mint(token *jwt.Token) error {

	if token.Claims.Subject == RealUsername {
		msg, _ := token.BuildBaseString()
		token.BaseString = msg

		token.Signature = []byte("real-signature")

		token.Token = fmt.Sprintf("%s.%s", token.BaseString, base64.URLEncoding.EncodeToString(token.Signature))

		return nil
	} else {
		return errors.New("failed to create jwt signature")
	}

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

func TestMintToken(t *testing.T) {

	testCases := []struct {
		name        string
		claims      jwt.Claims
		jwt         *jwt.Token
		expectedErr error
	}{
		{
			name: "success - signed token",
			claims: jwt.Claims{
				Jti:       "1234",
				Issuer:    util.ServiceName,
				Subject:   RealUsername,
				Audience:  types.BuildAudiences(RealScopes),
				IssuedAt:  time.Now().UTC().Unix(),
				NotBefore: time.Now().UTC().Unix(),
				Expires:   time.Now().Add(AccessTokenDuration * time.Minute).Unix(),
				Scopes:    RealScopes,
			},
			jwt: &jwt.Token{
				Header: jwt.Header{
					Alg: "HS256",
					Typ: jwt.TokenType,
				},
				Claims: jwt.Claims{
					Jti:       "1234",
					Issuer:    util.ServiceName,
					Subject:   RealUsername,
					Audience:  types.BuildAudiences(RealScopes),
					IssuedAt:  time.Now().UTC().Unix(),
					NotBefore: time.Now().UTC().Unix(),
					Expires:   time.Now().Add(AccessTokenDuration * time.Minute).Unix(),
					Scopes:    RealScopes,
				},
			},
			expectedErr: nil,
		},
		{
			name: "failure - triggering jwt.Mint error",
			claims: jwt.Claims{
				Jti:       "1234",
				Issuer:    util.ServiceName,
				Subject:   "trigger error",
				Audience:  types.BuildAudiences(RealScopes),
				IssuedAt:  time.Now().UTC().Unix(),
				NotBefore: time.Now().UTC().Unix(),
				Expires:   time.Now().Add(AccessTokenDuration * time.Minute).Unix(),
				Scopes:    RealScopes,
			},
			jwt:         nil,
			expectedErr: errors.New("failed to sign jwt"),
		},
	}

	authservice := NewService(&mockAuthSqlRepository{}, &mockSigner{}, &mockAuthIndexer{}, nil, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jot, err := authservice.MintToken(tc.claims)

			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
			if err == nil {

				if jot.BaseString == "" {
					t.Errorf("expected base string to be populated")
				}

				if jot.Signature == nil {
					t.Errorf("expected signature to be populated")
				}

				if jot.Token == "" {
					t.Errorf("expected token to be populated")
				} else {
					segments := strings.Split(jot.Token, ".")
					if len(segments) != 3 {
						t.Errorf("expected token to have 3 segments, got %d", len(segments))
					}
				}

			}
		})
	}
}

func TestPersistRefresh(t *testing.T) {

	testCases := []struct {
		name        string
		refresh     types.UserRefresh
		expectedErr error
	}{
		{
			name: "success - refresh token persisted",
			refresh: types.UserRefresh{
				ClientId:     "1234",
				RefreshToken: "1234-5678-9012-3456",
				Username:     RealUsername,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: nil,
		},
		{
			name: "failure - failed to encrypt refresh token",
			refresh: types.UserRefresh{
				ClientId:     "1234",
				RefreshToken: "failed to encrypt",
				Username:     RealUsername,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to encrypt"),
		},
		{
			name: "failure - multiple encryption failures",
			refresh: types.UserRefresh{
				ClientId:     "failed to ecncrypt",
				RefreshToken: "failed to encrypt",
				Username:     RealUsername,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to encrypt"),
		},
		{
			name: "failure - failed to persist refresh token",
			refresh: types.UserRefresh{
				ClientId:     "1234",
				RefreshToken: "failed to persist",
				Username:     RealUsername,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to insert"),
		},
	}

	authservice := NewService(&mockAuthSqlRepository{}, nil, &mockAuthIndexer{}, &mockCryptor{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := authservice.PersistRefresh(tc.refresh)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}

}
