package oauth

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	RealUserId   = "0505e360-022a-4b53-8e1f-2cb3cbf897fb"
	RealUsername = "darth.vader@empire.com"
	RealNonce    = "real-nonce"
	RealClient   = "real-client-uuid"
	RealRedirect = "https://real-redirect-url.com"

	RealAccountUuid = "real-account-uuid"
	RealUserIndex   = "index-" + RealUsername
	RealClientUuid  = "real-client-uuid"

	ScopeOneId   = "1234-scope"
	ScopeTwoId   = "5678-scope"
	ScopeThreeId = "9012-scope"
	ScopeFourId  = "3456-scope"
	ScopeFiveId  = "7890-scope"

	RealScopes = "r:service-one:*,r:service-two:*"
)

var TestScopes = []types.Scope{
	{
		Uuid:        ScopeOneId,
		ServiceName: "service-one",
		Scope:       "r:service-one:*",
		Name:        "Read Blog",
		Description: "read the blog",
		Active:      true,
	},
	{
		Uuid:        ScopeTwoId,
		ServiceName: "service-two",
		Scope:       "r:service-two:*",
		Name:        "Read Profile",
		Description: "read the profile",
		Active:      true,
	},
}

// mock sql repository
type mockSqlRepository struct {
}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {

	switch r := records.(type) {

	default:
		return fmt.Errorf("SelectRecords() records interface was given unexpected type, expected []AccountScope, got %T", r)
	}
}

// mocks the SelectRecord method of the SqlRepository interface used by isValidRedirect func
func (dao *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	switch r := record.(type) {
	case *ClientRedirect:
		if args[0] != RealClient || args[1] != RealRedirect {
			return sql.ErrNoRows
		} else {

			*record.(*ClientRedirect) = ClientRedirect{
				Id:              "1234",
				ClientId:        RealClient,
				ClientEnabled:   true,
				ClientExpired:   false,
				ClientLocked:    false,
				RedirectUrl:     RealRedirect,
				RedirectEnabled: true,
			}
		}
		return nil
	case *AccountClient:
		if args[0] != RealUserIndex || args[1] != RealClient {
			return sql.ErrNoRows
		} else {
			*record.(*AccountClient) = AccountClient{
				AccountUuid:    RealAccountUuid,
				UserIndex:      RealUserIndex,
				AccountEnabled: true,
				AccountExpired: false,
				AccountLocked:  false,
				ClientUuid:     RealClientUuid,
				ClientId:       RealClient,
				ClientEnabled:  true,
				ClientExpired:  false,
				ClientLocked:   false,
			}
		}
		return nil
	case *string:
		if args[0] == RealUserIndex {
			*record.(*string) = RealUserId
			fmt.Print("atomic dog")
		} else if args[0] == "index-persistance-failure" {
			*record.(*string) = "value-to-force-downstream-failure-to-persist"
		} else {
			return sql.ErrNoRows
		}
		return nil

		// retrieve user data lookups
	case *OauthUserData:
		switch args[0] {
		case "index-valid-auth-code-value":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-auth-code-revoked":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   true,
			}
			return nil
		case "index-auth-code-claimed":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   true,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-auth-code-expired":
			expired := time.Now().Add(-time.Hour * 2)
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: expired},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-user-has-been-disabled":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           false,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-user-has-been-locked":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     true,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-user-record-has-expired":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    true,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-failed-decrypt-username":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "failed-decrypt-username",
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "valid-auth-code-value",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-auth-code-mismatch":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "this should be impossible",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-client-id-mismatch":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "client-id-mismatch",
				ClientId:          "encrypted-" + "Wrong Client",
				RedirectUrl:       "encrypted-" + RealRedirect,
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-redirect-mismatch":
			*record.(*OauthUserData) = OauthUserData{
				Username:          "encrypted-" + RealUsername,
				Firstname:         "encrypted-" + "Darth",
				Lastname:          "encrypted-" + "Vader",
				BirthDate:         "encrypted-" + "1977-05-25",
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				Authcode:          "encrypted-" + "redirect-mismatch",
				ClientId:          "encrypted-" + RealClient,
				RedirectUrl:       "encrypted-" + "Wrong Redirect",
				Scopes:            "encrypted-" + RealScopes,
				AuthcodeCreatedAt: data.CustomTime{Time: time.Now()},
				AuthcodeClaimed:   false,
				AuthcodeRevoked:   false,
			}
			return nil
		case "index-invalid-auth-code-value":
			return sql.ErrNoRows
		default:
			return sql.ErrNoRows
		}

	default:
		return fmt.Errorf("SelectRecord() record interface was given unexpected type, expected ClientRedirect or AccountClient, got %T", r)
	}
}
func (dao *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockSqlRepository) InsertRecord(query string, record interface{}) error {

	reflected := reflect.ValueOf(record)
	if reflected.Type() == reflect.TypeOf(AuthcodeAccount{}) {
		if reflected.FieldByName("AccountUuid").String() == "value-to-force-downstream-failure-to-persist" {
			return errors.New("failed to insert authcode_account xref record for")
		}
	}

	return nil
}
func (dao *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) Close() error                                         { return nil }

type mockCryptor struct{}

func (c *mockCryptor) EncryptServiceData(plaintext string) (string, error) {
	if plaintext == "failed-encryption" {
		return "", errors.New("failed to encrypt client id:")
	}
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}

func (c *mockCryptor) DecryptServiceData(ciphertext string) (string, error) {
	if strings.Contains(ciphertext, "failed-") {
		return "", errors.New("failed to decrypt")
	}
	return strings.ReplaceAll(ciphertext, "encrypted-", ""), nil
}

// mock Indexer
type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(identifier string) (string, error) {
	if strings.Contains(identifier, "index-failed") {
		return "", errors.New("failed to generate auth code index:")
	}
	return fmt.Sprintf("index-%s", identifier), nil
}

func TestIsValidRedirect(t *testing.T) {
	testCases := []struct {
		name     string
		clientId string
		redirect string
		valid    bool
		err      error
	}{
		{
			name:     "valid redirect",
			clientId: RealClient,
			redirect: RealRedirect,
			valid:    true,
			err:      nil,
		},
		{
			name:     "invalid client",
			clientId: "invalid-client-uuid",
			redirect: RealRedirect,
			valid:    false,
			err:      errors.New("client/redirect pair not found"),
		},
		{
			name: "empty client",
			// empty client
			clientId: "",
			redirect: RealRedirect,
			valid:    false,
			err:      errors.New("client/redirect pair not found"),
		},
		{
			name:     "invalid redirect",
			clientId: RealClient,
			redirect: "https://invalid-redirect-url.com",
			valid:    false,
			err:      errors.New("client/redirect pair not found"),
		},
		{
			name:     "empty redirect",
			clientId: RealClient,
			redirect: "",
			valid:    false,
			err:      errors.New("client/redirect pair not found"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// create a new clientRegistration with a mockSqlRepository
			cr := NewService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})

			valid, err := cr.IsValidRedirect(tc.clientId, tc.redirect)
			if valid != tc.valid {
				t.Errorf("expected %v, got %v", tc.valid, valid)
			}
			if !valid && err.Error() != tc.err.Error() {
				t.Errorf("expected %v, got %v", tc.err.Error(), err.Error())
			}
		})
	}

}

func TestIsValidClient(t *testing.T) {
	testCases := []struct {
		name     string
		username string
		client   string
		valid    bool
		err      error
	}{
		{
			name:     "valid account and client",
			username: RealUsername,
			client:   RealClient,
			valid:    true,
			err:      nil,
		},
		{
			name:     "invalid user",
			username: "invalid-username",
			client:   RealClient,
			valid:    false,
			err:      fmt.Errorf("association not found"),
		},
		{
			name:     "empty user",
			username: "",
			client:   RealClient,
			valid:    false,
			err:      fmt.Errorf("association not found"),
		},
		{
			name:     "invalid client",
			username: RealUsername,
			client:   "invalid-client-uuid",
			valid:    false,
			err:      fmt.Errorf("association not found"),
		},
		{
			name:     "empty client",
			username: RealUsername,
			client:   "",
			valid:    false,
			err:      fmt.Errorf("association not found"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// create a new clientRegistration with a mockSqlRepository
			cr := NewService(&mockSqlRepository{}, &mockIndexer{}, nil)

			valid, err := cr.IsValidClient(tc.client, tc.username)
			if valid != tc.valid {
				t.Errorf("expected %v, got %v", tc.valid, valid)
			}
			if !valid && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected error to contain %v, got %v", tc.err.Error(), err.Error())
			}
		})
	}
}

func TestGenerateAuthCode(t *testing.T) {
	testCases := []struct {
		name     string
		username string
		nonce    string
		clientId string
		redirect string
		scopes   []types.Scope
		err      error
	}{
		{
			name:     "valid auth code generation",
			username: RealUsername,
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      nil,
		},
		{
			name:     "invalid user",
			username: "invalid-username@invalid.domain",
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to retrieve user uuid for invalid-username@invalid.domain:"),
		},
		{
			name:     "empty user",
			username: "",
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: username is empty"),
		},
		{
			name:     "empty nonce",
			username: RealUsername,
			nonce:    "",
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: nonce is empty"),
		},
		{
			name:     "empty client",
			username: RealUsername,
			nonce:    RealNonce,
			clientId: "",
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: client id is empty"),
		},
		{
			name:     "empty redirect",
			username: RealUsername,
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: "",
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: redirect url is empty"),
		},
		{
			name:     "empty scopes",
			username: RealUsername,
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   []types.Scope{},
			err:      errors.New("failed to generate auth code: scopes are empty"),
		},
		{
			name:     "nil scopes",
			username: RealUsername,
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   nil,
			err:      errors.New("failed to generate auth code: scopes are empty"),
		},
		{
			name:     "failed to generate user index",
			username: "index-failed",
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code index:"),
		},
		{
			name:     "failed to encrypt client id", // represents a failure to encrypt any value in record generation process
			username: RealUsername,
			nonce:    RealNonce,
			clientId: "failed-encryption",
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to encrypt client id:"),
		},
		{
			name:     "failed to insert auth code record",
			username: "persistance-failure",
			nonce:    RealNonce,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to insert authcode_account xref record for"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			oauthSvc := NewService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})

			code, err := oauthSvc.GenerateAuthCode(tc.username, tc.nonce, tc.clientId, tc.redirect, tc.scopes)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected %v, got %v", tc.err, err)
			}
			if err == nil && !validate.IsValidUuid(code) {
				t.Errorf("expected auth code as valid uuid, got %v", code)
			}
		})
	}
}

func TestRetrieveUserData(t *testing.T) {
	testCases := []struct {
		name string
		cmd  types.AccessTokenCmd
		user *OauthUserData
		err  error
	}{
		{
			name: "success - valid access code cmd",
			cmd: types.AccessTokenCmd{
				AuthCode:    "valid-auth-code-value",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: &OauthUserData{
				Username:        RealUsername,
				Firstname:       "Darth",
				Lastname:        "Vader",
				BirthDate:       "1977-05-25",
				Enabled:         true,
				AccountExpired:  false,
				AccountLocked:   false,
				Authcode:        "valid-auth-code-value",
				Nonce:           RealNonce,
				ClientId:        RealClient,
				RedirectUrl:     RealRedirect,
				Scopes:          RealScopes,
				AuthcodeClaimed: false,
				AuthcodeRevoked: false,
			},
			err: nil,
		},
		// only need to test one validation failure to test the error behavior
		{
			name: "invalid auth code - auth code empty",
			cmd: types.AccessTokenCmd{
				AuthCode:    "",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrValidateAuthCode),
		},
		{
			name: "failed - invalid grant type",
			cmd: types.AccessTokenCmd{
				AuthCode:    "valid-auth-code-value",
				Grant:       "invalid_grant_type",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrInvalidGrantType),
		},
		{
			name: "failed - index failed to generate",
			cmd: types.AccessTokenCmd{
				AuthCode:    "index-failed-auth-code-value",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrGenAuthCodeIndex),
		},
		{
			name: "failed - invalid auth code not found",
			cmd: types.AccessTokenCmd{
				AuthCode:    "invalid-auth-code-value",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrIndexNotFound),
		},
		{
			name: "failed - auth code revoked",
			cmd: types.AccessTokenCmd{
				AuthCode:    "auth-code-revoked",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrAuthcodeRevoked),
		},
		{
			name: "failed - auth code claimed",
			cmd: types.AccessTokenCmd{
				AuthCode:    "auth-code-claimed",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrAuthcodeClaimed),
		},
		{
			name: "failed - auth code expired",
			cmd: types.AccessTokenCmd{
				AuthCode:    "auth-code-expired",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrAuthcodeExpired),
		},
		{
			name: "failed - user disabled",
			cmd: types.AccessTokenCmd{
				AuthCode:    "user-has-been-disabled",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrUserDisabled),
		},
		{
			name: "failed - user locked",
			cmd: types.AccessTokenCmd{
				AuthCode:    "user-has-been-locked",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrUserAccountLocked),
		},
		{
			name: "failed - user expired",
			cmd: types.AccessTokenCmd{
				AuthCode:    "user-record-has-expired",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrUserAccountExpired),
		},
		// only need to test one decrypt failure to test the error behavior
		{
			name: "failed - decrypt username",
			cmd: types.AccessTokenCmd{
				AuthCode:    "failed-decrypt-username",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrDecryptUsername),
		},
		{
			name: "failed - authcode mismatch",
			cmd: types.AccessTokenCmd{
				AuthCode:    "auth-code-mismatch",
				Grant:       "authorization_code",
				ClientId:    "invalid-client-uuid",
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrMismatchAuthcode),
		},
		{
			name: "failed - redirect mismatch",
			cmd: types.AccessTokenCmd{
				AuthCode:    "client-id-mismatch",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: "https://invalid-redirect-url.com",
			},
			user: nil,
			err:  errors.New(ErrMismatchClientid),
		},
		{
			name: "failed - redirect mismatch",
			cmd: types.AccessTokenCmd{
				AuthCode:    "redirect-mismatch",
				Grant:       "authorization_code",
				ClientId:    RealClient,
				RedirectUrl: RealRedirect,
			},
			user: nil,
			err:  errors.New(ErrMismatchRedirect),
		},
	}

	oauthSvc := NewService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			user, err := oauthSvc.RetrieveUserData(tc.cmd)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected %v, got %v", tc.err, err)
				}
			}

			if err == nil {

				if user.Username != tc.user.Username {
					t.Errorf("expected username %v, got %v", tc.user.Username, user.Username)
				}

				if user.Firstname != tc.user.Firstname {
					t.Errorf("expected first name %v, got %v", tc.user.Firstname, user.Firstname)
				}

				if user.Lastname != tc.user.Lastname {
					t.Errorf("expected last name %v, got %v", tc.user.Lastname, user.Lastname)
				}

				if user.BirthDate != tc.user.BirthDate {
					t.Errorf("expected birthdate %v, got %v", tc.user.BirthDate, user.BirthDate)
				}

				if user.Enabled != tc.user.Enabled {
					t.Errorf("expected enabled %v, got %v", tc.user.Enabled, user.Enabled)
				}

				if user.AccountExpired != tc.user.AccountExpired {
					t.Errorf("expected account expired %v, got %v", tc.user.AccountExpired, user.AccountExpired)
				}

				if user.AccountLocked != tc.user.AccountLocked {
					t.Errorf("expected account locked %v, got %v", tc.user.AccountLocked, user.AccountLocked)
				}

				if user.Authcode != tc.user.Authcode {
					t.Errorf("expected auth code %v, got %v", tc.user.Authcode, user.Authcode)
				}

				if user.ClientId != tc.user.ClientId {
					t.Errorf("expected client id %v, got %v", tc.user.ClientId, user.ClientId)
				}

				if user.RedirectUrl != tc.user.RedirectUrl {
					t.Errorf("expected redirect url %v, got %v", tc.user.RedirectUrl, user.RedirectUrl)
				}

				if user.Scopes != tc.user.Scopes {
					t.Errorf("expected scopes %v, got %v", tc.user.Scopes, user.Scopes)
				}

				if user.AuthcodeClaimed != tc.user.AuthcodeClaimed {
					t.Errorf("expected auth code claimed %v, got %v", tc.user.AuthcodeClaimed, user.AuthcodeClaimed)
				}

				if user.AuthcodeRevoked != tc.user.AuthcodeRevoked {
					t.Errorf("expected auth code revoked %v, got %v", tc.user.AuthcodeRevoked, user.AuthcodeRevoked)
				}
			}
		})
	}
}
