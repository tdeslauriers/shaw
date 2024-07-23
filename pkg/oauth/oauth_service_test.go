package oauth

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	RealUserId   = "0505e360-022a-4b53-8e1f-2cb3cbf897fb"
	RealUsername = "darth.vader@empire.com"
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

func (c *mockCryptor) DecryptServiceData(ciphertext string) (string, error) { return ciphertext, nil }

// mock Indexer
type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(identifier string) (string, error) {
	if identifier == "index-failed" {
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
			cr := NewService(&mockSqlRepository{}, nil, &mockIndexer{})

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
			cr := NewService(&mockSqlRepository{}, nil, &mockIndexer{})

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
		clientId string
		redirect string
		scopes   []types.Scope
		err      error
	}{
		{
			name:     "valid auth code generation",
			username: RealUsername,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      nil,
		},
		{
			name:     "invalid user",
			username: "invalid-username@invalid.domain",
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to retrieve user uuid for invalid-username@invalid.domain:"),
		},
		{
			name:     "empty user",
			username: "",
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: username is empty"),
		},
		{
			name:     "empty client",
			username: RealUsername,
			clientId: "",
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: client id is empty"),
		},
		{
			name:     "empty redirect",
			username: RealUsername,
			clientId: RealClient,
			redirect: "",
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code: redirect url is empty"),
		},
		{
			name:     "empty scopes",
			username: RealUsername,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   []types.Scope{},
			err:      errors.New("failed to generate auth code: scopes are empty"),
		},
		{
			name:     "nil scopes",
			username: RealUsername,
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   nil,
			err:      errors.New("failed to generate auth code: scopes are empty"),
		},
		{
			name:     "failed to generate user index",
			username: "index-failed",
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to generate auth code index:"),
		},
		{
			name:     "failed to encrypt client id", // represents a failure to encrypt any value in record generation process
			username: RealUsername,
			clientId: "failed-encryption",
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to encrypt client id:"),
		},
		{
			name:     "failed to insert auth code record",
			username: "persistance-failure",
			clientId: RealClient,
			redirect: RealRedirect,
			scopes:   TestScopes,
			err:      errors.New("failed to insert authcode_account xref record for"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			oauthSvc := NewService(&mockSqlRepository{}, &mockCryptor{}, &mockIndexer{})

			code, err := oauthSvc.GenerateAuthCode(tc.username, tc.clientId, tc.redirect, tc.scopes)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected %v, got %v", tc.err, err)
			}
			if err == nil && !validate.IsValidUuid(code) {
				t.Errorf("expected auth code as valid uuid, got %v", code)
			}
		})
	}
}
