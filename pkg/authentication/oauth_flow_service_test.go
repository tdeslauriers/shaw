package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/session"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
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

// mock sql repository
type mockSqlRepository struct {
}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {

	switch r := records.(type) {
	case *[]AccountScope:
		if args[0] != RealUserIndex {
			return sql.ErrNoRows
		} else {
			*records.(*[]AccountScope) = []AccountScope{
				{
					AccountUuid: RealAccountUuid,
					ScopeUuid:   ScopeOneId,
				},
				{
					AccountUuid: RealAccountUuid,
					ScopeUuid:   ScopeTwoId,
				},
			}
			return nil
		}
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
	default:
		return fmt.Errorf("SelectRecord() record interface was given unexpected type, expected ClientRedirect or AccountClient, got %T", r)
	}

}
func (dao *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) Close() error                                         { return nil }

type mockCryptor struct{}

func (c *mockCryptor) EncryptServiceData(plaintext string) (string, error) {
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}

func (c *mockCryptor) DecryptServiceData(ciphertext string) (string, error) { return ciphertext, nil }

// mock Indexer
type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(identifier string) (string, error) {
	return fmt.Sprintf("index-%s", identifier), nil
}

// mock S2sTokenProvider
type mockS2sTokenProvider struct{}

func (s2s *mockS2sTokenProvider) GetServiceToken(serviceName string) (string, error) {
	return fmt.Sprintf("valid-%s-service-token", serviceName), nil
}

// mock S2sCaller
type mockS2sCaller struct{}

func (s2s *mockS2sCaller) GetServiceData(endpoint, s2sToken, AccessToken string, data interface{}) error {

	switch d := data.(type) {
	case *[]session.Scope:
		*data.(*[]session.Scope) = []session.Scope{
			{
				Uuid:        ScopeOneId,
				ServiceName: "service-one",
				Scope:       "r:service-one:scope-one:*",
				Name:        "scope-one",
				Description: "scope-one",
				Active:      true,
			},
			{
				Uuid:        ScopeTwoId,
				ServiceName: "service-two",
				Scope:       "r:service-two:scope-two:*",
				Name:        "scope-two",
				Description: "scope-two",
				Active:      false,
			},
			{
				Uuid:        ScopeThreeId,
				ServiceName: "service-three",
				Scope:       "r:service-three:scope-three:*",
				Name:        "scope-three",
				Description: "scope-three",
				Active:      true,
			},
			{
				Uuid:        ScopeFourId,
				ServiceName: "service-four",
				Scope:       "r:service-four:scope-four:*",
				Name:        "scope-four",
				Description: "scope-four",
				Active:      true,
			},
			{
				Uuid:        ScopeFiveId,
				ServiceName: "service-five",
				Scope:       "r:service-five:scope-five:*",
				Name:        "scope-five",
				Description: "scope-five",
				Active:      true,
			},
		}
		return nil
	default:
		return fmt.Errorf("GetServiceData() data interface was given unexpected type, expected []Scope, got %T", d)
	}
}

func (s2s *mockS2sCaller) PostToService(endpoint, s2sToken, AccessToken string, cmd interface{}, data interface{}) error {
	return nil
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
			cr := NewOauthFlowService(&mockSqlRepository{}, nil, &mockIndexer{}, nil, nil)

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
			cr := NewOauthFlowService(&mockSqlRepository{}, nil, &mockIndexer{}, nil, nil)

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
		err      error
	}{
		{
			name:     "valid auth code generation",
			username: RealUsername,
			clientId: RealClient,
			redirect: RealRedirect,
			err:      nil,
		},
		{
			name:     "invalid user",
			username: "invalid-username@invalid.domain",
			clientId: RealClient,
			redirect: RealRedirect,
			err:      errors.New("no scopes found for user"),
		},
		{
			name:     "empty user",
			username: "",
			clientId: RealClient,
			redirect: RealRedirect,
			err:      errors.New("no scopes found for user"),
		},
		{
			name:     "invalid client",
			username: RealUsername,
			clientId: "invalid-client-uuid",
			redirect: RealRedirect,
			err:      errors.New("no scopes found for user"),
		},
		{
			name:     "empty client",
			username: RealUsername,
			clientId: "",
			redirect: RealRedirect,
			err:      errors.New("no scopes found for user"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// create a new clientRegistration with a mockSqlRepository
			cr := NewOauthFlowService(&mockSqlRepository{}, &mockCryptor{}, &mockIndexer{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

			code, err := cr.GenerateAuthCode(tc.username, tc.clientId, tc.redirect)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected %v, got %v", tc.err, err)
			}
			if err == nil && !validate.IsValidUuid(code) {
				t.Errorf("expected auth code as valid uuid, got %v", code)
			}
		})
	}
}
