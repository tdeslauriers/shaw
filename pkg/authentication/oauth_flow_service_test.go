package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	RealClient   = "real-client-uuid"
	RealRedirect = "https://real-redirect-url.com"

	RealAccountUuid = "real-account-uuid"
	RealUserIndex   = "index-" + RealUsername
	RealClientUuid  = "real-client-uuid"
)

type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(username string) (string, error) {

	return fmt.Sprintf("index-%s", username), nil
}

type mockSqlRepository struct {
}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by isValidRedirect func
func (dao *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	switch record.(type) {
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
		return errors.New("error with mock Select Record method")
	}

}
func (dao *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) Close() error                                         { return nil }

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
			cr := NewOauthFlowService(&mockSqlRepository{}, &mockIndexer{})

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
			cr := NewOauthFlowService(&mockSqlRepository{}, &mockIndexer{})

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
