package authentication

import (
	"database/sql"
	"testing"
)

const (
	RealClient   = "real-client-uuid"
	RealRedirect = "https://real-redirect-url.com"
)

type mockSqlRepository struct {
}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by isValidRedirect func
func (dao *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	if args[0] != RealClient || args[1] != RealRedirect {
		return sql.ErrNoRows
	}
	return nil
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
		err      string
	}{
		{
			name:     "valid redirect",
			clientId: RealClient,
			redirect: RealRedirect,
			valid:    false,
			err:      "client disabled", // sql result interface{} in func ClientRedirect has default false bool values
		},
		{
			name:     "invalid redirect",
			clientId: "invalid-client-uuid",
			redirect: "https://invalid-redirect-url.com",
			valid:    false,
			err:      "client/redirect pair not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// create a new clientRegistration with a mockSqlRepository
			cr := NewClientService(&mockSqlRepository{})

			valid, err := cr.IsValidRedirect(tc.clientId, tc.redirect)
			if valid != tc.valid {
				t.Errorf("expected %v, got %v", tc.valid, valid)
			}
			if err.Error() != tc.err {
				t.Errorf("expected %v, got %v", tc.err, err.Error())
			}
		})
	}

}
