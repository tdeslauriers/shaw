package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

func TestGetRefreshToken(t *testing.T) {

	testCases := []struct {
		name        string
		refresh     string
		token       *types.UserRefresh
		expectedErr error
	}{
		{
			name:    "success - refresh token retrieved",
			refresh: "valid-refresh-token",
			token: &types.UserRefresh{
				ClientId:     "1234",
				RefreshToken: "1234-5678-9012-3456",
				Username:     RealUsername,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: nil,
		},
		{
			name:        "failure - invalid refresh token",
			refresh:     "too-short",
			token:       nil,
			expectedErr: errors.New("invalid refresh token"),
		},
		{
			name:        "failure - cannot generate blind index",
			refresh:     IncorrectUserIndex,
			token:       nil,
			expectedErr: errors.New("failed to generate blind index"),
		},
		{
			name:        "failure - record does not exist",
			refresh:     "refresh-does-not-exist",
			token:       nil,
			expectedErr: errors.New(ErrRefreshNotFound),
		},
		// one test of the drcypt process if fine, since it is all the same function
		{
			name:        "failure - failed to decrypt refresh token",
			refresh:     "failed-to-decrypt",
			token:       nil,
			expectedErr: errors.New("failed to decrypt"),
		},
	}

	svc := NewRefreshService(&mockRefreshSqlRepository{}, &mockRefreshIndexer{}, &mockRefreshCryptor{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			refresh, err := svc.GetRefreshToken(tc.refresh)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}

			if refresh != nil {
				if refresh.ClientId != tc.token.ClientId {
					t.Errorf("expected %v, got %v", tc.token.ClientId, refresh.ClientId)
				}
				if refresh.RefreshToken != tc.token.RefreshToken {
					t.Errorf("expected %v, got %v", tc.token.RefreshToken, refresh.RefreshToken)
				}
				if refresh.Username != tc.token.Username {
					t.Errorf("expected %v, got %v", tc.token.Username, refresh.Username)
				}
				if refresh.Revoked != tc.token.Revoked {
					t.Errorf("expected %v, got %v", tc.token.Revoked, refresh.Revoked)
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

	svc := NewRefreshService(&mockRefreshSqlRepository{}, &mockRefreshIndexer{}, &mockCryptor{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.PersistRefresh(tc.refresh)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}

}

func TestDestroyToken(t *testing.T) {

	testCases := []struct {
		name        string
		refresh     string
		expectedErr error
	}{
		{
			name:        "success - refresh token destroyed",
			refresh:     "valid-refresh-token",
			expectedErr: nil,
		},
		{
			name:        "failure - invalid refresh token",
			refresh:     "too-short",
			expectedErr: errors.New("invalid refresh token"),
		},
		{
			name:        "failure - cannot generate blind index",
			refresh:     IncorrectUserIndex,
			expectedErr: errors.New("failed to generate blind index"),
		},
		{
			name:        "faiure - record does not exist",
			refresh:     "record-does-not-exist",
			expectedErr: errors.New("record does not exist"),
		},
		{
			name:        "failure - failed to delete record",
			refresh:     "failed-to-delete-record",
			expectedErr: errors.New("failed to delete"),
		},
	}

	svc := NewRefreshService(&mockRefreshSqlRepository{}, &mockRefreshIndexer{}, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.DestroyRefresh(tc.refresh)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {

	testCases := []struct {
		name        string
		refresh     string
		expectedErr error
	}{
		{
			name:        "success - refresh token revoked",
			refresh:     "valid-refresh-token",
			expectedErr: nil,
		},
		{
			name:        "failure - invalid refresh token",
			refresh:     "too-short",
			expectedErr: errors.New("invalid refresh token"),
		},
		{
			name:        "failure - cannot generate blind index",
			refresh:     IncorrectUserIndex,
			expectedErr: errors.New("failed to generate blind index"),
		},
		{
			name:        "faiure - record does not exist",
			refresh:     "record-does-not-exist",
			expectedErr: errors.New("record does not exist"),
		},
		{
			name:        "failure - failed to revoke refresh",
			refresh:     "failed-to-update-record",
			expectedErr: errors.New("failed to revoke"),
		},
	}

	svc := NewRefreshService(&mockRefreshSqlRepository{}, &mockRefreshIndexer{}, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.RevokeRefresh(tc.refresh)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

// mocks

type mockRefreshIndexer struct{}

func (idx *mockRefreshIndexer) ObtainBlindIndex(input string) (string, error) {
	if input == IncorrectUserIndex {
		return "", fmt.Errorf("failed to obtain blind index for user lookup")
	}

	return "index-" + input, nil
}

type mockRefreshCryptor struct{}

func (c *mockRefreshCryptor) EncryptServiceData(data string) (string, error) {
	if data == "failed to encrypt" {
		return "", errors.New("failed to encrypt")
	}

	return "encrypted+" + data, nil
}

func (c *mockRefreshCryptor) DecryptServiceData(data string) (string, error) {
	if data == "failed-to-decrypt" {
		return "", errors.New("failed to decrypt")
	}

	return strings.TrimPrefix(data, "encrypted-"), nil
}

type mockRefreshSqlRepository struct{}

func (dao *mockRefreshSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil

}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockRefreshSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	switch {
	case args[0] == "index-"+"valid-refresh-token":
		*record.(*types.UserRefresh) = types.UserRefresh{
			ClientId:     "encrypted-1234",
			RefreshToken: "encrypted-1234-5678-9012-3456",
			Username:     "encrypted-" + RealUsername,
			CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
			Revoked:      false,
		}
		return nil

	case args[0] == "index-"+"failed-to-decrypt":
		*record.(*types.UserRefresh) = types.UserRefresh{
			ClientId:     "1234",
			RefreshToken: "failed-to-decrypt",
		}
		return nil

	default:
		return sql.ErrNoRows
	}
}
func (dao *mockRefreshSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	if args[0] == "index-"+"record-does-not-exist" {
		return false, nil
	}
	return true, nil
}
func (dao *mockRefreshSqlRepository) InsertRecord(query string, record interface{}) error {
	// mock failed insert
	if record.(types.UserRefresh).RefreshToken == "failed to persist" {
		return errors.New("failed to insert")
	}
	return nil
}
func (dao *mockRefreshSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	if args[0] == "failed-to-update-record" {
		return errors.New("failed to update record")
	}
	return nil
}
func (dao *mockRefreshSqlRepository) DeleteRecord(query string, args ...interface{}) error {
	if args[0] == "failed-to-delete-record" {
		return errors.New("failed to delete record")
	}
	return nil
}
func (dao *mockRefreshSqlRepository) Close() error { return nil }
