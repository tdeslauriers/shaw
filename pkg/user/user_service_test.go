package user

import (
	"database/sql"
	"errors"
	"fmt"
	"shaw/pkg/scope"

	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"golang.org/x/crypto/bcrypt"
)

const (
	ValidUsername  = "darth.vader@empire.com"
	ValidFirstname = "Darth"
	ValidLastname  = "Vader"
	ValidDob       = "1977-05-25"
	ValidSlug      = "24373f96-cc7c-443a-adf9-f0230af6feb2"
)

func BenchmarkGetUsers(t *testing.B) {

	svc := NewService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockUserCryptor{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

	_, err := svc.GetUsers()
	if err != nil {
		t.Errorf("failed to get users: %s", err.Error())
	}
}

func TestGetProfile(t *testing.T) {

	// test cases
	testCases := []struct {
		name         string
		username     string
		expectedUser *Profile
		expectedErr  error
	}{
		{
			name:     "success - valid username",
			username: "darth.vader@empire.com",
			expectedUser: &Profile{
				Id:        "uuid-1",
				Username:  "darth.vader@empire.com",
				Firstname: "Darth",
				Lastname:  "Vader",
				BirthDate: "1977-05-25",
				Slug:      "darth-vader",
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

	svc := NewService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockUserCryptor{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.GetProfile(tc.username)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

func TestUpdate(t *testing.T) {

	// test cases
	testCases := []struct {
		name        string
		user        *Profile
		expectedErr error
	}{
		{
			name: "success - valid update",
			user: &Profile{
				Username:  ValidUsername,
				Firstname: ValidFirstname,
				Lastname:  ValidLastname,
				BirthDate: ValidDob,
				Slug:      ValidSlug,
			},
			expectedErr: nil,
		},
		{
			name: "failure - empty firstname",
			user: &Profile{
				Username:  ValidUsername,
				Firstname: "",
				Lastname:  ValidLastname,
				BirthDate: ValidDob,
				Slug:      ValidSlug,
			},
			expectedErr: errors.New("invalid firstname"),
		},
		{
			name: "failure - empty lastname",
			user: &Profile{
				Username:  ValidUsername,
				Firstname: ValidFirstname,
				Lastname:  "",
				BirthDate: ValidDob,
				Slug:      ValidSlug,
			},
			expectedErr: errors.New("invalid lastname"),
		},
		{
			name: "failure - empty dob month",
			user: &Profile{
				Username:  ValidUsername,
				Firstname: ValidFirstname,
				Lastname:  ValidLastname,
				BirthDate: "1977-05",
				Slug:      ValidSlug,
			},
			expectedErr: errors.New("birth date not properly formatted"),
		},
		{
			name: "failure - dob in future",
			user: &Profile{
				Username:  ValidUsername,
				Firstname: ValidFirstname,
				Lastname:  ValidLastname,
				BirthDate: "2122-05-25",
				Slug:      ValidSlug,
			},
			expectedErr: errors.New("birth date cannot be in the future"),
		},
		{
			name: "failure - update failure",
			user: &Profile{
				Username:  "failure-to-update-user",
				Firstname: ValidFirstname,
				Lastname:  ValidLastname,
				BirthDate: ValidDob,
				Slug:      ValidSlug,
			},
			expectedErr: errors.New("failed to update user"),
		},
	}

	svc := NewService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockUserCryptor{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Update(tc.user)
			if err != nil && !strings.Contains(err.Error(), tc.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

const (
	ValidCurrentPassword = "1Valid-current-password"
	ValidHashedCurrentPw = "$2a$13$Hf.z3NLU6ZWB4.XIRbdHvOrdUzfQw6uGKjlcm/fFKKaN.sS0e3D26"
	ValidNewPassword     = "1Valid-new-password"
	ValidHashedNewPw     = "$2a$13$VUxTUCoPfgweMKI./ZLgreFanJ.Ilu2/du4cbrrkfrkXz6OYFkEHG"
	ValidHistroyPassword = "history-password"
	ValidHashedHistoryPw = "$2a$13$Odr9Y4KKcok7TWpVmMswD.gh/HUl8hEedx8nvwBlAr3IXHwmIhRga"
)

func TestResetPassword(t *testing.T) {

	// test cases
	testCases := []struct {
		name        string
		username    string
		resetCmd    profile.ResetCmd
		expectedErr error
	}{
		{
			name:     "success - valid reset",
			username: ValidUsername,
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: nil,
		},
		{
			name:     "failure - invalid username",
			username: "luke@",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New("username must be between"),
		},
		{
			name:     "failure - invalid current password",
			username: ValidUsername,
			resetCmd: profile.ResetCmd{
				CurrentPassword: "short",
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New("current password must be between"),
		},
		{
			name:     "failure - invalid new password",
			username: ValidUsername,
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     "this-password-is-invalid",
				ConfirmPassword: "this-password-is-invalid",
			},
			expectedErr: errors.New("new password fails complexity requirements"),
		},
		{
			name:     "failure - new and confirm password do not match",
			username: ValidUsername,
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: "passwords-do-not-match",
			},
			expectedErr: errors.New(ErrNewConfirmPwMismatch),
		},
		{
			name:     "failure - failed to generate blind index",
			username: ErrGenUserIndex,
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrGenUserIndex),
		},
		{
			name:     "failure - record does not exist",
			username: "record-does-not-exist",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrUserNotFound),
		},
		{
			name:     "failure - user account is disabled",
			username: ValidUsername + "-disabled",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrUserDisabled),
		},
		{
			name:     "failure - user account is locked",
			username: ValidUsername + "-locked",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrUserLocked),
		},
		{
			name:     "failure - user account is expired",
			username: ValidUsername + "-expired",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrUserExpired),
		},
		{
			name:     "failure - invalid current password",
			username: ValidUsername,
			resetCmd: profile.ResetCmd{
				CurrentPassword: "invalid-current-password",
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New(ErrInvalidPassword),
		},
		{
			name:     "failure - reuse of password",
			username: ValidUsername + "-password-reuse",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidCurrentPassword,
				ConfirmPassword: ValidCurrentPassword,
			},
			expectedErr: errors.New(ErrPasswordUsedPreviously),
		},
		{
			name:     "failure - failed update password in account table",
			username: ValidUsername + "-failed-to-update-password",
			resetCmd: profile.ResetCmd{
				CurrentPassword: ValidCurrentPassword,
				NewPassword:     ValidNewPassword,
				ConfirmPassword: ValidNewPassword,
			},
			expectedErr: errors.New("failed to update"),
		},
	}

	svc := NewService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockUserCryptor{}, &mockS2sTokenProvider{}, &mockS2sCaller{})

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			err := svc.ResetPassword(tc.username, tc.resetCmd)
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
	case *Profile:
		switch args[0] {
		case "index-" + ValidUsername:
			r.Id = "uuid-1"
			r.Username = "encrypted-" + ValidUsername
			r.Firstname = "encrypted-" + ValidFirstname
			r.Lastname = "encrypted-" + ValidLastname
			r.BirthDate = "encrypted-" + ValidDob
			r.Slug = "encrypted-" + ValidSlug
			return nil
		case "index-" + "luke.skywalker@rebels.com":
			r.Id = "uuid-1"
			r.Username = "encrypted-" + ValidUsername
			r.Firstname = "failed-to-decrypt-firstname"
			r.Lastname = "encrypted-" + ValidLastname
			r.BirthDate = "encrypted-" + ValidDob
			r.Slug = "encrypted-" + ValidSlug
			return nil
		default:
			return sql.ErrNoRows
		}
	default:
		return sql.ErrNoRows
	}
}

func (m *mockUserSqlRepository) SelectRecords(query string, dest interface{}, args ...interface{}) error {

	switch d := dest.(type) {
	case *[]Profile:
		p1 := Profile{
			Id:        "uuid-1",
			Username:  "encrypted-" + ValidUsername,
			Firstname: "encrypted-" + ValidFirstname,
			Lastname:  "encrypted-" + ValidLastname,
			BirthDate: "encrypted-" + ValidDob,
			Slug:      "encrypted-" + ValidSlug,
		}
		*d = append(*d, p1)

		p2 := Profile{
			Id:        "uuid-2",
			Username:  "encrypted-" + "luke.skywalker@rebels.com",
			Firstname: "encrypted-" + "Luke",
			Lastname:  "encrypted-" + "Skywalker",
			BirthDate: "encrypted-" + "1977-05-25",
			Slug:      "encrypted-" + "luke-skywalker",
		}
		*d = append(*d, p2)

		return nil
	case *[]UserPasswordHistory:
		switch args[0] {
		case "index-" + "record-does-not-exist":
			return sql.ErrNoRows
		case "index-" + "failed-to-retrieve-password-history":
			return errors.New("failed to retrieve user")
		case "index-" + ValidUsername:
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedHistoryPw,
			})
			return nil
		case "index-" + ValidUsername + "-disabled":
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           false,
				AccountExpired:    false,
				AccountLocked:     false,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedHistoryPw,
			})
			return nil
		case "index-" + ValidUsername + "-locked":
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     true,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedHistoryPw,
			})
			return nil
		case "index-" + ValidUsername + "-expired":
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           true,
				AccountExpired:    true,
				AccountLocked:     false,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedHistoryPw,
			})
			return nil
		case "index-" + ValidUsername + "-password-reuse":
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedCurrentPw,
			})
			return nil
		case "index-" + ValidUsername + "-failed-to-update-password":
			*d = append(*d, UserPasswordHistory{
				AccountId:         "uuid-1",
				Username:          "encrypted-" + ValidUsername,
				CurrentPassword:   ValidHashedCurrentPw,
				Enabled:           true,
				AccountExpired:    false,
				AccountLocked:     false,
				PasswordHisotryId: "uuid-1",
				HistoryPassword:   ValidHashedCurrentPw,
			})
			return nil
		default:
			return nil
		}
	default:
		return sql.ErrNoRows
	}

}

func (m *mockUserSqlRepository) UpdateRecord(query string, args ...interface{}) error {

	fmt.Println("args: ", args[0])

	// reset password test case
	if args[1] == "index-"+ValidUsername {
		return nil
	}

	if args[1] == "index-"+ValidUsername+"-failed-to-update-password" {
		return errors.New("failed to update")
	}

	// update user test case
	if args[6] == "index-failure-to-update-user" { // args[6] is the username index
		return errors.New("failed to update user")
	}
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
	if input == ErrGenUserIndex {
		return "", errors.New(ErrGenUserIndex)
	}
	return "index-" + input, nil
}

type mockUserCryptor struct{}

// mock cryptor
func (m *mockUserCryptor) EncryptServiceData(data []byte) (string, error) {
	return "encrypted-" + string(data), nil
}

func (m *mockUserCryptor) DecryptServiceData(data string) ([]byte, error) {
	if strings.Contains(data, "failed-to-decrypt-username") {
		return nil, errors.New(ErrDecryptFirstname)
	}
	return []byte(data[10:] + data), nil
}

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

func TestBcrypt(t *testing.T) {
	current, err := bcrypt.GenerateFromPassword([]byte(ValidCurrentPassword), 13)
	if err != nil {
		t.Error("failed to hash password")
	}
	t.Logf("hashed current password: %s", string(current))

	newpw, err := bcrypt.GenerateFromPassword([]byte(ValidNewPassword), 13)
	if err != nil {
		t.Error("failed to compare password")
	}
	t.Logf("hashed new password: %s", string(newpw))

	historypw, err := bcrypt.GenerateFromPassword([]byte("hisotry-password"), 13)
	if err != nil {
		t.Error("failed to compare password")
	}
	t.Logf("hashed history password: %s", string(historypw))
}

func BenchmarkDecryptProfile(b *testing.B) {

	svc := userService{
		&mockUserSqlRepository{},
		&mockUserIndexer{},
		&mockUserCryptor{},
		scope.NewScopesService(&mockUserSqlRepository{}, &mockUserIndexer{}, &mockS2sTokenProvider{}, &mockS2sCaller{}),

		slog.Default(),
	}

	p := &Profile{
		Username:  "encrypted-" + ValidUsername,
		Firstname: "encrypted-" + ValidFirstname,
		Lastname:  "encrypted-" + ValidLastname,
		BirthDate: "encrypted-" + ValidDob,
		Slug:      "encrypted-" + ValidSlug,
	}

	err := svc.decryptProfile(p)
	if err != nil {
		b.Logf("failed to decrypt profile: %s", err.Error())
	}
}
