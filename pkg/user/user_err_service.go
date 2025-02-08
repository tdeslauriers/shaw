package user

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// UserErrService is an interface for handling errors that occur during user service operations.
type UserErrService interface {
	// HandleServiceErr handles errors that occur during user service operations.
	HandleServiceErr(err error, w http.ResponseWriter)
}

// NewUserErrService creates a new UserErrService interface by returning a pointer to a new concrete implementation of the UserErrService interface.
func NewUserErrService() UserErrService {
	return &userErrService{}
}

var _ UserErrService = (*userErrService)(nil)

// userErrService is a concrete implementation of the UserErrService interface.
type userErrService struct{}

// HandleServiceErr handles errors that occur during user service operations and sends a json error response.
func (s *userErrService) HandleServiceErr(err error, w http.ResponseWriter) {
	switch {
	case strings.Contains(err.Error(), ErrUserNotFound):
	case strings.Contains(err.Error(), ErrUserDisabled):
	case strings.Contains(err.Error(), ErrUserLocked):
	case strings.Contains(err.Error(), ErrUserExpired):
	case strings.Contains(err.Error(), ErrInvalidPassword):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrInvalidUserData):
	case strings.Contains(err.Error(), ErrPasswordUsedPreviously):
	case strings.Contains(err.Error(), ErrNewConfirmPwMismatch):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
