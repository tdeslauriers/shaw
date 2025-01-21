package user

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type UserErrService interface {
	// HandleServiceErr handles errors that occur during user service operations.
	HandleServiceErr(err error, w http.ResponseWriter)
}

// HandleServiceErr handles errors that occur during user service operations and sends a json error response.
func (s *userService) HandleServiceErr(err error, w http.ResponseWriter) {
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
