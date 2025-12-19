package authentication

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	util "github.com/tdeslauriers/shaw/internal/definition"
)

// AuthErrService is an interface for handling errors returned by the service methods and sending the appropriate error response to the client.
type AuthErrService interface {
	// HandleAuthErr handles errors returned by the service methods and sends the appropriate error response to the client.
	HandleServiceErr(err error, w http.ResponseWriter)
}

// NewAuthErrService creates an implementation of the AuthErrService interface.
func NewAuthErrService() AuthErrService {
	return &errAuth{
		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ AuthErrService = (*errAuth)(nil)

// errAuth is an implementation of the AuthErrService interface.
type errAuth struct {
	logger *slog.Logger
}

// HandleServiceErr handles errors returned by the service methods and sends the appropriate error response to the client.
func (s *errAuth) HandleServiceErr(err error, w http.ResponseWriter) {
	switch {
	case strings.Contains(err.Error(), ErrInvalidUsernamePassword):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrInvalidUsernamePassword,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserDisabled):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserDisabled),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserLocked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserLocked),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrUserExipred):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("user %s", ErrUserExipred),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRefreshNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRefreshNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "not found"),
		strings.Contains(err.Error(), "does not exist"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    "not found",
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "invalid refresh token"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid refresh token",
		}
		e.SendJsonErr(w)
		return
	default:
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

}
