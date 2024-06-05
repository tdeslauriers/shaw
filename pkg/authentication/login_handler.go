package authentication

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"shaw/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(service session.UserAuthService) LoginHandler {
	return &loginHandler{
		authService: service,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	authService session.UserAuthService

	logger *slog.Logger
}

// HandleLogin handles the login request from users and returns an auth code and redirect/state/nonce
func (h *loginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.UserLoginCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode user login command",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation: check for empty fields or too long
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate user credentials
	if err := h.authService.ValidateCredentials(cmd.Username, cmd.Password); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(), // TOOD: add swithc for different error messages, eg, internal server error, user not found, etc.
		}
		e.SendJsonErr(w)
		return
	}

	// validate redirect url

	// create token

	// create refresh

	// respond with auth code, etc.
}

