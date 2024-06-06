package authentication

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(user session.UserAuthService, client ClientService) LoginHandler {
	return &loginHandler{
		authService:   user,
		clientService: client,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	authService   session.UserAuthService
	clientService ClientService

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

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// validate user credentials
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := h.authService.ValidateCredentials(cmd.Username, cmd.Password); err != nil {
			h.logger.Error("failed to validate user credentials", "err", err.Error())
			errChan <- err
		}
	}()

	// validate redirect url
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.clientService.IsValidRedirect(cmd.ClientId, cmd.Redirect); !valid {
			h.logger.Error("failed to validate redirect url", "err", err.Error())
		}
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	// consolidate and return any login errors
	var loginErrors []error
	for e := range errChan {
		loginErrors = append(loginErrors, e)
	}
	if len(loginErrors) > 0 {
		var builder strings.Builder
		for i, e := range loginErrors {
			builder.WriteString(e.Error())
			if i < len(loginErrors)-1 {
				builder.WriteString(", ")
			}
		}

		errHttp := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    builder.String(),
		}
		errHttp.SendJsonErr(w)
		return
	}

	// create token

	// create refresh

	// respond with auth code, etc.
}
