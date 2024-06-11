package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(user session.UserAuthService, oauthFlow OuathFlowService, verifier jwt.JwtVerifier) LoginHandler {
	return &loginHandler{
		authService:      user,
		oauthFlowService: oauthFlow,
		s2sVerifier:      verifier,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	authService      session.UserAuthService
	oauthFlowService OuathFlowService
	s2sVerifier      jwt.JwtVerifier

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

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(allowed, svcToken); !authorized {
		if strings.Contains(err.Error(), "unauthorized") {
			h.logger.Error("registration handler service token", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			h.logger.Error("login handler service token authorization failed", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "service token authorization failed due to interal server error",
			}
			e.SendJsonErr(w)
			return
		}
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
			h.logger.Error(fmt.Sprintf("failed to validate user credentials to for user %s", cmd.Username), "err", err.Error())
			errChan <- err
		}
	}()

	// validate redirect url association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauthFlowService.IsValidRedirect(cmd.ClientId, cmd.Redirect); !valid {
			h.logger.Error(fmt.Sprintf("failed to validate redirect url (%s) association with client id (%s)", cmd.Username, cmd.Redirect), "err", err.Error())
			errChan <- err
		}
	}()

	// validate user association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauthFlowService.IsValidClient(cmd.ClientId, cmd.Username); !valid {
			h.logger.Error(fmt.Sprintf("failed to validate user (%s) association with client (%s)", cmd.Username, cmd.ClientId), "err", err.Error())
			errChan <- err
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

	// generate and persist auth code
	authCode, err := h.oauthFlowService.GenerateAuthCode(cmd.Username, cmd.ClientId, cmd.Redirect)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to generate auth code for user %s", cmd.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to generate auth code",
		}
		e.SendJsonErr(w)
		return
	}

	// return auth code
	authCodeResponse := session.AuthCodeResponse{
		AuthCode: authCode,
		State:    cmd.State,
		Nonce:    cmd.Nonce,
		ClientId: cmd.ClientId,
		Redirect: cmd.Redirect,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authCodeResponse); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode auth code response for user (%s) login", cmd.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to send auth code response body due to internal service error",
		}
		e.SendJsonErr(w)
		return
	}
}
