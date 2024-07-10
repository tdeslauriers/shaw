package login

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/oauth"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type Handler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewHandler(user types.UserAuthService, oauthFlow oauth.Service, verifier jwt.JwtVerifier) Handler {
	return &handler{
		auth:        user,
		oauth:       oauthFlow,
		s2sVerifier: verifier,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	auth        types.UserAuthService
	oauth       oauth.Service
	s2sVerifier jwt.JwtVerifier

	logger *slog.Logger
}

// HandleLogin handles the login request from users and returns an auth code and redirect/state/nonce
func (h *handler) HandleLogin(w http.ResponseWriter, r *http.Request) {

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
		h.logger.Error("login handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: user login cmd data
	var cmd types.UserLoginCmd
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
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate user credentials, redirect url, client id, and response type concurrently
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// validate user credentials
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := h.auth.ValidateCredentials(cmd.Username, cmd.Password); err != nil {
			h.logger.Error(fmt.Sprintf("failed to validate user credentials for user %s", cmd.Username), "err", err.Error())
			errChan <- err
		}
	}()

	// validate redirect url association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauth.IsValidRedirect(cmd.ClientId, cmd.Redirect); !valid {
			h.logger.Error(fmt.Sprintf("failed to validate redirect url's (%s) association with client (%s)", cmd.Redirect, cmd.ClientId), "err", err.Error())
			errChan <- err
		}
	}()

	// validate user association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauth.IsValidClient(cmd.ClientId, cmd.Username); !valid {
			h.logger.Error(fmt.Sprintf("failed to validate user's (%s) association with client Id (%s)", cmd.Username, cmd.ClientId), "err", err.Error())
			errChan <- err
		}
	}()

	// validate response type is appropriate
	wg.Add(1)
	go func() {
		defer wg.Done()
		if cmd.ResponseType != string(types.AuthCode) {
			errChan <- fmt.Errorf("invalid response type")
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
	authCode, err := h.oauth.GenerateAuthCode(cmd.Username, cmd.ClientId, cmd.Redirect)
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
	authCodeResponse := types.AuthCodeExchange{
		AuthCode:     authCode,
		ResponseType: types.ResponseType(cmd.ResponseType),
		State:        cmd.State,
		Nonce:        cmd.Nonce,
		ClientId:     cmd.ClientId,
		Redirect:     cmd.Redirect,
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
