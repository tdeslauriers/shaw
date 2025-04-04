package login

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"shaw/pkg/oauth"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

type Handler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewHandler(u authentication.Service, o oauth.Service, v jwt.Verifier) Handler {
	return &handler{
		auth:        u,
		oauth:       o,
		s2sVerifier: v,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	auth        authentication.Service
	oauth       oauth.Service
	s2sVerifier jwt.Verifier

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
	if _, err := h.s2sVerifier.BuildAuthorized(allowed, svcToken); err != nil {
		h.logger.Error("login handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: user login cmd data
	var cmd types.UserLoginCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode login command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode user login command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation: check for empty fields or too long
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("failed to validate user login command request body", "err", err.Error())
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
			h.logger.Error(err.Error())
			errChan <- err
		}
	}()

	// validate user association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauth.IsValidClient(cmd.ClientId, cmd.Username); !valid {
			h.logger.Error(err.Error())
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

	wg.Wait()
	close(errChan)

	// consolidate and return any login errors
	length := len(errChan)
	if length > 0 {
		var builder strings.Builder
		counter := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if counter < length-1 {
				builder.WriteString("; ")
			}
			counter++
		}

		errHttp := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    builder.String(),
		}
		errHttp.SendJsonErr(w)
		return
	}

	// get user scopes for auth code generation.
	// service param in GetScopes is ignored for now because user scopes are not service specific (yet).
	scopes, err := h.auth.GetScopes(cmd.Username, "")
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user scopes for user %s", cmd.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get user scopes for auth code generation",
		}
		e.SendJsonErr(w)
		return
	}

	// generate and persist auth code
	authCode, err := h.oauth.GenerateAuthCode(cmd.Username, cmd.Nonce, cmd.ClientId, cmd.Redirect, scopes)
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
