package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/shaw/internal/authentication"
	"github.com/tdeslauriers/shaw/internal/oauth"
	"github.com/tdeslauriers/shaw/internal/util"
	api "github.com/tdeslauriers/shaw/pkg/api/login"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

// Handler is the interface for handling the logins request from the client
type Handler interface {

	// HandleLogin handles the login request from users and returns an auth code and redirect/state/nonce
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler and returns and underlying pointer to
// a concrete implementation of the Handler interface
func NewHandler(u authentication.Service, o oauth.Service, v jwt.Verifier) Handler {
	return &handler{
		auth:        u,
		oauth:       o,
		s2sVerifier: v,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageLogin)).
			With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface which
// handles the login request from users and returns an auth code and redirect/state/nonce
type handler struct {
	auth        authentication.Service
	oauth       oauth.Service
	s2sVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleLogin is the concrete implementation of the interface method which
// handles the login request from users and returns an auth code and redirect/state/nonce
func (h *handler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate method
	if r.Method != http.MethodPost {
		log.Error("invalid http method", "err", "only POST http method allowed")
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
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: user login cmd data
	var cmd api.UserLoginCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode login command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode user login command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation: check for empty fields or too long
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate user login command request body", "err", err.Error())
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
			log.Error(authentication.ErrInvalidUsernamePassword, "err", err.Error())
			errChan <- errors.New(authentication.ErrInvalidUsernamePassword)
			return
		}
	}()

	// validate redirect url association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauth.IsValidRedirect(cmd.ClientId, cmd.Redirect); !valid {
			log.Error(err.Error())
			errChan <- err
			return
		}
	}()

	// validate user association with client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if valid, err := h.oauth.IsValidClient(cmd.ClientId, cmd.Username); !valid {
			log.Error(err.Error())
			errChan <- err
			return
		}
	}()

	// validate response type is appropriate
	wg.Add(1)
	go func() {
		defer wg.Done()
		if cmd.ResponseType != string(types.AuthCode) {
			errChan <- fmt.Errorf("invalid response type")
			return
		}
	}()

	wg.Wait()
	close(errChan)

	// consolidate and return any login errors

	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}

		log.Error("login failed", "err", errors.Join(errs...))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("login failed: %v", errors.Join(errs...)),
		}
		e.SendJsonErr(w)
		return
	}

	// get user scopes for auth code generation.
	// service param in GetScopes is ignored for now because user scopes are not service specific (yet).
	scopes, err := h.auth.GetScopes(ctx, cmd.Username, "")
	if err != nil {
		log.Error(fmt.Sprintf("failed to get user scopes for user %s", cmd.Username), "err", err.Error())
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
		log.Error(fmt.Sprintf("failed to generate auth code for user %s", cmd.Username), "err", err.Error())
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

	log.Info(fmt.Sprintf("successfully generated auth code for user %s", cmd.Username))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authCodeResponse); err != nil {
		log.Error(fmt.Sprintf("failed to encode auth code response for user (%s) login", cmd.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to send auth code response body due to internal service error",
		}
		e.SendJsonErr(w)
		return
	}
}
