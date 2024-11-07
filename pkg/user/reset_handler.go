package user

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
)

type ResetHandler interface {
	// HandleReset handles the reset request from users where the user knows their current password
	HandleReset(w http.ResponseWriter, r *http.Request)
}

// NewResetHandler creates a pointer to a new concrete implementation of the ResetHandler interface
func NewResetHandler(s Service, a authentication.Service, s2s jwt.Verifier, iam jwt.Verifier) ResetHandler {
	return &resetHandler{
		service:     s,
		auth:        a,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentUser)).
			With(slog.String(util.ComponentKey, util.ComponentReset)),
	}
}

var _ ResetHandler = (*resetHandler)(nil)

type resetHandler struct {
	service     Service
	auth        authentication.Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleReset is a concrete implementation which handles the reset request from users where the user knows their current password
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(updateAllowed, svcToken); !authorized {
		h.logger.Error("password reset handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(updateAllowed, accessToken); !authorized {
		h.logger.Error("password reset handler failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode json reset request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode json reset request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate reset inputs
	// checks if new and confirm passwords match
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// parse token for username
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error("failed to parse jwt token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
		return
	}

	// update password
	// this will check if the user exists, is valid, and if the current password is correct
	if err := h.service.ResetPassword(jot.Claims.Subject, cmd); err != nil {
		h.service.HandleServiceErr(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("user %s's password was successfully reset.", jot.Claims.Subject))

	// return 204
	w.WriteHeader(http.StatusNoContent)
}
