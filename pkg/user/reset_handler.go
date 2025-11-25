package user

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/shaw/internal/util"
)

// ResetHandler is the interface for handling the reset request from users where the user knows their current password
type ResetHandler interface {
	// HandleReset handles the reset request from users where the user knows their current password
	HandleReset(w http.ResponseWriter, r *http.Request)
}

// NewResetHandler creates a pointer to a new concrete implementation of the ResetHandler interface
func NewResetHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) ResetHandler {
	return &resetHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentReset)),
	}
}

var _ ResetHandler = (*resetHandler)(nil)

// resetHandler is the concrete implementation of the ResetHandler interface which
// handles the reset request from users where the user knows their current password
type resetHandler struct {
	service Service

	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleReset is a concrete implementation which handles the reset request from users where the user knows their current password
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for callstack + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != http.MethodPost {
		log.Error("http method not allowed", "err", "only POST http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(updateProfileAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(updateProfileAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam access token", "err", err.Error())
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
		log.Error("user reset cmd validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// update password
	// this function checks if the user exists, is valid, and if the current password is correct
	if err := h.service.ResetPassword(ctx, authorized.Claims.Subject, cmd); err != nil {
		h.service.HandleServiceErr(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("user %s's password was successfully reset.", authorized.Claims.Subject),
		"requesting_service", authedSvc.Claims.Subject,
		"actor", authorized.Claims.Subject)

	// return 204
	w.WriteHeader(http.StatusNoContent)
}
