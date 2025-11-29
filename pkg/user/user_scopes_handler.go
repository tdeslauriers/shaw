package user

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/shaw/internal/util"
)

// ScopesHandler is an interface for handling requests to update the user's assigned scopes
type ScopesHandler interface {
	// HandleScopes handles the request to update the user's assigned scopes
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewScopesHandler creates a new user scopes handler interface abstracting a concrete implementation
func NewScopesHandler(s Service, s2s, iam jwt.Verifier) ScopesHandler {
	
	return &scopesHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

type scopesHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleScopes is the concrete implementation of the interface function that handles
// the request to update the user's assigned scopes
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != http.MethodPut {
		log.Error("http method not allowed", "err", "only POST http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(updateUserAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(updateUserAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd UserScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode user scopes cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate cmd
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate user scope cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup user by slug
	u, err := h.service.GetUser(ctx, cmd.UserSlug)
	if err != nil {
		log.Error("failed to get user for scope update",
			"actor", authorized.Claims.Subject,
			"err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// update user scopes
	// dont need to check if cmd is empty, empty slice == remove all scopes
	if err := h.service.UpdateScopes(ctx, u, cmd.ScopeSlugs); err != nil {
		log.Error("failed to update user scopes",
			"actor", authorized.Claims.Subject,
			"err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// log success
	log.Info(fmt.Sprintf("successfully updated scopes for user %s", u.Username),
		"actor", authorized.Claims.Subject,
	)

	// respond 204
	w.WriteHeader(http.StatusNoContent)
}
