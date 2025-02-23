package user

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
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

	if r.Method != http.MethodPost {
		h.logger.Error("only POST http method allowed to /users/scopes")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed to /users/scopes",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	s2sToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(updateUserAllowed, s2sToken); !authorized {
		h.logger.Error(fmt.Sprintf("user scopes handler failed to authorize s2s token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(updateUserAllowed, iamToken); !authorized {
		h.logger.Error(fmt.Sprintf("user scopes handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd UserScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("user scopes handler failed to decode request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate cmd
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("user scopes handler failed to validate cmd: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup user by slug
	u, err := h.service.GetUser(cmd.UserSlug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("user scopes handler failed to get user: %s", err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// update user scopes
	// dont need to check if cmd is empty, empty slice == remove all scopes
	if err := h.service.UpdateScopes(u, cmd.ScopeSlugs); err != nil {
		h.logger.Error(fmt.Sprintf("user scopes handler failed to update user scopes: %s", err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// log success
	// unlikely to error here because already parsed successully above
	jot, _ := jwt.BuildFromToken(strings.TrimPrefix(iamToken, "Bearer "))
	h.logger.Info(fmt.Sprintf("user %s's scopes successfully updated by %s", u.Username, jot.Claims.Subject))

	// respond 204
	w.WriteHeader(http.StatusNoContent)
}
