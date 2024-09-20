package refresh

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

// Handler interface for refresh services such as refeshing the access token and destroying the refresh token
type Handler interface {
	// HandleRefresh handles the refresh request from users:
	// returns a new access token, and a replacement refresh token
	HandleRefresh(w http.ResponseWriter, r *http.Request)

	// HandleDestroy handles the destroy refresh token request from users
	HandleDestroy(w http.ResponseWriter, r *http.Request)
}

func NewHandler(a authentication.Service, v jwt.Verifier) Handler {
	return &handler{
		auth:     a,
		verifier: v,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentRefresh)),
	}
}

var _ Handler = (*handler)(nil)

// contrceate handler implementation
type handler struct {
	auth     authentication.Service
	verifier jwt.Verifier

	logger *slog.Logger
}

// HandleRefresh handles the refresh request from users:
// returns a new access token, and a replacement refresh token
func (h *handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {

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
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		h.logger.Error("login handler failed to authorize service token for /refresh", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// refresh cmd
	var cmd types.UserRefreshCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode refresh cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode refresh command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("user refresh cmd validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// retreive refresh token
	refresh, err := h.auth.GetRefresh(cmd.RefreshToken)
	if err != nil {
		h.logger.Error("failed to get user refresh token", "err", err.Error())
		h.auth.HandleServiceErr(err, w)
		return
	}
}

// HandleDestroy handles the destroy refresh token request from users
func (h *handler) HandleDestroy(w http.ResponseWriter, r *http.Request) {

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
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		h.logger.Error("login handler failed to authorize service token for /refresh/destroy", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// destory cmd
	var cmd types.DestroyRefreshCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode refresh cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode destroy refresh command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("user refresh cmd validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// destroy refresh token
	if err := h.auth.DestroyRefresh(cmd.DestroyRefreshToken); err != nil {
		h.logger.Error("failed to destroy user refresh token", "err", err.Error())
		h.auth.HandleServiceErr(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("user refresh token xxxxxx-%s destroyed", cmd.DestroyRefreshToken[len(cmd.DestroyRefreshToken)-6:]))

	// respond with success
	w.Header().Set("Content-Type", "application/json") // expected by s2sCaller: TODO: handle no content response
	w.WriteHeader(http.StatusNoContent)

}
