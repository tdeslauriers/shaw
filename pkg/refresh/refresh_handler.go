package refresh

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"shaw/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

type Handler interface {
	HandleRefresh(w http.ResponseWriter, r *http.Request)
}

func NewHandler(a types.UserAuthService, v jwt.Verifier) Handler {
	return &handler{
		auth:     a,
		verifier: v,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentRefresh)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	auth     types.UserAuthService
	verifier jwt.Verifier

	logger *slog.Logger
}

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
		h.logger.Error("login handler failed to authorize service token", "err", err.Error())
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
		h.logger.Error("refresh cmd validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: destroy refresh token
}
