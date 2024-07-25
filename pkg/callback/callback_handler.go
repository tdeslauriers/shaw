package callback

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/oauth"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type Handler interface {
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

func NewHandler(v jwt.JwtVerifier, u types.UserAuthService, o oauth.Service) Handler {
	return &handler{
		s2sVerifier: v,
		userAuth:    u,
		oauth:       o,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	s2sVerifier jwt.JwtVerifier
	userAuth    types.UserAuthService
	oauth       oauth.Service

	logger *slog.Logger
}

func (h *handler) HandleCallback(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(allowed, svcToken); !authorized {
		h.logger.Error("callback handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: auth code, state, nonce, client id, redirect url
	var cmd types.AccessTokenCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode callback command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation: check for empty fields or too long
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("failed to validate callback command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to validate callback command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// exchange auth code for user authentication data, if exists/valid
	userData, err := h.oauth.RetrieveUserData(cmd)
	if err != nil {
		h.oauth.HandleServiceErr(err, w)
		return
	}

	// TODO: mint jwt access token and refresh tokens

	// TODO: return Access Token response to gateway

}
