package callback

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"shaw/pkg/oauth"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type Handler interface {
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

func NewHandler(v jwt.Verifier, u types.UserAuthService, o oauth.Service) Handler {
	return &handler{
		s2sVerifier: v,
		userAuth:    u,
		oauth:       o,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	s2sVerifier jwt.Verifier
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

	// mint jwt access token
	accessToken, err := h.userAuth.MintToken(userData.Username, userData.Scopes)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to mint access token for user name %s", userData.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to mint jwt access token",
		}
		e.SendJsonErr(w)
		return
	}

	// access refresh token
	refresh, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to generate refresh token for user name %s", userData.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to generate refresh token",
		}
		e.SendJsonErr(w)
		return
	}

	// persist refresh token
	persist := types.UserRefresh{
		// uuid for refresh token created by persist refresh function
		// index created by persist refresh function
		ClientId:     userData.ClientId,
		RefreshToken: refresh.String(),
		Username:     userData.Username, // username index created by persist refresh function
		CreatedAt:    data.CustomTime{Time: time.Unix(accessToken.Claims.IssuedAt, 0).UTC()},
		Revoked:      false,
	}

	go func(r types.UserRefresh) {
		if err := h.userAuth.PersistRefresh(r); err != nil {
			h.logger.Error(fmt.Sprintf("failed to persist refresh token for user name %s", userData.Username), "err", err.Error())
		}
	}(persist)

	// TODO id token

	authz := provider.UserAuthorization{
		Jti:                accessToken.Claims.Jti,
		AccessToken:        accessToken.Token,
		AccessTokenExpires: data.CustomTime{Time: time.Unix(accessToken.Claims.Expires, 0).UTC()},
		Refresh:            refresh.String(),
		RefreshExpires:     data.CustomTime{Time: time.Unix(accessToken.Claims.IssuedAt, 0).UTC().Add(authentication.RefreshDuration * time.Hour)},
	}

	// TODO: return Access Token response to gateway
}
