package refresh

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"shaw/pkg/authentication"
	"shaw/pkg/user"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
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

func NewHandler(a authentication.Service, v jwt.Verifier, u user.Service) Handler {
	return &handler{
		auth:     a,
		verifier: v,
		user:     u,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentRefresh)),
	}
}

var _ Handler = (*handler)(nil)

// contrceate handler implementation
type handler struct {
	auth     authentication.Service
	verifier jwt.Verifier
	user     user.Service

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
	if _, err := h.verifier.BuildAuthorized(allowed, svcToken); err != nil {
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
	refresh, err := h.auth.GetRefreshToken(cmd.RefreshToken)
	if err != nil {
		h.logger.Error("failed to get user refresh token", "err", err.Error())
		h.auth.HandleServiceErr(err, w)
		return
	}

	// will also be used in access token + new refresh token generation
	now := time.Now().UTC()

	// check if refresh token is expired
	if refresh.CreatedAt.Add(time.Duration(12 * time.Hour)).Before(now) {
		h.logger.Error("user refresh token xxxxxx-%s is expired for user %s", refresh.RefreshToken[len(refresh.RefreshToken)-6:], refresh.Username)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "refresh token is expired",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data
	u, err := h.user.GetProfile(refresh.Username)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user %s data", refresh.Username), "err", err.Error())
		h.user.HandleServiceErr(err, w)
		return
	}

	// check if user is (still) active
	if active, err := h.user.IsActive(u); !active {
		h.logger.Error(fmt.Sprintf("user %s is not active", u.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// set up fields for new access token
	jti, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error("failed to generate jti for access token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to generate jti for access token",
		}
		e.SendJsonErr(w)
		return
	}

	// build access token claims
	accessClaims := jwt.Claims{
		Jti:       jti.String(),
		Issuer:    util.ServiceName,
		Subject:   u.Username,
		Audience:  types.BuildAudiences(refresh.Scopes),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(authentication.AccessTokenDuration * time.Minute).Unix(),
		Scopes:    refresh.Scopes,
	}

	// mint jwt access token
	accessToken, err := h.auth.MintToken(accessClaims)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to mint new access token for refresh uuid %s. username %s", refresh.Uuid, u.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to mint new access token",
		}
		e.SendJsonErr(w)
		return
	}

	// not typical to provide a new ID token when refreshing an access token
	// because no new user direct login/authentication has occurred

	// generate new refresh token
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error("failed to generate a new refresh token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to generate a new refresh token",
		}
		e.SendJsonErr(w)
		return
	}

	// set up new refresh token record for persistence
	persist := types.UserRefresh{
		ClientId:     refresh.ClientId,
		RefreshToken: refreshToken.String(),
		Username:     u.Username,
		Scopes:       refresh.Scopes,
		CreatedAt:    data.CustomTime{Time: time.Unix(now.Unix(), 0).UTC()},
		Revoked:      false,
	}

	// persist new refresh token
	go func(r types.UserRefresh) {
		if err := h.auth.PersistRefresh(r); err != nil {
			h.logger.Error(fmt.Sprintf("failed to persist new refresh token for user %s", u.Username), "err", err.Error())
			return
		}
	}(persist)

	// opportunistically delete old refresh token
	go func(r types.UserRefresh) {
		if err := h.auth.DestroyRefresh(r.RefreshToken); err != nil {
			h.logger.Error(fmt.Sprintf("failed to destroy old refresh uuid %s for user %s", r.Uuid, u.Username), "err", err.Error())
			return
		}
	}(*refresh)

	// respond with success + new tokens
	authz := provider.UserAuthorization{
		Jti:                jti.String(),
		AccessToken:        accessToken.Token,
		TokenType:          "Bearer",
		AccessTokenExpires: data.CustomTime{Time: time.Unix(accessClaims.Expires, 0).UTC()},
		Refresh:            refreshToken.String(),
		// original expiry is maintained to prevent endless refresh token generation
		RefreshExpires: data.CustomTime{Time: time.Unix(refresh.CreatedAt.Add(authentication.RefreshDuration*time.Hour).Unix(), 0).UTC()},
	}

	// respond with success + new tokens
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		h.logger.Error("failed to json encode refresh response body object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
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
	if _, err := h.verifier.BuildAuthorized(allowed, svcToken); err != nil {
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
