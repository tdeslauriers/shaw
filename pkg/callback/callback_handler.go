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

const (
	ErrMintToken string = "failed to mint jwt access token"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

type Handler interface {
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

func NewHandler(v jwt.Verifier, u authentication.Service, o oauth.Service) Handler {
	return &handler{
		s2sVerifier: v,
		auth:        u,
		oauth:       o,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	s2sVerifier jwt.Verifier
	auth        authentication.Service
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
	if _, err := h.s2sVerifier.BuildAuthorized(allowed, svcToken); err != nil {
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

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error("failed to generate jti for access token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    ErrMintToken,
		}
		e.SendJsonErr(w)
		return
	}

	now := time.Now().UTC()

	// build access token claims
	accessClaims := jwt.Claims{
		Jti:       jti.String(),
		Issuer:    util.ServiceName,
		Subject:   userData.Username,
		Audience:  types.BuildAudiences(userData.Scopes),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(authentication.AccessTokenDuration * time.Minute).Unix(),
		Scopes:    userData.Scopes,
	}

	// mint jwt access token
	accessToken, err := h.auth.MintToken(accessClaims)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to mint access token for user name %s", userData.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    ErrMintToken,
		}
		e.SendJsonErr(w)
		return
	}

	// build id token claims
	idClaims := jwt.Claims{
		Issuer:     util.ServiceName,
		Subject:    userData.Username,
		Audience:   []string{userData.ClientId}, // different from access token which si aimed at services
		IssuedAt:   now.Unix(),
		NotBefore:  now.Unix(),
		Expires:    now.Add(authentication.IdTokenDuration * time.Minute).Unix(),
		Nonce:      userData.Nonce,
		Email:      userData.Username,
		Name:       fmt.Sprintf("%s %s", userData.Firstname, userData.Lastname),
		GivenName:  userData.Firstname,
		FamilyName: userData.Lastname,
	}

	if userData.BirthDate != "" {
		idClaims.Birthdate = userData.BirthDate
	}

	// mint jwt id token
	idToken, err := h.auth.MintToken(idClaims)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to mint id token for user name %s", userData.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to mint id token",
		}
		e.SendJsonErr(w)
		return
	}

	// refresh token
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
		Scopes:       userData.Scopes,
		CreatedAt:    data.CustomTime{Time: time.Unix(accessToken.Claims.IssuedAt, 0).UTC()},
		Revoked:      false,
	}

	go func(r types.UserRefresh) {
		if err := h.auth.PersistRefresh(r); err != nil {
			h.logger.Error(fmt.Sprintf("failed to persist refresh token for user name %s", userData.Username), "err", err.Error())
		}
	}(persist)

	// return access, refresh, and id tokens to gateway
	authz := provider.UserAuthorization{
		Jti:                accessToken.Claims.Jti,
		AccessToken:        accessToken.Token,
		TokenType:          "Bearer",
		AccessTokenExpires: data.CustomTime{Time: time.Unix(accessToken.Claims.Expires, 0).UTC()},
		Refresh:            refresh.String(),
		RefreshExpires:     data.CustomTime{Time: time.Unix(accessToken.Claims.IssuedAt, 0).UTC().Add(authentication.RefreshDuration * time.Hour)},
		IdToken:            idToken.Token,
		IdTokenExpires:     data.CustomTime{Time: time.Unix(idToken.Claims.Expires, 0).UTC()},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode access token response for user (%s) callback", userData.Username), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode access token response due to internal service error",
		}
		e.SendJsonErr(w)
		return
	}
}
