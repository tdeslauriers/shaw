package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/shaw/internal/authentication"
	"github.com/tdeslauriers/shaw/internal/util"
	"github.com/tdeslauriers/shaw/pkg/api/oauth"
)

const (
	ErrMintToken string = "failed to mint jwt access token"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

// Handler is the interface for handling the callback request from the client after
// the user has authenticated, exchanging the auth code for the access token and
// id token, and returning them to the client
type Handler interface {

	// HandleCallback handles the callback request from the client after the user has
	// authenticated, exchanging the auth code for the access token and id token, and
	// returning them to the client
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler and returns and underlying pointer to a
// concrete implementation of the Handler interface
func NewHandler(s Service, u authentication.Service, v jwt.Verifier) Handler {

	return &handler{
		oauth:       s,
		auth:        u,
		s2sVerifier: v,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageOauth)).
			With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface which
// handles the callback request from the client after the user has authenticated, exchanging
// the auth code for the access token and id token, and returning them to the client
type handler struct {
	oauth       Service
	auth        authentication.Service
	s2sVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleCallback implements the Handler interface, handling the callback request
// from the client after the user has authenticated, exchanging the auth code for the
// access token and id token, and returning them to the client.
func (h *handler) HandleCallback(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate method
	if r.Method != http.MethodPost {
		log.Error("method not allowed", "err", "only POST http method allowed")
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
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: auth code, state, nonce, client id, redirect url
	var cmd oauth.AccessTokenCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode callback command request body",
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation: check for empty fields or too long
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate callback command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// exchange auth code for user authentication data, if exists/valid
	userData, err := h.oauth.RetrieveUserData(cmd)
	if err != nil {
		log.Error("failed to retrieve user data for callback command", "err", err.Error())
		switch {
		// 400
		case strings.Contains(err.Error(), ErrValidateAuthCode):
			e := connect.ErrorHttp{
				StatusCode: http.StatusBadRequest,
				Message:    ErrValidateAuthCode,
			}
			e.SendJsonErr(w)
			return
		// 401
		case strings.Contains(err.Error(), ErrInvalidGrantType),
			strings.Contains(err.Error(), ErrAuthcodeRevoked),
			strings.Contains(err.Error(), ErrAuthcodeClaimed),
			strings.Contains(err.Error(), ErrAuthcodeExpired),
			strings.Contains(err.Error(), ErrUserDisabled),
			strings.Contains(err.Error(), ErrUserAccountLocked),
			strings.Contains(err.Error(), ErrUserAccountExpired),
			strings.Contains(err.Error(), ErrMismatchAuthcode),
			strings.Contains(err.Error(), ErrMismatchClientid),
			strings.Contains(err.Error(), ErrMismatchRedirect):
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		//404
		case strings.Contains(err.Error(), ErrIndexNotFound):
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    ErrIndexNotFound,
			}
			e.SendJsonErr(w)
			return
		// 500
		default:
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error",
			}
			e.SendJsonErr(w)
			return
		}
	}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		log.Error("failed to generate jti for access token", "err", err.Error())
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
		log.Error(fmt.Sprintf("failed to mint access token for user name %s", userData.Username), "err", err.Error())
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
		log.Error(fmt.Sprintf("failed to mint id token for user name %s", userData.Username), "err", err.Error())
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
		log.Error(fmt.Sprintf("failed to generate refresh token for user name %s", userData.Username), "err", err.Error())
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
			log.Error(fmt.Sprintf("failed to persist refresh token for user name %s", userData.Username), "err", err.Error())
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

	log.Info(fmt.Sprintf("successfully generated access, identity, and refresh tokens for user %s", userData.Username))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		log.Error(fmt.Sprintf("failed to encode access token response for oauth callback for user %s", userData.Username),
			slog.String("error", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode access token response to json",
		}
		e.SendJsonErr(w)
		return
	}
}
