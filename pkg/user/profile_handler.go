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

// ProfileHandler interface for user profile services
type ProfileHandler interface {
	// HandleProfile handles the profile request from users
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new user profile handler
func NewProfileHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) ProfileHandler {
	return &profileHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceName)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

type profileHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleProfile handles the profile request from users
func (h *profileHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		h.handleGet(w, r)
	case "PUT":
	case "POST":
		h.handleUpdate(w, r)
	default:
		h.logger.Error("only GET, PUT, or POST http methods allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, PUT/POST http methods allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles the get requests for user profile
func (h *profileHandler) handleGet(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(getProfileAllowed, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/profile handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(getProfileAllowed, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("/profile handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse token for username
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to parse jwt token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data
	// Note: the username is part of the signed jwt token,
	// it is not submitted by requestor, ie, not a url parameter,
	// because a user should only be able to see their own profile
	// based on a cryptographically signed token value.
	u, err := h.service.GetProfile(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user profile %s: %s", jot.Claims.Subject, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// respond with user data
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(u); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode user profile: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdate handles the update requests for user profile
func (h *profileHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(updateProfileAllowed, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/profile handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(updateProfileAllowed, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("/profile handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	var cmd Profile
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode json update request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode json update request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// parse token for username: you can only update your own data record
	// username from put/poste cmd discarded
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to parse jwt token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data for audit log
	user, err := h.service.GetProfile(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user profile %s for update: %s", jot.Claims.Subject, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// prepare update model
	updated := Profile{
		Username:       user.Username, // user not allowed to update username
		Firstname:      cmd.Firstname,
		Lastname:       cmd.Lastname,
		BirthDate:      cmd.BirthDate,
		Slug:           user.Slug,           // user not allowed to update slug
		CreatedAt:      user.CreatedAt,      // user not allowed to update created at
		Enabled:        user.Enabled,        // user not allowed to update enabled
		AccountLocked:  user.AccountLocked,  // user not allowed to update account locked
		AccountExpired: user.AccountExpired, // user not allowed to update account expired
	}

	// update user data
	if err := h.service.Update(&updated); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update user profile %s: %s", cmd.Username, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// audit log
	if user.Firstname != cmd.Firstname {
		h.logger.Info(fmt.Sprintf("user profile firstname updated from %s to %s by %s", user.Firstname, cmd.Firstname, jot.Claims.Subject))
	}

	if user.Lastname != cmd.Lastname {
		h.logger.Info(fmt.Sprintf("user profile lastname updated from %s to %s by %s", user.Lastname, cmd.Lastname, jot.Claims.Subject))
	}

	if user.BirthDate != cmd.BirthDate {
		h.logger.Info(fmt.Sprintf("user profile date of birth updated from %s to %s by %s", user.BirthDate, cmd.BirthDate, jot.Claims.Subject))
	}

	w.Header().Set("Content-Type", "application/json")
	// respond with success
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode user profile: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
