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
	"github.com/tdeslauriers/carapace/pkg/profile"
)

// service scopes required
var (
	getAllowed    = []string{"r:shaw:profile:*"}
	updateAllowed = []string{"w:shaw:profile:*"}
)

// Handler interface for user profile services
type Handler interface {
	// HandleProfile handles the profile request from users
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new user profile handler
func NewHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) Handler {
	return &handler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleProfile handles the profile request from users
func (h *handler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		h.handleGet(w, r)
	case "PUT":
	case "POST":
		h.handleUpdate(w, r)
	default:
		h.logger.Error("only GET, PUT http methods allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, POST, PUT http methods allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handleGet(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(getAllowed, svcToken); !authorized {
		h.logger.Error("profile handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(getAllowed, accessToken); !authorized {
		h.logger.Error("profile handler failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse token for username
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error("failed to parse jwt token", "err", err.Error())
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
	u, err := h.service.GetByUsername(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user profile: %s", jot.Claims.Subject), "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// respond with user data
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(u); err != nil {
		h.logger.Error("failed to json encode user profile", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handleUpdate(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(updateAllowed, svcToken); !authorized {
		h.logger.Error("registration handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(updateAllowed, accessToken); !authorized {
		h.logger.Error("registration handler failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	var cmd profile.User
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode json update request body", "err", err.Error())
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
		h.logger.Error("failed to parse jwt token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data for audit log
	user, err := h.service.GetByUsername(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get user profile: %s", jot.Claims.Subject), "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// prepare update model
	updated := profile.User{
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
		h.logger.Error(fmt.Sprintf("failed to update user profile: %s", cmd.Username), "err", err.Error())
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
		h.logger.Error("failed to json encode user profile", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
