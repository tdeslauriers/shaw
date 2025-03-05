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

// UserHandler interface for user request handling from downstream services
type UserHandler interface {

	// HandleUsers handles the request for all users
	HandleUsers(w http.ResponseWriter, r *http.Request)

	// HandleUser handles the request for a single user
	HandleUser(w http.ResponseWriter, r *http.Request)
}

// NewUserHandler creates a new UserHandler interface by returning a pointer to a new concrete implementation of the UserHandler interface
func NewUserHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) UserHandler {
	return &userHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ UserHandler = (*userHandler)(nil)

// userHandler struct for user request handling
type userHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleUsers handles the request for all users
func (h *userHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(getUserAllowed, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/users handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(getUserAllowed, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("/users handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get users from user service
	users, err := h.service.GetUsers()
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users handler failed to get users: %s", err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// send user records response
	usersJson, err := json.Marshal(users)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users handler failed to marshal users: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to marshal users",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(usersJson) // writes status code 200 as part of execution
}

// HandleUser handles the requests for a single user
func (h *userHandler) HandleUser(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetUser(w, r)
		return
	case http.MethodPost:
		h.handleUpdateUser(w, r)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and POST http methods allowed",
		}
		e.SendJsonErr(w)
		return
	}

}

// handleGetUser handles the get request for a single user record by user slug
func (h *userHandler) handleGetUser(w http.ResponseWriter, r *http.Request) {

	// break path into segments
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		errMsg := "no user slug provided in get /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		errMsg := "invalid user slug provided in get /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// determine allowed scopes based on whether iamVerifier is nil --> service endpoint or user endpoint
	var allowedRead []string
	if h.iamVerifier == nil {
		allowedRead = s2sGetUserAllowed
	} else {
		allowedRead = getUserAllowed
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(allowedRead, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/users/%s get-handler failed to authorize service token: %s", slug, err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user iam token
	if h.iamVerifier != nil {
		accessToken := r.Header.Get("Authorization")
		if authorized, err := h.iamVerifier.IsAuthorized(allowedRead, accessToken); !authorized {
			h.logger.Error(fmt.Sprintf("/users/%s get-handler failed to authorize iam token: %s", slug, err.Error()))
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
	}

	// get user from user service
	user, err := h.service.GetUser(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s get-handler failed to get user: %s", slug, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// send user record response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s get-handler failed to json encode user: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateUser handles the update request for a single user record by user slug
func (h *userHandler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {

	// break path into segments
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		errMsg := "no user slug provided in post /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// lightweight validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		errMsg := "invalid user slug provided in post /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(updateUserAllowed, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to authorize service token: %s", slug, err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(updateUserAllowed, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to authorize iam token: %s", slug, err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// needed for the audit log (who is making the changes)
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to parse jwt token: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
		return
	}

	// update cmd record
	var cmd Profile
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to decode user: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode user",
		}
		e.SendJsonErr(w)
		return
	}

	// validate user fields in request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to validate user: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get user data for username/user index and audit log
	user, err := h.service.GetUser(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to get user: %s", slug, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// prepare update model
	updated := Profile{
		Id:             user.Id,       // not used by update service
		Username:       user.Username, // needed for update user by user_index -> must not come from user input
		Firstname:      cmd.Firstname,
		Lastname:       cmd.Lastname,
		BirthDate:      cmd.BirthDate,
		Slug:           user.Slug,      // not used by update service
		CreatedAt:      user.CreatedAt, // not used by update service
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
	}

	if err := h.service.Update(&updated); err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to update user: %s", slug, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// audit log
	if user.Firstname != cmd.Firstname {
		h.logger.Info(fmt.Sprintf("%s updated user %s's firstname from %s to %s", jot.Claims.Subject, user.Username, user.Firstname, cmd.Firstname))
	}

	if user.Lastname != cmd.Lastname {
		h.logger.Info(fmt.Sprintf("%s updated user %s's lastname from %s to %s", jot.Claims.Subject, user.Username, user.Lastname, cmd.Lastname))
	}

	if user.BirthDate != cmd.BirthDate {
		h.logger.Info(fmt.Sprintf("%s updated user %s's birthdate from %s to %s", jot.Claims.Subject, user.Username, user.BirthDate, cmd.BirthDate))
	}

	if user.Enabled != cmd.Enabled {
		h.logger.Info(fmt.Sprintf("%s updated user %s's enabled status from %t to %t", jot.Claims.Subject, user.Username, user.Enabled, cmd.Enabled))
	}

	if user.AccountExpired != cmd.AccountExpired {
		h.logger.Info(fmt.Sprintf("%s updated user %s's account expired status from %t to %t", jot.Claims.Subject, user.Username, user.AccountExpired, cmd.AccountExpired))
	}

	if user.AccountLocked != cmd.AccountLocked {
		h.logger.Info(fmt.Sprintf("%s updated user %s's account locked status from %t to %t", jot.Claims.Subject, user.Username, user.AccountLocked, cmd.AccountLocked))
	}

	// send user record response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s post-handler failed to json encode updated user: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode updated user",
		}
		e.SendJsonErr(w)
		return
	}
}
