package user

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"

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

	// get correct scopes
	var requiredScopes []string
	if h.iamVerifier == nil {
		requiredScopes = s2sGetUserAllowed
	} else {
		requiredScopes = getUserAllowed
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(requiredScopes, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/users handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user iam token
	if h.iamVerifier != nil {
		accessToken := r.Header.Get("Authorization")
		if _, err := h.iamVerifier.BuildAuthorized(requiredScopes, accessToken); err != nil {
			h.logger.Error(fmt.Sprintf("/users handler failed to authorize iam token: %s", err.Error()))
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
	}

	// get users from user service
	users, err := h.service.GetUsers()
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users handler failed to get users: %s", err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// send user records response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.logger.Error(fmt.Sprintf("/users handler failed to json encode users: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode users",
		}
		e.SendJsonErr(w)
		return
	}

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

	// get correct scopes
	var requiredScopes []string
	if h.iamVerifier == nil {
		requiredScopes = s2sGetUserAllowed
	} else {
		requiredScopes = getUserAllowed
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(requiredScopes, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/users/slug get-handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user iam token
	if h.iamVerifier != nil {
		accessToken := r.Header.Get("Authorization")
		if _, err := h.iamVerifier.BuildAuthorized(requiredScopes, accessToken); err != nil {
			h.logger.Error(fmt.Sprintf("/users/slug get-handler failed to authorize iam token: %s", err.Error()))
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get user from user service
	user, err := h.service.GetUser(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users/%s get-handler failed to get user: %s", slug, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	// send user records response
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
// takes in the subject of an authorized token to log the user update
func (h *userHandler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(updateUserAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/users/slug get-handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user iam token

	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(updateUserAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/users/slug get-handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
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
		h.logger.Info(fmt.Sprintf("%s updated user %s's firstname from %s to %s", authorized.Claims.Subject, user.Username, user.Firstname, cmd.Firstname))
	}

	if user.Lastname != cmd.Lastname {
		h.logger.Info(fmt.Sprintf("%s updated user %s's lastname from %s to %s", authorized.Claims.Subject, user.Username, user.Lastname, cmd.Lastname))
	}

	if user.BirthDate != cmd.BirthDate {
		h.logger.Info(fmt.Sprintf("%s updated user %s's birthdate from %s to %s", authorized.Claims.Subject, user.Username, user.BirthDate, cmd.BirthDate))
	}

	if user.Enabled != cmd.Enabled {
		h.logger.Info(fmt.Sprintf("%s updated user %s's enabled status from %t to %t", authorized.Claims.Subject, user.Username, user.Enabled, cmd.Enabled))
	}

	if user.AccountExpired != cmd.AccountExpired {
		h.logger.Info(fmt.Sprintf("%s updated user %s's account expired status from %t to %t", authorized.Claims.Subject, user.Username, user.AccountExpired, cmd.AccountExpired))
	}

	if user.AccountLocked != cmd.AccountLocked {
		h.logger.Info(fmt.Sprintf("%s updated user %s's account locked status from %t to %t", authorized.Claims.Subject, user.Username, user.AccountLocked, cmd.AccountLocked))
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
