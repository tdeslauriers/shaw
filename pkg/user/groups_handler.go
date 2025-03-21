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

// GroupsHandler interface for handling requests for groups of users
type GroupsHandler interface {

	// HandleUserGroups handles the requests for groups of users based on query param criteria
	HandleUserGroups(w http.ResponseWriter, r *http.Request)
}

// NewUserGroupsHandler creates a new user groups handler interface abstracting a concrete implementation
func NewGroupsHandler(s Service, s2s, iam jwt.Verifier) GroupsHandler {
	return &groupsHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceName)).
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ GroupsHandler = (*groupsHandler)(nil)

// groupsHandler is the concrete implementation of the GroupsHandler interface
type groupsHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleUserGroups is the concrete implementation of the interface function that handles
// the requests for groups of users based on query param criteria
func (h *groupsHandler) HandleUserGroups(w http.ResponseWriter, r *http.Request) {

	// check query params exist
	if r.URL.RawQuery == "" {
		h.logger.Error("no query params provided")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no query params provided",
		}
		e.SendJsonErr(w)
		return
	}

	// check if user endpoint  or service  endpoint handler and set scopes
	var requiredScopes []string
	if h.iamVerifier == nil {
		requiredScopes = s2sGetGroupsAllowed
	} else {
		requiredScopes = getGroupsAllowed
	}

	// validate s2s token
	s2sToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(requiredScopes, s2sToken); err != nil {
		h.logger.Error("user groups handler failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token if necessary
	if h.iamVerifier != nil {
		iamToken := r.Header.Get("Authorization")
		if _, err := h.iamVerifier.BuildAuthorized(requiredScopes, iamToken); err != nil {
			h.logger.Error("user groups handler failed to authorize iam token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
	}

	// get query params
	queryParams := r.URL.Query()

	// get scopes params
	scopes := queryParams.Get("scopes")
	if len(scopes) < 1 {
		h.logger.Error("no scopes provided")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no scopes provided",
		}
		e.SendJsonErr(w)
	}

	// light validation of scopes
	if len(scopes) > 512 {
		h.logger.Error("scopes url query param too long")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "scopes url query param too long",
		}
		e.SendJsonErr(w)
		return
	}

	// break up scopes by space delimiter
	scps := strings.Split(scopes, " ")

	// get scopes records from s2s service (source of truth)
	users, err := h.service.GetUsersWithScopes(scps)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get users with scopes '%s': %v", scopes, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

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
