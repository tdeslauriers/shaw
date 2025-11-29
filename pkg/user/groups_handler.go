package user

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/shaw/internal/util"
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

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for callstack + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// check query params exist
	if r.URL.RawQuery == "" {
		log.Error("no query params provided")
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
	authedSvc, err := h.s2sVerifier.BuildAuthorized(requiredScopes, s2sToken)
	if err != nil {
		log.Error("user groups handler failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token if necessary
	var authedUser *jwt.Token
	if h.iamVerifier != nil {
		iamToken := r.Header.Get("Authorization")
		authorized, err := h.iamVerifier.BuildAuthorized(requiredScopes, iamToken)
		if err != nil {
			log.Error("user groups handler failed to authorize iam token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authedUser = authorized
		log = log.With("actor", authedUser.Claims.Subject)
	}

	// get query params
	queryParams := r.URL.Query()

	// get scopes params
	scopes := queryParams.Get("scopes")
	if len(scopes) < 1 {
		log.Error("no scopes provided")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no scopes provided",
		}
		e.SendJsonErr(w)
	}

	// light validation of scopes
	if len(scopes) > 512 {
		log.Error("scopes url query param too long")
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
	users, err := h.service.GetUsersWithScopes(ctx, scps)
	if err != nil {
		log.Error("failed to get user groups for scopes", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d users with scopes '%s'", len(users), scopes))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Error("failed to json encode user groups response body object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
