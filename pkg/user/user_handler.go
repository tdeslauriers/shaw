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

// service scopes required
var (
	getUserAllowed    = []string{"r:shaw:user:*"}
	updateUserAllowed = []string{"w:shaw:user:*"}
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

	// validate iam token
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

// HandleUser handles the request for a single user
func (h *userHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
}
