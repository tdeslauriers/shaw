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
	case "POST":
	case "PUT":
		h.handleUpdate(w, r)
	default:
		h.logger.Error("only GET, POST, PUT http methods allowed")
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
	// it is not submitted by requestor, ie, not a url parameter
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
	if authorized, err := h.s2sVerifier.IsAuthorized(getAllowed, svcToken); !authorized {
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

	// parse token for username: you can only update your own data record
	// username from put/poste cmd will be discarded

}
