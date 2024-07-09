package register

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"shaw/internal/util"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type Handler interface {
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewHandler(reg Service, v jwt.JwtVerifier) Handler {
	return &handler{
		regService: reg,
		verifier:   v,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	regService Service
	verifier   jwt.JwtVerifier

	logger *slog.Logger
}

func (h *handler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

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
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		h.logger.Error("registration handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
	}

	// decode request body: user registration cmd data
	var cmd session.UserRegisterCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("failed to decode json registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode json registration request body",
		}
		e.SendJsonErr(w)
		return
	}

	// field input validation needs to happen here
	// to differenciate between bad request or internal server error response
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// register user
	if err := h.regService.Register(cmd); err != nil {
		if strings.Contains(err.Error(), UsernameUnavailableErrMsg) {
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to register user %s: %s", cmd.Username, err.Error()),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// return 201
	registered := session.UserAccountData{
		Username:  cmd.Username,
		Firstname: cmd.Firstname,
		Lastname:  cmd.Lastname,
		Birthdate: cmd.Birthdate,
	}
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode/send user (%s) registration response body", registered.Username), "err", err.Error())
	}
}
