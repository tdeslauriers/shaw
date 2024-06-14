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

type RegistrationHandler interface {
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(reg RegistrationService, v jwt.JwtVerifier) RegistrationHandler {
	return &registrationHandler{
		regService: reg,
		verifier:   v,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	regService RegistrationService
	verifier   jwt.JwtVerifier

	logger *slog.Logger
}

func (h *registrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		if strings.Contains(err.Error(), "unauthorized") {
			h.logger.Error("registration handler failed to validate service token", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			h.logger.Error("registration handler service token authorization failed", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "service token authorization failed due to interal server error",
			}
			e.SendJsonErr(w)
			return
		}
	}

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
		if strings.Contains(err.Error(), "username unavailable") {
			h.logger.Error(err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			h.logger.Error(fmt.Sprintf("failed to register new user %s", cmd.Username), "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "user registration failed due to internal service error",
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
