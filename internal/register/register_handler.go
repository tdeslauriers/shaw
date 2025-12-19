package register

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	util "github.com/tdeslauriers/shaw/internal/definition"
	"github.com/tdeslauriers/shaw/internal/user"
	api "github.com/tdeslauriers/shaw/pkg/api/register"
)

// service scopes required
var allowed []string = []string{"w:shaw:profile:*"}

type Handler interface {
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewHandler(reg Service, v jwt.Verifier) Handler {

	return &handler{
		regService: reg,
		verifier:   v,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageRegister)).
			With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	regService Service
	verifier   jwt.Verifier

	logger *slog.Logger
}

func (h *handler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for callstack + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != http.MethodPost {
		log.Error("http method not allowed", "err", "only POST http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.verifier.BuildAuthorized(allowed, svcToken); err != nil {
		log.Error("registration handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body: user registration cmd data
	var cmd api.UserRegisterCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json registration request body", "err", err.Error())
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
		log.Error("failed to validate user registration cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check client id -> not checked in ValidateCmd
	if len(cmd.ClientId) != 36 {
		log.Error("invalid client id", "err", "client id must be 36 characters long")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid client id",
		}
		e.SendJsonErr(w)
		return
	}

	// register user
	if err := h.regService.Register(ctx, cmd); err != nil {
		if strings.Contains(err.Error(), UsernameUnavailableErrMsg) {
			log.Error("failed to register user", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			log.Error("failed to register user", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to register user %s: %s", cmd.Username, err.Error()),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// return 201
	registered := user.UserAccount{
		Username:  cmd.Username,
		Firstname: cmd.Firstname,
		Lastname:  cmd.Lastname,
		Birthdate: cmd.Birthdate,
	}

	log.Info(fmt.Sprintf("successfully registered user %s", registered.Username))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode/send user (%s) registration response body", registered.Username),
			"err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode user registration response body",
		}
		e.SendJsonErr(w)
		return
	}
}
