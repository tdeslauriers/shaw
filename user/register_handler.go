package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/session"
)

// service scopes required
var allowed []string = []string{"w:shaw:*"}

type RegistrationHandler struct {
	RegService RegistrationService
	Verifier   jwt.JwtVerifier
}

func NewRegistrationHandler(reg RegistrationService, v jwt.JwtVerifier) *RegistrationHandler {
	return &RegistrationHandler{
		RegService: reg,
		Verifier:   v,
	}
}

func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

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
	if authorized, err := h.Verifier.IsAuthorized(allowed, svcToken); !authorized {
		if err.Error() == "unauthorized" {
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    fmt.Sprintf("invalid service token: %v", err),
			}
			e.SendJsonErr(w)
			return
		} else {
			log.Printf("service token authorization failed: %v", err)
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
		log.Printf("unable to decode json registration request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "unable to decode json registration request body",
		}
		e.SendJsonErr(w)
		return
	}

	// field input validation needs to happen here
	// to differenciate between bad request or internal server error response
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("bad request: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	if err := h.RegService.Register(cmd); err != nil {
		log.Printf("failed to register new user %s: %v", cmd.Username, err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user registration failed due to internal service error",
		}
		e.SendJsonErr(w)
		return
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
		log.Printf("failed to json encode/send user (%s) registration response body: %v", registered.Username, err)
	}
}
