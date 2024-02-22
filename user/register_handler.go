package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/session"
)

// service scopes required
var allowed []string = []string{"w.shaw:*"}

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
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.Verifier.IsAuthorized(allowed, svcToken); !authorized {
		if err.Error() == "unauthorized" {
			http.Error(w, fmt.Sprintf("invalid service token: %s", err), http.StatusUnauthorized)
			return
		} else {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
		}
	}

	var cmd session.UserRegisterCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// field input validation needs to happen here
	// to differenciate between bad request or internal server error response
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
		return
	}

	if err := h.RegService.Register(cmd); err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
}
