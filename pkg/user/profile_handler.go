package user

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/shaw/internal/util"
)

// ProfileHandler interface for user profile services
type ProfileHandler interface {
	// HandleProfile handles the profile request from users
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new user profile handler
func NewProfileHandler(s Service, s2s jwt.Verifier, iam jwt.Verifier) ProfileHandler {
	return &profileHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceName)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

type profileHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleProfile handles the profile request from users
func (h *profileHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
		return
	case http.MethodPut:
		h.handleUpdate(w, r)
		return
	default:
		// get telemetry from request
		tel := connect.ObtainTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)

		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles the get requests for user profile
func (h *profileHandler) handleGet(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(getProfileAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(getProfileAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get user data
	// Note: the username is part of the signed jwt token,
	// it is not submitted by requestor, ie, not a url parameter,
	// because a user should only be able to see their own profile
	// based on a cryptographically signed token value.
	u, err := h.service.GetProfile(authorized.Claims.Subject)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get user profile %s: %s", authorized.Claims.Subject, err.Error()))
		h.service.HandleServiceErr(err, w)
		return
	}

	log.Info("user successfully retrieved their profile")

	// respond with user data
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(u); err != nil {
		log.Error("failed to json encode user profile response body object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdate handles the update requests for user profile
func (h *profileHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(updateProfileAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(updateProfileAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authorized.Claims.Subject)

	var cmd Profile
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json update request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode json update request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate user profile update cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get record data for audit log
	record, err := h.service.GetProfile(authorized.Claims.Subject)
	if err != nil {
		log.Error("failed to get user's profile", "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// prepare update model
	updated := Profile{
		Username:       record.Username, // user not allowed to update username
		Firstname:      cmd.Firstname,
		Lastname:       cmd.Lastname,
		BirthDate:      cmd.BirthDate,
		Slug:           record.Slug,           // user not allowed to update slug
		CreatedAt:      record.CreatedAt,      // user not allowed to update created at
		Enabled:        record.Enabled,        // user not allowed to update enabled
		AccountLocked:  record.AccountLocked,  // user not allowed to update account locked
		AccountExpired: record.AccountExpired, // user not allowed to update account expired
	}

	// update user data
	if err := h.service.Update(&updated); err != nil {
		log.Error(fmt.Sprintf("failed to update user %s's profile", authorized.Claims.Subject), "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// audit log
	var changes []any

	if record.Firstname != updated.Firstname {
		changes = append(changes,
			slog.String("firstname_previous", record.Firstname),
			slog.String("firstname_updated", updated.Firstname))
	}

	if record.Lastname != updated.Lastname {
		changes = append(changes,
			slog.String("lastname_previous", record.Lastname),
			slog.String("lastname_updated", updated.Lastname))
	}

	if record.BirthDate != updated.BirthDate {
		changes = append(changes,
			slog.String("birth_date_previous", record.BirthDate),
			slog.String("birth_date_updated", updated.BirthDate))
	}

	if len(changes) > 0 {
		log = log.With(changes...)
		log.Info("user successfully updated their profile")
	} else {
		log.Info(fmt.Sprintf("update executed, but no fields changed for user %s's profile", authorized.Claims.Subject))
	}

	w.Header().Set("Content-Type", "application/json")
	// respond with success
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error("failed to json encode user profile update response body object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response to json",
		}
		e.SendJsonErr(w)
		return
	}
}
