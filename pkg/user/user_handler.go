package user

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/shaw/internal/util"
)

// UserHandler interface for user request handling from downstream services
type UserHandler interface {

	// HandleUsers handles requests against the /users endpoint
	HandleUsers(w http.ResponseWriter, r *http.Request)
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

// HandleUser handles the requests for a single user
func (h *userHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// get slug from path if it exists
		slug := r.PathValue("slug")
		if slug == "" {
			h.getUsers(w, r)
			return
		} else {
			h.getUser(w, r)
			return
		}
	case http.MethodPut:
		h.updateUser(w, r)
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

// getUsers handles the request for all users
func (h *userHandler) getUsers(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// get correct scopes
	var requiredScopes []string
	if h.iamVerifier == nil {
		requiredScopes = s2sGetUserAllowed
	} else {
		requiredScopes = getUserAllowed
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(requiredScopes, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// check if iamVerifier is nil, if not nil, validate user iam token
	var authedUser *jwt.Token
	if h.iamVerifier != nil {
		accessToken := r.Header.Get("Authorization")
		authorized, err := h.iamVerifier.BuildAuthorized(requiredScopes, accessToken)
		if err != nil {
			log.Error("failed to authorize iam token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authedUser = authorized
		log = log.With("actor", authedUser.Claims.Subject)
	}

	// get users from user service
	users, err := h.service.GetUsers()
	if err != nil {
		log.Error("failed to get users", "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d users", len(users)))

	// send user records response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Error("failed to json encode users", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode users",
		}
		e.SendJsonErr(w)
		return
	}
}

// getUser handles the get request for a single user record by user slug
func (h *userHandler) getUser(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get correct scopes
	var requiredScopes []string
	if h.iamVerifier == nil {
		requiredScopes = s2sGetUserAllowed
	} else {
		requiredScopes = getUserAllowed
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(requiredScopes, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// check if iamVerifier is nil, if not nil, validate user iam token
	var authedUser *jwt.Token
	if h.iamVerifier != nil {
		accessToken := r.Header.Get("Authorization")
		authorized, err := h.iamVerifier.BuildAuthorized(requiredScopes, accessToken)
		if err != nil {
			log.Error("failed to authorize iam token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authedUser = authorized
		log = log.With("actor", authedUser.Claims.Subject)
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get user from user service
	user, err := h.service.GetUser(ctx, slug)
	if err != nil {
		log.Error("failed to get user", "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	log.Info("successfully retrieved user")

	// send user records response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Error("failed to encode user data to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateUser handles the update request for a single user record by user slug
// takes in the subject of an authorized token to log the user update
func (h *userHandler) updateUser(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerifier.BuildAuthorized(updateUserAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// check if iamVerifier is nil, if not nil, validate user iam token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(updateUserAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authorized.Claims.Subject)

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// update cmd record
	var cmd Profile
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error(fmt.Sprintf("failed to decode update cmd for user %s", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate user fields in request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("update cmd validation failed for user", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get record data for username/record index and audit log
	record, err := h.service.GetUser(ctx, slug)
	if err != nil {
		log.Error("failed to get user record for update", "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// prepare update model
	updated := Profile{
		Id:             record.Id,       // not used by update service
		Username:       record.Username, // needed for update user by user_index -> must not come from user input
		Firstname:      cmd.Firstname,
		Lastname:       cmd.Lastname,
		BirthDate:      cmd.BirthDate,
		Slug:           record.Slug,      // not used by update service
		CreatedAt:      record.CreatedAt, // not used by update service
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
	}

	if err := h.service.Update(&updated); err != nil {
		log.Error("failed to update user", "err", err.Error())
		h.service.HandleServiceErr(err, w)
		return
	}

	// audit log
	var updatedFields []any
	if record.Firstname != updated.Firstname {
		updatedFields = append(updatedFields,
			slog.String("previous_firstname", record.Firstname),
			slog.String("updated_firstname", updated.Firstname),
		)
	}

	if record.Lastname != updated.Lastname {
		updatedFields = append(updatedFields,
			slog.String("previous_lastname", record.Lastname),
			slog.String("updated_lastname", updated.Lastname),
		)
	}

	if record.BirthDate != updated.BirthDate {
		updatedFields = append(updatedFields,
			slog.String("previous_birthdate", record.BirthDate),
			slog.String("updated_birthdate", updated.BirthDate),
		)
	}

	if record.Enabled != updated.Enabled {
		updatedFields = append(updatedFields,
			slog.Bool("previous_enabled", record.Enabled),
			slog.Bool("updated_enabled", updated.Enabled),
		)
	}

	if record.AccountExpired != updated.AccountExpired {
		updatedFields = append(updatedFields,
			slog.Bool("previous_account_expired", record.AccountExpired),
			slog.Bool("updated_account_expired", updated.AccountExpired),
		)
	}

	if record.AccountLocked != updated.AccountLocked {
		updatedFields = append(updatedFields,
			slog.Bool("previous_account_locked", record.AccountLocked),
			slog.Bool("updated_account_locked", updated.AccountLocked),
		)
	}

	if len(updatedFields) > 0 {
		log = log.With(updatedFields...)
		log.Info("user successfully updated")
	} else {
		log.Warn("user update executed but no fields were changed")
	}

	// send user record response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error("failed to json encode updated user", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode updated user",
		}
		e.SendJsonErr(w)
		return
	}
}
