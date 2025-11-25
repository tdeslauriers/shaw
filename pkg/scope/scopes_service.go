package scope

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/ran/pkg/scopes"
	ran "github.com/tdeslauriers/ran/pkg/scopes"
	"github.com/tdeslauriers/shaw/internal/util"
)

// ScopesService is the interface for the scopes service functionality like retrieving user scopes by username from the db.
type ScopesService interface {

	// GetAll returns all scopes from the s2s service.
	GetAll(ctx context.Context) ([]scopes.Scope, error)

	// GetScopes gets scopes specific to a service for a given username.
	GetUserScopes(ctx context.Context, user, service string) ([]scopes.Scope, error)
}

func NewScopesService(
	db data.SqlRepository,
	i data.Indexer,
	p provider.S2sTokenProvider,
	s2s *connect.S2sCaller,
) ScopesService {

	return &scopesService{
		db:      db,
		indexer: i,
		tkn:     p,
		s2s:     s2s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageScope)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ ScopesService = (*scopesService)(nil)

type scopesService struct {
	db      data.SqlRepository
	indexer data.Indexer
	tkn     provider.S2sTokenProvider
	s2s     *connect.S2sCaller

	logger *slog.Logger
}

// GetAll gets all scopes from the s2s service.
func (s *scopesService) GetAll(ctx context.Context) ([]ran.Scope, error) {

	// declare local log for this function
	log := s.logger

	// get telemetry from context if exists
	telemetry, ok := connect.GetTelemetryFromContext(ctx)
	if ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("failed to extract telemetry from context of s2s getAllScopes call")
	}

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.tkn.GetServiceToken(ctx, util.ServiceNameS2s)
	if err != nil {
		return nil, fmt.Errorf("failed to get s2s token: %v", err.Error())
	}

	// call scopes endpoint
	all, err := connect.GetServiceData[[]ran.Scope](
		ctx,
		s.s2s,
		"/s2s/scopes",
		s2stoken,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get all scopes data from s2s scopes endpoint: %v", err.Error())
	}

	log.Info(fmt.Sprintf("successfully retrieved %d scopes from s2s scopes endpoint", len(all)))

	return all, nil
}

// GetScopes is the concrete implementation of ScopesServices's GetScopes method and gets the user scopes for username.
// Note: service param is not used in this implementation because a user's scopes are not service specific (yet).
func (s *scopesService) GetUserScopes(ctx context.Context, username, service string) ([]ran.Scope, error) {

	// get user's scopes and all allScopes
	var (
		wg sync.WaitGroup

		allCh  = make(chan []ran.Scope, 1)
		userCh = make(chan []AccountScope, 1)
		errCh  = make(chan error, 2)
	)

	wg.Add(2)
	go s.lookupUserScopes(ctx, username, userCh, errCh, &wg)
	go s.getAllScopes(ctx, allCh, errCh, &wg)

	wg.Wait()
	close(allCh)
	close(userCh)
	close(errCh)

	// handle errors from concurrent calls if any
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to get scopes: %v", errors.Join(errs...))
	}

	// collect user scopes to slices from channels
	var userScopes []AccountScope
	for us := range userCh {
		userScopes = append(userScopes, us...)
	}
	if len(userScopes) < 1 {
		return nil, fmt.Errorf("no scopes found for user (%s)", username)
	}

	// collect all scopes from channel
	var allScopes []ran.Scope
	for as := range allCh {
		allScopes = append(allScopes, as...)
	}
	if len(allScopes) < 1 {
		return nil, errors.New("no scopes returned from s2s scopes endpoint")
	}

	idSet := make(map[string]struct{})
	for _, scope := range userScopes {
		idSet[scope.ScopeUuid] = struct{}{}
	}

	// filter out scopes that user does not have
	var filtered []ran.Scope
	for _, scope := range allScopes {
		if _, exists := idSet[scope.Uuid]; exists && scope.Active {
			filtered = append(filtered, scope)
		}
	}

	return filtered, nil
}

// lookupUserScopes gets individual user's scopes uuids from account_scope table.
// Note: returns uuids only.  Needs additional functionality to get the actual scope records
// from the scope table in the s2s service.
func (s *scopesService) lookupUserScopes(
	ctx context.Context,
	username string,
	asCh chan []AccountScope,
	errCh chan error,
	wg *sync.WaitGroup,
) {

	defer wg.Done()

	// declare local log for this function
	log := s.logger

	// get telemetry from context if exists
	telemetry, ok := connect.GetTelemetryFromContext(ctx)
	if ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("failed to extract telemetry from context of s2s getAllScopes call")
	}

	// user index
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		errCh <- fmt.Errorf("failed to generate user index for user %s: %v", username, err.Error())
		return
	}

	qry := `
		SELECT
			asp.id,
			asp.account_uuid,
			asp.scope_uuid,
			asp.created_at
		FROM account_scope asp
			LEFT OUTER JOIN account a ON asp.account_uuid = a.uuid
		WHERE a.user_index = ?`

	var scopes []AccountScope
	if err := s.db.SelectRecords(qry, &scopes, index); err != nil {
		if err == sql.ErrNoRows {
			errCh <- fmt.Errorf("no scopes found for user %s: %v", username, err.Error())
			return
		} else {
			errCh <- fmt.Errorf("failed to retrieve scopes for user %s: %v", username, err.Error())
			return
		}
	}

	log.Info(fmt.Sprintf("successfully retrieved %d scopes for user %s", len(scopes), username))

	asCh <- scopes
}

// getAllScopes is a helper function for using GetAll() concurrently.
func (s *scopesService) getAllScopes(
	ctx context.Context,
	scopesCh chan []ran.Scope,
	errCh chan error,
	wg *sync.WaitGroup,
) {

	defer wg.Done()

	all, err := s.GetAll(ctx)
	if err != nil {
		errCh <- err
		return
	}

	scopesCh <- all
}
