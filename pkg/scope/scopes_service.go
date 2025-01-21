package scope

import (
	"database/sql"
	"errors"
	"fmt"

	"log/slog"
	"shaw/internal/util"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// ScopesService is the interface for the scopes service functionality like retrieving user scopes by username from the db.
type ScopesService interface {

	// GetScopes gets scopes specific to a service for a given username.
	GetUserScopes(user, service string) ([]types.Scope, error)
}

func NewScopesService(db data.SqlRepository, i data.Indexer, p provider.S2sTokenProvider, call connect.S2sCaller) ScopesService {
	return &scopesService{
		db:               db,
		indexer:          i,
		s2sTokenProvider: p,
		s2sCaller:        call,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ ScopesService = (*scopesService)(nil)

type scopesService struct {
	db               data.SqlRepository
	indexer          data.Indexer
	s2sTokenProvider provider.S2sTokenProvider
	s2sCaller        connect.S2sCaller

	logger *slog.Logger
}

// GetScopes is the concrete implementation of ScopesServices's GetScopes method and gets the user scopes for username.
// Note: service is not used in this implementation because a user's scopes are not service specific (yet).
func (s *scopesService) GetUserScopes(username, service string) ([]types.Scope, error) {

	// get user's allScopes and all allScopes
	var (
		wg         sync.WaitGroup
		userScopes []AccountScope
		allScopes  []types.Scope
	)

	wg.Add(2)
	go s.lookupUserScopes(username, &wg, &userScopes)
	go s.getAllScopes(&wg, &allScopes)
	wg.Wait()

	// return error either call returns no scopes
	if len(userScopes) < 1 {
		return nil, fmt.Errorf("no scopes found for user (%s)", username)
	}
	if len(allScopes) < 1 {
		return nil, errors.New("no scopes returned from s2s scopes endpoint")
	}

	idSet := make(map[string]struct{})
	for _, scope := range userScopes {
		idSet[scope.ScopeUuid] = struct{}{}
	}

	// filter out scopes that user does not have
	var filtered []types.Scope
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
func (s *scopesService) lookupUserScopes(username string, wg *sync.WaitGroup, acctScopes *[]AccountScope) {

	defer wg.Done()

	// user index
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		s.logger.Error(fmt.Sprintf("%s for username %s", ErrGenerateIndex, username), "err", err.Error())
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
			s.logger.Error(fmt.Sprintf("no scopes found for user %s", username), "err", err.Error())
			return
		} else {
			s.logger.Error(fmt.Sprintf("failed to retrieve scopes for user %s", username), "err", err.Error())
			return
		}
	}

	*acctScopes = scopes
}

// getAllScopes gets scopes data objects/records from s2s scopes endpoint
func (s *scopesService) getAllScopes(wg *sync.WaitGroup, scopes *[]types.Scope) {

	defer wg.Done()

	// get s2s service endpoint token to retreive scopes
	s2stoken, err := s.s2sTokenProvider.GetServiceToken(util.ServiceNameS2s)
	if err != nil {
		s.logger.Error("failed to get s2s token: %v", "err", err.Error())
		return
	}

	// call scopes endpoint
	var s2sScopes []types.Scope
	if err := s.s2sCaller.GetServiceData("/scopes", s2stoken, "", &s2sScopes); err != nil {
		s.logger.Error("failed to get scopes data from s2s scopes endpoint", "err", err.Error())
		return
	}

	*scopes = s2sScopes
}
