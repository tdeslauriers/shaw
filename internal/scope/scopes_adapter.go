package scope

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// ScopesRepository is an interface for database operations related to scopes
type ScopesRepository interface {

	// FindAccountScopeXrefs retrieves account scope xrefs from the database
	FindAccountScopeXrefs(userIndex string) ([]AccountScope, error)
}

// NewScopesRepository creates a new ScopesAdaptor interface by returning
// a pointer to a new concrete implementation
func NewScopesRepository(sql *sql.DB) ScopesRepository {
	return &scopesRepository{
		db: sql,
	}
}

var _ ScopesRepository = (*scopesRepository)(nil)

// scopesRepository is the concrete implementation of the ScopesAdaptor interface
type scopesRepository struct {
	db *sql.DB
}

// FindAccountScopeXrefs is a concrete implementation which retrieves account scope xrefs from the database
func (r *scopesRepository) FindAccountScopeXrefs(userIndex string) ([]AccountScope, error) {

	qry := `
		SELECT
			asp.id,
			asp.account_uuid,
			asp.scope_uuid,
			asp.created_at
		FROM account_scope asp
			LEFT OUTER JOIN account a ON asp.account_uuid = a.uuid
		WHERE a.user_index = ?`
	xrefs, err := data.SelectRecords[AccountScope](r.db, qry, userIndex)
	if err != nil {
		return nil, err
	}

	return xrefs, nil
}
