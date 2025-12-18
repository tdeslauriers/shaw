package user

import (
	"database/sql"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
	api "github.com/tdeslauriers/shaw/pkg/api/user"
)

// GroupsRepository defines the groups repository interface for group data operations.
type GroupsRepository interface {

	// FindUsersWithScopes retrieves users who have one of a slice of scopes.
	FindUsersWithScopes(scopeIds []string) ([]api.Profile, error)
}

// NewGroupsRepository creates a new implementation of the groups repository interface, returning
// a pointer to the concrete implementation.
func NewGroupsRepository(sql *sql.DB) GroupsRepository {

	return &groupsRepository{
		sql: sql,
	}
}

var _ GroupsRepository = (*groupsRepository)(nil)

// groupsRepository is the concrete implementation of the groups repository interface.
type groupsRepository struct {
	sql *sql.DB
}

// FindUsersWithScopes retrieves users who have one of a slice of scopes from the database.
// Note: the slice returned may (probably will) contain duplicates if a user has multiple of the requested scopes.
func (r *groupsRepository) FindUsersWithScopes(scopeIds []string) ([]api.Profile, error) {

	// build query
	var query strings.Builder
	query.WriteString(`
			SELECT
				a.uuid,
				a.username,
				a.firstname,
				a.lastname,
				a.birth_date,
				a.slug,
				a.created_at,
				a.enabled,
				a.account_expired,
				a.account_locked
			FROM account a 
				LEFT OUTER JOIN account_scope a_s ON a.uuid = a_s.account_uuid
			WHERE a_s.scope_uuid IN (`)

	for i := range scopeIds {
		query.WriteString(`?`)
		if i < len(scopeIds)-1 {
			query.WriteString(`, `)
		}
	}
	query.WriteString(`)`)
	query.WriteString(` ORDER BY a.lastname, a.firstname ASC`)

	records, err := data.SelectRecords[api.Profile](r.sql, query.String(), sliceToVariatic(scopeIds)...)
	if err != nil {

		return nil, err
	}

	return records, nil
}
