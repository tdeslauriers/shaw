package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// NewRefreshService creates a new refresh service concrete implmentation for user refresh token functionality.
func NewRefreshService(db data.SqlRepository, i data.Indexer, c data.Cryptor) types.RefreshService[types.UserRefresh] {
	return &refresh{
		db:      db,
		indexer: i,
		cryptor: c,
	}
}

var _ types.RefreshService[types.UserRefresh] = (*refresh)(nil)

type refresh struct {
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor
}

// GetRefreshToken retreives a refresh token by recreating the blind index, selecting, and then decrypting the record.
func (r *refresh) GetRefreshToken(refreshToken string) (*types.UserRefresh, error) {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return nil, errors.New("invalid refresh token")
	}

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// retrieve record
	qry := `SELECT 
				uuid, 
				refresh_index,
				client_id, 
				refresh_token, 
				username,
				username_index,
				created_at,
				revoked
			FROM refresh 
			WHERE refresh_index = ?`
	var refresh types.UserRefresh
	if err := r.db.SelectRecord(qry, &refresh, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s - xxxxxx-%s", ErrRefreshNotFound, refreshToken[len(refreshToken)-6:])
		}
		return nil, fmt.Errorf("failed to retrieve refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	// decrypt refresh token, client id, and username
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 3)

		decryptedRefresh  string
		decryptedClientId string
		decryptedUsername string
	)

	wg.Add(3)
	go r.decrypt(refresh.ClientId, ErrDecryptClientId, &decryptedClientId, errChan, &wg)
	go r.decrypt(refresh.RefreshToken, ErrDecryptRefresh, &decryptedRefresh, errChan, &wg)
	go r.decrypt(refresh.Username, ErrDecryptUsername, &decryptedUsername, errChan, &wg)

	wg.Wait()
	close(errChan)

	// consolidate errors
	lenErrs := len(errChan)
	if lenErrs > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if count < lenErrs-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return nil, fmt.Errorf("failed decryption process for refresh token id %s - xxxxxx-%s: %s", refresh.Uuid, refreshToken[len(refreshToken)-6:], builder.String())
	}

	return &types.UserRefresh{
		Uuid:          refresh.Uuid,
		RefreshIndex:  refresh.RefreshIndex,
		ClientId:      decryptedClientId,
		RefreshToken:  decryptedRefresh,
		Username:      decryptedUsername,
		UsernameIndex: refresh.UsernameIndex,
		CreatedAt:     refresh.CreatedAt,
		Revoked:       refresh.Revoked,
	}, nil
}

// decrypt is a helper function that abstracts the service decryption process for encrypted strings.
func (r *refresh) decrypt(encrypted, errMsg string, decrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	plaintext, err := r.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*decrypted = plaintext
}

// PersistRefresh persists the refresh token for user authentication service.
// It encrypts the refresh token and creates the primary key and blind index before persisting it.
func (r *refresh) PersistRefresh(ur types.UserRefresh) error {

	var (
		wgRecord          sync.WaitGroup
		id                uuid.UUID
		refreshIndex      string
		encryptedClientId string
		encryptedRefresh  string
		encryptedUsername string
		usernameIndex     string
	)
	errChan := make(chan error, 6)

	// create primary key
	wgRecord.Add(1)
	go func(id *uuid.UUID, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to generate uuid for refresh token: %v", err)
			return
		}
		*id = i
	}(&id, errChan, &wgRecord)

	// encrypt client id, refresh token, and username
	wgRecord.Add(3)
	go r.encrypt(ur.ClientId, fmt.Sprintf("%s %s", ErrEncryptClientId, ur.ClientId), &encryptedClientId, errChan, &wgRecord)
	go r.encrypt(ur.RefreshToken, fmt.Sprintf("%s xxxxxx-%s", ErrEncryptRefresh, ur.RefreshToken[len(ur.RefreshToken)-6:]), &encryptedRefresh, errChan, &wgRecord)
	go r.encrypt(ur.Username, fmt.Sprintf("%s %s", ErrEncryptUsername, ur.Username), &encryptedUsername, errChan, &wgRecord)

	// create blind indices for refresh and username
	wgRecord.Add(2)
	go r.index(ur.RefreshToken, fmt.Sprintf("%s for refresh token xxxxxx-%s", ErrGenerateIndex, ur.RefreshToken[len(ur.RefreshToken)-6:]), &refreshIndex, errChan, &wgRecord)
	go r.index(ur.Username, fmt.Sprintf("%s for username %s", ErrGenerateIndex, ur.Username), &usernameIndex, errChan, &wgRecord)

	// wait for all go routines to finish
	wgRecord.Wait()
	close(errChan)

	// consolidate errors
	lenErrs := len(errChan)
	if lenErrs > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if count < lenErrs-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return fmt.Errorf("failed to persist refresh token: %s", builder.String())
	}

	// update refresh struct
	ur.Uuid = id.String()
	ur.RefreshIndex = refreshIndex
	ur.ClientId = encryptedClientId
	ur.RefreshToken = encryptedRefresh
	ur.Username = encryptedUsername
	ur.UsernameIndex = usernameIndex

	// insert record
	qry := `INSERT INTO refresh (uuid, refresh_index, client_id, refresh_token, username, username_index, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := r.db.InsertRecord(qry, ur); err != nil {
		return fmt.Errorf("failed to insert refresh token record: %v", err)
	}

	return nil
}

// encrypt is a helper function that abstracts the service encryption process for plaintext strings.
func (r *refresh) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	enc, err := r.cryptor.EncryptServiceData(plaintext)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = enc
}

// index is a helper function that abstracts the service indexing process for records.
func (r *refresh) index(record, errMsg string, index *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	ndx, err := r.indexer.ObtainBlindIndex(record)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*index = ndx
}

// DestroyRefresh removes the refresh token from the persistence store.
func (r *refresh) DestroyRefresh(refreshToken string) error {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	if exists, err := r.db.SelectExists(qry, index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist", refreshToken[len(refreshToken)-6:])
	}

	// delete record
	qry = `DELETE FROM refresh WHERE refresh_index = ?`
	if err := r.db.DeleteRecord(qry, index); err != nil {
		return fmt.Errorf("failed to delete refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	return nil
}

// RevokeRefresh revokes the user refresh token by updating the record in the persistence store.
func (r *refresh) RevokeRefresh(refreshToken string) error {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return errors.New("invalid refresh token")
	}

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	if exists, err := r.db.SelectExists(qry, index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist", refreshToken[len(refreshToken)-6:])
	}

	// update record to revoked
	qry = `UPDATE refresh SET revoked = ? WHERE refresh_index = ?`
	if err := r.db.UpdateRecord(qry, true, index); err != nil {
		return fmt.Errorf("failed to revoke refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	return nil
}
