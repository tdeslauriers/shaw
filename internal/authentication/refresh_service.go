package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// NewRefreshService creates a new refresh service concrete implmentation for user refresh token functionality.
func NewRefreshService(db *sql.DB, i data.Indexer, c data.Cryptor) types.RefreshService[types.UserRefresh] {
	return &refresh{
		db:      NewRefreshRepository(db),
		indexer: i,
		cryptor: c,
	}
}

var _ types.RefreshService[types.UserRefresh] = (*refresh)(nil)

type refresh struct {
	db      RefreshRepository
	indexer data.Indexer
	cryptor data.Cryptor
}

// GetRefreshToken retreives a refresh token by recreating the blind index, selecting, and then decrypting the record.
func (r *refresh) GetRefreshToken(ctx context.Context, refreshToken string) (*types.UserRefresh, error) {

	// light validation: redundant check, but good practice
	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return nil, errors.New("invalid refresh token")
	}

	// create blind index
	index, err := r.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// retrieve refresh token record from persistence
	refresh, err := r.db.FindUserRefresh(index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s - xxxxxx-%s", ErrRefreshNotFound, refreshToken[len(refreshToken)-6:])
		}
		return nil, fmt.Errorf("failed to retrieve refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	// decrypt refresh token, client id, and username
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 3)

		decryptedRefresh  []byte
		decryptedClientId []byte
		decryptedUsername []byte
		decryptedScopes   []byte
	)

	wg.Add(4)
	go r.decrypt(
		refresh.ClientId,
		ErrDecryptClientId,
		&decryptedClientId,
		errChan,
		&wg,
	)
	go r.decrypt(
		refresh.RefreshToken,
		ErrDecryptRefresh,
		&decryptedRefresh,
		errChan,
		&wg,
	)
	go r.decrypt(
		refresh.Username,
		ErrDecryptUsername,
		&decryptedUsername,
		errChan,
		&wg,
	)
	go r.decrypt(refresh.Scopes, ErrDecryptScopes, &decryptedScopes, errChan, &wg)

	wg.Wait()
	close(errChan)

	// consolidate errors
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt refresh token fields for user %s: %v", string(decryptedUsername), errors.Join(errs...))
	}

	return &types.UserRefresh{
		Uuid:          refresh.Uuid,
		RefreshIndex:  refresh.RefreshIndex,
		ClientId:      string(decryptedClientId),
		RefreshToken:  string(decryptedRefresh),
		Username:      string(decryptedUsername),
		UsernameIndex: refresh.UsernameIndex,
		Scopes:        string(decryptedScopes),
		CreatedAt:     refresh.CreatedAt,
		Revoked:       refresh.Revoked,
	}, nil
}

// decrypt is a helper function that abstracts the service decryption process for encrypted strings.
func (r *refresh) decrypt(encrypted, errMsg string, decrypted *[]byte, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	clear, err := r.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*decrypted = clear
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
		encryptedScopes   string
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
	wgRecord.Add(4)
	go r.encrypt(
		ur.ClientId,
		fmt.Sprintf("%s %s", ErrEncryptClientId, ur.ClientId),
		&encryptedClientId,
		errChan,
		&wgRecord,
	)
	go r.encrypt(
		ur.RefreshToken,
		fmt.Sprintf("%s xxxxxx-%s", ErrEncryptRefresh, ur.RefreshToken[len(ur.RefreshToken)-6:]),
		&encryptedRefresh,
		errChan,
		&wgRecord,
	)
	go r.encrypt(
		ur.Username,
		fmt.Sprintf("%s %s", ErrEncryptUsername, ur.Username),
		&encryptedUsername,
		errChan,
		&wgRecord,
	)
	go r.encrypt(
		ur.Scopes,
		fmt.Sprintf("%s for user %s", ErrEncryptScopes, ur.Username),
		&encryptedScopes,
		errChan,
		&wgRecord,
	)

	// create blind indices for refresh and username
	wgRecord.Add(2)
	go r.index(
		ur.RefreshToken,
		fmt.Sprintf("%s for refresh token xxxxxx-%s", ErrGenerateIndex, ur.RefreshToken[len(ur.RefreshToken)-6:]),
		&refreshIndex,
		errChan,
		&wgRecord,
	)
	go r.index(
		ur.Username,
		fmt.Sprintf("%s for username %s", ErrGenerateIndex, ur.Username),
		&usernameIndex,
		errChan,
		&wgRecord,
	)

	// wait for all go routines to finish
	wgRecord.Wait()
	close(errChan)

	// consolidate errors
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return fmt.Errorf("failed to encrypte refresh token fields for user %s: %v", ur.Username, errors.Join(errs...))
	}

	// update refresh struct
	ur.Uuid = id.String()
	ur.RefreshIndex = refreshIndex
	ur.ClientId = encryptedClientId
	ur.RefreshToken = encryptedRefresh
	ur.Username = encryptedUsername
	ur.UsernameIndex = usernameIndex
	ur.Scopes = encryptedScopes

	// insert record in to persistence
	if err := r.db.InsertUserRefresh(ur); err != nil {
		return fmt.Errorf("failed to insert refresh token record: %v", err)
	}

	return nil
}

// encrypt is a helper function that abstracts the service encryption process for plaintext strings.
func (r *refresh) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	enc, err := r.cryptor.EncryptServiceData([]byte(plaintext))
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
		return fmt.Errorf("%s for refresh token xxxxxx-%s: %v",
			ErrGenerateIndex, refreshToken[len(refreshToken)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	if exists, err := r.db.RefreshExists(index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v",
			refreshToken[len(refreshToken)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist",
			refreshToken[len(refreshToken)-6:])
	}

	// delete record
	if err := r.db.DeleteUserRefresh(index); err != nil {
		return fmt.Errorf("failed to delete refresh token xxxxxx-%s record: %v",
			refreshToken[len(refreshToken)-6:], err)
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

	// get refresh token record from persistence
	token, err := r.db.FindUserRefresh(index)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%s - xxxxxx-%s", ErrRefreshNotFound, refreshToken[len(refreshToken)-6:])
		}
		return fmt.Errorf("failed to retrieve refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	// check if already revoked
	if token.Revoked {
		// already revoked
		return nil
	}

	// set revoked to true
	token.Revoked = true

	// update record to revoked
	// NOTE: at this time, only the revoked field may be updated
	if err := r.db.UpdateUserRefresh(*token); err != nil {
		return fmt.Errorf("failed to revoke refresh token xxxxxx-%s record: %v", refreshToken[len(refreshToken)-6:], err)
	}

	return nil
}
