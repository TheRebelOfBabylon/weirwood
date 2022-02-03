/*
Copyright (C) 2015-2018 Lightning Labs and The Lightning Network Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package macaroons

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/btcsuite/btcwallet/snacl"
	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
	bolt "go.etcd.io/bbolt"
)

var (
	rootKeyBucketName        = []byte("macrootkeys")
	RootKeyIDContextKey      = contextKey{"rootkeyid"}
	RootKeyLen               = 32
	DefaultRootKeyID         = []byte("0")
	encryptionKeyID          = []byte("enckey")
	ErrAlreadyUnlocked       = fmt.Errorf("macaroon store already unlocked")
	ErrContextRootKeyID      = fmt.Errorf("failed to read root key ID from context")
	ErrKeyValueForbidden     = fmt.Errorf("root key ID value is not allowed")
	ErrPasswordRequired      = fmt.Errorf("a non-nil password is required")
	ErrStoreLocked           = fmt.Errorf("macaroon store is locked")
	ErrRootKeyBucketNotFound = fmt.Errorf("Root key bucket not found")
	ErrEncKeyNotFound        = fmt.Errorf("macaroon encryption key not found")
	ErrDeletionForbidden     = fmt.Errorf("the specified ID cannot be deleted")
)

type contextKey struct {
	Name string
}

type RootKeyStorage struct {
	kvdb.DB
	encKey *snacl.SecretKey // Don't roll your own crypto
}

// InitRootKeyStorage initializes the top level bucket within the bbolt db for macaroons
func InitRootKeyStorage(db kvdb.DB) (*RootKeyStorage, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(rootKeyBucketName)
		return err
	}); err != nil {
		return nil, err
	}
	return &RootKeyStorage{
		DB:     db,
		encKey: nil,
	}, nil
}

// Get returns the root key for the given id. If the item is not there, it returns an error
func (r *RootKeyStorage) Get(_ context.Context, id []byte) ([]byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}
	var rootKey []byte
	err := r.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		dbKey := bucket.Get(id) //get the encryption key kv pair
		if len(dbKey) == 0 {
			return fmt.Errorf("Root key with id %s doesn't exist", string(id))
		}
		decKey, err := r.encKey.Decrypt(dbKey)
		if err != nil {
			return err
		}
		rootKey = make([]byte, len(decKey))
		copy(rootKey[:], decKey)
		return nil
	})
	if err != nil {
		rootKey = nil
		return nil, err
	}
	return rootKey, nil
}

// RootKeyIDFromContext retrieves the root key ID from context using the key
// RootKeyIDContextKey.
func RootKeyIDFromContext(ctx context.Context) ([]byte, error) {
	id, ok := ctx.Value(RootKeyIDContextKey).([]byte)
	if !ok {
		return nil, ErrContextRootKeyID
	}
	if len(id) == 0 {
		return nil, ErrMissingRootKeyID
	}
	return id, nil
}

// generateAndStoreNewRootKey creates a new random RootKeyLen-byte root key,
// encrypts it with the given encryption key and stores it in the bucket.
// Any previously set key will be overwritten.
func generateAndStoreNewRootKey(bucket *bolt.Bucket, id []byte,
	key *snacl.SecretKey) ([]byte, error) {

	rootKey := make([]byte, RootKeyLen)
	if _, err := io.ReadFull(rand.Reader, rootKey); err != nil {
		return nil, err
	}

	encryptedKey, err := key.Encrypt(rootKey)
	if err != nil {
		return nil, err
	}
	return rootKey, bucket.Put(id, encryptedKey)
}

// Implements RootKey from the bakery.RootKeyStorage interface
func (r *RootKeyStorage) RootKey(ctx context.Context) ([]byte, []byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()
	if r.encKey == nil {
		return nil, nil, ErrStoreLocked
	}
	id, err := RootKeyIDFromContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(id, encryptionKeyID) {
		return nil, nil, ErrKeyValueForbidden
	}
	var rootKey []byte
	err = r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return fmt.Errorf("Root key bucket not found")
		}
		dbKey := bucket.Get(id) //get the encryption key kv pair
		if len(dbKey) != 0 {
			decKey, err := r.encKey.Decrypt(dbKey)
			if err != nil {
				return err
			}

			rootKey = make([]byte, len(decKey))
			copy(rootKey[:], decKey[:])
			return nil
		}
		newKey, err := generateAndStoreNewRootKey(bucket, id, r.encKey)
		rootKey = newKey
		return err
	})
	if err != nil {
		rootKey = nil
		return nil, nil, err
	}
	return rootKey, id, err
}

// CreateUnlock sets an encryption key if one isn't already set or checks if the password is correct for the existing encryption key.
func (r *RootKeyStorage) CreateUnlock(password *[]byte) error {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if r.encKey != nil {
		return ErrAlreadyUnlocked
	}
	if password == nil {
		return ErrPasswordRequired
	}
	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName) // get the rootkey bucket
		if bucket == nil {
			return fmt.Errorf("Root key bucket not found")
		}
		dbKey := bucket.Get(encryptionKeyID) //get the encryption key kv pair
		if len(dbKey) > 0 {
			// dbKey has already been set
			encKey := &snacl.SecretKey{}
			err := encKey.Unmarshal(dbKey)
			if err != nil {
				return err
			}
			err = encKey.DeriveKey(password)
			if err != nil {
				return err
			}
			r.encKey = encKey
			return nil
		}
		// no key has been set so creating a new one
		encKey, err := snacl.NewSecretKey(
			password, snacl.DefaultN, snacl.DefaultR, snacl.DefaultP,
		)
		if err != nil {
			return err
		}
		err = bucket.Put(encryptionKeyID, encKey.Marshal())
		if err != nil {
			return err
		}
		r.encKey = encKey
		return nil
	})
}

// Close resets the encryption key in memory
func (r *RootKeyStorage) Close() error {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if r.encKey != nil {
		r.encKey.Zero()
		r.encKey = nil
	}
	return nil
}

// ChangePassword decrypts the macaroon root key with the old password and then
// encrypts it again with the new password.
func (r *RootKeyStorage) ChangePassword(oldPw, newPw []byte) error {
	// We need the store to already be unlocked. With this we can make sure
	// that there already is a key in the DB.
	if r.encKey == nil {
		return ErrStoreLocked
	}

	// Check if a nil password has been passed; return an error if so.
	if oldPw == nil || newPw == nil {
		return ErrPasswordRequired
	}

	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName)
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		encKeyDb := bucket.Get(encryptionKeyID)
		rootKeyDb := bucket.Get(DefaultRootKeyID)

		// Both the encryption key and the root key must be present
		// otherwise we are in the wrong state to change the password.
		if len(encKeyDb) == 0 || len(rootKeyDb) == 0 {
			return ErrEncKeyNotFound
		}

		// Unmarshal parameters for old encryption key and derive the
		// old key with them.
		encKeyOld := &snacl.SecretKey{}
		err := encKeyOld.Unmarshal(encKeyDb)
		if err != nil {
			return err
		}
		err = encKeyOld.DeriveKey(&oldPw)
		if err != nil {
			return err
		}

		// Create a new encryption key from the new password.
		encKeyNew, err := snacl.NewSecretKey(
			&newPw, snacl.DefaultN, snacl.DefaultR, snacl.DefaultP,
		)
		if err != nil {
			return err
		}

		// Now try to decrypt the root key with the old encryption key,
		// encrypt it with the new one and then store it in the DB.
		decryptedKey, err := encKeyOld.Decrypt(rootKeyDb)
		if err != nil {
			return err
		}
		rootKey := make([]byte, len(decryptedKey))
		copy(rootKey, decryptedKey)
		encryptedKey, err := encKeyNew.Encrypt(rootKey)
		if err != nil {
			return err
		}
		err = bucket.Put(DefaultRootKeyID, encryptedKey)
		if err != nil {
			return err
		}

		// Finally, store the new encryption key parameters in the DB
		// as well.
		err = bucket.Put(encryptionKeyID, encKeyNew.Marshal())
		if err != nil {
			return err
		}

		r.encKey = encKeyNew
		return nil
	})
}

// GenerateNewRootKey generates a new macaroon root key, replacing the previous
// root key if it existed.
func (r *RootKeyStorage) GenerateNewRootKey() error {
	// We need the store to already be unlocked. With this we can make sure
	// that there already is a key in the DB that can be replaced.
	if r.encKey == nil {
		return ErrStoreLocked
	}
	return r.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(rootKeyBucketName)
		if bucket == nil {
			return ErrRootKeyBucketNotFound
		}
		_, err := generateAndStoreNewRootKey(
			bucket, DefaultRootKeyID, r.encKey,
		)
		return err
	})
}

// ListMacaroonIDs returns all the root key ID values except the value of
// encryptedKeyID.
func (r *RootKeyStorage) ListMacaroonIDs(_ context.Context) ([][]byte, error) {
	r.Mutex.RLock()
	defer r.Mutex.RUnlock()

	// Check it's unlocked.
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}

	var rootKeySlice [][]byte

	// Read all the items in the bucket and append the keys, which are the
	// root key IDs we want.
	err := r.DB.View(func(tx *bolt.Tx) error {
		// As this is meant to be a read-only operation, rollback any unintended changes
		defer func() {
			rootKeySlice = nil
			tx.Rollback()
		}()
		// appendRootKey is a function closure that appends root key ID
		// to rootKeySlice.
		appendRootKey := func(k, _ []byte) error {
			// Only append when the key value is not encryptedKeyID.
			if !bytes.Equal(k, encryptionKeyID) {
				rootKeySlice = append(rootKeySlice, k)
			}
			return nil
		}

		return tx.Bucket(rootKeyBucketName).ForEach(appendRootKey)
	})
	if err != nil {
		return nil, err
	}

	return rootKeySlice, nil
}

// DeleteMacaroonID removes one specific root key ID. If the root key ID is
// found and deleted, it will be returned.
func (r *RootKeyStorage) DeleteMacaroonID(
	_ context.Context, rootKeyID []byte) ([]byte, error) {

	r.Mutex.RLock()
	defer r.Mutex.RUnlock()

	// Check it's unlocked.
	if r.encKey == nil {
		return nil, ErrStoreLocked
	}

	// Check the rootKeyID is not empty.
	if len(rootKeyID) == 0 {
		return nil, ErrMissingRootKeyID
	}

	// Deleting encryptedKeyID or DefaultRootKeyID is not allowed.
	if bytes.Equal(rootKeyID, encryptionKeyID) ||
		bytes.Equal(rootKeyID, DefaultRootKeyID) {

		return nil, ErrDeletionForbidden
	}

	var rootKeyIDDeleted []byte
	err := r.DB.Update(func(tx *bolt.Tx) error {
		// As this is meant to be a read-only operation, rollback any unintended changes
		defer func() {
			rootKeyIDDeleted = nil
		}()
		bucket := tx.Bucket(rootKeyBucketName)

		// Check the key can be found. If not, return nil.
		if bucket.Get(rootKeyID) == nil {
			return nil
		}

		// Once the key is found, we do the deletion.
		if err := bucket.Delete(rootKeyID); err != nil {
			return err
		}
		rootKeyIDDeleted = rootKeyID

		return nil
	})
	if err != nil {
		return nil, err
	}

	return rootKeyIDDeleted, nil
}
