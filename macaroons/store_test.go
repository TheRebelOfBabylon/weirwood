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
	"context"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"gitlab.com/cypher-engineers/bitswarmd/kvdb"
)

// createDummyRootKeyStore returns a temporary directory, a cleanup function and an instantiated RootKeyStorage
func createDummyRootKeyStorage(t *testing.T) (string, func(), *RootKeyStorage) {
	tempDir, err := ioutil.TempDir("", "macaroonstore-")
	if err != nil {
		t.Fatalf("Error creating temporary directory: %v", err)
	}
	db, err := kvdb.NewDB(path.Join(tempDir, "macaroon.db"))
	if err != nil {
		t.Fatalf("Could not create macaroon.db in temporary directory: %v", err)
	}
	rks, err := InitRootKeyStorage(*db)
	if err != nil {
		t.Fatalf("Could not instantiate RootKeyStorage: %v", err)
	}
	cleanUp := func() {
		_ = rks.Close()
		_ = db.Close()
	}
	return tempDir, cleanUp, rks
}

// TestStore tests the normal use cases of the store like creating, unlocking,
// reading keys and closing it.
func TestStorage(t *testing.T) {
	tempDir, cleanUp, rks := createDummyRootKeyStorage(t)
	defer cleanUp()
	defer os.RemoveAll(tempDir)

	_, _, err := rks.RootKey(context.TODO())
	if err != ErrStoreLocked {
		t.Fatalf("Unexpected error: %v", err)
	}
	pw := []byte("password")
	err = rks.CreateUnlock(&pw)
	if err != nil {
		t.Fatalf("Could not unlock key store: %v", err)
	}

	// Context with no root key id
	_, _, err = rks.RootKey(context.TODO())
	if err != ErrContextRootKeyID {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Try empty key ID
	emptyKeyID := make([]byte, 0)
	ctx := ContextWithRootKeyId(context.TODO(), emptyKeyID)
	_, _, err = rks.RootKey(ctx)
	if err != ErrMissingRootKeyID {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Try with bad key ID
	encryptedKeyID := []byte("enckey")
	ctx = ContextWithRootKeyId(context.TODO(), encryptedKeyID)
	_, _, err = rks.RootKey(ctx)
	if err != ErrKeyValueForbidden {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now the real deal
	key, id, err := rks.RootKey(ContextWithRootKeyId(context.Background(), DefaultRootKeyID))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	key2, err := rks.Get(ContextWithRootKeyId(context.Background(), DefaultRootKeyID), id)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(key, key2) {
		t.Fatalf("Key mismatch: expected: %v, received: %v: %v", key, key2, err)
	}
	rootId := id
	if !reflect.DeepEqual(rootId, DefaultRootKeyID) {
		t.Fatalf("The value of id %v should be the same as DefaultRootKeyId %v: %v", id, DefaultRootKeyID, err)
	}

	// Already unlocked test
	dummyPw := []byte("abcdefgh")
	err = rks.CreateUnlock(&dummyPw)
	if err != ErrAlreadyUnlocked {
		t.Fatalf("Unexpected error: %v", err)
	}

	cleanUp()

	// Try reopening
	db, err := kvdb.NewDB(path.Join(tempDir, "macaroon.db"))
	if err != nil {
		t.Fatalf("Could not create/open macaroon.db in temporary directory: %v", err)
	}
	rks, err = InitRootKeyStorage(*db)
	if err != nil {
		t.Fatalf("Could not instantiate RootKeyStorage: %v", err)
	}
	defer func() {
		db.Close()
		rks.Close()
	}()
	err = rks.CreateUnlock(&dummyPw)
	if err != snacl.ErrInvalidPassword {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = rks.CreateUnlock(nil)
	if err != ErrPasswordRequired {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, _, err = rks.RootKey(ContextWithRootKeyId(context.Background(), DefaultRootKeyID))
	if err != ErrStoreLocked {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = rks.Get(ContextWithRootKeyId(context.Background(), DefaultRootKeyID), nil)
	if err != ErrStoreLocked {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = rks.CreateUnlock(&pw)
	if err != nil {
		t.Fatalf("Could not unlock key store: %v", err)
	}
	key, err = rks.Get(ContextWithRootKeyId(context.Background(), DefaultRootKeyID), rootId)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(key2, key) {
		t.Fatalf("The value of key2 %v should be the same as key %v: %v", key2, key, err)
	}
	key, id2, err := rks.RootKey(ContextWithRootKeyId(context.Background(), DefaultRootKeyID))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(key2, key) {
		t.Fatalf("The value of key2 %v should be the same as key %v: %v", key2, key, err)
	}
	if !reflect.DeepEqual(id2, rootId) {
		t.Fatalf("The value of id2 %v should be the same as id %v: %v", id2, rootId, err)
	}
}
