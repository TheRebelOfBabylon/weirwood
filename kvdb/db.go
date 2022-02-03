package kvdb

import (
	"sync"

	bolt "go.etcd.io/bbolt"
)

type DB struct {
	bolt.DB
	Mutex sync.RWMutex
}

// NewDB instantiates the bbolt kvdb and returns it along with a RWMutex to make it read/write safe in goroutines
func NewDB(db_path string) (*DB, error) {
	db, err := bolt.Open(db_path, 0755, nil)
	if err != nil {
		return nil, err
	}
	return &DB{
		DB: *db,
	}, nil
}
