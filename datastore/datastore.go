package datastore

import (
	"log"

	"github.com/dgraph-io/badger/v4"
)

var db *badger.DB

// OpenDB : open datastore
func OpenDB(path string) {
	opt := badger.DefaultOptions(path)
	if path == "" {
		opt.WithInMemory(true)
	}
	var err error
	db, err = badger.Open(opt)
	if err != nil {
		log.Fatalln(err)
	}
}

// CloseDB : close datastore
func CloseDB() {
	if db != nil {
		db.Close()
	}
}
