package datastore

import (
	"log"

	"github.com/dgraph-io/badger/v4"
)

var db *badger.DB

// OpenDB : open log database
func OpenDB() {
	dbPath := Config.DBPath
	if dbPath == "" {
		dbPath = Config.LogPath
	}
	opt := badger.DefaultOptions(dbPath)
	if dbPath == "" {
		opt = opt.WithInMemory(true)
	}
	var err error
	db, err = badger.Open(opt)
	if err != nil {
		log.Fatalln(err)
	}
}

// CloseLogDB : close log database
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func GetDBSize() int64 {
	if db == nil {
		return 0
	}
	lsm, dbs := db.Size()
	return lsm + dbs
}
