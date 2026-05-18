package datastore

import (
	"os"
	"testing"
)

func TestOpenCloseDB(t *testing.T) {
	// Test in-memory DB
	Config.DBPath = ""
	OpenDB()
	if db == nil {
		t.Fatal("db should not be nil after OpenDB")
	}
	size := GetDBSize()
	if size < 0 {
		t.Errorf("GetDBSize() returned negative value: %d", size)
	}
	CloseDB()

	// Test disk DB (temporary)
	tmpDir, err := os.MkdirTemp("", "twlogeye_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	Config.DBPath = tmpDir
	OpenDB()
	if db == nil {
		t.Fatal("db should not be nil after OpenDB with path")
	}
	CloseDB()
}

func TestGetDBSize_Nil(t *testing.T) {
	db = nil // Ensure db is nil
	size := GetDBSize()
	if size != 0 {
		t.Errorf("GetDBSize() on nil db should return 0, got %d", size)
	}
}
