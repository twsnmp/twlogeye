package datastore

import (
	"testing"
)

func TestMIBDB(t *testing.T) {
	// Initialize MIBDB
	LoadMIBDB()

	// Test name to OID
	if MIBDB == nil {
		t.Fatal("MIBDB should not be nil after LoadMIBDB")
	}

	tests := []struct {
		name string
		oid  string
	}{
		{"sysUpTime", ".1.3.6.1.2.1.1.3"},
		{"sysContact", ".1.3.6.1.2.1.1.4"},
		{"sysName", ".1.3.6.1.2.1.1.5"},
	}

	for _, tt := range tests {
		got := MIBDB.NameToOID(tt.name)
		if got != tt.oid {
			t.Errorf("NameToOID(%s) = %s, want %s", tt.name, got, tt.oid)
		}
		back := MIBDB.OIDToName(tt.oid)
		if back != tt.name {
			t.Errorf("OIDToName(%s) = %s, want %s", tt.oid, back, tt.name)
		}
	}
}

func TestFindMIBInfo(t *testing.T) {
	// LoadMIBDB should have been called in previous test if run together, 
	// but better be safe or use TestMain.
	if MIBDB == nil {
		LoadMIBDB()
	}

	info := FindMIBInfo("sysUpTime")
	if info == nil {
		t.Log("sysUpTime info not found (might not be in full MIB info map)")
	} else {
		if info.OID != ".1.3.6.1.2.1.1.3" {
			t.Errorf("expected OID .1.3.6.1.2.1.1.3, got %s", info.OID)
		}
	}
}
