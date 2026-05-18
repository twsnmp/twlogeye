package datastore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenPrivateKey(t *testing.T) {
	bits := 2048
	pemStr, key, err := genPrivateKey(bits)
	if err != nil {
		t.Fatalf("genPrivateKey failed: %v", err)
	}
	if pemStr == "" {
		t.Error("pemStr should not be empty")
	}
	if key == nil {
		t.Error("key should not be nil")
	}
	if key.N.BitLen() != bits {
		t.Errorf("expected %d bits, got %d", bits, key.N.BitLen())
	}
}

func TestGetMyIPs(t *testing.T) {
	ips := getMyIPs()
	// At least loopback should be there usually, but it filters out non-IPv4 or specific things?
	// The code filters for To4() != nil.
	// We don't necessarily know if the test environment has active IPv4 interfaces, 
	// but we can check it doesn't crash.
	t.Logf("Detected IPs: %v", ips)
}

func TestGenCerts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_ca_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")

	// Test GenServerCert
	GenServerCert(certPath, keyPath, "test-server")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("server cert was not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("server key was not created")
	}

	// Test GenClientCert
	clientCertPath := filepath.Join(tmpDir, "client.crt")
	clientKeyPath := filepath.Join(tmpDir, "client.key")
	GenClientCert(clientCertPath, clientKeyPath, "test-client")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		t.Error("client cert was not created")
	}
	if _, err := os.Stat(clientKeyPath); os.IsNotExist(err) {
		t.Error("client key was not created")
	}
}
