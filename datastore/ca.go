package datastore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// genPrivateKey : Generate RSA Key
func genPrivateKey(bits int) (string, *rsa.PrivateKey, error) {
	// Generate the key of length bits
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", nil, err
	}
	// Convert it to pem
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block)), key, nil
}

func getMyIPs() []net.IP {
	ret := []net.IP{}
	ifs, err := net.Interfaces()
	if err != nil {
		log.Printf("get my ips err=%v", err)
		return ret
	}
	for _, i := range ifs {
		if (i.Flags & net.FlagUp) != net.FlagUp {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			cidr := a.String()
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			ret = append(ret, ip)
		}
	}
	return ret
}

func GenServerCert(cert, key, cn string) {
	kPem, keyBytes, err := genPrivateKey(4096)
	if err != nil {
		log.Fatalf("gen  cert err=%v", err)
	}
	host, err := os.Hostname()
	if err != nil {
		log.Printf("gen server cert err=%v", err)
		host = "localhost"
	}
	if cn == "" {
		cn = host
	}
	subject := pkix.Name{
		CommonName: cn,
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("gen cert err=%v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = append(template.DNSNames, host)
	if host != "localhost" {
		template.DNSNames = append(template.DNSNames, "localhost")
	}
	template.IPAddresses = getMyIPs()
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &keyBytes.PublicKey, keyBytes)
	if err != nil {
		log.Fatalf("gen cert err=%v", err)
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(cert, []byte(c), 0600); err != nil {
		log.Fatalf("gen cert err=%v", err)

	}
	if err := os.WriteFile(key, []byte(kPem), 0600); err != nil {
		log.Fatalf("gen cert err=%v", err)
	}
}

func GenClientCert(cert, key, cn string) {
	kPem, keyBytes, err := genPrivateKey(4096)
	if err != nil {
		log.Fatalf("gen  cert err=%v", err)
	}
	if cn == "" {
		cn = "twlogeye"
	}
	subject := pkix.Name{
		CommonName: cn,
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("gen client cert err=%v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &keyBytes.PublicKey, keyBytes)
	if err != nil {
		log.Fatalf("gen client cert err=%v", err)
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(cert, []byte(c), 0600); err != nil {
		log.Fatalf("gen client cert err=%v", err)

	}
	if err := os.WriteFile(key, []byte(kPem), 0600); err != nil {
		log.Fatalf("gen client cert err=%v", err)
	}
}
