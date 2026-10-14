package security

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	additionalHosts := []string{"192.168.1.100", "radar.local", "custom.domain.internal"}
	validity := 48 * time.Hour

	cert, certPEM, keyPEM, err := GenerateSelfSignedCert(additionalHosts, validity)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("Expected non-empty PEM outputs")
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Expected at least one certificate in tls.Certificate")
	}

	// Parse certificate DER
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode cert PEM block")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse X.509 cert: %v", err)
	}

	// Verify key algorithm
	if _, ok := parsed.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected ECDSA public key, got %T", parsed.PublicKey)
	}

	// Verify SANs
	foundLocalhost := false
	foundCustomDNS := false
	for _, dns := range parsed.DNSNames {
		if dns == "localhost" {
			foundLocalhost = true
		}
		if dns == "radar.local" {
			foundCustomDNS = true
		}
	}
	if !foundLocalhost {
		t.Errorf("Expected 'localhost' in DNS SANs, found: %v", parsed.DNSNames)
	}
	if !foundCustomDNS {
		t.Errorf("Expected 'radar.local' in DNS SANs, found: %v", parsed.DNSNames)
	}

	foundLoopbackIP := false
	foundCustomIP := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundLoopbackIP = true
		}
		if ip.Equal(net.ParseIP("192.168.1.100")) {
			foundCustomIP = true
		}
	}
	if !foundLoopbackIP {
		t.Errorf("Expected 127.0.0.1 in IP SANs, found: %v", parsed.IPAddresses)
	}
	if !foundCustomIP {
		t.Errorf("Expected 192.168.1.100 in IP SANs, found: %v", parsed.IPAddresses)
	}

	// Verify validity bounds
	now := time.Now()
	if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
		t.Errorf("Cert validity bounds invalid: notBefore=%v, notAfter=%v, now=%v", parsed.NotBefore, parsed.NotAfter, now)
	}
}

func TestLoadOrGenerateTLSConfig_AutoGenerate(t *testing.T) {
	cfg, err := LoadOrGenerateTLSConfig("", "", true, []string{"localhost"})
	if err != nil {
		t.Fatalf("LoadOrGenerateTLSConfig failed: %v", err)
	}

	if cfg == nil {
		t.Fatalf("Expected non-nil tls.Config")
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("Expected 1 certificate in config, got %d", len(cfg.Certificates))
	}

	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("Expected MinVersion TLS 1.2 (0x0303), got 0x%04x", cfg.MinVersion)
	}
}

func TestLoadOrGenerateTLSConfig_FromDisk(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	_, certPEM, keyPEM, err := GenerateSelfSignedCert([]string{"127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate test certs: %v", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key: %v", err)
	}

	cfg, err := LoadOrGenerateTLSConfig(certPath, keyPath, false, nil)
	if err != nil {
		t.Fatalf("LoadOrGenerateTLSConfig failed loading from disk: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("Expected 1 certificate loaded from disk, got %d", len(cfg.Certificates))
	}
}

func TestLoadOrGenerateTLSConfig_Errors(t *testing.T) {
	// Neither files nor autogen specified
	_, err := LoadOrGenerateTLSConfig("", "", false, nil)
	if err == nil {
		t.Errorf("Expected error when neither files nor autogen are specified")
	}

	// Missing disk files
	_, err = LoadOrGenerateTLSConfig("nonexistent_cert.pem", "nonexistent_key.pem", false, nil)
	if err == nil {
		t.Errorf("Expected error loading nonexistent files")
	}
}
