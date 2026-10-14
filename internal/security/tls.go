package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// GenerateSelfSignedCert creates an in-memory ECDSA P-256 self-signed X.509 certificate
// with Subject Alternative Names (SANs) covering localhost, loopbacks, and host interfaces.
func GenerateSelfSignedCert(additionalHosts []string, validDuration time.Duration) (tls.Certificate, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate ecdsa private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	if validDuration <= 0 {
		validDuration = 365 * 24 * time.Hour
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(validDuration)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Dock-Radar Standalone"},
			CommonName:    "Dock-Radar Secure Gateway",
			Country:       []string{"US"},
			Locality:      []string{"Localhost"},
			StreetAddress: []string{"Internal Service"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Always seed localhost and loopback interfaces
	dnsNames := map[string]struct{}{
		"localhost": {},
	}
	ipAddresses := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}

	// Add local hostname
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		dnsNames[strings.ToLower(hostname)] = struct{}{}
	}

	// Enumerate local network interface addresses for LAN dashboard access
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip := ipnet.IP.To4(); ip != nil {
					ipAddresses[ip.String()] = ip
				}
			}
		}
	}

	// Append any additional caller-specified hosts
	for _, h := range additionalHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ipAddresses[ip.String()] = ip
		} else {
			dnsNames[strings.ToLower(h)] = struct{}{}
		}
	}

	for dns := range dnsNames {
		template.DNSNames = append(template.DNSNames, dns)
	}
	for _, ip := range ipAddresses {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to marshal ecdsa key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to load generated key pair: %w", err)
	}

	return tlsCert, certPEM, keyPEM, nil
}

// LoadOrGenerateTLSConfig resolves or creates a modern TLS configuration.
// If certPath and keyPath are provided, they are loaded from disk.
// Otherwise, if autoGenerate is true, a self-signed certificate is dynamically generated.
func LoadOrGenerateTLSConfig(certPath, keyPath string, autoGenerate bool, hosts []string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certPath != "" && keyPath != "" {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls certificate from files (%s, %s): %w", certPath, keyPath, err)
		}
	} else if autoGenerate {
		cert, _, _, err = GenerateSelfSignedCert(hosts, 365*24*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-generate self-signed tls cert: %w", err)
		}
	} else {
		return nil, fmt.Errorf("neither tls cert files nor auto-generation were specified")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	return tlsConfig, nil
}
