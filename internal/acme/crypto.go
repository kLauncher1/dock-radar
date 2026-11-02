package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// GenerateAccountKey generates a new ECDSA P-256 private key for ACME account registration.
func GenerateAccountKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateCertKey generates a new ECDSA P-256 private key for server TLS certificates.
func GenerateCertKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ComputeJWKThumbprint computes the RFC 7638 SHA-256 JWK thumbprint for an ECDSA P-256 public key.
func ComputeJWKThumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("unsupported or nil public key curve, expected P-256")
	}

	crv := "P-256"
	kty := "EC"

	// Coordinates must be 32 bytes zero-padded
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	padX := make([]byte, 32)
	padY := make([]byte, 32)
	copy(padX[32-len(xBytes):], xBytes)
	copy(padY[32-len(yBytes):], yBytes)

	// Lexicographically sorted canonical JWK members: crv, kty, x, y
	jwkCanonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		crv,
		kty,
		base64.RawURLEncoding.EncodeToString(padX),
		base64.RawURLEncoding.EncodeToString(padY),
	)

	h := sha256.Sum256([]byte(jwkCanonical))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// ComputeKeyAuthorization computes the RFC 8555 Key Authorization string: "<token>.<thumbprint>".
func ComputeKeyAuthorization(token string, pub *ecdsa.PublicKey) (string, error) {
	thumb, err := ComputeJWKThumbprint(pub)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, thumb), nil
}

// ComputeDNSKeyAuthDigest computes the SHA-256 base64url digest of the key authorization for DNS-01 TXT record.
func ComputeDNSKeyAuthDigest(keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GenerateCSR creates a PEM-encoded Certificate Signing Request for primary domain and additional SANs.
func GenerateCSR(key *ecdsa.PrivateKey, primaryDomain string, sans []string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil private key provided")
	}
	if err := ValidateDomain(primaryDomain); err != nil {
		return nil, fmt.Errorf("invalid primary domain: %w", err)
	}

	dnsMap := map[string]struct{}{
		strings.ToLower(primaryDomain): {},
	}
	var ipAddrs []net.IP

	for _, s := range sans {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsMap[strings.ToLower(s)] = struct{}{}
		}
	}

	var dnsNames []string
	for name := range dnsMap {
		dnsNames = append(dnsNames, name)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   primaryDomain,
			Organization: []string{"Dock-Radar Autonomous ACME"},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// SignJWS creates an RFC 7515 / RFC 8555 JSON Web Signature for ACME request payloads using ES256.
func SignJWS(priv *ecdsa.PrivateKey, kid string, nonce string, url string, payload []byte) ([]byte, error) {
	headerMap := map[string]any{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}

	if kid != "" {
		headerMap["kid"] = kid
	} else {
		// Embed JWK
		xBytes := priv.PublicKey.X.Bytes()
		yBytes := priv.PublicKey.Y.Bytes()
		padX := make([]byte, 32)
		padY := make([]byte, 32)
		copy(padX[32-len(xBytes):], xBytes)
		copy(padY[32-len(yBytes):], yBytes)

		headerMap["jwk"] = map[string]string{
			"crv": "P-256",
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(padX),
			"y":   base64.RawURLEncoding.EncodeToString(padY),
		}
	}

	headerJSON, err := json.Marshal(headerMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWS header: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	var encodedPayload string
	if len(payload) > 0 {
		encodedPayload = base64.RawURLEncoding.EncodeToString(payload)
	}

	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	sigHash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, sigHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWS: %w", err)
	}

	// Format signature as IEEE P1363 (R || S, 32 bytes each)
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	jwsBody := map[string]string{
		"protected": encodedHeader,
		"payload":   encodedPayload,
		"signature": base64.RawURLEncoding.EncodeToString(sigBytes),
	}

	return json.Marshal(jwsBody)
}

// FormatFingerprintSHA256 returns colon-separated hex format for an X.509 certificate SHA-256 digest.
func FormatFingerprintSHA256(certDER []byte) string {
	h := sha256.Sum256(certDER)
	var hexParts []string
	for _, b := range h {
		hexParts = append(hexParts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(hexParts, ":")
}

// ParseCertificatePEM decodes PEM bytes and returns the parsed x509.Certificate and tls.Certificate.
func ParseCertificatePEM(certPEM, keyPEM []byte) (*x509.Certificate, *tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse tls key pair: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("no certificate PEM block found")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	return x509Cert, &tlsCert, nil
}

// GenerateFallbackSelfSigned creates a temporary self-signed TLS cert for fallback SNI routing.
func GenerateFallbackSelfSigned(domain string, duration time.Duration) ([]byte, []byte, error) {
	priv, err := GenerateCertKey()
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(duration)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Dock-Radar Fallback Gateway"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if net.ParseIP(domain) != nil {
		template.IPAddresses = []net.IP{net.ParseIP(domain)}
	} else {
		template.DNSNames = []string{domain}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}
