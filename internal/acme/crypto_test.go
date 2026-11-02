package acme

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeys(t *testing.T) {
	accKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey failed: %v", err)
	}
	if accKey.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve")
	}

	certKey, err := GenerateCertKey()
	if err != nil {
		t.Fatalf("GenerateCertKey failed: %v", err)
	}
	if certKey.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve")
	}
}

func TestComputeJWKThumbprintAndKeyAuth(t *testing.T) {
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	thumb, err := ComputeJWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint failed: %v", err)
	}
	if thumb == "" || strings.Contains(thumb, "=") || strings.Contains(thumb, "+") || strings.Contains(thumb, "/") {
		t.Fatalf("thumbprint must be valid base64url without padding, got %q", thumb)
	}

	token := "sample-challenge-token-12345"
	keyAuth, err := ComputeKeyAuthorization(token, &key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeKeyAuthorization failed: %v", err)
	}
	expectedPrefix := token + "."
	if !strings.HasPrefix(keyAuth, expectedPrefix) {
		t.Fatalf("expected keyAuth to start with %q, got %q", expectedPrefix, keyAuth)
	}

	dnsDigest := ComputeDNSKeyAuthDigest(keyAuth)
	if dnsDigest == "" || strings.Contains(dnsDigest, "=") {
		t.Fatalf("dnsDigest must be raw base64url, got %q", dnsDigest)
	}
}

func TestGenerateCSR(t *testing.T) {
	key, err := GenerateCertKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	csrPEM, err := GenerateCSR(key, "dock.example.com", []string{"api.dock.example.com", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}
	if !strings.Contains(string(csrPEM), "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("expected PEM certificate request header")
	}
}

func TestSignJWS_WithEmbeddedJWKAndKID(t *testing.T) {
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	nonce := "test-replay-nonce-abcdef"
	reqURL := "https://acme.example.com/acme/new-order"
	payload := []byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`)

	// 1. With embedded JWK (no KID)
	jwsBytes, err := SignJWS(key, "", nonce, reqURL, payload)
	if err != nil {
		t.Fatalf("SignJWS with JWK failed: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(jwsBytes, &parsed); err != nil {
		t.Fatalf("failed to parse JWS json: %v", err)
	}
	if parsed["protected"] == "" || parsed["payload"] == "" || parsed["signature"] == "" {
		t.Fatalf("missing required JWS fields")
	}

	// Verify protected header contents
	headerBytes, err := base64.RawURLEncoding.DecodeString(parsed["protected"])
	if err != nil {
		t.Fatalf("failed to decode protected header: %v", err)
	}
	var headerMap map[string]any
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		t.Fatalf("failed to unmarshal header map: %v", err)
	}
	if headerMap["alg"] != "ES256" || headerMap["nonce"] != nonce || headerMap["url"] != reqURL {
		t.Fatalf("mismatched header values: %v", headerMap)
	}
	if _, hasJWK := headerMap["jwk"]; !hasJWK {
		t.Fatalf("expected embedded jwk in header")
	}

	// 2. With KID
	kid := "https://acme.example.com/acme/acct/12345"
	jwsKID, err := SignJWS(key, kid, nonce, reqURL, payload)
	if err != nil {
		t.Fatalf("SignJWS with kid failed: %v", err)
	}
	var parsedKID map[string]string
	_ = json.Unmarshal(jwsKID, &parsedKID)
	hdrKIDBytes, _ := base64.RawURLEncoding.DecodeString(parsedKID["protected"])
	var hdrKIDMap map[string]any
	_ = json.Unmarshal(hdrKIDBytes, &hdrKIDMap)
	if hdrKIDMap["kid"] != kid {
		t.Fatalf("expected kid %s, got %v", kid, hdrKIDMap["kid"])
	}
}

func TestGenerateFallbackSelfSignedAndParse(t *testing.T) {
	certPEM, keyPEM, err := GenerateFallbackSelfSigned("monitor.local", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateFallbackSelfSigned failed: %v", err)
	}

	x509Cert, tlsCert, err := ParseCertificatePEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}
	if x509Cert.Subject.CommonName != "monitor.local" {
		t.Fatalf("expected CommonName=monitor.local, got %s", x509Cert.Subject.CommonName)
	}
	if tlsCert == nil || len(tlsCert.Certificate) == 0 {
		t.Fatalf("expected valid tls.Certificate")
	}

	fp := FormatFingerprintSHA256(x509Cert.Raw)
	if !strings.Contains(fp, ":") {
		t.Fatalf("expected colon-formatted fingerprint, got %s", fp)
	}
}
