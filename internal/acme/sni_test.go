package acme

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestSNIRouter_RegisterAndMatch(t *testing.T) {
	certPEM1, keyPEM1, err := GenerateFallbackSelfSigned("app1.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateFallbackSelfSigned failed: %v", err)
	}
	x509Cert1, tlsCert1, err := ParseCertificatePEM(certPEM1, keyPEM1)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}

	certPEM2, keyPEM2, err := GenerateFallbackSelfSigned("wildcard.net", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateFallbackSelfSigned failed: %v", err)
	}
	x509Cert2, tlsCert2, err := ParseCertificatePEM(certPEM2, keyPEM2)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}

	fallbackPEM, fallbackKey, err := GenerateFallbackSelfSigned("localhost", 24*time.Hour)
	if err != nil {
		t.Fatalf("fallback cert failed: %v", err)
	}
	_, fallbackTLSCert, _ := ParseCertificatePEM(fallbackPEM, fallbackKey)

	router := NewSNIRouter(fallbackTLSCert)

	managed1 := &ManagedCert{
		Domain:     "app1.example.com",
		SANs:       []string{"api1.example.com", "admin1.example.com"},
		TLSCert:    tlsCert1,
		ParsedX509: x509Cert1,
		Status:     CertStatusValid,
	}
	if err := router.Register(managed1); err != nil {
		t.Fatalf("failed to register cert1: %v", err)
	}

	managed2 := &ManagedCert{
		Domain:     "*.wildcard.net",
		SANs:       []string{"wildcard.net", "*.wildcard.net"},
		TLSCert:    tlsCert2,
		ParsedX509: x509Cert2,
		Status:     CertStatusValid,
	}
	if err := router.Register(managed2); err != nil {
		t.Fatalf("failed to register cert2: %v", err)
	}

	// 1. Exact match on primary
	hello := &tls.ClientHelloInfo{ServerName: "app1.example.com"}
	gotCert, err := router.GetCertificate(hello)
	if err != nil || gotCert != tlsCert1 {
		t.Fatalf("expected cert1 for app1.example.com")
	}

	// 2. Exact match on SAN
	helloSAN := &tls.ClientHelloInfo{ServerName: "api1.example.com"}
	gotCertSAN, err := router.GetCertificate(helloSAN)
	if err != nil || gotCertSAN != tlsCert1 {
		t.Fatalf("expected cert1 for api1.example.com")
	}

	// 3. Wildcard match
	helloWild := &tls.ClientHelloInfo{ServerName: "sub.wildcard.net"}
	gotCertWild, err := router.GetCertificate(helloWild)
	if err != nil || gotCertWild != tlsCert2 {
		t.Fatalf("expected cert2 for sub.wildcard.net")
	}

	// 4. Fallback match for unknown domain
	helloUnknown := &tls.ClientHelloInfo{ServerName: "random.unknown.io"}
	gotFallback, err := router.GetCertificate(helloUnknown)
	if err != nil || gotFallback != fallbackTLSCert {
		t.Fatalf("expected fallback for random.unknown.io")
	}

	// 5. Empty SNI fallback
	helloEmpty := &tls.ClientHelloInfo{ServerName: ""}
	gotFallbackEmpty, err := router.GetCertificate(helloEmpty)
	if err != nil || gotFallbackEmpty != fallbackTLSCert {
		t.Fatalf("expected fallback for empty SNI")
	}

	// 6. Routes and Count
	routes := router.Routes()
	if len(routes) < 4 {
		t.Errorf("expected at least 4 indexed routes, got %d", len(routes))
	}
	uniqueCerts, totalRoutes := router.Count()
	if uniqueCerts != 2 || totalRoutes < 4 {
		t.Errorf("expected 2 unique certs and >=4 routes, got %d, %d", uniqueCerts, totalRoutes)
	}

	// 7. Remove cert1
	router.Remove("app1.example.com")
	if _, ok := router.Get("app1.example.com"); ok {
		t.Errorf("expected cert1 to be removed")
	}
	gotFallbackAfterRemove, _ := router.GetCertificate(hello)
	if gotFallbackAfterRemove != fallbackTLSCert {
		t.Errorf("expected fallback after removing cert1")
	}
}

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		match   bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "nested.sub.example.com", false},
		{"app.local", "other.local", false},
	}

	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.match {
			t.Errorf("MatchDomain(%q, %q) = %v, expected %v", c.pattern, c.host, got, c.match)
		}
	}
}
