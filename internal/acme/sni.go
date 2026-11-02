package acme

import (
	"crypto/tls"
	"errors"
	"strings"
	"sync"
)

// SNIRouter handles dynamic Server Name Indication (SNI) multiplexing,
// matching incoming TLS handshakes to exact or wildcard domain certificates in memory.
type SNIRouter struct {
	mu           sync.RWMutex
	certs        map[string]*ManagedCert // primary domain -> cert
	sanIndex     map[string]*ManagedCert // all SANs (lowercase) -> cert
	fallbackCert *tls.Certificate
}

// NewSNIRouter initializes an empty SNIRouter.
func NewSNIRouter(fallback *tls.Certificate) *SNIRouter {
	return &SNIRouter{
		certs:        make(map[string]*ManagedCert),
		sanIndex:     make(map[string]*ManagedCert),
		fallbackCert: fallback,
	}
}

// SetFallbackCertificate updates the default certificate used when no SNI matches.
func (r *SNIRouter) SetFallbackCertificate(fallback *tls.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallbackCert = fallback
}

// Register adds or updates a managed certificate and indexes all its SANs.
func (r *SNIRouter) Register(cert *ManagedCert) error {
	if cert == nil || cert.TLSCert == nil {
		return errors.New("cannot register nil certificate or nil TLSCert")
	}

	primary := strings.ToLower(strings.TrimSpace(cert.Domain))
	if primary == "" {
		return errors.New("certificate domain cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.certs[primary] = cert
	r.sanIndex[primary] = cert

	for _, san := range cert.SANs {
		normSAN := strings.ToLower(strings.TrimSpace(san))
		if normSAN != "" {
			r.sanIndex[normSAN] = cert
		}
	}

	return nil
}

// Remove unregisters a certificate by primary domain name.
func (r *SNIRouter) Remove(domain string) {
	norm := strings.ToLower(strings.TrimSpace(domain))
	r.mu.Lock()
	defer r.mu.Unlock()

	cert, exists := r.certs[norm]
	if !exists {
		return
	}

	delete(r.certs, norm)
	delete(r.sanIndex, norm)

	for _, san := range cert.SANs {
		sanNorm := strings.ToLower(strings.TrimSpace(san))
		// Only remove if it points to this cert
		if r.sanIndex[sanNorm] == cert {
			delete(r.sanIndex, sanNorm)
		}
	}
}

// Get retrieves a managed certificate by exact domain name.
func (r *SNIRouter) Get(domain string) (*ManagedCert, bool) {
	norm := strings.ToLower(strings.TrimSpace(domain))
	r.mu.RLock()
	defer r.mu.RUnlock()

	cert, ok := r.certs[norm]
	if !ok {
		cert, ok = r.sanIndex[norm]
	}
	return cert, ok
}

// List returns a slice of all registered managed certificates.
func (r *SNIRouter) List() []*ManagedCert {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ManagedCert, 0, len(r.certs))
	for _, c := range r.certs {
		result = append(result, c)
	}
	return result
}

// Routes returns a lookup map of [SNI Name] -> [Primary Certificate Domain].
func (r *SNIRouter) Routes() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make(map[string]string, len(r.sanIndex))
	for san, cert := range r.sanIndex {
		routes[san] = cert.Domain
	}
	return routes
}

// Count returns the number of unique certificates and indexed routes.
func (r *SNIRouter) Count() (int, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.certs), len(r.sanIndex)
}

// GetCertificate implements the tls.Config GetCertificate hook for dynamic SNI multiplexing.
func (r *SNIRouter) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return r.getFallback()
	}

	serverName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))

	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. Exact match in SAN index
	if cert, ok := r.sanIndex[serverName]; ok && cert.TLSCert != nil {
		return cert.TLSCert, nil
	}

	// 2. Wildcard match (*.domain.com)
	if parts := strings.Split(serverName, "."); len(parts) > 1 {
		wildcardKey := "*." + strings.Join(parts[1:], ".")
		if cert, ok := r.sanIndex[wildcardKey]; ok && cert.TLSCert != nil {
			return cert.TLSCert, nil
		}
	}

	// 3. Fallback certificate
	return r.getFallback()
}

func (r *SNIRouter) getFallback() (*tls.Certificate, error) {
	if r.fallbackCert != nil {
		return r.fallbackCert, nil
	}
	return nil, errors.New("no matching certificate or fallback available for SNI")
}

// MatchDomain reports whether host matches a certificate pattern (exact or wildcard).
func MatchDomain(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	h := strings.ToLower(strings.TrimSpace(host))

	if p == h {
		return true
	}

	if strings.HasPrefix(p, "*.") {
		parent := p[2:]
		parts := strings.Split(h, ".")
		if len(parts) >= 2 {
			hostParent := strings.Join(parts[1:], ".")
			return hostParent == parent
		}
	}

	return false
}

// BuildTLSConfig constructs a modern tls.Config configured with SNI routing.
func (r *SNIRouter) BuildTLSConfig() *tls.Config {
	cfg := &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
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

	r.mu.RLock()
	if r.fallbackCert != nil {
		cfg.Certificates = []tls.Certificate{*r.fallbackCert}
	}
	r.mu.RUnlock()

	return cfg
}
