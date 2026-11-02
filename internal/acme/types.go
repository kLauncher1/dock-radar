package acme

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ACMEProvider identifies the ACME certificate authority endpoint.
type ACMEProvider string

const (
	ProviderLetsEncrypt        ACMEProvider = "letsencrypt"
	ProviderLetsEncryptStaging ACMEProvider = "letsencrypt-staging"
	ProviderZeroSSL            ACMEProvider = "zerossl"
	ProviderCustom             ACMEProvider = "custom"
)

// Standard ACME Directory URLs.
const (
	LetsEncryptDirectoryURL        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLDirectoryURL            = "https://acme.zerossl.com/v2/DV90"
)

// ChallengeType represents the validation challenge mechanism.
type ChallengeType string

const (
	ChallengeHTTP01 ChallengeType = "http-01"
	ChallengeDNS01  ChallengeType = "dns-01"
)

// CertStatus represents the lifecycle state of a managed certificate.
type CertStatus string

const (
	CertStatusValid        CertStatus = "valid"
	CertStatusExpiringSoon CertStatus = "expiring_soon"
	CertStatusExpired      CertStatus = "expired"
	CertStatusRenewing     CertStatus = "renewing"
	CertStatusFailed       CertStatus = "failed"
)

var domainNameRegex = regexp.MustCompile(`^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$|^localhost$`)

// ACMEConfig defines operational parameters for the ACME Certbot and Dynamic SNI engine.
type ACMEConfig struct {
	Enabled            bool          `json:"enabled"`
	Provider           ACMEProvider  `json:"provider"`
	DirectoryURL       string        `json:"directory_url"`
	Email              string        `json:"email"`
	TermsAgreed        bool          `json:"terms_agreed"`
	ChallengeType      ChallengeType `json:"challenge_type"`
	RenewThresholdDays int           `json:"renew_threshold_days"`
	CheckInterval      time.Duration `json:"check_interval"`
	DataDir            string        `json:"data_dir"`
	AutoProvisionSANs  []string      `json:"auto_provision_sans"`
}

// DefaultACMEConfig returns production-ready default settings.
func DefaultACMEConfig() ACMEConfig {
	return ACMEConfig{
		Enabled:            true,
		Provider:           ProviderLetsEncryptStaging,
		DirectoryURL:       LetsEncryptStagingDirectoryURL,
		Email:              "",
		TermsAgreed:        true,
		ChallengeType:      ChallengeHTTP01,
		RenewThresholdDays: 30,
		CheckInterval:      1 * time.Hour,
		DataDir:            "data/acme",
		AutoProvisionSANs:  []string{},
	}
}

// ManagedCert encapsulates an active or managed TLS certificate and its metadata.
type ManagedCert struct {
	Domain             string           `json:"domain"`
	SANs               []string         `json:"sans"`
	Issuer             string           `json:"issuer"`
	Subject            string           `json:"subject"`
	SerialNumber       string           `json:"serial_number"`
	FingerprintSHA256  string           `json:"fingerprint_sha256"`
	NotBefore          time.Time        `json:"not_before"`
	NotAfter           time.Time        `json:"not_after"`
	DaysUntilExpire    int              `json:"days_until_expire"`
	Status             CertStatus       `json:"status"`
	AutoRenew          bool             `json:"auto_renew"`
	Provider           ACMEProvider     `json:"provider"`
	LastRenewedAt      time.Time        `json:"last_renewed_at,omitempty"`
	LastError          string           `json:"last_error,omitempty"`
	CertPEM            string           `json:"cert_pem,omitempty"`
	TLSCert            *tls.Certificate `json:"-"`
	ParsedX509         *x509.Certificate `json:"-"`
}

// CertSummary provides high-level certificate data for UI listings.
type CertSummary struct {
	Domain            string       `json:"domain"`
	SANs              []string     `json:"sans"`
	Issuer            string       `json:"issuer"`
	FingerprintSHA256 string       `json:"fingerprint_sha256"`
	NotAfter          time.Time    `json:"not_after"`
	DaysUntilExpire   int          `json:"days_until_expire"`
	Status            CertStatus   `json:"status"`
	AutoRenew         bool         `json:"auto_renew"`
	Provider          ACMEProvider `json:"provider"`
}

// ChallengeRecord tracks active HTTP-01 or DNS-01 verification challenge tokens.
type ChallengeRecord struct {
	Token            string        `json:"token"`
	KeyAuthorization string        `json:"key_authorization"`
	Domain           string        `json:"domain"`
	Type             ChallengeType `json:"type"`
	DNSRecordName    string        `json:"dns_record_name,omitempty"`
	DNSKeyAuthDigest string        `json:"dns_key_auth_digest,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	Verified         bool          `json:"verified"`
}

// ACMEStatus describes the runtime status of the ACME and SNI engine.
type ACMEStatus struct {
	Enabled             bool         `json:"enabled"`
	Provider            ACMEProvider `json:"provider"`
	DirectoryURL        string       `json:"directory_url"`
	Email               string       `json:"email"`
	AccountRegistered   bool         `json:"account_registered"`
	TotalCertificates   int          `json:"total_certificates"`
	ValidCertificates   int          `json:"valid_certificates"`
	ExpiringSoonCount   int          `json:"expiring_soon_count"`
	ExpiredCount        int          `json:"expired_count"`
	TotalRenewals       int64        `json:"total_renewals"`
	FailedRenewals      int64        `json:"failed_renewals"`
	ActiveChallenges    int          `json:"active_challenges"`
	SNIRoutesCount      int          `json:"sni_routes_count"`
	ChallengeType       ChallengeType `json:"challenge_type"`
	RenewThresholdDays  int          `json:"renew_threshold_days"`
	LastEvaluationAt    time.Time    `json:"last_evaluation_at"`
}

// ValidateDomain checks whether a domain string conforms to valid DNS formatting.
func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return errors.New("domain name cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain name exceeds 253 characters (%d)", len(domain))
	}
	if net.ParseIP(domain) != nil {
		return nil // IP SANs are allowed
	}
	if !domainNameRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain name format: %s", domain)
	}
	return nil
}

// ValidateACMEConfig verifies ACME configuration parameter bounds.
func ValidateACMEConfig(cfg ACMEConfig) error {
	if cfg.RenewThresholdDays < 1 || cfg.RenewThresholdDays > 90 {
		return fmt.Errorf("renew_threshold_days must be between 1 and 90 (got %d)", cfg.RenewThresholdDays)
	}
	if cfg.CheckInterval < 1*time.Minute || cfg.CheckInterval > 24*time.Hour {
		return fmt.Errorf("check_interval must be between 1m and 24h (got %s)", cfg.CheckInterval)
	}
	switch cfg.ChallengeType {
	case ChallengeHTTP01, ChallengeDNS01:
	default:
		return fmt.Errorf("unsupported challenge_type: %s", cfg.ChallengeType)
	}
	switch cfg.Provider {
	case ProviderLetsEncrypt, ProviderLetsEncryptStaging, ProviderZeroSSL, ProviderCustom:
	default:
		return fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
	if cfg.Provider == ProviderCustom && strings.TrimSpace(cfg.DirectoryURL) == "" {
		return errors.New("directory_url must be specified when using custom provider")
	}
	for _, san := range cfg.AutoProvisionSANs {
		if err := ValidateDomain(san); err != nil {
			return fmt.Errorf("invalid auto provision SAN %q: %w", san, err)
		}
	}
	return nil
}

// ResolveDirectoryURL returns the canonical directory URL for a provider.
func ResolveDirectoryURL(p ACMEProvider, customURL string) string {
	switch p {
	case ProviderLetsEncrypt:
		return LetsEncryptDirectoryURL
	case ProviderLetsEncryptStaging:
		return LetsEncryptStagingDirectoryURL
	case ProviderZeroSSL:
		return ZeroSSLDirectoryURL
	case ProviderCustom:
		if customURL != "" {
			return customURL
		}
		return LetsEncryptStagingDirectoryURL
	default:
		return LetsEncryptStagingDirectoryURL
	}
}
