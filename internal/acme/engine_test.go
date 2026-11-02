package acme

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_LifecycleAndIssue(t *testing.T) {
	auditLog := audit.NewLogger(100)

	cfg := DefaultACMEConfig()
	cfg.RenewThresholdDays = 30
	cfg.AutoProvisionSANs = []string{"monitor.infra.local"}

	engine, err := NewEngine(cfg, auditLog, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Issue certificate
	cert, err := engine.IssueCertificate(ctx, "app.example.com", []string{"api.example.com"}, ProviderLetsEncryptStaging, ChallengeHTTP01)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}
	if cert.Domain != "app.example.com" {
		t.Fatalf("expected domain app.example.com, got %s", cert.Domain)
	}
	if cert.Status != CertStatusValid {
		t.Fatalf("expected status valid, got %s", cert.Status)
	}

	// 2. Lookup in SNIRouter
	gotCert, ok := engine.Router().Get("api.example.com")
	if !ok || gotCert == nil {
		t.Fatalf("expected to find cert via SAN api.example.com")
	}

	// 3. Status check
	st := engine.Status()
	if st.TotalCertificates < 1 || st.ValidCertificates < 1 {
		t.Fatalf("expected >=1 valid certs in status, got %+v", st)
	}
	if st.SNIRoutesCount < 2 {
		t.Fatalf("expected >=2 SNI routes, got %d", st.SNIRoutesCount)
	}

	// 4. Force Renewal
	renewed, err := engine.RenewCertificate(ctx, "app.example.com")
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}
	if renewed.Domain != "app.example.com" {
		t.Fatalf("expected renewed domain app.example.com")
	}

	// 5. Challenges
	challenges := engine.ListChallenges()
	if len(challenges) == 0 {
		t.Fatalf("expected at least 1 challenge registered")
	}

	// 6. Complete DNS-01 Challenge
	engine.RegisterChallenge(&ChallengeRecord{
		Token:    "dns-token-1",
		Domain:   "dns.example.com",
		Type:     ChallengeDNS01,
		Verified: false,
	})
	if !engine.CompleteDNS01Challenge("dns.example.com") {
		t.Fatalf("expected CompleteDNS01Challenge to succeed")
	}

	// 7. Update Config
	cfg.RenewThresholdDays = 45
	if err := engine.UpdateConfig(cfg, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if engine.Config().RenewThresholdDays != 45 {
		t.Fatalf("expected threshold 45, got %d", engine.Config().RenewThresholdDays)
	}

	// 8. Revoke Certificate
	if err := engine.RevokeCertificate(ctx, "app.example.com"); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}
	if _, found := engine.Router().Get("app.example.com"); found {
		t.Fatalf("expected cert to be removed from router")
	}
}

func TestEngine_StartAutoProvision(t *testing.T) {
	auditLog := audit.NewLogger(50)
	cfg := DefaultACMEConfig()
	cfg.AutoProvisionSANs = []string{"auto.domain.local"}
	cfg.CheckInterval = 1 * time.Minute

	engine, err := NewEngine(cfg, auditLog, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Check if auto-provisioned
	cert, ok := engine.Router().Get("auto.domain.local")
	if !ok || cert == nil {
		t.Fatalf("expected auto-provisioned cert for auto.domain.local")
	}
}
