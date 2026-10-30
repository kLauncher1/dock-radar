package gitops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyWebhookHMAC(t *testing.T) {
	secret := "my-secret-key-999"
	body := []byte(`{"ref":"refs/heads/main","after":"a1b2c3d4e5"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	// Test valid with sha256= prefix
	if !VerifyWebhookHMAC(body, secret, "sha256="+sigHex) {
		t.Errorf("expected valid HMAC verification")
	}

	// Test valid raw hex
	if !VerifyWebhookHMAC(body, secret, sigHex) {
		t.Errorf("expected valid raw hex HMAC verification")
	}

	// Test invalid signature
	if VerifyWebhookHMAC(body, secret, "sha256=badbadbad") {
		t.Errorf("expected failed verification on corrupted signature")
	}

	// Test empty secret
	if VerifyWebhookHMAC(body, "", sigHex) {
		t.Errorf("expected failure on empty secret")
	}

	// Test modified payload
	if VerifyWebhookHMAC([]byte(`{"tampered":true}`), secret, sigHex) {
		t.Errorf("expected failure on tampered body")
	}
}

func TestVerifyGitLabToken(t *testing.T) {
	secret := "gitlab-secret-token"

	if !VerifyGitLabToken(secret, secret) {
		t.Errorf("expected token match")
	}

	if VerifyGitLabToken("wrong-token", secret) {
		t.Errorf("expected token mismatch")
	}

	if VerifyGitLabToken("", secret) {
		t.Errorf("expected failure for empty provided token")
	}
}

func TestParseRawGitCommit(t *testing.T) {
	raw := `tree 1234567890abcdef1234567890abcdef12345678
author Alice Dev <alice@example.com> 1672531199 +0000
committer Bob Lead <bob@example.com> 1672531199 +0000
gpgsig -----BEGIN PGP SIGNATURE-----
 Version: GnuPG v2
 [signature data here]
 -----END PGP SIGNATURE-----

feat: enhance deployment pipeline with auto-rollback`

	commit, err := ParseRawGitCommit("e2f89c6b7a8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error parsing commit: %v", err)
	}

	if commit.Author != "Alice Dev" {
		t.Errorf("expected author 'Alice Dev', got: %s", commit.Author)
	}
	if commit.Email != "alice@example.com" {
		t.Errorf("expected email 'alice@example.com', got: %s", commit.Email)
	}
	if commit.Message != "feat: enhance deployment pipeline with auto-rollback" {
		t.Errorf("unexpected message: %s", commit.Message)
	}
	if commit.SignatureKeyID != "pgp-signed" {
		t.Errorf("expected pgp-signed key ID, got: %s", commit.SignatureKeyID)
	}
}

func TestEvaluateSignaturePolicy(t *testing.T) {
	commitSigned := &CommitInfo{
		Author:          "Alice Dev",
		Email:           "alice@example.com",
		Signature:       "-----BEGIN PGP SIGNATURE-----\n...-----END PGP SIGNATURE-----",
		SignatureKeyID:  "pgp-signed",
		SignatureStatus: SigStatusValid,
	}

	commitUnsigned := &CommitInfo{
		Author:          "Bob Dev",
		Email:           "bob@example.com",
		SignatureStatus: SigStatusUnsigned,
	}

	// 1. PolicyDisabled
	status, err := EvaluateSignaturePolicy(commitUnsigned, nil, PolicyDisabled)
	if err != nil || status != SigStatusValid {
		t.Errorf("expected valid status under PolicyDisabled, got %s / %v", status, err)
	}

	// 2. PolicyWarn with unsigned
	status, err = EvaluateSignaturePolicy(commitUnsigned, nil, PolicyWarn)
	if err != nil || status != SigStatusUnsigned {
		t.Errorf("expected unsigned status under PolicyWarn, got %s / %v", status, err)
	}

	// 3. PolicyStrict with unsigned
	status, err = EvaluateSignaturePolicy(commitUnsigned, nil, PolicyStrict)
	if err == nil || status != SigStatusInvalid {
		t.Errorf("expected rejection under PolicyStrict for unsigned commit")
	}

	// 4. PolicyStrict with signed and matching signer
	signers := []string{"alice@example.com"}
	status, err = EvaluateSignaturePolicy(commitSigned, signers, PolicyStrict)
	if err != nil || status != SigStatusValid {
		t.Errorf("expected valid status for authorized signer, got %s / %v", status, err)
	}

	// 5. PolicyStrict with signed but unauthorized signer
	unauthorizedSigners := []string{"charlie@example.com"}
	status, err = EvaluateSignaturePolicy(commitSigned, unauthorizedSigners, PolicyStrict)
	if err == nil || status != SigStatusUntrusted {
		t.Errorf("expected untrusted rejection for unauthorized signer")
	}
}
