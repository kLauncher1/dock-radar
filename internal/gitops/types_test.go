package gitops

import (
	"testing"
)

func TestValidateRepoConfig(t *testing.T) {
	valid := &GitRepoConfig{
		ID:              "web-service",
		Name:            "Production Web",
		RepoURL:         "https://github.com/example/web-app.git",
		Branch:          "main",
		TargetContainer: "web-app-container",
		TargetImage:     "registry.example.com/web-app:latest",
		SignaturePolicy: PolicyStrict,
		PollIntervalSec: 60,
	}

	if err := ValidateRepoConfig(valid); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	// Test nil
	if err := ValidateRepoConfig(nil); err == nil {
		t.Errorf("expected error for nil config")
	}

	// Test invalid ID
	invalidID := *valid
	invalidID.ID = "invalid/id with spaces"
	if err := ValidateRepoConfig(&invalidID); err == nil {
		t.Errorf("expected error for invalid ID")
	}

	// Test invalid URL
	invalidURL := *valid
	invalidURL.RepoURL = "ftp://invalid-scheme.com/repo"
	if err := ValidateRepoConfig(&invalidURL); err == nil {
		t.Errorf("expected error for invalid repo URL scheme")
	}

	// Test valid SSH URL
	sshConfig := *valid
	sshConfig.RepoURL = "git@github.com:example/web-app.git"
	if err := ValidateRepoConfig(&sshConfig); err != nil {
		t.Errorf("expected valid SSH URL, got: %v", err)
	}

	// Test missing target container
	missingContainer := *valid
	missingContainer.TargetContainer = ""
	if err := ValidateRepoConfig(&missingContainer); err == nil {
		t.Errorf("expected error for missing target container")
	}

	// Test invalid signature policy
	invalidPolicy := *valid
	invalidPolicy.SignaturePolicy = SignaturePolicy("unrecognized")
	if err := ValidateRepoConfig(&invalidPolicy); err == nil {
		t.Errorf("expected error for invalid signature policy")
	}
}

func TestMaskRepoSecret(t *testing.T) {
	repo := GitRepoConfig{
		ID:            "repo-1",
		WebhookSecret: "super-secret-token-12345",
	}

	masked := MaskRepoSecret(repo)
	if masked.WebhookSecret == repo.WebhookSecret {
		t.Errorf("expected secret to be masked")
	}
	if len(masked.WebhookSecret) < 4 || masked.WebhookSecret[2:6] != "****" {
		t.Errorf("unexpected masked format: %s", masked.WebhookSecret)
	}

	// Short secret
	repoShort := GitRepoConfig{
		ID:            "repo-2",
		WebhookSecret: "abc",
	}
	maskedShort := MaskRepoSecret(repoShort)
	if maskedShort.WebhookSecret != "****" {
		t.Errorf("expected short secret to be '****', got: %s", maskedShort.WebhookSecret)
	}
}

func TestIsValidCommitSHA(t *testing.T) {
	validSHA1 := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	if !IsValidCommitSHA(validSHA1) {
		t.Errorf("expected %s to be valid SHA1", validSHA1)
	}

	validSHA256 := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if !IsValidCommitSHA(validSHA256) {
		t.Errorf("expected %s to be valid SHA256", validSHA256)
	}

	invalidSHA := "not-a-hash"
	if IsValidCommitSHA(invalidSHA) {
		t.Errorf("expected %s to be invalid", invalidSHA)
	}
}
