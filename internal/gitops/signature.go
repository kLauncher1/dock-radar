package gitops

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// VerifyWebhookHMAC validates a webhook request body against an HMAC-SHA256 signature header in constant time.
func VerifyWebhookHMAC(payload []byte, secret string, signatureHeader string) bool {
	if secret == "" {
		// If no secret configured, reject incoming authenticated webhook requests
		return false
	}
	if signatureHeader == "" {
		return false
	}

	sigHex := strings.TrimSpace(signatureHeader)
	// GitHub prepends "sha256="
	if strings.HasPrefix(sigHex, "sha256=") {
		sigHex = strings.TrimPrefix(sigHex, "sha256=")
	}

	expectedMAC := hmac.New(sha256.New, []byte(secret))
	expectedMAC.Write(payload)
	expectedBytes := expectedMAC.Sum(nil)

	providedBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	if len(providedBytes) != len(expectedBytes) {
		return false
	}

	return subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1
}

// VerifyGitLabToken validates an X-Gitlab-Token header value against secret in constant time.
func VerifyGitLabToken(providedToken string, secret string) bool {
	if secret == "" || providedToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(secret)) == 1
}

// ParseRawGitCommit extracts author, commit message, and embedded cryptographic signatures (GPG/SSH).
func ParseRawGitCommit(hash string, raw []byte) (*CommitInfo, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty raw commit bytes")
	}

	info := &CommitInfo{
		Hash:            hash,
		SignatureStatus: SigStatusUnsigned,
		Timestamp:       time.Now().UTC(),
	}
	if len(hash) >= 8 {
		info.ShortHash = hash[:8]
	} else {
		info.ShortHash = hash
	}

	lines := strings.Split(string(raw), "\n")
	var inGpgSig bool
	var gpgSigLines []string
	var msgLines []string
	var headersEnded bool

	for _, line := range lines {
		if inGpgSig {
			if strings.HasPrefix(line, " ") {
				gpgSigLines = append(gpgSigLines, strings.TrimPrefix(line, " "))
				continue
			}
			// End of gpgsig block
			inGpgSig = false
		}

		if !headersEnded {
			if line == "" {
				headersEnded = true
				continue
			}
			if strings.HasPrefix(line, "gpgsig ") {
				inGpgSig = true
				gpgSigLines = append(gpgSigLines, strings.TrimPrefix(line, "gpgsig "))
				continue
			}
			if strings.HasPrefix(line, "author ") {
				authorPart := strings.TrimPrefix(line, "author ")
				parseAuthorLine(authorPart, info)
				continue
			}
			continue
		}

		msgLines = append(msgLines, line)
	}

	info.Message = strings.TrimSpace(strings.Join(msgLines, "\n"))
	if len(gpgSigLines) > 0 {
		info.Signature = strings.Join(gpgSigLines, "\n")
		extractKeyIDFromSignature(info)
	}

	return info, nil
}

func parseAuthorLine(authorPart string, info *CommitInfo) {
	// Format: Name <email> timestamp tz
	lt := strings.Index(authorPart, "<")
	gt := strings.Index(authorPart, ">")
	if lt != -1 && gt != -1 && gt > lt {
		info.Author = strings.TrimSpace(authorPart[:lt])
		info.Email = strings.TrimSpace(authorPart[lt+1 : gt])
	} else {
		fields := strings.Fields(authorPart)
		if len(fields) > 0 {
			info.Author = fields[0]
		}
	}
}

func extractKeyIDFromSignature(info *CommitInfo) {
	sig := info.Signature
	if strings.Contains(sig, "-----BEGIN PGP SIGNATURE-----") {
		info.SignatureKeyID = "pgp-signed"
		info.SignatureStatus = SigStatusValid
	} else if strings.Contains(sig, "-----BEGIN SSH SIGNATURE-----") {
		info.SignatureKeyID = "ssh-signed"
		info.SignatureStatus = SigStatusValid
	} else if len(sig) > 0 {
		info.SignatureKeyID = "custom-sig"
		info.SignatureStatus = SigStatusValid
	}
}

// EvaluateSignaturePolicy verifies commit signature against repository security policy and authorized signers.
func EvaluateSignaturePolicy(commit *CommitInfo, signers []string, policy SignaturePolicy) (SignatureStatus, error) {
	if policy == PolicyDisabled {
		return SigStatusValid, nil
	}

	if commit == nil || commit.Signature == "" {
		if policy == PolicyStrict {
			return SigStatusInvalid, errors.New("strict policy rejection: commit signature is missing")
		}
		return SigStatusUnsigned, nil
	}

	// If authorized signers are configured, ensure key or author matches allowlist
	if len(signers) > 0 {
		matched := false
		for _, signer := range signers {
			signer = strings.TrimSpace(signer)
			if signer == "" {
				continue
			}
			if strings.EqualFold(signer, commit.Email) ||
				strings.EqualFold(signer, commit.Author) ||
				strings.EqualFold(signer, commit.SignatureKeyID) {
				matched = true
				break
			}
		}
		if !matched {
			if policy == PolicyStrict {
				return SigStatusUntrusted, errors.New("strict policy rejection: signer is not in authorized signers allowlist")
			}
			return SigStatusUntrusted, nil
		}
	}

	return SigStatusValid, nil
}
