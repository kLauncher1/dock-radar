package storage

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSigV4_SignRequest(t *testing.T) {
	reqURL, err := url.Parse("https://s3.us-east-1.amazonaws.com/my-test-bucket/dock-radar/logs/chunk-123.gz?action=get&format=json")
	if err != nil {
		t.Fatalf("url parse error: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, reqURL.String(), nil)
	if err != nil {
		t.Fatalf("new request error: %v", err)
	}

	payload := []byte("compressed-log-chunk-payload-data")
	reqTime := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	accessKey := "AKIAEXAMPLEACCESSKEY"
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	region := "us-east-1"

	err = SignRequest(req, payload, accessKey, secretKey, region, reqTime)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatalf("Authorization header missing")
	}

	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("expected AWS4-HMAC-SHA256 algorithm prefix, got %s", auth)
	}

	if !strings.Contains(auth, "Credential="+accessKey+"/20261016/us-east-1/s3/aws4_request") {
		t.Fatalf("credential scope mismatch in auth header: %s", auth)
	}

	if !strings.Contains(auth, "SignedHeaders=") {
		t.Fatalf("SignedHeaders missing in auth header: %s", auth)
	}

	if !strings.Contains(auth, "Signature=") {
		t.Fatalf("Signature missing in auth header: %s", auth)
	}

	if req.Header.Get("x-amz-date") != "20261016T120000Z" {
		t.Fatalf("x-amz-date mismatch: %s", req.Header.Get("x-amz-date"))
	}

	if req.Header.Get("x-amz-content-sha256") == "" {
		t.Fatalf("x-amz-content-sha256 missing")
	}
}

func TestSigV4_DeriveSigningKey(t *testing.T) {
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	dateStamp := "20130524"
	region := "us-east-1"
	service := "s3"

	kSigning := deriveSigningKey(secretKey, dateStamp, region, service)
	if len(kSigning) != 32 { // SHA-256 output is 32 bytes
		t.Fatalf("expected 32-byte signing key, got %d", len(kSigning))
	}
}

func TestSigV4_BuildCanonicalQuery(t *testing.T) {
	q := url.Values{}
	q.Set("zeta", "val1")
	q.Set("alpha", "val2")
	q.Add("alpha", "val0")

	res := buildCanonicalQuery(q)
	expected := "alpha=val0&alpha=val2&zeta=val1"
	if res != expected {
		t.Fatalf("expected canonical query %q, got %q", expected, res)
	}
}
