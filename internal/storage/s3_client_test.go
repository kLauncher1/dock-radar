package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestS3Client_Operations(t *testing.T) {
	var receivedMethod string
	var receivedPath string
	var receivedAuth string
	var receivedPayload []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")
		receivedPayload, _ = io.ReadAll(r.Body)

		if strings.Contains(r.URL.Path, "forbidden") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("AccessDenied"))
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := S3Config{
		Endpoint:       server.URL,
		Region:         "us-east-1",
		Bucket:         "test-bucket",
		Prefix:         "radar-logs",
		AccessKey:      "TESTKEY",
		SecretKey:      "TESTSECRET",
		ForcePathStyle: true,
	}

	client := NewS3Client(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. HeadBucket
	err := client.HeadBucket(ctx)
	if err != nil {
		t.Fatalf("HeadBucket failed: %v", err)
	}
	if receivedMethod != http.MethodHead {
		t.Fatalf("expected HEAD, got %s", receivedMethod)
	}
	if receivedPath != "/test-bucket" {
		t.Fatalf("expected /test-bucket, got %s", receivedPath)
	}
	if !strings.HasPrefix(receivedAuth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("expected Authorization header to start with AWS4-HMAC-SHA256")
	}

	// 2. PutObject
	testData := []byte("hello-compressed-chunk")
	err = client.PutObject(ctx, "chunk-100.gz", testData, "application/gzip", "STANDARD")
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if receivedMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", receivedMethod)
	}
	if receivedPath != "/test-bucket/radar-logs/chunk-100.gz" {
		t.Fatalf("expected path /test-bucket/radar-logs/chunk-100.gz, got %s", receivedPath)
	}
	if string(receivedPayload) != string(testData) {
		t.Fatalf("payload mismatch")
	}

	// 3. DeleteObject
	err = client.DeleteObject(ctx, "chunk-100.gz")
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if receivedMethod != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", receivedMethod)
	}

	// 4. Error response
	err = client.PutObject(ctx, "forbidden/chunk.gz", testData, "", "")
	if err == nil {
		t.Fatalf("expected error on 403 response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected status 403 in error message: %v", err)
	}
}

func TestS3Client_BuildURL_Routing(t *testing.T) {
	// Virtual-host style
	cfgVH := S3Config{
		Endpoint:       "https://s3.amazonaws.com",
		Bucket:         "my-bucket",
		ForcePathStyle: false,
	}
	clientVH := NewS3Client(cfgVH)
	u, err := clientVH.buildURL("test.gz")
	if err != nil {
		t.Fatalf("buildURL error: %v", err)
	}
	if u.Host != "my-bucket.s3.amazonaws.com" || u.Path != "/test.gz" {
		t.Fatalf("unexpected virtual-host URL: %s", u.String())
	}

	// Path style
	cfgPath := S3Config{
		Endpoint:       "http://localhost:9000",
		Bucket:         "my-bucket",
		ForcePathStyle: true,
	}
	clientPath := NewS3Client(cfgPath)
	u2, err := clientPath.buildURL("test.gz")
	if err != nil {
		t.Fatalf("buildURL error: %v", err)
	}
	if u2.Host != "localhost:9000" || u2.Path != "/my-bucket/test.gz" {
		t.Fatalf("unexpected path-style URL: %s", u2.String())
	}
}
