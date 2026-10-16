package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3Client executes object storage operations against S3-compatible backends (AWS S3, MinIO, Cloudflare R2).
type S3Client struct {
	cfg        S3Config
	httpClient *http.Client
}

// NewS3Client constructs an S3Client with default HTTP timeout.
func NewS3Client(cfg S3Config) *S3Client {
	return &S3Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Config returns the active S3 configuration.
func (c *S3Client) Config() S3Config {
	return c.cfg
}

// BuildObjectKey combines the configured prefix with the chunk key.
func (c *S3Client) BuildObjectKey(key string) string {
	prefix := strings.Trim(c.cfg.Prefix, "/")
	cleanKey := strings.TrimPrefix(key, "/")
	if prefix == "" {
		return cleanKey
	}
	return prefix + "/" + cleanKey
}

// buildURL generates the target endpoint URL respecting path-style vs virtual-host routing.
func (c *S3Client) buildURL(key string) (*url.URL, error) {
	rawEndpoint := strings.TrimSpace(c.cfg.Endpoint)
	if rawEndpoint == "" {
		rawEndpoint = "s3.us-east-1.amazonaws.com"
	}

	if !strings.HasPrefix(rawEndpoint, "http://") && !strings.HasPrefix(rawEndpoint, "https://") {
		if strings.HasPrefix(rawEndpoint, "localhost") || strings.HasPrefix(rawEndpoint, "127.0.0.1") {
			rawEndpoint = "http://" + rawEndpoint
		} else {
			rawEndpoint = "https://" + rawEndpoint
		}
	}

	parsedEndpoint, err := url.Parse(rawEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid s3 endpoint URL: %w", err)
	}

	bucket := strings.TrimSpace(c.cfg.Bucket)
	if bucket == "" {
		return nil, fmt.Errorf("s3 bucket cannot be empty")
	}

	// ForcePathStyle is true by default or for localhost/IPs/custom ports
	usePathStyle := c.cfg.ForcePathStyle ||
		strings.Contains(parsedEndpoint.Host, "localhost") ||
		strings.Contains(parsedEndpoint.Host, "127.0.0.1") ||
		strings.Contains(parsedEndpoint.Host, ":")

	var targetURL *url.URL
	if usePathStyle {
		targetURL = parsedEndpoint
		pathPrefix := strings.TrimSuffix(parsedEndpoint.Path, "/")
		if key == "" {
			targetURL.Path = pathPrefix + "/" + bucket
		} else {
			targetURL.Path = pathPrefix + "/" + bucket + "/" + strings.TrimPrefix(key, "/")
		}
	} else {
		// Virtual-host style: https://<bucket>.<endpoint-host>/<key>
		targetURL = parsedEndpoint
		targetURL.Host = fmt.Sprintf("%s.%s", bucket, parsedEndpoint.Host)
		if key == "" {
			targetURL.Path = "/"
		} else {
			targetURL.Path = "/" + strings.TrimPrefix(key, "/")
		}
	}

	return targetURL, nil
}

// PutObject uploads an object to the S3 bucket with SigV4 authentication.
func (c *S3Client) PutObject(ctx context.Context, key string, data []byte, contentType, storageClass string) error {
	fullKey := c.BuildObjectKey(key)
	targetURL, err := c.buildURL(fullKey)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL.String(), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	if contentType == "" {
		contentType = "application/gzip"
	}
	req.Header.Set("Content-Type", contentType)

	if storageClass == "" {
		storageClass = c.cfg.StorageClass
	}
	if storageClass != "" {
		req.Header.Set("x-amz-storage-class", storageClass)
	}

	region := c.cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	if err := SignRequest(req, data, c.cfg.AccessKey, c.cfg.SecretKey, region, time.Now().UTC()); err != nil {
		return fmt.Errorf("failed to sign S3 PUT request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3 PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 PUT failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// HeadBucket tests S3 connectivity and bucket accessibility.
func (c *S3Client) HeadBucket(ctx context.Context) error {
	targetURL, err := c.buildURL("")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create HEAD request: %w", err)
	}

	region := c.cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	if err := SignRequest(req, nil, c.cfg.AccessKey, c.cfg.SecretKey, region, time.Now().UTC()); err != nil {
		return fmt.Errorf("failed to sign S3 HEAD request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3 HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("s3 HEAD bucket failed with status %d", resp.StatusCode)
	}

	return nil
}

// DeleteObject deletes an object from the S3 bucket.
func (c *S3Client) DeleteObject(ctx context.Context, key string) error {
	fullKey := c.BuildObjectKey(key)
	targetURL, err := c.buildURL(fullKey)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, targetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request: %w", err)
	}

	region := c.cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	if err := SignRequest(req, nil, c.cfg.AccessKey, c.cfg.SecretKey, region, time.Now().UTC()); err != nil {
		return fmt.Errorf("failed to sign S3 DELETE request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3 DELETE request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 DELETE failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
