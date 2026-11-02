package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DirectoryEndpoints holds discovered RFC 8555 directory URLs.
type DirectoryEndpoints struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// OrderResponse represents an ACME order resource.
type OrderResponse struct {
	Status         string   `json:"status"`
	Expires        string   `json:"expires"`
	Identifiers    []any    `json:"identifiers"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	OrderURL       string   `json:"-"`
}

// Challenge represents an authorization challenge object.
type Challenge struct {
	Type   ChallengeType `json:"type"`
	URL    string        `json:"url"`
	Token  string        `json:"token"`
	Status string        `json:"status"`
	Error  any           `json:"error,omitempty"`
}

// AuthorizationResponse represents an ACME authorization object.
type AuthorizationResponse struct {
	Status     string      `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
}

// Client executes RFC 8555 ACME protocol operations.
type Client struct {
	httpClient   *http.Client
	directoryURL string
	accountKey   *ecdsa.PrivateKey
	accountKID   string
	directory    *DirectoryEndpoints
	nonceMu      sync.Mutex
	cachedNonce  string
}

// NewClient creates an ACME protocol client.
func NewClient(directoryURL string, accountKey *ecdsa.PrivateKey) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 25 * time.Second,
		},
		directoryURL: directoryURL,
		accountKey:   accountKey,
	}
}

// SetAccountKID assigns the registered account URL (KID).
func (c *Client) SetAccountKID(kid string) {
	c.accountKID = kid
}

// AccountKID returns the current account identifier.
func (c *Client) AccountKID() string {
	return c.accountKID
}

// FetchDirectory retrieves the ACME directory endpoints.
func (c *Client) FetchDirectory(ctx context.Context) (*DirectoryEndpoints, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dock-radar-acme/3.2.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch acme directory (%s): %w", c.directoryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("directory fetch error HTTP %d: %s", resp.StatusCode, string(body))
	}

	var dir DirectoryEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("failed to decode directory json: %w", err)
	}

	c.directory = &dir
	return &dir, nil
}

// GetNonce acquires a fresh replay nonce from the ACME server.
func (c *Client) GetNonce(ctx context.Context) (string, error) {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()

	if c.cachedNonce != "" {
		n := c.cachedNonce
		c.cachedNonce = ""
		return n, nil
	}

	if c.directory == nil || c.directory.NewNonce == "" {
		if _, err := c.FetchDirectory(ctx); err != nil {
			return "", err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.directory.NewNonce, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "dock-radar-acme/3.2.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve replay nonce: %w", err)
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("acme server did not provide Replay-Nonce header")
	}
	return nonce, nil
}

// postJWS sends a signed JWS request to an ACME endpoint with auto-nonce retry.
func (c *Client) postJWS(ctx context.Context, endpointURL string, payload []byte, useKID bool) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt < 3; attempt++ {
		nonce, nErr := c.GetNonce(ctx)
		if nErr != nil {
			return nil, nErr
		}

		kid := ""
		if useKID {
			kid = c.accountKID
		}

		jwsBytes, signErr := SignJWS(c.accountKey, kid, nonce, endpointURL, payload)
		if signErr != nil {
			return nil, signErr
		}

		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(jwsBytes))
		if rErr != nil {
			return nil, rErr
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "dock-radar-acme/3.2.0")

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		// Store any returned nonce for subsequent request
		if nextNonce := resp.Header.Get("Replay-Nonce"); nextNonce != "" {
			c.nonceMu.Lock()
			c.cachedNonce = nextNonce
			c.nonceMu.Unlock()
		}

		// If badNonce error, retry
		if resp.StatusCode == http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "badNonce") {
				continue
			}
			return nil, fmt.Errorf("acme POST error HTTP %d: %s", resp.StatusCode, string(body))
		}

		return resp, nil
	}

	return resp, err
}

// RegisterAccount registers an ACME account or retrieves existing account KID.
func (c *Client) RegisterAccount(ctx context.Context, email string, termsAgreed bool) (string, error) {
	if c.directory == nil {
		if _, err := c.FetchDirectory(ctx); err != nil {
			return "", err
		}
	}

	payloadMap := map[string]any{
		"termsOfServiceAgreed": termsAgreed,
	}
	if email != "" {
		payloadMap["contact"] = []string{fmt.Sprintf("mailto:%s", email)}
	}

	payloadJSON, _ := json.Marshal(payloadMap)
	resp, err := c.postJWS(ctx, c.directory.NewAccount, payloadJSON, false)
	if err != nil {
		return "", fmt.Errorf("account registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("account creation error HTTP %d: %s", resp.StatusCode, string(body))
	}

	kid := resp.Header.Get("Location")
	if kid == "" {
		// Fallback to existing account header or parse
		kid = c.directory.NewAccount
	}

	c.accountKID = kid
	return kid, nil
}

// CreateOrder initiates a new certificate order for the specified DNS identifiers.
func (c *Client) CreateOrder(ctx context.Context, domains []string) (*OrderResponse, error) {
	if c.directory == nil {
		if _, err := c.FetchDirectory(ctx); err != nil {
			return nil, err
		}
	}

	var identifiers []map[string]string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d != "" {
			identifiers = append(identifiers, map[string]string{
				"type":  "dns",
				"value": d,
			})
		}
	}

	payloadJSON, _ := json.Marshal(map[string]any{
		"identifiers": identifiers,
	})

	resp, err := c.postJWS(ctx, c.directory.NewOrder, payloadJSON, true)
	if err != nil {
		return nil, fmt.Errorf("create order failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("order creation HTTP %d: %s", resp.StatusCode, string(body))
	}

	var order OrderResponse
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, fmt.Errorf("failed to decode order response: %w", err)
	}
	order.OrderURL = resp.Header.Get("Location")

	return &order, nil
}

// GetAuthorization inspects an authorization resource URL.
func (c *Client) GetAuthorization(ctx context.Context, authURL string) (*AuthorizationResponse, error) {
	resp, err := c.postJWS(ctx, authURL, nil, true)
	if err != nil {
		return nil, fmt.Errorf("get authorization failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get authorization HTTP %d: %s", resp.StatusCode, string(body))
	}

	var auth AuthorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("failed to decode authorization json: %w", err)
	}
	return &auth, nil
}

// TriggerChallenge informs the ACME server that a challenge is satisfied.
func (c *Client) TriggerChallenge(ctx context.Context, challengeURL string) error {
	resp, err := c.postJWS(ctx, challengeURL, []byte("{}"), true)
	if err != nil {
		return fmt.Errorf("trigger challenge failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("trigger challenge HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// FinalizeOrder submits the CSR to finalize an ACME order.
func (c *Client) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) (*OrderResponse, error) {
	payloadJSON, _ := json.Marshal(map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	})

	resp, err := c.postJWS(ctx, finalizeURL, payloadJSON, true)
	if err != nil {
		return nil, fmt.Errorf("finalize order failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("finalize order HTTP %d: %s", resp.StatusCode, string(body))
	}

	var order OrderResponse
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, fmt.Errorf("failed to decode finalized order response: %w", err)
	}
	return &order, nil
}

// DownloadCertificate fetches the signed X.509 certificate chain PEM bytes.
func (c *Client) DownloadCertificate(ctx context.Context, certURL string) ([]byte, error) {
	resp, err := c.postJWS(ctx, certURL, nil, true)
	if err != nil {
		return nil, fmt.Errorf("download certificate failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download cert HTTP %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}
