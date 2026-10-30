package raft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrPeerUnreachable = errors.New("remote raft peer unreachable")
	ErrRPCFailed       = errors.New("raft rpc execution failed")
)

// HTTPTransport coordinates inter-node Raft consensus RPCs over HTTP/REST.
type HTTPTransport struct {
	client  *http.Client
	timeout time.Duration
	token   string
}

// NewHTTPTransport instantiates a production HTTP consensus transport with timeouts.
func NewHTTPTransport(timeout time.Duration, token string) *HTTPTransport {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	return &HTTPTransport{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
		token:   token,
	}
}

// BuildPeerURL sanitizes and builds the target endpoint URL for peer communication.
func BuildPeerURL(peerAddr, endpoint string) (string, error) {
	peerAddr = strings.TrimSpace(peerAddr)
	if peerAddr == "" {
		return "", errors.New("empty peer address")
	}
	if !strings.HasPrefix(peerAddr, "http://") && !strings.HasPrefix(peerAddr, "https://") {
		peerAddr = "http://" + peerAddr
	}

	u, err := url.Parse(peerAddr)
	if err != nil {
		return "", fmt.Errorf("malformed peer address %q: %w", peerAddr, err)
	}

	endpoint = "/" + strings.TrimPrefix(endpoint, "/")
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, endpoint), nil
}

// RequestVote sends a candidate vote solicitation to a peer node.
func (t *HTTPTransport) RequestVote(ctx context.Context, peerAddr string, args RequestVoteArgs) (*RequestVoteReply, error) {
	endpoint, err := BuildPeerURL(peerAddr, "/api/raft/rpc/vote")
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RequestVoteArgs: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to construct RequestVote request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrPeerUnreachable, peerAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: peer %s returned status %d: %s", ErrRPCFailed, peerAddr, resp.StatusCode, string(body))
	}

	var reply RequestVoteReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, fmt.Errorf("failed to decode RequestVoteReply from %s: %w", peerAddr, err)
	}
	return &reply, nil
}

// AppendEntries replicates log entries or transmits heartbeats to a follower node.
func (t *HTTPTransport) AppendEntries(ctx context.Context, peerAddr string, args AppendEntriesArgs) (*AppendEntriesReply, error) {
	endpoint, err := BuildPeerURL(peerAddr, "/api/raft/rpc/append")
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AppendEntriesArgs: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to construct AppendEntries request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrPeerUnreachable, peerAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: peer %s returned status %d: %s", ErrRPCFailed, peerAddr, resp.StatusCode, string(body))
	}

	var reply AppendEntriesReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, fmt.Errorf("failed to decode AppendEntriesReply from %s: %w", peerAddr, err)
	}
	return &reply, nil
}
