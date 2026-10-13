package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LogMessage encapsulates a parsed container log frame.
type LogMessage struct {
	ContainerID string    `json:"id"`
	Stream      string    `json:"stream"` // "stdout", "stderr", or "system"
	Timestamp   time.Time `json:"timestamp"`
	Message     string    `json:"message"`
}

// FetchLogs retrieves the most recent log entries for a container without blocking.
func (c *Client) FetchLogs(ctx context.Context, id string, tail int) ([]LogMessage, error) {
	if err := ValidateContainerID(id); err != nil {
		return nil, err
	}
	if tail <= 0 {
		tail = 50
	}
	if tail > 1000 {
		tail = 1000
	}

	reqURL := fmt.Sprintf("%s/v1.43/containers/%s/logs?stdout=1&stderr=1&tail=%d&timestamps=1", c.BaseURL(), id, tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create logs request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrContainerNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("docker engine returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	outChan := make(chan LogMessage, tail+10)
	errChan := make(chan error, 1)

	go func() {
		defer close(outChan)
		errChan <- ParseDockerLogStream(resp.Body, id, outChan)
	}()

	var entries []LogMessage
	for msg := range outChan {
		entries = append(entries, msg)
	}

	if streamErr := <-errChan; streamErr != nil && streamErr != io.EOF {
		return entries, streamErr
	}

	return entries, nil
}

// StreamLogs continuously streams logs from the Docker daemon until context cancellation.
func (c *Client) StreamLogs(ctx context.Context, id string, tail int, out chan<- LogMessage) error {
	if err := ValidateContainerID(id); err != nil {
		return err
	}
	if tail <= 0 {
		tail = 50
	}

	reqURL := fmt.Sprintf("%s/v1.43/containers/%s/logs?stdout=1&stderr=1&follow=1&tail=%d&timestamps=1", c.BaseURL(), id, tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create log stream request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrContainerNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return ParseDockerLogStream(resp.Body, id, out)
}

// ParseDockerLogStream decodes either multiplexed Docker 8-byte frames or raw TTY streams.
func ParseDockerLogStream(r io.Reader, containerID string, out chan<- LogMessage) error {
	reader := bufio.NewReader(r)

	for {
		header, err := reader.Peek(8)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Docker multiplexed header: byte 0 is stream type (1=stdout, 2=stderr), bytes 1-3 are zero.
		if (header[0] == 1 || header[0] == 2) && header[1] == 0 && header[2] == 0 && header[3] == 0 {
			// Discard the 8-byte header from reader
			if _, err := reader.Discard(8); err != nil {
				return err
			}

			streamType := "stdout"
			if header[0] == 2 {
				streamType = "stderr"
			}

			frameSize := binary.BigEndian.Uint32(header[4:8])
			// Cap single frame read to 64KB for defense-in-depth against malicious frames
			if frameSize > 65536 {
				frameSize = 65536
			}

			payload := make([]byte, frameSize)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return err
			}

			line := string(payload)
			for _, sub := range strings.Split(line, "\n") {
				sub = strings.TrimRight(sub, "\r")
				if sub == "" {
					continue
				}
				ts, cleanMsg := extractTimestamp(sub)
				out <- LogMessage{
					ContainerID: containerID,
					Stream:      streamType,
					Timestamp:   ts,
					Message:     cleanMsg,
				}
			}
		} else {
			// Raw TTY or unmultiplexed text line
			line, err := reader.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				ts, cleanMsg := extractTimestamp(line)
				out <- LogMessage{
					ContainerID: containerID,
					Stream:      "stdout",
					Timestamp:   ts,
					Message:     cleanMsg,
				}
			}
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
}

// extractTimestamp attempts to extract an RFC3339/ISO8601 timestamp prefix.
func extractTimestamp(raw string) (time.Time, string) {
	if len(raw) > 30 && (raw[4] == '-' && raw[7] == '-' && (raw[10] == 'T' || raw[10] == ' ')) {
		fields := strings.SplitN(raw, " ", 2)
		if len(fields) == 2 {
			if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
				return t, fields[1]
			}
		}
	}
	return time.Now().UTC(), raw
}
