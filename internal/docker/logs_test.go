package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func buildMultiplexedFrame(streamType byte, message string) []byte {
	var buf bytes.Buffer
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:8], uint32(len(message)))
	buf.Write(header)
	buf.WriteString(message)
	return buf.Bytes()
}

func TestParseDockerLogStream_Multiplexed(t *testing.T) {
	var streamData bytes.Buffer
	ts1 := "2026-10-14T05:00:00.000000000Z"
	ts2 := "2026-10-14T05:00:01.000000000Z"

	streamData.Write(buildMultiplexedFrame(1, ts1+" application started successfully\n"))
	streamData.Write(buildMultiplexedFrame(2, ts2+" warning: database connection slow\n"))

	outChan := make(chan LogMessage, 10)
	err := ParseDockerLogStream(&streamData, "test-container-1", outChan)
	if err != nil {
		t.Fatalf("unexpected error parsing stream: %v", err)
	}
	close(outChan)

	var messages []LogMessage
	for msg := range outChan {
		messages = append(messages, msg)
	}

	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}

	if messages[0].Stream != "stdout" || messages[0].Message != "application started successfully" {
		t.Errorf("expected stdout message, got %+v", messages[0])
	}
	if messages[1].Stream != "stderr" || messages[1].Message != "warning: database connection slow" {
		t.Errorf("expected stderr message, got %+v", messages[1])
	}
}

func TestParseDockerLogStream_RawTTY(t *testing.T) {
	raw := "2026-10-14T05:00:00.000000000Z standard output line without docker header\nanother line\n"
	r := bytes.NewReader([]byte(raw))

	outChan := make(chan LogMessage, 10)
	err := ParseDockerLogStream(r, "tty-container", outChan)
	if err != nil {
		t.Fatalf("unexpected error parsing TTY stream: %v", err)
	}
	close(outChan)

	var messages []LogMessage
	for msg := range outChan {
		messages = append(messages, msg)
	}

	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
	if messages[0].Stream != "stdout" {
		t.Errorf("expected default stdout stream for TTY, got %s", messages[0].Stream)
	}
}

func TestFetchLogs_MockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/web-service/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stdout") != "1" || r.URL.Query().Get("stderr") != "1" {
			t.Errorf("expected stdout=1 and stderr=1 query params")
		}
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		_, _ = w.Write(buildMultiplexedFrame(1, "2026-10-14T05:01:00.000000000Z web service ready on :8080\n"))
	})
	mux.HandleFunc("/v1.43/containers/missing-svc/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Successful log fetch
	logs, err := client.FetchLogs(ctx, "web-service", 50)
	if err != nil {
		t.Fatalf("expected successful logs fetch, got: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logs))
	}
	if logs[0].Message != "web service ready on :8080" {
		t.Errorf("unexpected log message: %s", logs[0].Message)
	}

	// 2. Container not found
	_, err = client.FetchLogs(ctx, "missing-svc", 50)
	if err == nil {
		t.Fatalf("expected error for missing-svc, got nil")
	}

	// 3. Invalid container ID
	_, err = client.FetchLogs(ctx, "../bad-path", 50)
	if err == nil {
		t.Fatalf("expected error for invalid ID, got nil")
	}
}
