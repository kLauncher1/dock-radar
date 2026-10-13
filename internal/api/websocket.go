package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	wsGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	opText          = 0x1
	opClose         = 0x8
	opPing          = 0x9
	opPong          = 0xA
	maxFramePayload = 1024 * 1024 // 1 MB payload protection
)

var (
	// ErrNotWebSocketUpgrade indicates standard HTTP request without WebSocket upgrade headers.
	ErrNotWebSocketUpgrade = errors.New("request does not contain valid websocket upgrade headers")
	// ErrConnectionClosed indicates client closed the websocket session.
	ErrConnectionClosed = errors.New("websocket connection closed")
)

// ComputeSecWebSocketAccept calculates the RFC 6455 handshake response token.
func ComputeSecWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// WebSocketConn wraps a hijacked TCP connection for standard RFC 6455 framing.
type WebSocketConn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex
}

// UpgradeWebSocket upgrades an HTTP connection to RFC 6455 WebSocket.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WebSocketConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, ErrNotWebSocketUpgrade
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, ErrNotWebSocketUpgrade
	}

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("http.ResponseWriter does not support http.Hijacker")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("failed to hijack connection: %w", err)
	}

	accept := ComputeSecWebSocketAccept(key)
	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	)

	if _, err := rw.WriteString(response); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to write websocket handshake: %w", err)
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to flush websocket handshake: %w", err)
	}

	return &WebSocketConn{
		conn: conn,
		rw:   rw,
	}, nil
}

// WriteTextMessage sends a text frame (opcode 0x1) to the client.
func (ws *WebSocketConn) WriteTextMessage(payload []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	var header []byte
	length := len(payload)

	switch {
	case length <= 125:
		header = []byte{0x80 | opText, byte(length)}
	case length <= 65535:
		header = make([]byte, 4)
		header[0] = 0x80 | opText
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		header = make([]byte, 10)
		header[0] = 0x80 | opText
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
	}

	if _, err := ws.rw.Write(header); err != nil {
		return err
	}
	if _, err := ws.rw.Write(payload); err != nil {
		return err
	}
	return ws.rw.Flush()
}

// WritePong responds to client ping frames.
func (ws *WebSocketConn) WritePong(payload []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	header := []byte{0x80 | opPong, byte(len(payload))}
	if _, err := ws.rw.Write(header); err != nil {
		return err
	}
	if _, err := ws.rw.Write(payload); err != nil {
		return err
	}
	return ws.rw.Flush()
}

// ReadFrame decodes the next incoming frame from the client.
func (ws *WebSocketConn) ReadFrame() (byte, []byte, error) {
	firstTwo := make([]byte, 2)
	if _, err := io.ReadFull(ws.rw, firstTwo); err != nil {
		return 0, nil, err
	}

	opcode := firstTwo[0] & 0x0F
	masked := (firstTwo[1] & 0x80) != 0
	payloadLen := uint64(firstTwo[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(ws.rw, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(ws.rw, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	if payloadLen > maxFramePayload {
		return 0, nil, errors.New("frame payload exceeds maximum permitted size")
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(ws.rw, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.rw, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := uint64(0); i < payloadLen; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	if opcode == opClose {
		return opClose, payload, ErrConnectionClosed
	}

	if opcode == opPing {
		_ = ws.WritePong(payload)
	}

	return opcode, payload, nil
}

// Close terminates the hijacked underlying connection.
func (ws *WebSocketConn) Close() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.conn.Close()
}
