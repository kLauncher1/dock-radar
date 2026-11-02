package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestACMEClient_MockDirectoryFlow(t *testing.T) {
	accKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey failed: %v", err)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-mock-nonce-12345")

		switch r.URL.Path {
		case "/directory":
			dir := DirectoryEndpoints{
				NewNonce:   srv.URL + "/new-nonce",
				NewAccount: srv.URL + "/new-account",
				NewOrder:   srv.URL + "/new-order",
				RevokeCert: srv.URL + "/revoke-cert",
			}
			_ = json.NewEncoder(w).Encode(dir)

		case "/new-nonce":
			w.WriteHeader(http.StatusOK)

		case "/new-account":
			w.Header().Set("Location", srv.URL+"/account/101")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case "/new-order":
			w.Header().Set("Location", srv.URL+"/order/500")
			w.WriteHeader(http.StatusCreated)
			order := OrderResponse{
				Status:         "pending",
				Authorizations: []string{srv.URL + "/auth/600"},
				Finalize:       srv.URL + "/finalize/500",
			}
			_ = json.NewEncoder(w).Encode(order)

		case "/auth/600":
			w.WriteHeader(http.StatusOK)
			auth := AuthorizationResponse{
				Status: "pending",
				Challenges: []Challenge{
					{
						Type:   ChallengeHTTP01,
						URL:    srv.URL + "/challenge/700",
						Token:  "test-token-700",
						Status: "pending",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(auth)

		case "/challenge/700":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case "/finalize/500":
			w.WriteHeader(http.StatusOK)
			order := OrderResponse{
				Status:      "valid",
				Certificate: srv.URL + "/cert/800",
			}
			_ = json.NewEncoder(w).Encode(order)

		case "/cert/800":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := NewClient(srv.URL+"/directory", accKey)

	// 1. Fetch directory
	dir, err := client.FetchDirectory(ctx)
	if err != nil {
		t.Fatalf("FetchDirectory failed: %v", err)
	}
	if dir.NewAccount == "" {
		t.Fatalf("expected NewAccount URL")
	}

	// 2. Register Account
	kid, err := client.RegisterAccount(ctx, "admin@example.com", true)
	if err != nil {
		t.Fatalf("RegisterAccount failed: %v", err)
	}
	if kid != srv.URL+"/account/101" {
		t.Fatalf("unexpected kid: %s", kid)
	}

	// 3. Create Order
	order, err := client.CreateOrder(ctx, []string{"radar.example.com"})
	if err != nil {
		t.Fatalf("CreateOrder failed: %v", err)
	}
	if len(order.Authorizations) == 0 {
		t.Fatalf("expected authorizations in order")
	}

	// 4. Get Authorization
	auth, err := client.GetAuthorization(ctx, order.Authorizations[0])
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}
	if len(auth.Challenges) == 0 {
		t.Fatalf("expected challenges in auth")
	}

	// 5. Trigger Challenge
	if err := client.TriggerChallenge(ctx, auth.Challenges[0].URL); err != nil {
		t.Fatalf("TriggerChallenge failed: %v", err)
	}

	// 6. Finalize Order
	mockCSR := []byte("mock-csr-der-bytes")
	finalized, err := client.FinalizeOrder(ctx, order.Finalize, mockCSR)
	if err != nil {
		t.Fatalf("FinalizeOrder failed: %v", err)
	}
	if finalized.Certificate == "" {
		t.Fatalf("expected certificate url in finalized order")
	}

	// 7. Download Certificate
	certPEM, err := client.DownloadCertificate(ctx, finalized.Certificate)
	if err != nil {
		t.Fatalf("DownloadCertificate failed: %v", err)
	}
	if string(certPEM) == "" {
		t.Fatalf("expected cert PEM")
	}
}

func TestACMEClient_BadNonceRetry(t *testing.T) {
	accKey, _ := GenerateAccountKey()
	attempts := 0

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", attempts))

		if r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(DirectoryEndpoints{
				NewNonce:   srv.URL + "/new-nonce",
				NewAccount: srv.URL + "/new-account",
			})
			return
		}

		if r.URL.Path == "/new-nonce" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if attempts == 2 {
			// First post: simulate badNonce
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce","detail":"Replay nonce is invalid"}`))
			return
		}

		w.Header().Set("Location", "/account/success")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL+"/directory", accKey)
	ctx := context.Background()

	kid, err := client.RegisterAccount(ctx, "test@test.com", true)
	if err != nil {
		t.Fatalf("expected success with nonce retry, got: %v", err)
	}
	if kid != "/account/success" {
		t.Fatalf("unexpected kid: %s", kid)
	}
}
