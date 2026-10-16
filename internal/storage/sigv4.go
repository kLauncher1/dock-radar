package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	sigv4Algorithm = "AWS4-HMAC-SHA256"
	sigv4Service   = "s3"
	sigv4Request   = "aws4_request"
	iso8601Basic   = "20060102T150405Z"
	dateStampBasic = "20060102"
)

// SignRequest signs an HTTP request using AWS Signature Version 4 (SigV4) with HMAC-SHA256.
func SignRequest(req *http.Request, payload []byte, accessKey, secretKey, region string, reqTime time.Time) error {
	if reqTime.IsZero() {
		reqTime = time.Now().UTC()
	} else {
		reqTime = reqTime.UTC()
	}

	dateStamp := reqTime.Format(dateStampBasic)
	amzDate := reqTime.Format(iso8601Basic)

	// Set required AWS headers
	req.Header.Set("x-amz-date", amzDate)

	payloadHash := sha256.Sum256(payload)
	payloadHashHex := hex.EncodeToString(payloadHash[:])
	req.Header.Set("x-amz-content-sha256", payloadHashHex)

	// Determine host header
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.Header.Set("Host", host)

	canonicalReq, signedHeaders := buildCanonicalRequest(req, payloadHashHex)
	canonicalReqHash := sha256.Sum256([]byte(canonicalReq))
	canonicalReqHashHex := hex.EncodeToString(canonicalReqHash[:])

	credentialScope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, region, sigv4Service, sigv4Request)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		sigv4Algorithm,
		amzDate,
		credentialScope,
		canonicalReqHashHex,
	)

	signingKey := deriveSigningKey(secretKey, dateStamp, region, sigv4Service)
	signature := hmacHex(signingKey, []byte(stringToSign))

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigv4Algorithm,
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

// buildCanonicalRequest creates the canonical request string per AWS SigV4 specification.
func buildCanonicalRequest(req *http.Request, payloadHashHex string) (string, string) {
	// 1. Method
	method := req.Method

	// 2. Canonical URI
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalURI = uriEncodePath(canonicalURI)

	// 3. Canonical Query String
	canonicalQuery := buildCanonicalQuery(req.URL.Query())

	// 4. Canonical Headers and Signed Headers
	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req.Header)

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHashHex,
	)

	return canonicalRequest, signedHeaders
}

// buildCanonicalHeaders extracts and formats sorted canonical headers.
func buildCanonicalHeaders(headers http.Header) (string, string) {
	type headerEntry struct {
		name  string
		value string
	}

	var entries []headerEntry
	var signedNames []string

	for k, vals := range headers {
		lowerK := strings.ToLower(strings.TrimSpace(k))
		// Skip authorization header itself
		if lowerK == "authorization" {
			continue
		}

		// Clean values: trim and join with comma if multiple
		var cleanVals []string
		for _, v := range vals {
			cleanVals = append(cleanVals, strings.TrimSpace(v))
		}
		valStr := strings.Join(cleanVals, ",")

		entries = append(entries, headerEntry{name: lowerK, value: valStr})
		signedNames = append(signedNames, lowerK)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})
	sort.Strings(signedNames)

	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.name)
		b.WriteString(":")
		b.WriteString(entry.value)
		b.WriteString("\n")
	}

	signedHeaders := strings.Join(signedNames, ";")
	return b.String(), signedHeaders
}

// buildCanonicalQuery formats and sorts query parameters.
func buildCanonicalQuery(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		escapedKey := uriEncode(k)
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, fmt.Sprintf("%s=%s", escapedKey, uriEncode(v)))
		}
	}

	return strings.Join(parts, "&")
}

// deriveSigningKey calculates HMAC-SHA256 derived key: kSecret -> kDate -> kRegion -> kService -> kSigning.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacRaw([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacRaw(kDate, []byte(region))
	kService := hmacRaw(kRegion, []byte(service))
	kSigning := hmacRaw(kService, []byte(sigv4Request))
	return kSigning
}

func hmacRaw(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hmacHex(key, data []byte) string {
	raw := hmacRaw(key, data)
	return hex.EncodeToString(raw)
}

// uriEncode encodes characters according to RFC 3986.
func uriEncode(s string) string {
	encoded := url.QueryEscape(s)
	// QueryEscape turns space to +, RFC 3986 expects %20
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	return encoded
}

// uriEncodePath encodes each segment of a URI path while preserving forward slashes.
func uriEncodePath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}

	parts := strings.Split(path, "/")
	var encodedParts []string
	for _, p := range parts {
		if p == "" {
			encodedParts = append(encodedParts, "")
		} else {
			encodedParts = append(encodedParts, uriEncode(p))
		}
	}
	return strings.Join(encodedParts, "/")
}
