package gitops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockFetcher struct {
	sha string
	err error
}

func (m *mockFetcher) FetchRemoteRef(ctx context.Context, repoURL string, branch string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.sha, nil
}

func TestRepoTracker_CheckUpdate(t *testing.T) {
	mock := &mockFetcher{
		sha: "8888888888888888888888888888888888888888",
	}
	tracker := NewRepoTracker(mock)

	repo := &GitRepoConfig{
		ID:            "test-repo",
		RepoURL:       "https://github.com/org/repo.git",
		Branch:        "main",
		LastCommitSHA: "7777777777777777777777777777777777777777",
	}

	newSHA, hasUpdate, err := tracker.CheckUpdate(context.Background(), repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasUpdate {
		t.Errorf("expected update detected")
	}
	if newSHA != mock.sha {
		t.Errorf("expected %s, got %s", mock.sha, newSHA)
	}

	// When already at latest SHA
	repo.LastCommitSHA = mock.sha
	_, hasUpdate2, err := tracker.CheckUpdate(context.Background(), repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasUpdate2 {
		t.Errorf("expected no update when SHAs match")
	}
}

func TestGitHTTPFetcher_SmartRefsParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/info/refs") {
			http.NotFound(w, r)
			return
		}
		// Return git-upload-pack format
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		body := "001e# service=git-upload-pack\n" +
			"0000\n" +
			"00958888888888888888888888888888888888888888 refs/heads/main\x00multi_ack\n" +
			"003f9999999999999999999999999999999999999999 refs/heads/dev\n" +
			"0000\n"
		w.Write([]byte(body))
	}))
	defer server.Close()

	fetcher := NewGitHTTPFetcher(0)
	sha, err := fetcher.FetchRemoteRef(context.Background(), server.URL, "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sha != "8888888888888888888888888888888888888888" {
		t.Errorf("unexpected parsed sha: %s", sha)
	}

	// Test branch not found
	_, err = fetcher.FetchRemoteRef(context.Background(), server.URL, "feature-missing")
	if err == nil {
		t.Errorf("expected error for missing branch")
	}
}
