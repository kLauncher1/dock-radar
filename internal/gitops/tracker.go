package gitops

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteHeadFetcher defines an interface for fetching remote Git branch references.
type RemoteHeadFetcher interface {
	FetchRemoteRef(ctx context.Context, repoURL string, branch string) (string, error)
}

// GitHTTPFetcher fetches branch refs via standard Git Smart HTTP transport (info/refs).
type GitHTTPFetcher struct {
	Client *http.Client
}

// NewGitHTTPFetcher creates a new Git smart protocol HTTP reference resolver.
func NewGitHTTPFetcher(timeout time.Duration) *GitHTTPFetcher {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &GitHTTPFetcher{
		Client: &http.Client{
			Timeout: timeout,
		},
	}
}

// FetchRemoteRef queries the remote Git server for the latest commit SHA of a given branch.
func (f *GitHTTPFetcher) FetchRemoteRef(ctx context.Context, repoURL string, branch string) (string, error) {
	if repoURL == "" || branch == "" {
		return "", errors.New("repo URL and branch must not be empty")
	}

	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("invalid repo URL: %w", err)
	}
	p := strings.TrimSuffix(parsed.Path, "/")
	if !strings.HasSuffix(p, ".git") && !strings.Contains(p, "/info/refs") {
		p += ".git"
	}
	parsed.Path = p + "/info/refs"
	parsed.RawQuery = "service=git-upload-pack"
	infoRefsURL := parsed.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoRefsURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create git info/refs request: %w", err)
	}
	req.Header.Set("User-Agent", "git/2.40.0 (dock-radar-gitops)")

	resp, err := f.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query remote git info/refs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote git server returned status %d", resp.StatusCode)
	}

	return parseGitSmartRefs(resp.Body, branch)
}

// parseGitSmartRefs scans Git pkt-line protocol output looking for refs/heads/<branch> or HEAD.
func parseGitSmartRefs(r io.Reader, branch string) (string, error) {
	scanner := bufio.NewScanner(r)
	targetRef := "refs/heads/" + branch

	for scanner.Scan() {
		line := scanner.Text()
		// Pkt-line format: 4 hex length prefix followed by content (e.g. "003f7a1b... refs/heads/main\n")
		// Often packet lines have null byte "\x00" capabilities after the ref name
		clean := strings.TrimSpace(line)
		// Repeatedly strip pkt-line 4-hex prefixes (such as 0000 flush pkt or pkt length)
		for len(clean) >= 4 && isHex4(clean[:4]) {
			fields := strings.Fields(clean)
			if len(fields) > 0 && IsValidCommitSHA(fields[0]) {
				break
			}
			clean = strings.TrimSpace(clean[4:])
		}
		if strings.HasPrefix(clean, "#") || clean == "" {
			continue
		}

		parts := strings.Fields(clean)
		if len(parts) >= 2 {
			sha := parts[0]
			ref := parts[1]
			// Trim possible null byte capabilities
			if idx := strings.Index(ref, "\x00"); idx != -1 {
				ref = ref[:idx]
			}
			if ref == targetRef || (branch == "HEAD" && ref == "HEAD") {
				if IsValidCommitSHA(sha) {
					return sha, nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading git refs stream: %w", err)
	}

	return "", fmt.Errorf("target branch %q not found in remote references", branch)
}

func isHex4(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// RepoTracker tracks git repository branches and detects new commit releases.
type RepoTracker struct {
	fetcher RemoteHeadFetcher
}

// NewRepoTracker initializes a repository state tracker.
func NewRepoTracker(fetcher RemoteHeadFetcher) *RepoTracker {
	if fetcher == nil {
		fetcher = NewGitHTTPFetcher(15 * time.Second)
	}
	return &RepoTracker{
		fetcher: fetcher,
	}
}

// CheckUpdate queries remote repository and checks if a new commit has landed on the tracked branch.
func (t *RepoTracker) CheckUpdate(ctx context.Context, repo *GitRepoConfig) (newSHA string, hasUpdate bool, err error) {
	if repo == nil {
		return "", false, errors.New("repository config is nil")
	}

	latestSHA, err := t.fetcher.FetchRemoteRef(ctx, repo.RepoURL, repo.Branch)
	if err != nil {
		return "", false, err
	}

	if latestSHA != repo.LastCommitSHA && latestSHA != "" {
		return latestSHA, true, nil
	}

	return latestSHA, false, nil
}
