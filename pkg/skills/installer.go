package skills

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/utils"
)

// GitHubContent represents a file or directory in GitHub API response
type GitHubContent struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // "file" or "dir"
	DownloadURL string `json:"download_url"`
	URL         string `json:"url"` // API URL for subdirectories
}

// GitHubRef represents a parsed GitHub reference
type GitHubRef struct {
	Owner    string // Repository owner
	RepoName string // Repository name
	Ref      string // Git reference (branch, tag, or commit)
	SubPath  string // Path within the repository
}

type gitHubTarget struct {
	Ref       GitHubRef
	Endpoints gitHubEndpoints
}

const (
	maxGitHubArtifactFiles = 4096
	maxGitHubArtifactDepth = 16
	maxGitHubFileBytes     = 5 << 20
	maxGitHubArtifactBytes = 64 << 20
	maxGitHubMetadataBytes = 2 << 20
)

type githubRetrievalBudget struct {
	apiOrigin  string
	apiPrefix  string
	rawOrigins map[string]struct{}
	files      int
	bytes      int64
}

type SkillInstaller struct {
	workspace        string
	client           *http.Client
	githubBaseURL    string
	githubAPIBaseURL string
	githubRawBaseURL string
	githubToken      string
	proxy            string
}

// NewSkillInstaller creates a new skill installer.
// proxy is an optional HTTP/HTTPS/SOCKS5 proxy URL for downloading skills.
func NewSkillInstaller(workspace, githubToken, proxy string) (*SkillInstaller, error) {
	return NewSkillInstallerWithBaseURL(workspace, "", githubToken, proxy)
}

// NewSkillInstallerWithBaseURL creates a new skill installer with a custom GitHub base URL.
// For github.com this can be left empty. For GitHub Enterprise, set it to the web URL.
func NewSkillInstallerWithBaseURL(workspace, githubBaseURL, githubToken, proxy string) (*SkillInstaller, error) {
	endpoints, err := resolveGitHubEndpoints(githubBaseURL)
	if err != nil {
		return nil, err
	}
	client, err := newRegistryHTTPClient(endpoints.WebBaseURL, githubToken, proxy, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create bounded GitHub client: %w", err)
	}

	return &SkillInstaller{
		workspace:        workspace,
		client:           client,
		githubBaseURL:    endpoints.WebBaseURL,
		githubAPIBaseURL: endpoints.APIBaseURL,
		githubRawBaseURL: endpoints.RawBaseURL,
		githubToken:      githubToken,
		proxy:            proxy,
	}, nil
}

type gitHubEndpoints struct {
	WebBaseURL string
	APIBaseURL string
	RawBaseURL string
}

func resolveGitHubEndpoints(baseURL string) (gitHubEndpoints, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return gitHubEndpoints{
			WebBaseURL: "https://github.com",
			APIBaseURL: "https://api.github.com",
			RawBaseURL: "https://raw.githubusercontent.com",
		}, nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return gitHubEndpoints{}, fmt.Errorf("invalid github base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return gitHubEndpoints{}, fmt.Errorf("invalid github base url %q", baseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackRegistryHost(u.Hostname())) {
		return gitHubEndpoints{}, fmt.Errorf("github base url must use HTTPS outside explicit loopback development")
	}

	trimmedPath := strings.TrimSuffix(u.Path, "/")
	origin := u.Scheme + "://" + u.Host

	if u.Host == "api.github.com" {
		return gitHubEndpoints{
			WebBaseURL: "https://github.com",
			APIBaseURL: "https://api.github.com",
			RawBaseURL: "https://raw.githubusercontent.com",
		}, nil
	}

	if strings.HasSuffix(trimmedPath, "/api/v3") {
		webBaseURL := origin + strings.TrimSuffix(trimmedPath, "/api/v3")
		webBaseURL = strings.TrimSuffix(webBaseURL, "/")
		if webBaseURL == origin {
			webBaseURL = origin
		}
		return gitHubEndpoints{
			WebBaseURL: webBaseURL,
			APIBaseURL: origin + trimmedPath,
			RawBaseURL: webBaseURL + "/raw",
		}, nil
	}

	webBaseURL := origin + trimmedPath
	webBaseURL = strings.TrimSuffix(webBaseURL, "/")
	if u.Host == "github.com" {
		return gitHubEndpoints{
			WebBaseURL: "https://github.com",
			APIBaseURL: "https://api.github.com",
			RawBaseURL: "https://raw.githubusercontent.com",
		}, nil
	}

	return gitHubEndpoints{
		WebBaseURL: webBaseURL,
		APIBaseURL: webBaseURL + "/api/v3",
		RawBaseURL: webBaseURL + "/raw",
	}, nil
}

func parseGitHubRefPathParts(repoURL *url.URL, githubBaseURL string) []string {
	parts := strings.Split(strings.Trim(repoURL.Path, "/"), "/")
	if len(parts) == 0 {
		return parts
	}
	if githubBaseURL == "" {
		return parts
	}
	baseURL, err := url.Parse(strings.TrimSpace(githubBaseURL))
	if err != nil {
		return parts
	}
	if !strings.EqualFold(repoURL.Host, baseURL.Host) || !strings.EqualFold(repoURL.Scheme, baseURL.Scheme) {
		return parts
	}
	baseParts := strings.Split(strings.Trim(baseURL.Path, "/"), "/")
	if len(baseParts) == 1 && baseParts[0] == "" {
		baseParts = nil
	}
	if len(baseParts) == 0 || len(parts) < len(baseParts)+2 {
		return parts
	}
	for i, part := range baseParts {
		if parts[i] != part {
			return parts
		}
	}
	return parts[len(baseParts):]
}

func supportedGitHubBaseURL(repoURL *url.URL, githubBaseURL string) string {
	if repoURL == nil {
		return ""
	}
	trimmedBaseURL := strings.TrimSpace(githubBaseURL)
	if trimmedBaseURL != "" && matchesGitHubWebBase(repoURL, trimmedBaseURL) {
		return trimmedBaseURL
	}
	if matchesGitHubWebBase(repoURL, "https://github.com") {
		return "https://github.com"
	}
	return ""
}

func matchesGitHubWebBase(repoURL *url.URL, webBaseURL string) bool {
	baseURL, err := url.Parse(strings.TrimSpace(webBaseURL))
	if err != nil {
		return false
	}
	if !strings.EqualFold(repoURL.Scheme, baseURL.Scheme) {
		return false
	}
	if !strings.EqualFold(repoURL.Host, baseURL.Host) {
		return false
	}
	basePath := strings.Trim(baseURL.Path, "/")
	if basePath == "" {
		return true
	}
	repoPath := strings.Trim(repoURL.Path, "/")
	return repoPath == basePath || strings.HasPrefix(repoPath, basePath+"/")
}

func splitGitHubTreeOrBlobRefPath(parts []string, defaultRef string) (string, string) {
	if len(parts) == 0 {
		return defaultRef, ""
	}
	if anchor := knownSkillSubPathAnchor(parts); anchor > 0 {
		return strings.Join(parts[:anchor], "/"), strings.Join(parts[anchor:], "/")
	}
	if parts[len(parts)-1] == "SKILL.md" {
		return strings.Join(parts[:len(parts)-1], "/"), "SKILL.md"
	}
	return parts[0], strings.Join(parts[1:], "/")
}

func knownSkillSubPathAnchor(parts []string) int {
	for i := 1; i < len(parts); i++ {
		candidateSubPath := strings.Join(parts[i:], "/")
		if strings.HasPrefix(candidateSubPath, ".agents/skills/") || strings.HasPrefix(candidateSubPath, "skills/") {
			return i
		}
	}
	return -1
}

func isSkillMarkdownPath(subPath string) bool {
	subPath = strings.Trim(strings.TrimSpace(subPath), "/")
	return subPath == "SKILL.md" || strings.HasSuffix(subPath, "/SKILL.md")
}

// parseGitHubRef parses a GitHub reference.
// Supports: "owner/repo", "owner/repo/path", or full URL like "https://github.com/owner/repo/tree/ref/path"
func parseGitHubRef(repo string) (GitHubRef, error) {
	return parseGitHubRefWithBaseURL(repo, "", "main")
}

func parseGitHubRefWithBaseURL(repo, githubBaseURL, defaultRef string) (GitHubRef, error) {
	target, err := parseGitHubTargetWithBaseURL(repo, githubBaseURL, defaultRef)
	if err != nil {
		return GitHubRef{}, err
	}
	return target.Ref, nil
}

func parseGitHubTargetWithBaseURL(repo, githubBaseURL, defaultRef string) (gitHubTarget, error) {
	repo = strings.TrimSpace(repo)
	defaultRef = strings.TrimSpace(defaultRef)

	// Handle full URL
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		u, err := url.Parse(repo)
		if err != nil {
			return gitHubTarget{}, fmt.Errorf("invalid URL: %w", err)
		}
		matchedBaseURL := supportedGitHubBaseURL(u, githubBaseURL)
		if matchedBaseURL == "" {
			return gitHubTarget{}, fmt.Errorf("invalid GitHub URL host %q", u.Host)
		}
		endpoints, err := resolveGitHubEndpoints(matchedBaseURL)
		if err != nil {
			return gitHubTarget{}, err
		}
		parts := parseGitHubRefPathParts(u, matchedBaseURL)
		if len(parts) < 2 {
			return gitHubTarget{}, fmt.Errorf("invalid GitHub URL")
		}
		if len(parts) > 2 {
			if parts[2] != "tree" && parts[2] != "blob" {
				return gitHubTarget{}, fmt.Errorf("invalid GitHub repository URL path %q", u.Path)
			}
			if len(parts) < 4 {
				return gitHubTarget{}, fmt.Errorf("invalid GitHub %s URL path %q", parts[2], u.Path)
			}
		}
		ref := GitHubRef{
			Owner:    parts[0],
			RepoName: parts[1],
			Ref:      defaultRef,
		}
		// Look for /tree/ or /blob/ in the path
		for i := 2; i < len(parts); i++ {
			if parts[i] == "tree" || parts[i] == "blob" {
				if i+1 < len(parts) {
					ref.Ref, ref.SubPath = splitGitHubTreeOrBlobRefPath(parts[i+1:], defaultRef)
				}
				break
			}
		}
		return gitHubTarget{Ref: ref, Endpoints: endpoints}, nil
	}

	endpoints, err := resolveGitHubEndpoints(githubBaseURL)
	if err != nil {
		return gitHubTarget{}, err
	}

	// Handle shorthand format
	parts := strings.Split(strings.Trim(repo, "/"), "/")
	if len(parts) < 2 {
		return gitHubTarget{}, fmt.Errorf("invalid format %q: expected 'owner/repo'", repo)
	}
	ref := GitHubRef{
		Owner:    parts[0],
		RepoName: parts[1],
		Ref:      defaultRef,
	}
	if len(parts) > 2 {
		ref.SubPath = strings.Join(parts[2:], "/")
	}
	return gitHubTarget{Ref: ref, Endpoints: endpoints}, nil
}

type gitHubRepository struct {
	DefaultBranch string `json:"default_branch"`
}

func (si *SkillInstaller) resolveGitHubTarget(ctx context.Context, repo, version string) (gitHubTarget, error) {
	target, err := parseGitHubTargetWithBaseURL(repo, si.githubBaseURL, "")
	if err != nil {
		return gitHubTarget{}, err
	}
	if version != "" {
		target.Ref.Ref = version
		return target, nil
	}
	if target.Ref.Ref != "" {
		return target, nil
	}
	defaultBranch, err := si.fetchDefaultBranchWithAPIBaseURL(
		ctx,
		target.Endpoints.APIBaseURL,
		target.Ref.Owner,
		target.Ref.RepoName,
	)
	if err != nil {
		return gitHubTarget{}, err
	}
	target.Ref.Ref = defaultBranch
	return target, nil
}

func (si *SkillInstaller) fetchDefaultBranchWithAPIBaseURL(
	ctx context.Context,
	apiBaseURL, owner, repo string,
) (string, error) {
	apiURL := fmt.Sprintf("%s/repos/%s/%s", strings.TrimRight(apiBaseURL, "/"), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	if si.githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+si.githubToken)
	}

	resp, err := utils.DoRequestWithRetry(restrictedHTTPClient(si.client, urlOrigin(req.URL), si.githubToken != ""), req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read repository metadata: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to resolve default branch: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var repository gitHubRepository
	if err := json.Unmarshal(body, &repository); err != nil {
		return "", fmt.Errorf("failed to parse repository metadata: %w", err)
	}
	if strings.TrimSpace(repository.DefaultBranch) == "" {
		return "", fmt.Errorf("repository %s/%s did not report a default branch", owner, repo)
	}
	return repository.DefaultBranch, nil
}

func githubInstallDirNameWithBaseURL(repo, githubBaseURL string) (string, error) {
	if !strings.HasPrefix(repo, "http://") && !strings.HasPrefix(repo, "https://") {
		if err := ValidateInstallTarget(repo); err != nil {
			return "", err
		}
	}
	ref, err := parseGitHubRefWithBaseURL(repo, githubBaseURL, "main")
	if err != nil {
		return "", err
	}
	if ref.SubPath != "" {
		if isSkillMarkdownPath(ref.SubPath) {
			skillDir := path.Dir(strings.Trim(ref.SubPath, "/"))
			if skillDir == "." || skillDir == "" {
				return ref.RepoName, nil
			}
			return path.Base(skillDir), nil
		}
		return filepath.Base(ref.SubPath), nil
	}
	return ref.RepoName, nil
}

func (si *SkillInstaller) InstallFromGitHub(ctx context.Context, repo string) error {
	_, _ = ctx, repo
	return errors.New("direct workspace Skill installation is disabled; use the trusted quarantine, evaluation, Admission, Promotion, and installation pipeline")
}

func (si *SkillInstaller) InstallFromGitHubToDir(
	ctx context.Context,
	repo, version, skillDirectory string,
) (*InstallResult, error) {
	target, err := si.resolveGitHubTarget(ctx, repo, version)
	if err != nil {
		return nil, err
	}
	ref := target.Ref
	apiSubPath := strings.Trim(ref.SubPath, "/")
	if isSkillMarkdownPath(apiSubPath) {
		if dir := path.Dir(apiSubPath); dir == "." {
			apiSubPath = ""
		} else {
			apiSubPath = dir
		}
	}

	// Build GitHub API URL
	apiPath := path.Join(ref.Owner, ref.RepoName, "contents")
	if apiSubPath != "" {
		apiPath = path.Join(apiPath, apiSubPath)
	}
	apiURL := fmt.Sprintf("%s/repos/%s?ref=%s", target.Endpoints.APIBaseURL, apiPath, url.QueryEscape(ref.Ref))

	if err := si.getGithubDirAllFiles(ctx, apiURL, skillDirectory, true); err != nil {
		// Fallback to raw download
		if downloadErr := si.downloadRaw(
			ctx,
			target.Endpoints.RawBaseURL,
			ref.Owner,
			ref.RepoName,
			ref.Ref,
			ref.SubPath,
			skillDirectory,
		); downloadErr != nil {
			return nil, downloadErr
		}
	} else if _, err := os.Stat(filepath.Join(skillDirectory, "SKILL.md")); err != nil {
		return nil, fmt.Errorf("SKILL.md not found in repository")
	}

	return &InstallResult{Version: ref.Ref}, nil
}

// downloadDir recursively downloads a directory from GitHub API
// isRoot: true if this is the skill root directory (only download SKILL.md at root)
func (si *SkillInstaller) getGithubDirAllFiles(ctx context.Context, apiURL, localDir string, isRoot bool) error {
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("invalid GitHub API URL")
	}
	prefix := parsed.Path
	if index := strings.Index(prefix, "/contents"); index >= 0 {
		prefix = prefix[:index+len("/contents")]
	}
	rawOrigins := map[string]struct{}{urlOrigin(parsed): {}}
	if raw, parseErr := url.Parse(si.githubRawBaseURL); parseErr == nil && raw.Scheme != "" && raw.Host != "" {
		rawOrigins[urlOrigin(raw)] = struct{}{}
	}
	budget := &githubRetrievalBudget{apiOrigin: urlOrigin(parsed), apiPrefix: prefix, rawOrigins: rawOrigins}
	return si.getGithubDirAllFilesBounded(ctx, apiURL, localDir, isRoot, 0, budget)
}

func (si *SkillInstaller) getGithubDirAllFilesBounded(ctx context.Context, apiURL, localDir string, isRoot bool, depth int, budget *githubRetrievalBudget) error {
	if depth > maxGitHubArtifactDepth || !urlWithin(apiURL, budget.apiOrigin, budget.apiPrefix) {
		return errors.New("GitHub API traversal escaped the pinned repository origin")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return err
	}
	if si.githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+si.githubToken)
	}

	resp, err := utils.DoRequestWithRetry(restrictedHTTPClient(si.client, budget.apiOrigin, si.githubToken != ""), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxGitHubMetadataBytes+1))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return errors.New("GitHub metadata must be a bounded JSON array")
	}
	itemCount := 0
	for decoder.More() {
		itemCount++
		if itemCount > maxGitHubArtifactFiles {
			return errors.New("GitHub metadata exceeds item-count limit")
		}
		var item GitHubContent
		if err := decoder.Decode(&item); err != nil {
			return err
		}
		if !canonicalPathSegment(item.Name) {
			return fmt.Errorf("GitHub API returned unsafe path segment %q", item.Name)
		}
		localPath := filepath.Join(localDir, item.Name)

		switch item.Type {
		case "file":
			if !shouldDownload(item.Name, isRoot) {
				continue
			}
			budget.files++
			if budget.files > maxGitHubArtifactFiles {
				return errors.New("GitHub artifact exceeds file-count limit")
			}
			if err := si.downloadFileBounded(ctx, item.DownloadURL, localPath, budget); err != nil {
				return fmt.Errorf("download %s: %w", item.Name, err)
			}
		case "dir":
			if !isSkillDirectory(item.Name) {
				continue
			}
			if err := si.getGithubDirAllFilesBounded(ctx, item.URL, localPath, false, depth+1, budget); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("GitHub metadata contains trailing data")
	}
	return nil
}

// downloadRaw is a fallback that downloads just SKILL.md from raw.githubusercontent.com
func (si *SkillInstaller) downloadRaw(
	ctx context.Context,
	rawBaseURL, owner, repo, ref, subPath, localDir string,
) error {
	urlPath := path.Join(owner, repo, ref)
	if subPath != "" {
		if isSkillMarkdownPath(subPath) {
			urlPath = strings.TrimSuffix(path.Join(urlPath, subPath), "/SKILL.md")
		} else {
			urlPath = path.Join(urlPath, subPath)
		}
	}
	rawURL := fmt.Sprintf("%s/%s/SKILL.md", strings.TrimRight(rawBaseURL, "/"), urlPath)

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Use chunked download to temporary file.
	parsedRaw, parseErr := url.Parse(rawURL)
	if parseErr != nil || parsedRaw.User != nil {
		return errors.New("invalid pinned raw download URL")
	}
	tmpPath, err := utils.DownloadToFile(ctx, restrictedHTTPClient(si.client, urlOrigin(parsedRaw), false), req, maxGitHubFileBytes)
	if err != nil {
		return fmt.Errorf("failed to fetch skill: %w", err)
	}
	defer os.Remove(tmpPath)

	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return fmt.Errorf("failed to create skill directory: %w", err)
	}

	localPath := filepath.Join(localDir, "SKILL.md")

	if err := fileutil.CopyFile(tmpPath, localPath, 0o600); err != nil {
		return fmt.Errorf("failed to write skill file: %w", err)
	}
	return nil
}

func (si *SkillInstaller) downloadFile(ctx context.Context, rawURL, localPath string) error {
	budget := &githubRetrievalBudget{rawOrigins: map[string]struct{}{}}
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		budget.rawOrigins[urlOrigin(parsed)] = struct{}{}
	}
	return si.downloadFileBounded(ctx, rawURL, localPath, budget)
}

func (si *SkillInstaller) downloadFileBounded(ctx context.Context, rawURL, localPath string, budget *githubRetrievalBudget) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	origin := urlOrigin(parsed)
	if _, ok := budget.rawOrigins[origin]; !ok || parsed.User != nil {
		return errors.New("download URL escaped the pinned origin")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return err
	}

	// Use chunked download to temporary file, then move atomically to target.
	tmpPath, err := utils.DownloadToFile(ctx, restrictedHTTPClient(si.client, origin, false), req, maxGitHubFileBytes)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	info, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if info.Size() > maxGitHubArtifactBytes-budget.bytes {
		return errors.New("GitHub artifact exceeds aggregate byte limit")
	}
	budget.bytes += info.Size()

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	if err := fileutil.CopyFile(tmpPath, localPath, 0o600); err != nil {
		return fmt.Errorf("failed to move downloaded file: %w", err)
	}
	return nil
}

func canonicalPathSegment(name string) bool {
	return name != "" && name != "." && name != ".." && utf8.ValidString(name) && norm.NFC.IsNormalString(name) &&
		!strings.ContainsAny(name, "/\\") && filepath.Base(name) == name
}

func urlOrigin(value *url.URL) string {
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Host)
}

func urlWithin(raw, origin, pathPrefix string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || urlOrigin(parsed) != origin {
		return false
	}
	clean := path.Clean(parsed.Path)
	return clean == pathPrefix || strings.HasPrefix(clean, strings.TrimRight(pathPrefix, "/")+"/")
}

func restrictedHTTPClient(base *http.Client, origin string, credentialed bool) *http.Client {
	clone := *base
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.User != nil || urlOrigin(req.URL) != origin {
			return errors.New("redirect escaped pinned origin")
		}
		if credentialed {
			return errors.New("credentialed registry redirects are forbidden")
		}
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return nil
	}
	return &clone
}

func newRegistryHTTPClient(baseURL, token, proxy string, timeout time.Duration) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("registry base URL is invalid")
	}
	localDevelopment := parsed.Scheme == "http" && isLoopbackRegistryHost(parsed.Hostname())
	if parsed.Scheme != "https" && !localDevelopment {
		return nil, errors.New("registry base URL must use HTTPS; HTTP is limited to a literal loopback development address")
	}
	if strings.TrimSpace(proxy) != "" {
		return nil, errors.New("trusted registry retrieval forbids proxies until an authenticated proxy profile is admitted")
	}
	whitelist := []string(nil)
	if localDevelopment {
		whitelist = []string{parsed.Hostname()}
	}
	client, err := utils.CreateSafeHTTPClient(utils.SafeHTTPClientOptions{Timeout: timeout, MaxRedirects: 3,
		PrivateHostWhitelist: whitelist})
	if err != nil {
		return nil, err
	}
	if transport, ok := client.Transport.(*http.Transport); ok {
		// CreateSafeHTTPClient preserves the general application's proxy behavior.
		// Capability acquisition is stricter: no ambient or caller-selected proxy
		// may become an unbound credential/destination authority.
		transport.Proxy = nil
		transport.DialTLS = nil
		transport.DialTLSContext = nil
	}
	origin := urlOrigin(parsed)
	client.CheckRedirect = restrictedHTTPClient(client, origin, token != "").CheckRedirect
	return client, nil
}

func isLoopbackRegistryHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

// shouldDownload determines if a file should be downloaded
// root: true if we're at the skill root directory
func shouldDownload(name string, root bool) bool {
	if root {
		return name == "SKILL.md"
	}
	return true
}

// isSkillDir checks if a directory is a standard skill resource directory
func isSkillDirectory(name string) bool {
	switch name {
	case "scripts", "references", "assets", "templates", "docs":
		return true
	}
	return false
}

func (si *SkillInstaller) Uninstall(skillName string) error {
	_, _ = si, skillName
	return errors.New("direct Skill removal is disabled; use an authorized capability.remove action so leases, references, and tombstones are preserved")
}
