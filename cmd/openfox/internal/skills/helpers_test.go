package skills

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
)

type allowCLIacquisitionFence struct{}

func (allowCLIacquisitionFence) AdmitCapabilityAcquisition(context.Context, capabilitycontrol.CapabilityAcquisitionRequest) error {
	return nil
}

func TestSkillsInstallFromRegistryWritesOriginMetadata(t *testing.T) {
	workspace := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Earning.OwnerID, cfg.Earning.AgentID = "owner", "agent"
	cfg.Agents.Defaults.Workspace = workspace

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/foo/bar":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"default_branch": "master"}))
		case "/api/v3/repos/foo/bar/contents/.agents/skills/pr-review":
			assert.Equal(t, "ref=master", r.URL.RawQuery)
			require.NoError(t, json.NewEncoder(w).Encode([]map[string]any{{
				"type":         "file",
				"name":         "SKILL.md",
				"download_url": server.URL + "/raw/foo/bar/master/.agents/skills/pr-review/SKILL.md",
			}}))
		case "/raw/foo/bar/master/.agents/skills/pr-review/SKILL.md":
			_, _ = w.Write([]byte("---\nname: pr-review\ndescription: PR review skill\n---\n# PR Review\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	githubRegistry, ok := cfg.Tools.Skills.Registries.Get("github")
	require.True(t, ok)
	githubRegistry.BaseURL = server.URL
	cfg.Tools.Skills.Registries.Set("github", githubRegistry)

	target := server.URL + "/foo/bar/tree/master/.agents/skills/pr-review"
	require.NoError(t, skillsInstallFromRegistryWithFence(cfg, "github", target, allowCLIacquisitionFence{}))

	matches, globErr := filepath.Glob(filepath.Join(workspace, "state", "trusted-capabilities", "quarantine", "*", ".skill-origin.json"))
	require.NoError(t, globErr)
	require.Empty(t, matches, "mutable origin metadata must not be retained inside the committed executable closure")
	_, activeErr := os.Stat(filepath.Join(workspace, "skills", "pr-review", "SKILL.md"))
	assert.True(t, os.IsNotExist(activeErr), "quarantined Skill must not be loader-visible")
}

func TestSkillsInstallFromRegistryRejectsInvalidSkillArchive(t *testing.T) {
	workspace := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Earning.OwnerID, cfg.Earning.AgentID = "owner", "agent"
	cfg.Agents.Defaults.Workspace = workspace

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/foo/bar":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"default_branch": "master"}))
		case "/api/v3/repos/foo/bar/contents/.agents/skills/pr-review":
			require.NoError(t, json.NewEncoder(w).Encode([]map[string]any{{
				"type":         "file",
				"name":         "SKILL.md",
				"download_url": server.URL + "/raw/foo/bar/master/.agents/skills/pr-review/SKILL.md",
			}}))
		case "/raw/foo/bar/master/.agents/skills/pr-review/SKILL.md":
			_, _ = w.Write([]byte("---\nname: bad_skill\ndescription: Invalid skill name\n---\n# Invalid\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	githubRegistry, ok := cfg.Tools.Skills.Registries.Get("github")
	require.True(t, ok)
	githubRegistry.BaseURL = server.URL
	cfg.Tools.Skills.Registries.Set("github", githubRegistry)

	target := server.URL + "/foo/bar/tree/master/.agents/skills/pr-review"
	err := skillsInstallFromRegistryWithFence(cfg, "github", target, allowCLIacquisitionFence{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a valid skill")
	_, statErr := os.Stat(filepath.Join(workspace, "skills", "pr-review"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestSkillsRemoveFromWorkspaceRejectsDotTarget(t *testing.T) {
	workspace := t.TempDir()
	skillsDir := filepath.Join(workspace, "skills")
	require.NoError(t, os.MkdirAll(skillsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "keep.txt"), []byte("keep"), 0o644))

	err := skillsRemoveFromWorkspace(workspace, config.DefaultConfig().Tools.Skills, ".")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "direct Skill deletion is disabled")

	_, statErr := os.Stat(skillsDir)
	assert.NoError(t, statErr)
	_, fileErr := os.Stat(filepath.Join(skillsDir, "keep.txt"))
	assert.NoError(t, fileErr)
}

func TestSkillsRemoveFromWorkspaceUsesLastPathSegment(t *testing.T) {
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "skills", "pr-review")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))

	err := skillsRemoveFromWorkspace(
		workspace,
		config.DefaultConfig().Tools.Skills,
		"https://github.com/foo/bar/tree/main/.agents/skills/pr-review",
	)
	require.Error(t, err)

	_, statErr := os.Stat(targetDir)
	assert.NoError(t, statErr)
}

func TestSkillsRemoveFromWorkspaceSupportsRepoRootGitHubBlobURL(t *testing.T) {
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "skills", "bar")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))

	err := skillsRemoveFromWorkspace(
		workspace,
		config.DefaultConfig().Tools.Skills,
		"https://github.com/foo/bar/blob/feature/skills-registry/SKILL.md",
	)
	require.Error(t, err)

	_, statErr := os.Stat(targetDir)
	assert.NoError(t, statErr)
}

func TestSkillsRemoveFromWorkspaceSupportsGitHubEnterpriseURL(t *testing.T) {
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "skills", "pr-review")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))

	cfg := config.DefaultConfig()
	githubRegistry, ok := cfg.Tools.Skills.Registries.Get("github")
	require.True(t, ok)
	githubRegistry.BaseURL = "https://ghe.example.com/git"
	cfg.Tools.Skills.Registries.Set("github", githubRegistry)

	err := skillsRemoveFromWorkspace(
		workspace,
		cfg.Tools.Skills,
		"https://ghe.example.com/git/foo/bar/tree/main/.agents/skills/pr-review",
	)
	require.Error(t, err)

	_, statErr := os.Stat(targetDir)
	assert.NoError(t, statErr)
}

func TestSkillsRemoveFromWorkspaceDoesNotRequireEnabledGitHubRegistry(t *testing.T) {
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "skills", "pr-review")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))

	cfg := config.DefaultConfig()
	githubRegistry, ok := cfg.Tools.Skills.Registries.Get("github")
	require.True(t, ok)
	githubRegistry.Enabled = false
	cfg.Tools.Skills.Registries.Set("github", githubRegistry)

	err := skillsRemoveFromWorkspace(
		workspace,
		cfg.Tools.Skills,
		"https://github.com/foo/bar/tree/main/.agents/skills/pr-review",
	)
	require.Error(t, err)

	_, statErr := os.Stat(targetDir)
	assert.NoError(t, statErr)
}
