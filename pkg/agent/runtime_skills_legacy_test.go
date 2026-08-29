package agent

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/skills"
)

// Legacy loader behavior is available only in the test binary so historical
// prompt/command tests do not create a production capability bypass.
func init() {
	runtimeSkillsLoaderFactory = func(workspace string) *skills.SkillsLoader {
		builtin := strings.TrimSpace(os.Getenv(config.EnvBuiltinSkills))
		if builtin == "" {
			if cwd, err := os.Getwd(); err == nil {
				builtin = filepath.Join(cwd, "skills")
			}
		}
		return skills.NewSkillsLoader(workspace, "", builtin)
	}
}
