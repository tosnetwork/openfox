package evolution

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/skills"
)

type Applier struct {
	paths Paths
	now   func() time.Time
	// quarantineOnly is used by every production constructor. It prevents a
	// model-authored draft from becoming a loaded Skill without the trusted
	// capability Admission and Promotion pipeline.
	quarantineOnly   bool
	acquisitionFence capabilitycontrol.CapabilityAcquisitionFence
	ownerID, agentID []byte
}

// NewTrustedApplier creates the production fail-closed draft path. The draft
// is materialized as evidence under the evolution quarantine, never under a
// loader-visible skills directory.
func NewTrustedApplier(paths Paths, now func() time.Time) *Applier {
	return NewApplier(paths, now)
}

// NewTrustedApplierWithAcquisition is the only production materialization
// constructor. Every model-authored draft enters the same Owner/Agent
// acquisition namespace, quota ledger and external owner-exit fence as Web,
// CLI and model-requested registry imports.
func NewTrustedApplierWithAcquisition(paths Paths, now func() time.Time, fence capabilitycontrol.CapabilityAcquisitionFence, ownerID, agentID []byte) *Applier {
	applier := NewApplier(paths, now)
	applier.acquisitionFence = fence
	applier.ownerID = append([]byte(nil), ownerID...)
	applier.agentID = append([]byte(nil), agentID...)
	return applier
}

// NewApplier is deliberately quarantine-only. There is no public constructor
// for writing model-generated material into a loader-visible directory.
func NewApplier(paths Paths, now func() time.Time) *Applier {
	if now == nil {
		now = time.Now
	}
	return &Applier{
		paths:          paths,
		now:            now,
		quarantineOnly: true,
	}
}

func (a *Applier) ApplyDraft(ctx context.Context, workspace string, draft SkillDraft) error {
	rollback, err := a.applyDraftWithRollback(ctx, workspace, draft)
	if err != nil {
		return err
	}
	_ = rollback
	return nil
}

func (a *Applier) applyDraftWithRollback(
	ctx context.Context,
	workspace string,
	draft SkillDraft,
) (func() error, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if validateErr := skills.ValidateSkillName(draft.TargetSkillName); validateErr != nil {
		return nil, validateErr
	}

	var existingBody, backupPath string
	var hadOriginal bool
	var err error
	if a.quarantineOnly {
		existingBody, hadOriginal, err = readCurrentSkill(workspace, draft.TargetSkillName)
	} else {
		existingBody, backupPath, hadOriginal, err = a.backupCurrentSkill(workspace, draft.TargetSkillName)
	}
	if err != nil {
		return nil, err
	}

	renderedBody, err := renderAppliedBody(draft, existingBody, hadOriginal)
	if err != nil {
		return nil, err
	}

	if err := validateAppliedSkillBody(
		renderedBody,
		draft.TargetSkillName,
		allowsExistingFrontmatterFields(draft.ChangeKind, hadOriginal),
	); err != nil {
		return nil, err
	}

	if a.quarantineOnly {
		return a.quarantineDraft(ctx, workspace, draft, renderedBody)
	}
	skillDir := filepath.Join(workspace, "skills", draft.TargetSkillName)
	if mkdirErr := os.MkdirAll(skillDir, 0o755); mkdirErr != nil {
		return nil, mkdirErr
	}

	skillPath := filepath.Join(skillDir, "SKILL.md")
	if err := fileutil.WriteFileAtomic(skillPath, []byte(renderedBody), 0o644); err != nil {
		return nil, err
	}

	return func() error {
		return a.rollbackSkill(skillPath, backupPath, hadOriginal)
	}, nil
}

func (a *Applier) quarantineDraft(ctx context.Context, workspace string, draft SkillDraft, renderedBody string) (func() error, error) {
	if a.acquisitionFence == nil || len(a.ownerID) == 0 || len(a.agentID) == 0 {
		return nil, errors.New("adaptive draft materialization requires the common external capability-acquisition fence")
	}
	root := filepath.Join(workspace, "state", "trusted-capabilities", "quarantine")
	ledger, err := capabilitycontrol.OpenQuarantineLedger(root, a.now, a.acquisitionFence, a.ownerID, a.agentID)
	if err != nil {
		return nil, err
	}
	defer ledger.Close()
	workspaceDigest := sha256.Sum256([]byte(filepath.Clean(workspace)))
	reservation, err := ledger.Reserve(ctx, fmt.Sprintf("evolution:%x", workspaceDigest[:]), "adaptive-model-draft", 1)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = ledger.Abort(reservation.ID)
		}
	}()
	staging, err := os.MkdirTemp(root, ".evolution-draft-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	skillDir := filepath.Join(staging, draft.TargetSkillName)
	if err := os.Mkdir(skillDir, 0o700); err != nil {
		return nil, err
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(skillDir, "SKILL.md"), []byte(renderedBody), 0o600); err != nil {
		return nil, err
	}
	digest, err := capabilitycontrol.HashTree(staging)
	if err != nil {
		return nil, err
	}
	if _, _, err := ledger.Commit(ctx, reservation.ID, staging, digest); err != nil {
		return nil, err
	}
	committed = true
	// Commit durably stores the exact registration receipt in the ledger object
	// record. A later local audit/store failure or this API's error-only return
	// shape therefore cannot strand the acknowledged candidate.
	return func() error { return nil }, nil
}

func readCurrentSkill(workspace, skillName string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(workspace, "skills", skillName, "SKILL.md"))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(data), true, nil
}

func (a *Applier) backupCurrentSkill(
	workspace, skillName string,
) (currentBody, backupPath string, hadOriginal bool, err error) {
	if validateErr := skills.ValidateSkillName(skillName); validateErr != nil {
		return "", "", false, validateErr
	}

	skillPath := filepath.Join(workspace, "skills", skillName, "SKILL.md")
	data, err := os.ReadFile(skillPath)
	if os.IsNotExist(err) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}

	backupDir := filepath.Join(
		a.paths.BackupsDir,
		workspaceScopeDir(workspace),
		skillName,
		a.now().Format("20060102-150405.000000000"),
	)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", "", false, err
	}

	backupPath = filepath.Join(backupDir, "SKILL.md")
	if err := fileutil.WriteFileAtomic(backupPath, data, 0o644); err != nil {
		return "", "", false, err
	}
	return string(data), backupPath, true, nil
}

func (a *Applier) rollbackSkill(skillPath, backupPath string, hadOriginal bool) error {
	if hadOriginal {
		data, err := os.ReadFile(backupPath)
		if err != nil {
			return err
		}
		return fileutil.WriteFileAtomic(skillPath, data, 0o644)
	}
	if err := os.Remove(skillPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	skillDir := filepath.Dir(skillPath)
	if err := os.Remove(skillDir); err != nil && !os.IsNotExist(err) && !isDirNotEmptyError(err) {
		return err
	}
	return nil
}

func isDirNotEmptyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "directory not empty")
}

func validateAppliedSkillBody(body, targetSkillName string, allowExtraFrontmatterFields bool) error {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "---\n") {
		return fmt.Errorf("skill frontmatter is required")
	}
	if !strings.Contains(body, "\n# ") {
		return fmt.Errorf("skill heading is required")
	}
	frontmatter, _ := splitSkillFrontmatter(body)
	fields, err := parseSkillFrontmatterFields(frontmatter, allowExtraFrontmatterFields)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(fields["name"])
	if name == "" {
		return fmt.Errorf("skill frontmatter name is required")
	}
	if name != targetSkillName {
		return fmt.Errorf("skill frontmatter name %q does not match target skill %q", name, targetSkillName)
	}
	if strings.TrimSpace(fields["description"]) == "" {
		return fmt.Errorf("skill frontmatter description is required")
	}
	return nil
}

func allowsExistingFrontmatterFields(kind ChangeKind, hadOriginal bool) bool {
	return hadOriginal && (kind == ChangeKindAppend || kind == ChangeKindMerge)
}

func renderAppliedBody(draft SkillDraft, existingBody string, hadOriginal bool) (string, error) {
	switch draft.ChangeKind {
	case ChangeKindCreate:
		if hadOriginal {
			return "", fmt.Errorf("cannot create skill %q: skill already exists", draft.TargetSkillName)
		}
		return renderDeployableSkillBody(draft.BodyOrPatch), nil
	case ChangeKindReplace:
		if !hadOriginal {
			return "", fmt.Errorf("cannot replace skill %q: skill does not exist", draft.TargetSkillName)
		}
		return renderDeployableSkillBody(draft.BodyOrPatch), nil
	case ChangeKindAppend:
		patch, err := renderDeployablePatchBody(draft.BodyOrPatch, draft.TargetSkillName)
		if err != nil {
			return "", err
		}
		if !hadOriginal || strings.TrimSpace(existingBody) == "" {
			return renderDeployableSkillBody(draft.BodyOrPatch), nil
		}
		return strings.TrimRight(existingBody, "\n") + "\n\n" + strings.TrimLeft(patch, "\n"), nil
	case ChangeKindMerge:
		patch, err := renderDeployablePatchBody(draft.BodyOrPatch, draft.TargetSkillName)
		if err != nil {
			return "", err
		}
		if !hadOriginal || strings.TrimSpace(existingBody) == "" {
			return renderDeployableSkillBody(draft.BodyOrPatch), nil
		}
		mergedSection := strings.Join([]string{
			"",
			"## Merged Knowledge",
			strings.TrimSpace(patch),
			"",
		}, "\n")
		return strings.TrimRight(existingBody, "\n") + mergedSection, nil
	default:
		return "", fmt.Errorf("unsupported change_kind %q", draft.ChangeKind)
	}
}

func renderDeployablePatchBody(body, targetSkillName string) (string, error) {
	body = renderDeployableSkillBody(body)
	frontmatter, markdownBody := splitSkillFrontmatter(body)
	if frontmatter == "" {
		markdownBody = body
	} else {
		fields, err := parseSkillFrontmatterFields(frontmatter, true)
		if err != nil {
			return "", err
		}
		if name := strings.TrimSpace(fields["name"]); name != "" && name != targetSkillName {
			return "", fmt.Errorf(
				"skill patch frontmatter name %q does not match target skill %q",
				name,
				targetSkillName,
			)
		}
	}
	return strings.TrimSpace(stripLeadingH1(markdownBody)), nil
}

func splitSkillFrontmatter(body string) (frontmatter, markdownBody string) {
	normalized := strings.ReplaceAll(strings.TrimSpace(body), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", body
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", body
	}
	return strings.Join(lines[1:end], "\n"), strings.TrimLeft(strings.Join(lines[end+1:], "\n"), "\n")
}

func parseSkillFrontmatterFields(frontmatter string, allowExtraFields bool) (map[string]string, error) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(frontmatter), &raw); err != nil {
		return nil, fmt.Errorf("invalid skill frontmatter: %w", err)
	}
	for key := range raw {
		if key != "name" && key != "description" {
			if allowExtraFields {
				continue
			}
			return nil, fmt.Errorf("unsupported skill frontmatter field %q", key)
		}
	}

	var typed struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(frontmatter), &typed); err != nil {
		return nil, fmt.Errorf("invalid skill frontmatter: %w", err)
	}
	return map[string]string{
		"name":        typed.Name,
		"description": typed.Description,
	}, nil
}

func stripLeadingH1(body string) string {
	lines := strings.Split(strings.TrimLeft(body, "\n"), "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "# ") {
		lines = lines[1:]
	}
	return strings.Join(lines, "\n")
}

func errorsJoin(errs ...error) error {
	var first error
	for _, err := range errs {
		if err == nil {
			continue
		}
		if first == nil {
			first = err
			continue
		}
		first = fmt.Errorf("%w; %v", first, err)
	}
	return first
}
