# Contributing to OpenFox

Thank you for your interest in OpenFox. We welcome bug fixes, features,
documentation, translations, and testing. OpenFox itself is developed with
substantial AI assistance; the contribution process embraces that workflow
while keeping contributors accountable for everything they submit.

## Code of conduct

Be kind, constructive, and respectful. Harassment and discrimination are not
accepted.

## Ways to contribute

- Report bugs with the bug-report issue template.
- Propose features with the feature-request template. Discuss large features
  before implementing them.
- Improve code, tests, documentation, comments, or translations.
- Run OpenFox on new hardware, channels, or LLM providers and report results.

## Getting started

1. Fork the repository on GitHub.
2. Clone your fork and enter it:

   ```bash
   git clone https://github.com/<your-username>/openfox.git
   cd openfox
   ```

3. Add the upstream repository:

   ```bash
   git remote add upstream https://github.com/tosnetwork/openfox.git
   ```

OpenFox requires Go 1.25 or newer and `make`.

```bash
make build       # generate code and build binaries
make generate    # generate code only
make check       # dependency, formatting, vet, test, and documentation checks
```

Useful focused commands include:

```bash
make test
go test -run TestName -v ./pkg/session/
go test -bench=. -benchmem -run='^$' ./...
make fmt
make vet
make lint
```

Run `make check` before submitting a change.

## Preparing a change

Create a descriptive feature branch from an up-to-date `main` branch. Do not
push directly to `main` or a `release/*` branch.

```bash
git checkout main
git pull upstream main
git checkout -b feat/descriptive-name
```

Write concise English commit messages in the imperative mood. Keep commits
focused, reference related issues when applicable, and follow the
[Conventional Commits specification](https://www.conventionalcommits.org/).
Before opening a pull request, fetch upstream and rebase your branch:

```bash
git fetch upstream
git rebase upstream/main
```

## AI-assisted contributions

Every pull request must complete the **AI Code Generation** disclosure in the
pull-request template. Select the level that most accurately describes the
work:

| Level | Meaning |
|---|---|
| Fully AI-generated | AI wrote the code; the contributor reviewed and verified it |
| Mostly AI-generated | AI produced the draft; the contributor made substantial changes |
| Mostly human-written | The contributor led the work; AI was limited or unused |

All three levels are acceptable. AI assistance does not reduce contributor
responsibility. Before submitting AI-generated code, you must:

- read and understand every line;
- test it in a real environment;
- review paths, external input, credentials, and command execution for security
  issues; and
- verify actual behavior rather than relying on plausible-looking code.

AI-generated and human-written code have the same quality bar: all checks must
pass, code must follow established Go and repository conventions, unnecessary
abstractions and dead code must be avoided, and tests must be updated where
appropriate.

## Pull requests

Before opening a pull request:

- run `make check`;
- complete the entire pull-request template, including the AI disclosure;
- link related issues;
- document the test environment and provide verification evidence when useful;
  and
- keep the change focused and reviewable.

The template asks for a description, change type, AI disclosure, related issue,
technical context, test environment, verification evidence, and a self-review
checklist.

## Branch and merge policy

`main` is the active development branch. `release/x.y` branches are created
when a release stabilizes. New features are not backported after a release
branch is cut; maintainers may cherry-pick critical security, data-loss, or
crash fixes.

A pull request can merge only after all CI checks pass, at least one maintainer
approves it, all review threads are resolved, and the template is complete.
Only maintainers merge pull requests. Squash merge is the default, although a
maintainer may retain a well-structured series of commits where it tells a
useful story.

## Review

Respond to feedback in a reasonable time, explain follow-up changes, and state
technical disagreements respectfully. Avoid force-pushing after review begins.
Reviewers should focus on correctness, security, architecture, simplicity, and
tests, and should provide specific, actionable feedback.

Current review contacts are maintained in the Chinese translation beside this
document. Open a GitHub issue or discussion for general design questions, and
use pull-request comments for change-specific discussion.

OpenFox has been built with significant AI assistance under human supervision.
Responsible AI-assisted development and human accountability are complementary:
the quality and safety of the submitted result remain what matter.
