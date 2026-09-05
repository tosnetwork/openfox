# Working on openfox

## Instruments lie by staying silent

A measurement that returns nothing is not an answer. Before trusting silence,
prove the instrument speaks.

Go is unusually good at reporting success for work it never did. A package with
no test files prints `no test files` and `go test ./...` still exits zero. A
test behind a build tag you did not enable never runs and never complains. A
`t.Skip` on a missing fixture is indistinguishable, in the summary line, from a
pass.

### A test that cannot fail is not evidence

Before believing a new test, **remove the thing it tests and watch it go red.**
If it stays green, it is measuring nothing.

This matters most for the tests we care about most: "the unauthorized caller is
rejected", "the malformed envelope is dropped", "the reservation is held while
ambiguous". Any error makes those pass — including an error in the setup that
means the code under test never executed.

### Running your own test is not running the suite

`1337e49e` added a diagnostic to the settlement sink. Its own new test passed,
and it was pushed. It had broken
`TestTOSCTLRunnerUsesSharedOutputBudgetAndRedactedErrors`
(`pkg/earning/tosctl_executable_test.go:206`), an existing invariant test
asserting that tosctl diagnostics never escape the redacted-error boundary. The
whole change was reverted in `3fb71a24`.

The subset you wrote passes because you wrote it to pass. **Run the package
suite before pushing anything that touches a shared path** — `pkg/earning` takes
a couple of minutes, which is cheaper than a revert.

### Local traps

**A skipped fixture is a silent hole.** Tests that need a built binary, a live
chain, or a large workload skip when it is absent. The run stays green and
covers nothing. When a suite is meant to be authoritative, make the missing
fixture an error rather than a skip, and say so in the test name.

**Golden vectors that regenerate on mismatch test nothing.** The cross-language
contracts here require Go, Rust and FunC to agree byte-for-byte. A golden test
that rewrites its expected file when it differs will agree with anything.
Goldens are regenerated deliberately, in their own commit, with the diff read.

**Crash-safety cannot be mocked.** Durable-cursor and exact-BOC recovery paths
are exactly the code whose bugs only appear when the process actually dies.
Kill it. A fake that returns an error where a crash would have happened tests
the fake.

**A concurrency test that passes once passes nothing.** Serialization,
reservation and fencing tests need repetition and `-race`; a single green run of
a scheduling-dependent test is a coin flip you called correctly.

## Conventions

- Financial arithmetic uses checked operations. A bound that holds "because of
  a limit declared elsewhere" is a dependency on a constant nobody will
  remember to re-check.
- Errors are handled explicitly and carry enough context to act on. Never
  discard one to make a signature tidy.
- Authority code — anything that decides what may be signed, spent or
  reserved — stays in the core process and is not delegated behind a boundary
  that cannot be checked. See `docs/architecture/capability-boundary.md`.
- Do not reference external project names or issue trackers in comments or
  commit messages. Comments explain intent, not history.

`CLAUDE.md` is a symlink to this file, so Codex and Claude Code read the same
instructions.
