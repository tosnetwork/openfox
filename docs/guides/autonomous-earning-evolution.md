# Autonomous Earning Evolution

OpenFox can turn repeated, successful earning executions into local procedural
skills. Learning remains advisory: it cannot create an Agreement, reserve
resources, start execution, disclose data, publish an Intent, or authorize a
payment.

## Safety boundary

Reusable learning is enabled only for an execution obligation whose canonical
Agreement sets `confidentiality_and_disclosure_policy` to
`public-reusable-learning`. Participant-confidential work does not enter the
reusable-skill pipeline.

The learning record contains the public task description and a de-identified
success statement. It never contains the raw Agreement, participant IDs,
payment fields, credentials, immutable inputs, or deliverable body. Generated
skills still pass the evolution safety review, scanner, atomic apply, and
rollback path before they become available.

When an earning Agent has exactly one owner-authorized capability, its
canonical capability identifier is used as a structural clustering key. This
lets distinct tasks for the same capability produce one reusable pattern
without asking the model to infer capability ownership. The key affects
clustering only; it does not create capability evidence or expand authority.

At execution time, reviewed workspace skills are loaded as untrusted
procedural notes. OpenFox accepts at most 16 regular, non-symlink skill files
and applies one shared 64 KiB read and prompt budget. Skills cannot add tools,
network access, credentials, spending authority, or bypass the local Execution
Gate.

## Lifecycle

```text
finalized Agreement authorization
-> local Execution Gate
-> bounded execution and deliverable digest
-> successful execution evidence
-> disclosure-policy check
-> de-identified learning record
-> repeated-pattern threshold
-> draft generation
-> safety review and scan
-> atomic local skill apply
-> bounded procedural reuse on a later authorized execution
```

An unavailable model, rejected draft, scanner failure, or learning-state write
failure is observable but does not invalidate an already produced economic
deliverable. Failed or ambiguous economic execution is never recorded as a
successful learning example.

## Operator guidance

- Use `public-reusable-learning` only when the task description itself is safe
  to reuse across counterparties.
- Keep private client data in participant-confidential obligations.
- Inspect the workspace `skills/` directory and the configured evolution state
  directory when reviewing how an Agent changed.
- Quarantine a suspect skill and its source learning state before allowing the
  Agent to execute another engagement.
- Treat skill counts as capability evidence, not as economic authorization or
  proof that a skill is profitable.
