# Branch Review Prompt

You are performing a full, detailed code review of a branch against `main` in
the dimpl repository (a Sans-IO DTLS 1.2 / 1.3 implementation in Rust). Treat
this as a merge-gating review: be exhaustive, specific, and cite file paths
with line numbers.

The prompt is branch-agnostic. Substitute `<BRANCH>` with the branch under
review.

## Scope

Review every commit on `<BRANCH>` that is not on `main`. Start with:

```sh
git log --oneline main..HEAD
git diff main...HEAD --stat
git diff main...HEAD
```

For each commit, read the full body (`git log -1 --format=%B <sha>`) — commit
messages on this project carry design rationale that the diff alone does not.

Cover **all** changes on the branch, not only the themes in the most recent
commit messages.

## Review Criteria

### 1. Correctness & Security (highest priority; security issues are always blocking)

- **Parse-before-auth ordering**: any attacker-controlled bytes that influence
  state before MAC/AEAD verification are a finding. Specifically for DTLS:
  on-wire CID, epoch, sequence number, version bytes must be authenticated
  before decryption advances state.
- **Replay window**: must advance **only** after successful MAC / AEAD
  verification (RFC 6347 §4.1.2.6). Any path that bumps the window on a
  dropped / undecryptable record is a blocker.
- **Session resumption auth**: cached sessions cannot be hijacked, replayed,
  downgraded, or resume under tightened policy (e.g., `require_client_certificate`
  turned on post-cache). `PeerCert` emission on resumed sessions must use the
  cached, previously-verified certificate — not peer-controlled bytes.
- **Typestate for dangerous operations**: vetting contracts (e.g.,
  `SessionCandidate → vet() → VettedSession`) must be compile-time
  preconditions, not runtime checks.
- **RFC conformance**: for each RFC the branch claims to implement, spot-check
  the specific sections (e.g. RFC 9146 §3 / §4 / §5, RFC 7627 §5.3, RFC 5246
  §7.4.1.1). Cite the RFC section when flagging.
- **No panics on attacker-controlled input**: every `unwrap`, `expect`, slice
  index, `[..n]`, `copy_from_slice`, `try_extend_from_slice`, and arithmetic op
  on parsed bytes must be provably safe. `try_extend_from_slice(...).unwrap()`
  patterns are only acceptable with a documented invariant (usually a config
  or RFC-size check upstream).
- **Constant-time comparisons** for secret-dependent equality (MACs, verify
  data, master secrets, CIDs used as auth metadata). `subtle::ConstantTimeEq`
  or equivalent — not `==`.
- **Buffer bounds**: single-copy / in-place mutation paths must not read or
  write past record boundaries. Check strip-in-place, length overwrites, and
  DTLSInnerPlaintext unwrap.
- **Zeroization**: secret material (master secrets, session tickets) wrapped
  in a zero-on-drop type. Any escape hatch out of the wrapper must be loudly
  named and documented.
- **Sans-IO API Contract (CLAUDE.md)**:
  - Poll-to-Timeout rule: every `handle_packet` / `handle_timeout` must be
    followed by a polling path that eventually yields `Output::Timeout`.
  - No sockets, threads, async, or wall-clock calls introduced. `Instant`
    must be caller-provided.
  - Internal state only observable as consistent after `Timeout`.

### 2. Correctness (non-security)

- Invariants asserted with `debug_assert!` that guard reachable state in
  release builds (e.g., precondition checks on `pub` methods whose callers
  are not provably correct) should be `assert!`.
- `Output::*` event ordering must match the pattern the rest of the codebase
  establishes (e.g., `PeerCert` before `Connected`, `SessionData` after
  `Connected`). Deviations on new code paths (e.g., resumed sessions) are a
  correctness finding even when the underlying pattern has predates the
  branch.
- Log messages (`trace!`/`debug!`) on security-relevant discard paths should
  be disambiguable — two distinct reasons that produce identical trace output
  will mask post-mortem signal.
- State-machine reentrancy: every branch that enters a state should have a
  return path that leaves the engine in a consistent state (timers stopped
  or rearmed, queues drained or deferred).

### 3. File & Code Style (CLAUDE.md — treat as blocking for maintainability)

- **File ordering** (general files):
  1. Imports
  2. Constants
  3. Primary type (matches module name: `foo.rs` → `struct Foo`)
  4. Related types, ordered by first appearance in the primary type's fields/variants
  5. `impl` block for the primary type
  6. Helper types and functions
  7. Standard trait impls (`Display`, `Debug`, `From`)
  8. Tests (`#[cfg(test)] mod tests`)
- **State machine files** (`client.rs`, `server.rs`):
  1. Module-level comment documenting protocol flow
  2. Imports
  3. Primary struct
  4. `State` enum (variants in protocol order)
  5. `impl PrimaryType` (public API: `new`, `handle_*`, `poll_*`)
  6. `impl State` (`name()`, `make_progress()`, then handlers in enum order)
  7. Free helper functions (ordered by first use in protocol flow)
- **Imports**: std → external → crate, alphabetical within groups, blank line
  between groups. Short paths (`std::Vec`, not `std::vec::Vec`).
- **Modules**: private modules with selective `pub use` re-exports.
- **Visibility**: `pub` preferred over `pub(crate)`. Only use `pub(crate)`
  when explicitly preventing items from becoming part of the public API —
  items in an already-private module don't need `pub(crate)`.
- **Fields private**, exposed via getters.
- **Unwrap comments**: every new `unwrap()` / `expect()` carries a
  `// unwrap: ...` (or `// expect: ...`) comment naming the invariant that
  makes it safe.
- **Doc examples**: must compile and run as tests. Never `ignore`. `no_run`
  only when hardware/network required.
- **No trailing task-specific comments** (`// removed for Y`, `// added for
  issue #123`): belongs in the PR description, not the code.

### 4. Memory Discipline (CLAUDE.md)

- Buffer pooling: cleared-but-retained capacity, no per-packet malloc/free in
  hot paths.
- Single-copy parsing: one network→buffer copy, then in-place parse / decrypt.
- Large inner data boxed for ABI (outer structs fit in registers).
- Bounded stack collections (`ArrayVec`) with explicit failure on overflow.
- Flag any new `Vec::new()` in a per-record or per-packet path.

### 5. Testing

- Every new behavior has direct unit or integration tests.
- Negative tests exist for every security property claimed (tampering
  detection, unsolicited records, policy tightening, malformed cache entries,
  replay window behavior).
- Tests don't rely on wall-clock time; they drive `Instant` explicitly.
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --
  --check` all pass. Report any failures verbatim; distinguish
  branch-introduced from pre-existing failures by checking out `main` and
  re-running.

### 6. Documentation

- Public items have rustdoc.
- RFC-implementing public API references the RFC and section.
- Rustdoc warns the caller about footguns introduced by the branch (e.g.,
  event-ordering hazards, process-local `Instant` semantics, zeroize not
  crossing trait boundaries).

## Blocker vs. Non-Blocker Classification

**Blockers** (must be fixed before merge):
- Any Security / Correctness finding in category 1.
- `cargo fmt --check` failures introduced by the branch.
- `cargo clippy --all-targets -- -D warnings` failures introduced by the
  branch (pre-existing failures are **not** the branch's responsibility —
  flag separately).
- `cargo test` failures introduced by the branch.
- Public-API panics reachable from attacker-controlled input.
- Missing `unwrap()` safety comments on new unwraps.

**Non-blocking**:
- Correctness findings in category 2 (ordering, debug_assert-vs-assert, log
  disambiguation) that match a pre-existing pattern in the codebase.
- Style / CLAUDE.md violations in category 3.
- Test-coverage gaps where the existing behavior is not security-relevant.
- Doc-only findings.

When in doubt, prefer blocking. Call out the classification explicitly for
each finding.

## Output Format

Structure the review as:

1. **Summary** (3–5 lines): ship / ship-with-fixes / block, plus the top
   reason.
2. **Blocking issues**: each with `file:line`, problem, suggested fix.
3. **Non-blocking issues**: grouped by category (correctness / style / test /
   doc), each with `file:line`.
4. **Per-commit notes**: one short paragraph per commit calling out anything
   specific to that commit.
5. **Verification performed**: commands run and their results. Distinguish
   branch-introduced failures from pre-existing ones (check out `main` and
   re-run when in doubt).
6. **Open questions for the author**: anything you could not verify without
   design context.

## Rules of Engagement

- Cite `file:line` for every concrete claim.
- Quote the offending code when flagging an issue.
- Do **not** fix issues — this is review-only. Propose diffs only when it
  clarifies the critique.
- Prefer reading the code over trusting commit messages.
- If a CLAUDE.md rule conflicts with existing code on `main`, note it but
  don't hold the branch responsible for pre-existing violations.
- When the user asks for "issues only" in a follow-up, suppress the "things
  we did right" / summary-of-successes sections.
- Be blunt. No hedging, no filler praise.
