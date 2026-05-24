# Review Issue Tracker

Working tracker for review findings from the current patch. Keep this document updated as issues move from triage to implementation and verification.

## Status Key

- `Open`: confirmed issue, not yet fixed.
- `In Progress`: fix is being implemented.
- `Fixed`: code change is complete, pending or passing verification noted.
- `Deferred`: intentionally not fixed in this patch, with rationale.

## Issues

| ID | Priority | Status | Area | Summary |
| --- | --- | --- | --- | --- |
| R1 | P1 | Open | DTLS 1.2 PSK config | Exclude all PSK-authenticated cipher suites when no PSK credentials are configured. |
| R2 | P2 | Open | CID validation | Do not reject DTLS 1.3-only configs just because a connection ID is set. |
| R3 | P2 | Open | Public crypto API | Preserve `Aad` tuple field compatibility for downstream provider crates. |

## R1: Exclude ECDHE-PSK Suites Without PSK Credentials

- Priority: `P1`
- File: `src/config.rs`
- Current concern: the no-PSK filter only removes `PSK_AES128_CCM_8`, while `ECDHE_PSK_CHACHA20_POLY1305_SHA256` can remain because `is_psk()` is false for that suite.
- Impact: configs can build with ECDHE-PSK suites and no `with_psk_*` credentials, then fail during handshake after being classified as PSK-only.
- Expected direction: when PSK credentials are absent, filter out every suite that skips certificate authentication, not just pure PSK suites.
- Verification target: add or update a config test proving ECDHE-PSK suites are removed or rejected when no PSK credentials are configured.

## R2: Allow DTLS 1.3-Only Configs With Connection ID

- Priority: `P2`
- File: `src/config.rs`
- Current concern: shared builder validation rejects `with_connection_id(...)` whenever the DTLS 1.2 suite set is empty.
- Impact: callers cannot build a DTLS 1.3-only config with a connection ID, even though `Dtls::new_13` is expected to ignore connection IDs.
- Expected direction: move or narrow the CID validation so it applies only to auto or DTLS 1.2 runtime paths that can actually use RFC 9146.
- Verification target: add or update a test proving DTLS 1.3-only config builds successfully with a connection ID.

## R3: Preserve `Aad` Public Tuple Field Compatibility

- Priority: `P2`
- File: `src/crypto/dtls_aead.rs`
- Current concern: `Aad` changed from `pub struct Aad(pub ArrayVec<...>)` to a tuple struct with a private field.
- Impact: downstream crypto-provider crates that construct `Aad(...)` or read `aad.0` will fail to compile after upgrading.
- Expected direction: keep the public tuple field for source compatibility while retaining any added convenience APIs such as `Deref` or `as_slice`.
- Verification target: compile-time coverage or an existing test/example that constructs `Aad(...)` and accesses `aad.0`.

## Verification Log

- Pending: no fixes have been implemented yet.
