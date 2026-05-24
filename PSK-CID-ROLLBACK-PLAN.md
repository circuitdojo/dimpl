# PSK + CID Rollback Plan from `b959fac`

## Goal

Define what should be done if the branch is rolled back to commit
`b959fac` (`Implement DTLS 1.2 Connection ID (RFC 9146)`) and the work is
restarted with a narrower product goal:

- DTLS 1.2
- PSK authentication
- IoT devices that may change IP address / port while the DTLS association
  remains active
- Minimal added complexity beyond what is required to make CID safe and
  operationally useful

This document is **not** a plan to re-apply the current branch as-is.
It is a rewrite plan for a reduced scope.

## Product Intent

The main feature is:

- Keep an active DTLS 1.2 session alive across path changes by using
  Connection ID (CID) instead of the UDP 5-tuple as the stable transport key.

The main feature is **not**:

- certificate-authenticated session continuity on resumed sessions
- preserving `Output::PeerCert` semantics across abbreviated handshakes
- building a general-purpose DTLS 1.2 session resumption framework with
  strong identity-vetting APIs

For this use case, CID is the value. Resumption is optional optimization.

## Scope Decision

If we roll back to `b959fac`, the rewrite should be split into two phases.

### Phase 1: must-have

Ship a PSK-focused, CID-safe DTLS 1.2 implementation.

This phase includes:

- CID negotiation
- CID record parsing and framing correctness
- CID authentication at the AEAD/AAD boundary
- replay-window correctness on dropped / undecryptable CID records
- handshake activation behavior that works when packets are reordered,
  retransmitted, or path changes happen mid-connection
- PSK interoperability and tests for CID paths

This phase does **not** include session resumption.

### Phase 2: optional

Add PSK session resumption only if measurements show that the CPU or latency
 savings matter in the target deployment.

This phase should be explicitly PSK-only at first. Do not start by rebuilding
the certificate-oriented resumption machinery from the current branch.

## Non-Goals

The rewrite should intentionally avoid these until there is a concrete need:

- `PeerCert` emission on resumed sessions
- `SessionCandidate -> vet() -> VettedSession` typestate APIs
- certificate policy carry-forward across resumed handshakes
- shared abstractions designed primarily for certificate-authenticated
  resumption
- broad API surface for persistent session stores

Those were responses to the branch growing into general DTLS 1.2 resumption.
They are not required for PSK + roaming IoT.

## Required Work After Rolling Back to `b959fac`

## 1. Re-audit CID parse/auth ordering

`b959fac` adds the core CID feature, but the follow-up branch found that the
incoming CID path still needed hardening.

The rewrite must ensure:

- on-wire CID bytes are treated as attacker-controlled until authenticated
- the decryption path builds AAD from the CID bytes actually observed on the
  wire, not only from locally configured state
- a CID mismatch is handled as a silent drop, not as accepted traffic
- no state transition happens before AEAD verification succeeds

Concrete requirement:

- replicate the security property from later follow-up work equivalent to
  `f75a575`, but re-implement it cleanly for the reduced-scope codebase

Relevant RFC intent:

- RFC 9146 Section 5.2
- RFC 6347 Section 4.1.2.7

## 2. Preserve replay-window correctness

CID tamper or decrypt failure must not advance the replay window.

Concrete requirement:

- confirm that failed CID-auth or AEAD-auth records are dropped without
  consuming the sequence number in the receive window
- add a regression test that delivers:
  - a tampered CID record
  - then the original valid record with the same sequence number
  - and proves the valid retransmit is still accepted

Relevant RFC intent:

- RFC 6347 Section 4.1.2.6

## 3. Rework CID activation into an explicit state model

`b959fac` introduced CID, but later work shows the tricky part is not just
negotiation. It is deciding exactly when each direction starts expecting CID.

For the PSK-only rewrite, CID activation should be an explicit engine-level
state model with separate per-direction flags.

Minimum state needed:

- negotiated inbound CID value
- negotiated outbound CID value
- inbound CID active
- outbound CID active

Why this matters:

- one side may need to keep sending legacy-framed retransmits while the other
  side is not yet ready to parse CID-framed traffic
- this becomes visible during handshake loss, delayed packets, and path changes

This can be rewritten more narrowly than the current branch, but the
per-direction activation concept should be kept.

## 4. Handle stray / unsolicited `tls12_cid` records safely

The parser must discard the offending record without dropping unrelated
coalesced records in the same datagram.

Concrete requirement:

- when CID is not negotiated for that direction, a stray `tls12_cid` record
  must be skipped and discarded
- later records in the same datagram must still be processed when framing
  permits it

This behavior was explicitly corrected later and should be retained in the
rewrite, even if implemented differently.

Relevant RFC intent:

- RFC 9146 Section 4
- RFC 6347 Section 4.1.2.7

## 5. Keep CID memory-safety / bounds checks

The rewrite should keep the hard-won bounds discipline from the branch without
dragging in unrelated resumption APIs.

Concrete requirements:

- CID length validated to `<= 255`
- AAD construction capacity sized for worst-case CID
- no `unwrap` / `expect` / slice access on attacker-controlled CID lengths
  without a documented invariant
- no poll-buffer panic when surfacing negotiated CID to the caller

This is especially important because CID length is configuration-driven but
still feeds record parsing and output formatting.

## 6. Re-test PSK + CID directly

The rewritten branch should treat PSK as the primary path, not an afterthought.

At minimum, add or preserve tests for:

- PSK handshake with CID negotiation
- post-handshake application data exchange with CID enabled
- IP/port/path change simulation while the association remains active
- tampered CID drop behavior
- replay-window behavior after tampered CID drop
- unsolicited CID record handling

If possible, add a test harness that simulates rebinding more directly by
changing the transport tuple associated with an existing engine instance.

## 7. Avoid implementing resumption in the first rewrite pass

This is the main scope-control rule.

Why:

- CID already solves the active-connection mobility problem
- PSK resumption is about reconnect cost, not preserving the live session
  across address changes
- most of the branch complexity came from trying to make general DTLS 1.2
  resumption preserve authentication semantics

Recommendation:

- remove session resumption from the first milestone entirely
- only revisit it after CID behavior is stable and after measuring real device
  CPU / reconnect costs

## Optional Second Phase: PSK-Only Resumption

If resumption is later needed, write it specifically for PSK first.

That phase should follow these rules:

- no certificate-specific persistence fields
- no `PeerCert` resume semantics
- no application vetting typestate in the first pass
- store only what PSK resumption actually requires
- enforce EMS binding and cipher-suite binding from the start

For PSK-only resumption, the must-have correctness items are:

- same session ID / cache hit semantics
- EMS status binding
- cipher suite binding
- constant-time comparison for secret material
- expiration handling
- transparent fallback to full handshake on cache miss or invalid cache entry

Do not expand that design toward certificate-authenticated resumption unless a
real product requirement appears.

## Suggested Implementation Order

1. Roll back to `b959fac`.
2. Re-run the full test suite and capture the baseline behavior.
3. Re-implement CID on-wire authentication in the incoming decrypt path.
4. Add replay-window regression tests for tampered CID records.
5. Refactor CID activation into explicit inbound/outbound activation state.
6. Fix unsolicited-CID datagram handling.
7. Add PSK-focused CID integration tests, including rebinding scenarios.
8. Ship if this satisfies the product need.
9. Only then evaluate whether PSK-only resumption is worth the extra code.

## File Areas Likely To Change

Primary files:

- `src/dtls12/incoming.rs`
- `src/dtls12/engine.rs`
- `src/dtls12/client.rs`
- `src/dtls12/server.rs`
- `src/crypto/dtls_aead.rs`
- `tests/dtls12/cid.rs`

Files that should probably stay untouched in phase 1 unless required:

- `src/config.rs` beyond CID config cleanup
- `src/lib.rs` beyond public CID API/doc updates
- any session-store or resumption-specific API files

## Acceptance Criteria

The rollback rewrite is good enough to ship for the PSK IoT use case when all
of the following are true:

- PSK DTLS 1.2 sessions survive path change via CID
- tampered CID records are dropped silently
- dropped/tampered CID records do not advance replay state
- stray CID records do not corrupt parsing of unrelated records
- no attacker-controlled CID path can panic
- the implementation passes `cargo test`, `cargo fmt -- --check`, and
  `cargo clippy --all-targets -- -D warnings`
- the code does not include certificate-resumption machinery that the product
  does not use

## Decision Rule

If a piece of work mainly exists to preserve certificate-authenticated identity
across session resumption, it should be excluded from the rollback rewrite.

If a piece of work makes CID record handling safer or more correct on the wire,
it should stay in scope.
