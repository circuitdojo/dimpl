# Review: `dtls-conn-id` against `main`

## 1. Summary

**Disposition: ship-with-fixes.**

Two clippy errors are introduced by the branch and fail
`cargo clippy --all-targets -- -D warnings` (the project's CI gate). They
are mechanical (`unnecessary_lazy_evaluations` on the new `CidState`
helpers) and trivial to fix. No security blockers were found in the
DTLS 1.2 CID or session-resumption work — parse-before-auth ordering,
replay-window discipline, EMS / cipher-suite / client-auth binding on
resumption, and the typestate split (`SessionCandidate → vet() →
VettedSession`) all hold up. RFC 9146 §3 zero-length-CID handling and
RFC 7627 §5.3 EMS binding on resumption are correctly implemented and
covered by negative tests. `cargo test` is green (410 passed, 4
ignored). `cargo fmt --check` is clean.

## 2. Blocking issues

### B1. Clippy fails on branch-introduced `unnecessary_lazy_evaluations`

`src/dtls12/engine.rs:1310` and `src/dtls12/engine.rs:1320`, both new on
this branch. With `-D warnings` (the contract from REVIEW-PROMPT.md),
this is a build failure.

```rust
pub fn inbound_cid(&self) -> Option<&[u8]> {
    self.inbound_active
        .then(|| self.ours.as_deref())   // <-- error
        .flatten()
        .filter(|c| !c.is_empty())
}
```

```rust
pub fn outbound_cid(&self) -> Option<&[u8]> {
    self.outbound_active
        .then(|| self.theirs.as_deref())  // <-- error
        .flatten()
        .filter(|c| !c.is_empty())
}
```

Confirmed not present on `main` (verified via `git stash -u && git
checkout main && cargo clippy --all-targets -- -D warnings`). Only
pre-existing clippy errors on `main` are `items_after_test_module`,
`redundant_pattern_matching`, and `collapsible_str_replace` — none in
the branch's edit surface.

**Fix:** `then_some(self.ours.as_deref())` /
`then_some(self.theirs.as_deref())` per clippy's hint. The
`flatten().filter()` chain is fine.

## 3. Non-blocking issues

### Correctness (category 2)

- **C1. AEAD-failure error propagation, not silent discard.**
  `src/dtls12/incoming.rs:299` — `decrypt.decrypt_data(&mut buffer,
  aad, nonce)?` propagates a `CryptoError` all the way out of
  `parse_packet → handle_packet`. RFC 6347 §4.1.2.7 says invalid
  records "SHOULD be silently discarded." A single forged ciphertext
  on a connected session triggers `Err` at the `Dtls::handle_packet`
  boundary, which most callers will treat as terminal. **Pre-existing
  on `main`** (verified with `git show main:src/dtls12/incoming.rs`),
  not the branch's responsibility per REVIEW-PROMPT.md, but the
  branch touched the surrounding code and could have fixed it cheaply
  by mapping the error to `Ok(None)` like the other discard paths.

- **C2. `decrypt_record` slice can panic on undersized fragment.**
  `src/dtls12/incoming.rs:293` — `let ciphertext = &mut buffer[ciph..]`
  where `ciph = HEADER_LEN + explicit_nonce_len`. After in-place CID
  strip, `buffer.len() = 13 + dtls.length`. A peer-controlled
  `dtls.length < explicit_nonce_len` (8 for AES-GCM) panics on the
  slice. There is no upstream length check forcing
  `length ≥ explicit_nonce_len` in `DTLSRecord::parse`. **Pre-existing
  on `main`**; the branch did not regress it but the new CID strip
  shares the same cliff.

- **C3. Unsolicited-CID skip uses zero-length-CID framing assumption.**
  `src/dtls12/incoming.rs:99` — when CID is not negotiated and a
  `tls12_cid` record arrives, the parser reads
  `length = u16::from_be_bytes([packet[11], packet[12]])` assuming
  the minimum 13-byte header. If the sender used a non-zero CID, the
  length field is at the wrong offset; the computed `record_end` is
  meaningless and trailing records mis-frame. The bounds check on
  `record_end > packet.len()` keeps it from indexing OOB, but the
  trace message at `incoming.rs:108-111` is the only signal that
  follow-on records may be lost. The trade-off is documented in
  the surrounding comment and the commit message for 53924f2; not
  fixable without out-of-band knowledge of the sender's CID length.
  Acceptable as-is; document the constraint more loudly in
  `RecordDecrypt::our_cid` as a footgun for callers that emit
  spurious `tls12_cid` records.

- **C4. `assert!` in `CidState::activate_*` is load-bearing on
  caller invariants.** `src/dtls12/engine.rs:1280, 1287` —
  `activate_inbound`/`activate_outbound` panic if their precondition
  (`ours.is_some()` / `theirs.is_some()`) fails. Callers
  (`server.rs:611`, `server.rs:1267`, `server.rs:1298`,
  `client.rs:657`) gate on `is_some_and(|c| !c.is_empty())` before
  calling, so panic is not reachable today. CLAUDE.md prefers
  `assert!` over `debug_assert!` for `pub` methods whose callers
  are not provably correct, so the choice itself is right; flagging
  only because the panic would be a silent footgun if someone
  reorders activation in a future refactor. Consider returning
  `Result<(), Error>` and surfacing as `SecurityError`.

- **C5. `ConnectionIdExtension::parse` ignores trailing bytes.**
  `src/dtls12/message/extensions/connection_id.rs:24-31` — both call
  sites (`client.rs:617`, `server.rs:423`) discard the `remaining`
  slice with `let (_, cid_ext) = ...`. RFC 9146 §3 says the
  extension data is exactly a `ConnectionId` structure; trailing
  junk should be a malformed extension. Not exploitable since the
  CID is bounded ≤255 bytes by the parser, but the looseness
  undercuts the otherwise-strict "parse failure is a SecurityError"
  stance taken by both call sites.

- **C6. Resumed-server CID activation gate misses zero-length-CID
  case.** `src/dtls12/server.rs:1264-1266` and `1294-1297` — guards
  on `peer_offered() && config().connection_id().is_some()`. Both
  can be true with one or both CIDs zero-length, in which case
  `activate_inbound`'s precondition (`ours.is_some()`) holds —
  because `set_ours` is gated on `our_non_empty && peer_non_empty`
  in `send_server_hello` (server.rs:608-616) — so this **doesn't**
  panic in practice. But the gate at line 1264 is internally
  inconsistent with the gate at line 610: the latter rejects empty
  CIDs, the former does not. If the gate at 610 changes (e.g., to
  allow zero-length advertisement on one side), the gate at 1264
  will silently activate inbound CID with `ours = None` and panic
  on `assert!`. Mirror the `our_non_empty && peer_non_empty` check
  here for consistency.

- **C7. `Output::SessionData` ordering.** `src/dtls12/server.rs:1303-1373`
  — within `emit_handshake_complete` the order is `Connected`,
  then `ConnectionId`, then `KeyingMaterial`, then `SessionData`.
  The doc comment on `Output::SessionData` (`src/lib.rs:687-695`)
  says "after `Connected`", which matches. On the resumed-server
  path, `await_finished` pushes `LocalEvent::PeerCert` *then* calls
  `emit_handshake_complete`, so the polled order is PeerCert →
  Connected → CID → KeyingMaterial → SessionData. Intended ordering;
  flagging only that there is no test asserting the order on the
  resumed paths beyond peer-cert-vs-connected.

### Style / CLAUDE.md (category 3)

- **S1. `CidState` impl block placement.** CLAUDE.md §"File Ordering"
  rule 4 — "Related types, ordered by first appearance in primary
  type's fields/variants." `Engine.cid: CidState` is declared at
  `src/dtls12/engine.rs:111`. The branch's working-tree refactor
  moves the `impl CidState` block to **after** `impl Engine`
  (engine.rs:1247-1325) — i.e. after the helper `cid_from_slice`
  function and after the `RecordDecrypt for Engine` trait impl.
  Per CLAUDE.md the `impl` for a related type should sit near its
  definition (lines 128-142), before helper functions and standard
  trait impls. The committed history (commit 53924f2) had it nearer
  the type; the working-tree change moved it. Per the prompt,
  working-tree changes are in scope.

- **S2. `MasterSecret::dangerously_into_vec` ManuallyDrop comment
  reads as if it leaks memory.** `src/config.rs:55-65` — the
  comment explains the `ManuallyDrop` + `mem::take` no-op leak.
  Slightly misleading: "the wrapper itself is then leaked" reads
  as "we leak memory." The wrapper is stack-allocated and the inner
  `Vec` is left empty by `mem::take`, so nothing is leaked; the
  only thing skipped is the `Drop` (zeroize) pass. Reword to make
  this explicit.

- **S3. `LocalEvent` visibility bumped to `pub`.**
  `src/dtls12/client.rs:117` — visibility was `pub(crate)` on main;
  the branch promotes it to `pub`. CLAUDE.md says prefer `pub` over
  `pub(crate)`, so this is consistent — but `LocalEvent` is an
  internal staging type for events that get translated to `Output`
  by `into_output`. `LocalEvent` is not re-exported from `lib.rs`,
  so the public surface didn't actually change (the `client` module
  is `pub(crate)` upstream). Confirm the intent.

- **S4. `Aad::new_dtls12_cid` magic constant 278.** `src/crypto/dtls_aead.rs:193`
  — extract a `pub const AAD_CID_MAX_LEN: usize = 23 + 255;` so the
  capacity has a name. Currently the relationship between the 278
  literal and `23 + 255` is only in the docstring.

### Testing (category 5)

- **T1. No test for AEAD failure on a CID record with a matching
  wire CID but tampered ciphertext.** The branch's regression test
  `dtls12_cid_tampered_record_is_dropped`
  (`tests/dtls12/cid.rs:973`) flips a CID byte, exercising the new
  wire-CID-mismatch path. It does NOT test "valid CID + tampered
  ciphertext"; that would exercise the AEAD-failure path C1. Adding
  such a test would surface C1 as a real assertion (the test would
  likely fail today, demonstrating that the error escapes
  `handle_packet`).

- **T2. No negative test for `dtls.length < explicit_nonce_len` on
  CID decrypt path.** See C2. A peer-controlled length of 0..7 on
  an AES-GCM CID record would panic. Add a fuzz / negative test.

- **T3. Resumed-client retransmit-silent-stop path is not tested
  in the silent-server case.** `Client::send_finished` (resuming
  branch, `src/dtls12/client.rs:1289-1300`) calls
  `flight_retransmit_optional()`. The existing tests drive an app-data
  reply from the server. A test where the server stays silent (no
  app data) until backoff exhaustion is needed to confirm the
  silent-stop path actually disables the timer instead of surfacing
  `Error::Timeout("handshake")`.

### Documentation (category 6)

- **D1. `RecordDecrypt::our_cid` rustdoc.**
  `src/dtls12/incoming.rs:422-423` — currently "Returns our CID
  if CID was negotiated (what the peer puts in records to us)."
  Misleading: the `Engine` impl returns `None` when CID was
  negotiated but `inbound_cid` is empty (zero-length advertisement)
  or when inbound is not yet active. Update to "Returns our
  non-empty inbound CID iff inbound CID is active."

- **D2. `Output::SessionData` doc could include a worked example.**
  `src/lib.rs:687-695` — clear on the vetting contract. Consider
  adding a code example that shows
  `match candidate.peer_certificate() { ... candidate.vet() ... }`.

## 4. Per-commit notes

- **b959fac (Implement DTLS 1.2 Connection ID, RFC 9146).** Foundational.
  Most of the wire-format work lives here. Style + correctness of the
  initial `Aad` struct (later refactored to enum), CID state on `Engine`
  (later consolidated into `CidState`), and the `connection_id`
  extension. The original `Aad` was a 278-byte `ArrayVec` on the
  hot path — fixed in 53924f2 with the enum split.

- **3fc87c3 (DTLS 1.2 session resumption with constant-time secret
  compare).** Adds `MasterSecret` zero-on-drop wrapper, `SessionStore`
  trait, and the abbreviated handshake flow. `MasterSecret::PartialEq`
  uses `subtle::ct_eq` — correct. The original commit predated the
  EMS / cipher-suite / client-auth bindings that landed in 587a688
  and e2f5c07.

- **587a688 (Cleanup and edge-case hardening).** Bulk of RFC 7627 §5.3
  EMS binding, RFC 5246 §7.4.1.1 cipher-suite binding, AAD-capacity
  fix (64 → 278), `dangerously_into_vec` rename, `Arc<StoredSession>`
  in `SessionStore::lookup`, and the in-place CID strip optimization
  on the decrypt hot path. Substantial — most of the resumption
  hardening lives in this commit.

- **e2f5c07 (Resumption auth hardening).** Two real security fixes:
  (P1) server no longer auto-populates `SessionStore` — applications
  must vet `PeerCert` first; (P2) abbreviated-handshake
  client-auth-policy binding via `client_authenticated` field.
  `StoredSession` becomes `non_exhaustive`. CID fields go private
  with getter/setter helpers per CLAUDE.md "fields private."
  Correct and well-justified.

- **f75a575 (Authenticate on-wire CID before decrypting).** RFC 9146
  §5.2 AAD-binding: previously the AAD was built from the locally
  configured CID, so a rewritten on-wire CID still decrypted. This
  commit captures the wire CID, constant-time compares against ours,
  silently discards on mismatch, and feeds the wire bytes into the
  AAD computation. Replay window not advanced on mismatch. Correct.

- **47ba22a / c693e5c (PeerCert on resumed sessions).** Mechanical
  fix to ensure `LocalEvent::PeerCert` fires on the resumed
  client/server. Original implementation pushed PeerCert before
  Finished verified — the working tree later corrected this to
  defer until Finished MAC verifies. Without that fix, an on-path
  attacker could echo a session ID and surface a PeerCert event
  the application might trust. The deferral is the right call.

- **53924f2 (Architectural tidy + style + unsolicited-CID).** Five
  threads squashed: (1) `Aad` enum split for hot-path size
  reduction, (2) CID state consolidation into `CidState`, (3)
  `SessionCandidate → vet → VettedSession` typestate, (4) eight
  CLAUDE.md style fixes, (5) preserve trailing records after an
  unsolicited `tls12_cid` record. The typestate is the most
  significant — `SessionStore::store` and `Dtls::new_12_resume`
  now accept only `VettedSession`, making the vet-before-resume
  contract a compile-time check.

## 5. Verification performed

| Command | Result |
|---|---|
| `cargo build` | OK (clean) |
| `cargo test` | 410 passed, 4 ignored, 0 failed |
| `cargo fmt -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | **3 errors**, 1 warning |

Clippy errors:
- `src/dtls12/engine.rs:1310` — `unnecessary_lazy_evaluations` (**branch-introduced**)
- `src/dtls12/engine.rs:1320` — `unnecessary_lazy_evaluations` (**branch-introduced**)
- `src/crypto/prf_hkdf.rs:215` — `collapsible_str_replace` (**pre-existing on main**, verified by checking out main and re-running)

Pre-existing clippy errors on `main` not present on the branch's
diff: `items_after_test_module`, `redundant_pattern_matching`. These
appear to have been incidentally cleaned up on the branch.

## 6. Open questions for the author

1. **C1 (AEAD-failure propagation).** Was the propagation of
   `CryptoError` out of `decrypt_record` an intentional choice for
   this branch, or inherited and untouched? The commit message for
   f75a575 mentions that wire-CID mismatch returns `Ok(None)` —
   should AEAD-tag mismatch on a CID record be similarly downgraded?
   RFC 6347 §4.1.2.7 says SHOULD silently discard.

2. **C6 (resumed-server CID activation gate).** The `assert!`
   in `activate_inbound` is unreachable today because the
   `set_ours` gate in `send_server_hello` filters empty CIDs. Is
   the intent that `activate_inbound`/`activate_outbound` callers
   carry the empty-CID guard, or that the activator carry it? The
   two gates are spread far enough apart that a future refactor
   could break one without noticing the other.

3. **S3 (`LocalEvent` visibility).** Was the bump from `pub(crate)`
   to `pub` deliberate, or fallout from a sweep? `LocalEvent` is
   not re-exported from `lib.rs`, so the public surface didn't
   actually change, but the visibility doesn't match the type's
   role as an internal event-staging type.

4. **`dangerously_into_vec` no-op leak comment.** The `ManuallyDrop`
   wrapper is stack-allocated and the inner `Vec` is left empty by
   `mem::take`. Nothing is leaked. Is the "leaked" wording
   intentional rhetoric to discourage callers, or an actual
   description that should be reworded?
