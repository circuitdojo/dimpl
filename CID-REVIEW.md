# DTLS 1.2 Connection ID (RFC 9146) — Compliance Review

Overall the implementation is solid: the extension codepoint (54 / 0x0036), `tls12_cid` content type (25), AAD layout (23 + N CID), `DTLSInnerPlaintext` unwrap, per-direction activation (with empty-CID → legacy-framing correctly modeled in `CidState`), unsolicited-CID datagram recovery, wire-CID binding to AAD, silent-discard on AEAD/too-short/bogus-inner-type, and the legacy-framed-on-CID-active reject gate are all RFC-compliant against RFC 9146 + RFC 6347 §4.1.2.7.

Verification runs (2026-04-23):

- `rtk cargo test dtls12_cid --tests` — 19 passed.
- `rtk cargo test legacy_framed_record_dropped_when_inbound_cid_expected --lib` — 1 passed.
- `rtk cargo test cid_record_with_bogus_inner_type_is_silently_dropped --lib` — 1 passed.
- `rtk cargo test cid_record_with_empty_inner_content --lib` — 1 passed.
- `rtk cargo test dtls13_with_connection_id_config_does_not_negotiate_cid --tests` — 1 passed.
- `rtk cargo test dtls12_handshake_mtu_too_small_fails_closed --tests` — 1 passed.
- `rtk cargo test dtls12_error_variants_are_distinct --tests` — 1 passed.
- `rtk cargo test --doc with_connection_id` — 1 passed.

## Shipped Hardening (history)

The following findings from prior review passes have all landed and are verified in the current working tree:

- CID overhead in encrypted handshake fragmentation: `Engine::outbound_record_overhead` is shared by both `create_handshake` and `create_record` (`src/dtls12/engine.rs`).
- `2^14` plaintext / inner-plaintext limit before `u16` casts in `create_record` (`src/dtls12/engine.rs`).
- DTLS 1.2 sequence-number exhaustion guard returns `Error::SequenceNumberExhausted { epoch, sequence }` before record serialization.
- Zero-progress handshake fragmentation under small MTU plus long peer CID returns `Error::MtuTooSmall { overhead, mtu }` deterministically (regression test `dtls12_handshake_mtu_too_small_fails_closed`).
- Handshake fragment body capped by both MTU and `DTLS12_MAX_PLAINTEXT_LEN`.
- AAD binds the wire record version: `Aad::new_dtls12` / `Aad::new_dtls12_cid` thread `version: [u8; 2]` from `dtls.version` instead of a literal `0xFEFD` (`src/crypto/dtls_aead.rs`, `src/dtls12/engine.rs`).
- HelloVerifyRequest pair CID equality enforced by binding raw offered-CID extension bytes into the stateless cookie HMAC (`src/dtls12/server.rs`, regression test `dtls12_cid_server_rejects_swap_across_hello_verify_pair`).
- Misleading generic "replayed" trace removed; reason-specific traces remain at each silent-discard site.
- Alert ownership documented as caller responsibility in `Config::with_connection_id` rustdoc.
- Zero-length inner content over CID covered by `cid_record_with_empty_inner_content`.
- DTLS 1.3 scope boundary covered by `dtls13_with_connection_id_config_does_not_negotiate_cid`.
- CID privacy / linkability discussion added to `Config::with_connection_id` rustdoc.
- `Config::mtu()` documented as a coalescing target rather than a per-record ceiling.
- Duplicate supported Hello extensions (incl. duplicate `connection_id`) rejected at parse time on both ClientHello and ServerHello; `try_push` returns a parse error instead of panicking. Regression tests `duplicate_connection_id_extension_rejected` cover both directions.
- Duplicate unknown Hello codepoints also rejected via a raw-`u16` tracker (capacity 64), now using `try_push(...).map_err(...)?` so overflow fails the parse — closing the RFC 5246 §7.4.1.4 gap even under a saturation attack (`src/dtls12/message/client_hello.rs:230`, `src/dtls12/message/server_hello.rs:150`).
- Malformed / truncated CID-framed record boundaries are silent drops rather than surfaced `Err(ParseIncomplete)`. A too-short CID header, a length field that overshoots the datagram, or a non-CID record whose length runs past the datagram all `break` the parse loop with a reason-specific `trace!`. `TooManyRecords` still surfaces so the local capacity limit is not masked.
- Receive-side enforcement of the RFC 9146 §5.3 / RFC 6347 §4.1.1 `2^14` inner-plaintext ceiling: `Record::decrypt_record` silent-drops when `dtls.length - aead_overhead > DTLS12_MAX_PLAINTEXT_LEN` before AAD construction. Symmetric with the send-path check.
- Epoch-0 `tls12_cid` records fail at `DTLSRecord::parse` because the epoch-0 content-type allowlist excludes `Tls12Cid` (`src/dtls12/message/record.rs:65-77`); RFC 9146 §3's "once encryption is enabled" rule is enforced at the parse layer.
- `Output::ConnectionId(&[])` semantics documented in `Config::with_connection_id` rustdoc: the event fires once on successful negotiation in both non-empty and zero-length inbound cases, with a warning that an empty slice is not a valid routing key.
- DTLS 1.3 client explicitly rejects `Unknown(0x0036)` in ServerHello (`src/dtls13/client.rs:573-588`) **and** in `EncryptedExtensions` (`src/dtls13/client.rs:683-693`) with `Error::SecurityError`, so a non-conforming peer cannot smuggle CID through the silent-ignore path.
- `CidState` doc correctly names the two mutators (`set_cid_negotiated`, `activate_inbound_cid`) — the stale `activate_outbound_cid` reference is gone (`src/dtls12/engine.rs:104-112`).
- Pre-CCS CID-framed records are cleartext-filtered against the negotiated inbound CID before consuming a `queue_rx` slot (`src/dtls12/incoming.rs:322-352`), blunting a pre-CCS queue-fill DoS vector while keeping AEAD-time authentication unchanged.
- `Config::build` rejects the combination `with_connection_id` + zero surviving DTLS 1.2 cipher suites with `Error::ConfigError` (`src/config.rs:740-756`); regression test `dtls12_cid_with_no_dtls12_suites_fails_config_build`.
- Auto-mode hybrid ClientHello now emits `connection_id(0x0036)` when configured (`src/auto.rs:188-199`), so CH1 and CH2 carry identical offered-CID bytes across HVR and the stateless cookie binds once.
- CID stripping on the decrypt path is in place rather than allocating a fresh `Buf` (`src/dtls12/incoming.rs:839-841`, `:984-985`), restoring pool reuse.
- `Dtls::set_active` documents that post-`Connected` role flips are unsupported, since negotiated CID labels are preserved across `into_client` / `into_server` (`src/lib.rs`).
- `Config::with_connection_id` rustdoc now states that `Dtls::handle_packet` returning `Ok(())` is **not** an authentication signal — invalid records are silently discarded and still surface as `Ok(())`. The documented pattern for peer-address updates requires observing an authentication-positive output (ApplicationData, handshake progression, keying-material export) before committing (`src/config.rs:599-633`).
- DTLS 1.3 CID scope wording updated: comments now correctly attribute DTLS 1.3 CID to RFC 9147 §9 and describe dimpl's current rejection as "dimpl does not implement DTLS 1.3 CID", not "the RFC forbids it" (`src/dtls13/client.rs:573-588`).
- `decrypt_record` replay-window ordering on CID records is an intentional tighter-than-RFC invariant: the AEAD-covered inner-type sanity check runs before `replay_update`, so peer bugs emitting disallowed inner types do not consume a sequence slot. Documented at `src/dtls12/incoming.rs:525-558`; reviewed and accepted as a design choice.
- `Dtls::newest_authenticated_record()` (`src/lib.rs:386-396`) exposes `(epoch, sequence_number)` of the newest authenticated record for the RFC 9146 §6 "strictly greater" freshness check on peer-address updates. DTLS 1.2 and DTLS 1.2 PSK paths populate it; DTLS 1.3 returns `None`.
- `Dtls::negotiated_connection_id()` (`src/lib.rs:411-417`) lets callers detect "CID was configured but the handshake did not negotiate it" — typically because the association resolved to DTLS 1.3, where dimpl does not implement RFC 9147 CID. Callers get a loud `None` instead of silent drop.
- DTLS 1.3 client's `Unknown(0x0036)` handler in both ServerHello (`src/dtls13/client.rs:573-600`) and EncryptedExtensions (`src/dtls13/client.rs:695-716`) silent-accepts the echo when `Config::connection_id()` is `Some` (our own hybrid CH solicited it) and only errors `SecurityError` on true unsolicited offers. RFC 8446 §4.2 is satisfied because dimpl's hybrid CH is the solicitation marker.
- DTLS 1.3 server's `Unknown(0x0036)` handler (`src/dtls13/server.rs:447-466`) explicitly ignores the CH offer with a `debug!` log — RFC 8446 §4.1.2 permits; symmetric with the 1.3 client reception policy until RFC 9147 CID is implemented.

- DTLS 1.3 silent-accept of `Unknown(0x0036)` is gated on a per-instance `offered_cid: bool` flag set true only by `Client::new_from_hybrid` when the hybrid CH solicited CID (`src/dtls13/client.rs:197,227`), and false on the direct `Dtls::new_13` path (`src/dtls13/client.rs:176`). Both the ServerHello handler (`src/dtls13/client.rs:594-617`) and the EncryptedExtensions handler (`src/dtls13/client.rs:711-730`) read the flag, so an unsolicited `0x0036` on the direct path now correctly aborts with `Error::SecurityError` per RFC 8446 §4.2, while hybrid-path echoes are silent-accepted + logged.

## Open Items

None — no actionable RFC 9146 / RFC 9147 / RFC 6347 §4.1.2.7 deviations or
public-API gaps remain in the current working tree. The full RFC 9147 DTLS 1.3
Connection ID feature (unified-header CID bit, `NewConnectionId` /
`RequestConnectionId` post-handshake messages, ServerHello / EncryptedExtensions
echo) remains out of scope for this branch and is tracked as a separate future
feature, not a review finding.

## RFC anchors (most recently cross-checked)

- RFC 9146 §3: `connection_id(54)`, `ConnectionId` structure, zero-length directional legacy framing, `tls12_cid` required only for non-zero CID once encryption is enabled, and legacy-framed encrypted records invalid when a non-zero CID is expected.
- RFC 9146 §4: CID-enhanced `DTLSCiphertext` format and encrypted `DTLSInnerPlaintext` (`content || real_type || zeros`).
- RFC 9146 §5.3: AEAD AAD layout (placeholder + `tls12_cid` + CID length + wire version + epoch + sequence + CID + inner plaintext length); `length_of_DTLSInnerPlaintext MUST NOT exceed 2^14`.
- RFC 9146 §6: peer-address update constraints (authenticated, fresh, reachability-checked) and silent-discard restatement.
- RFC 9146 §7: example exchange showing the CH1/HVR/CH2 pair carrying the same `connection_id` extension.
- RFC 9147 §9: DTLS 1.3 Connection ID mechanism (`NewConnectionId` / `RequestConnectionId` post-handshake messages, unified-header CID bit).
- RFC 6347 §4.1.1: `DTLSPlaintext.length` and plaintext fragment capped at 2^14.
- RFC 6347 §4.1.2.6: replay window updates only on MAC verification success.
- RFC 6347 §4.1.2.7: silent discard of invalid records.
- RFC 5246 §7.4.1.4: no duplicate Hello extension types; ServerHello extensions must have been requested by ClientHello.
- RFC 8446 §4.1.2 / §4.2: unknown-vs-unsolicited extension handling in ClientHello / ServerHello.

## Re-check — 2026-04-23 (latest tree)

Re-reviewed the current working tree after the newest CID-related changes.
No new actionable RFC 9146 / RFC 9147 / RFC 6347 issues were found beyond the
items already documented as accepted design choices in this file.

Confirmed closed in the current tree:

- `Dtls::newest_authenticated_record()` now exists and is documented as the
  RFC 9146 §6 freshness signal for peer-address updates (`src/lib.rs:368-396`,
  `src/config.rs:629-639`).
- `Dtls::negotiated_connection_id()` exists so callers can distinguish
  "CID requested" from "CID actually negotiated" (`src/lib.rs:398-417`).
- The freshness API is covered by
  `dtls12_newest_authenticated_record_advances_only_on_valid_records`
  (`tests/dtls12/cid.rs:2314-2401`).
- DTLS 1.3 path now logs a clear warning when `with_connection_id` is set but
  the association resolved to DTLS 1.3, where dimpl still does not implement
  RFC 9147 CID (`src/dtls13/client.rs:1048-1061`).

Net result: no additional fixes to append at this time.

## Re-check — 2026-04-23 (latest pass)

Re-reviewed the current CID-related DTLS 1.2 / DTLS 1.3 code after the most
recent tree changes.

No new actionable RFC 9146 / RFC 9147 / RFC 6347 issues were found.

Still confirmed in the current tree:

- `Dtls::newest_authenticated_record()` remains the intended RFC 9146 §6
  freshness signal for peer-address updates, and the supporting test
  `dtls12_newest_authenticated_record_advances_only_on_valid_records`
  still documents the required caller pattern.
- `Dtls::negotiated_connection_id()` remains the right API for detecting
  whether CID was actually negotiated, distinct from merely being configured.
- Auto-mode hybrid ClientHello continues to emit `connection_id` when
  configured, so CH1/CH2 CID binding across HVR stays consistent.
- DTLS 1.3 direct-path vs hybrid-path handling of `Unknown(0x0036)` remains
  explicitly differentiated and documented, with tests covering the rejection
  path.

Net result: no additional fixes to append from this review pass.

## Re-check — 2026-04-23 (Round 10)

Audited with focus on areas not exercised in prior rounds:

- **Server-side echo suppression when client offers CID but server does not
  configure one.** `src/dtls12/server.rs:522-540` gates `our_cid` on
  `server.engine.config().connection_id().is_some()`, so a CID-unaware server
  correctly declines to echo even when `server.peer_cid` was populated from
  the ClientHello. No CID is negotiated; `negotiated_connection_id()`
  returns `None` on both sides, matching RFC 9146 §3.
- **Zero-length inbound CID preserves asymmetric framing.** If the client
  offers `connection_id` with `cid_len == 0`, the server stores `peer_cid =
  Some(vec![])` and echoes its own non-empty `our_cid`. `set_cid_negotiated`
  is called with `inbound = server_cid` (non-empty) and `outbound = []`, so
  the server uses legacy framing outbound (client→server CID framing is the
  direction that stays live). The client path is symmetric. RFC 9146 §3
  "zero-length means legacy framing in that direction" is honored without
  special-casing on either side.
- **Out-of-order / retransmit records below `max_seq` do not spuriously
  advance the freshness signal.** `ReplayWindow::update`
  (`src/window.rs:49-67`) only moves `max_seq` forward on strictly-greater
  sequence numbers; records below `max_seq` just set a bit in the window
  and leave the max unchanged. `newest_authenticated_record()` therefore
  reports a monotonically non-decreasing `(epoch, seq)` and satisfies
  RFC 9146 §6 "strictly greater than the newest authenticated record" on
  the caller's comparison.
- **CID extension body with outer length ≠ inner cid_len is rejected.**
  `Extension::parse` takes the outer `u16` length into
  `extension_data_range`. `ConnectionIdExtension::parse` then reads a
  one-byte `cid_len`, takes exactly `cid_len` bytes, and errors on
  trailing bytes (`src/dtls12/message/extensions/connection_id.rs:23-40`).
  Either too-long or too-short inner encodings surface as
  `Error::SecurityError "Malformed connection_id extension from {client,
  server}"` per RFC 5246 §7.2.2 `decode_error`.
- **Hardcoding `epoch = 1` in `newest_authenticated_record` is correct
  for the DTLS 1.2 paths that populate the accessor.** DTLS 1.2 runs at
  epoch 0 (plaintext handshake) and epoch 1 (post-CCS encrypted); dimpl
  does not rekey or renegotiate, so every authenticated record on
  `Client12` / `Server12` is at epoch 1. The DTLS 1.3 path intentionally
  returns `None` and is documented as a separate follow-up.

Net result: no additional fixes to append from this review pass.
