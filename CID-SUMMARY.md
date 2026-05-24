# DTLS 1.2 Connection ID (RFC 9146) — Branch Summary

**Branch:** `dtls-conn-id` · **Commit:** `47618d5` · **Base:** `origin/main` (83e913f)

---

## Scope

Implements RFC 9146 Connection ID for DTLS 1.2, hardened against a multi-pass compliance review, with adjacent RFC 5246 / RFC 8446 / RFC 9147 extension-handling gaps closed. Scoped to PSK + roaming IoT use; certificate-based session resumption is intentionally *not* in this change.

## What you get

### Record layer (RFC 9146 / RFC 6347 §4.1.2)
- Wire CID constant-time compared and threaded into AAD (not the cached copy); wire version bytes threaded through AAD
- 2^14 plaintext ceiling, short AEAD records, malformed boundaries → silent drop per §4.1.2.7 (symmetric with send side)
- Epoch-0 `tls12_cid` rejected at `DTLSRecord::parse`; legacy-framed epoch-1 rejected when inbound CID expected
- Pre-CCS CID records cleartext-filtered against negotiated inbound CID before `queue_rx` (closes spray DoS vector)
- Replay window updates only after AEAD **and** CID inner-type unwrap both succeed

### CID state model
- Single private `CidState` enum — zero-length-direction-stays-legacy and per-direction arming (outbound at negotiation, inbound at peer CCS) enforced by the type, not cross-field discipline

### Handshake / extensions
- Duplicate extensions (supported **and** unknown) rejected fail-closed via 64-codepoint tracker + defense-in-depth `ExtensionVec` dedup
- HVR cookie HMAC binds offered-CID extension bytes with 0x00/0x01 marker — catches CH1/CH2 CID-swap
- `dtls13::Client` stateful `offered_cid` flag so direct `new_13` path still rejects unsolicited `0x0036` echoes per RFC 8446 §4.2

### Outbound sizing & lifetimes
- Shared `Engine::outbound_record_overhead` keeps `create_handshake` fragmentation in sync with CID + AEAD
- New errors: `Oversized`, `MtuTooSmall`, `SequenceNumberExhausted` (48-bit seq-wrap surfaced distinctly)

### Auto-mode
- Hybrid ClientHello emits `connection_id(0x0036)` when configured — CH1/CH2 carry identical CID bytes, stateless cookie binds once
- DTLS 1.3 client accepts server CID echo only when its own CH solicited it; DTLS 1.3 server/client explicitly log-ignore `0x0036`

## Public API (minimal)

```rust
Config::with_connection_id(cid: &[u8])          // builder
Output::ConnectionId(&'a [u8])                   // emitted once after Connected
Dtls::newest_authenticated_sequence() -> Option // for peer-address-change gating
```

Sans-IO contract unchanged: `handle_packet` / `poll_output` / `handle_timeout`.

## Diff against `origin/main`

| Area        | Code  | Comments | Blank | Total+ | Net     |
|-------------|------:|---------:|------:|-------:|--------:|
| `src/`      | 1,399 |    1,021 |   148 |  2,568 | +2,419  |
| `tests/`    | 2,234 |      485 |   440 |  3,159 | +3,059  |
| `README.md` |   —   |     —    |   —   |     21 |    +21  |
| **Total**   | **3,633** | **1,506** | **588** | **5,748** | **+5,499** |

- Tests-to-code ratio: **1.60 : 1** (by code lines)
- Comment share of non-blank src additions: **42%** — RFC rationale, not noise

## Files touched (top by modification weight)

| File                                              | +Lines | -Lines |
|---------------------------------------------------|-------:|-------:|
| `src/dtls12/incoming.rs`                          |    898 |     30 |
| `src/dtls12/engine.rs`                            |    365 |     37 |
| `src/config.rs`                                   |    253 |      3 |
| `src/dtls12/message/client_hello.rs`              |    185 |      5 |
| `src/crypto/dtls_aead.rs`                         |    153 |      6 |
| `src/dtls12/server.rs`                            |    131 |      6 |
| `src/dtls12/client.rs`                            |    105 |      3 |
| `src/dtls13/client.rs`                            |     90 |     10 |
| `src/dtls12/message/server_hello.rs`              |     73 |      4 |
| `src/lib.rs`                                      |     70 |      0 |
| `src/error.rs`                                    |     51 |      0 |
| `src/dtls12/message/extensions/connection_id.rs` |     97 |      0 (new file) |
| `tests/dtls12/cid.rs`                             |  2,404 |      0 (new file) |

## Quality gates (all green)

- `cargo test`: **455 passed**, 2 ignored (5 suites)
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo fmt --check`: clean

## Legacy / compatibility

- **No legacy protocols or ciphers enabled.** No DTLS 1.0 handshake/PRF/ciphers, no CBC modes, no RSA/DHE, no 3DES/RC4/MD5/SHA-1. The only `DTLS1_0` (0xFEFF) references are spec-mandated wire-level values (record-layer tolerance per RFC 6347 §4.1; HVR `server_version` per §4.2.1).
- **Pre-RFC CID codepoint 53 (draft-07)** — explicitly not implemented. Old OpenSSL (<3.2) and some embedded stacks won't negotiate CID; they fall back to legacy framing. Documented as known non-interop in README.

## Caller contract for peer-address updates (RFC 9146 §6)

CID is a *routing hint*, not authorization to change send address. Caller MUST:

1. Wait for an authentication-positive output (e.g. `ApplicationData` from `poll_output`) — `handle_packet → Ok(())` is **not** proof (invalid records silent-drop per RFC 6347 §4.1.2.7)
2. Require strict-monotonic `(epoch, sequence_number)` on the authenticated record — use `Dtls::newest_authenticated_sequence()`
3. Apply an address-reachability policy

Full pattern documented on `Config::with_connection_id` rustdoc.

## Branch history

Originated as four commits on `dtls-conn-id`, squashed onto `origin/main` as `47618d5`. Backup refs retained locally: branches `dtls-conn-id-pre-rebase-20260423` / `dtls-conn-id-pre-squash-20260423`, tag `pre-psk-cid-squash`.

## Not pushed

Branch is local. Ready for `git push --force-with-lease origin dtls-conn-id` + PR open when you give the go-ahead.
