Security Review Prompt: dimpl — DTLS 1.2/1.3 Implementation for WebRTC

### Project Overview

**dimpl** is a pure-Rust, Sans-IO implementation of DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147), purpose-built for WebRTC. It is ~54k lines of safe Rust (`#![forbid(unsafe_code)]`), with two pluggable crypto backends (aws-lc-rs, RustCrypto). The library handles no I/O directly — callers feed it UDP datagrams and poll for output.

### Scope

Review the implementation for protocol-level, cryptographic, and implementation vulnerabilities. The codebase is at: https://github.com/algesten/dimpl (or provided as a local checkout).

### Key Areas to Review

#### 1. Handshake State Machines
- **Files**: `src/dtls12/client.rs`, `src/dtls12/server.rs`, `src/dtls13/client.rs`, `src/dtls13/server.rs`
- Are state transitions strictly enforced? Can a peer send unexpected messages to skip states or cause re-entry?
- Is the DTLS 1.2 cookie exchange (HelloVerifyRequest) correctly enforced to prevent amplification attacks?
- Can a malicious peer force a downgrade from DTLS 1.3 to 1.2 via the auto-detection path (`src/detect.rs`)?
- Is the Finished message MAC verified before any application state changes?

#### 2. Record Layer & Parsing
- **Files**: `src/dtls12/engine.rs`, `src/dtls13/engine.rs`
- Can malformed records cause panics, excessive memory allocation, or infinite loops in the `nom`-based parser?
- Is epoch/sequence number validation correct? Are records from old epochs properly rejected?
- Is handshake message fragmentation and reassembly safe against overlapping or out-of-order fragments?
- Are record size limits enforced before allocation?

#### 3. Cryptographic Operations
- **Files**: `src/crypto/provider.rs`, `src/crypto/aws_lc_rs/`, `src/crypto/rust_crypto/`, `src/crypto/ccm_cipher.rs`
- Are AEAD nonces correctly constructed and never reused? Check both DTLS 1.2 (explicit nonce) and 1.3 (XOR with sequence number) constructions.
- Is the AEAD encryption limit (default 2^23) correctly enforced to prevent key wear-out?
- Is DTLS 1.3 record number encryption (RFC 9147 §4.3) correctly implemented?
- Are key derivation functions (TLS 1.2 PRF, TLS 1.3 HKDF-Expand-Label) implemented per spec? Cross-check with test vectors.
- Is the `subtle` crate used for all security-sensitive comparisons (Finished verify, AEAD tags)?

#### 4. PSK Mode (New, Unreleased)
- **Files**: `src/dtls12/message/client_key_exchange.rs`, `src/config.rs` (PskResolver trait), cipher suite modules
- Is PSK identity handled safely (no timing leaks on lookup failure)?
- Can a peer negotiate a PSK cipher suite when no PSK is configured, or vice versa?
- Is the PSK key derivation correct per RFC 4279?
- Are PSK-only cipher suites correctly excluded when certificates are expected?

#### 5. Anti-Replay
- **File**: `src/window.rs`
- Is the 64-bit sliding window correctly implemented? Can replayed packets pass the check?
- Is the window updated only *after* AEAD authentication succeeds (not before)?
- Does epoch rollover correctly reset the window?

#### 6. Memory & Buffer Safety
- **File**: `src/buffer.rs`, general buffer usage
- Can an attacker cause unbounded memory growth via fragmented handshakes or queued records?
- Are RX/TX queue bounds enforced? What happens when they're full — is it a clean error or silent drop?
- Is buffer pool reuse safe (no data leakage between sessions from reused buffers)?

#### 7. Timing & Side Channels
- Are all cryptographic comparisons constant-time?
- Does error handling leak information about *why* decryption failed (padding oracle equivalent for AEAD)?
- Is certificate/PSK lookup timing-safe?

#### 8. Certificate Handling
- **File**: `src/certificate.rs`
- The library does **not** validate certificate chains — it delegates this to the application via `Output::PeerCert`. Is this boundary clearly documented and safe?
- Is the self-signed certificate generation (rcgen) producing sufficiently random serial numbers?
- Is SHA-256 fingerprint computation correct?

#### 9. Denial of Service
- Can an attacker exhaust memory via many in-flight handshakes?
- Are retransmission timers (`src/timer.rs`) resistant to manipulation (e.g., attacker preventing timeout progression)?
- Can oversized or deeply fragmented handshake messages cause excessive CPU usage in reassembly?

#### 10. Dependency Supply Chain
- Review `Cargo.toml` and `deny.toml` for dependency hygiene.
- Are crypto dependencies pinned to known-good versions?
- Is `cargo-deny` configured to catch known advisories?

### Deliverables

1. **Findings report** with severity ratings (Critical / High / Medium / Low / Informational)
2. **RFC compliance gaps** — any deviations from RFC 6347, RFC 9147, RFC 4279, RFC 7627, RFC 5764
3. **Threat model assessment** — does the implementation correctly handle a network attacker (Dolev-Yao model)?
4. **Positive findings** — security controls that are well-implemented and noteworthy

### Test Approach Suggestions

- Fuzz `handle_packet()` with arbitrary byte sequences (both pre- and post-handshake)
- Inject crafted records with wrong epochs, replayed sequence numbers, truncated AEAD tags
- Attempt version downgrade via modified ServerHello in auto-detect mode
- Send overlapping handshake fragments with conflicting content
- Exhaust queue limits and verify clean failure
- Interop test against OpenSSL/WolfSSL (tests already exist in `tests/ossl/` and `tests/wolfssl/`)
