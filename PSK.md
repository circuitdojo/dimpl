# Plan: Write PSK Feature Plan for dimpl

## Context

The dimpl crate is a Sans-IO DTLS 1.2/1.3 implementation that currently only supports certificate-based ECDHE authentication. To use dimpl as a DTLS transport for CoAP servers (replacing webrtc-dtls in coapum), PSK support is needed. This plan creates a detailed feature roadmap `.md` file to place in the dimpl repo.

## What to produce

Write a single file `docs/psk-roadmap.md` in `/home/jared/Git/dimpl/` containing the full PSK implementation plan derived from the research above.

## Content outline for the file

The document covers 4 phases with specific files, types, and code patterns:

1. **Phase 1 — DTLS 1.2 Pure PSK** (highest priority for CoAP)
   - Config: `psk_callback`, `psk_identity`, `psk_identity_hint` fields
   - Cipher suites: `PSK_AES128_GCM_SHA256` (0x00A8), `PSK_AES256_GCM_SHA384` (0x00A9), `PSK_CHACHA20_POLY1305_SHA256` (0xCCAB)
   - `KeyExchangeAlgorithm::PSK` variant
   - Pre-master secret per RFC 4279 §2
   - Client/server state machine PSK paths (skip Certificate/CertificateVerify)
   - `Output::PskIdentity` variant
   - `new_12_psk()` constructor (no certificate required)

2. **Phase 2 — DTLS 1.2 ECDHE-PSK** (forward secrecy)
   - `ECDHE_PSK_AES128_GCM_SHA256` etc.
   - Combined ECDHE+PSK pre-master secret per RFC 5489 §2
   - Message types with both hint+ECDHE params and identity+ECDHE pubkey

3. **Phase 3 — DTLS 1.3 PSK** (native protocol support)
   - `pre_shared_key` and `psk_key_exchange_modes` extensions
   - Early secret derivation with PSK as IKM
   - Binder computation
   - `psk_ke` and `psk_dhe_ke` modes

4. **Phase 4 — Testing**
   - Unit tests for message parsing, cipher suite methods, config validation
   - Self-handshake integration tests
   - OpenSSL/wolfSSL interop tests

Plus sections on implementation order, risk areas, and critical files.

## Verification

- Review the written file for accuracy against dimpl source
- Ensure all file paths reference actual dimpl source locations
- Confirm RFC references are correct
