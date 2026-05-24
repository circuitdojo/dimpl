# RPK (Raw Public Keys, RFC 7250) Support Plan

Add Raw Public Key authentication as an alternative to X.509 in dimpl, for both
DTLS 1.2 and DTLS 1.3.

## Goals

- Negotiate `RawPublicKey` (cert type `2`) via the `client_certificate_type` /
  `server_certificate_type` extensions (RFC 7250 §3).
- Send/receive a bare `SubjectPublicKeyInfo` (SPKI) in the Certificate message
  in place of an X.509 chain.
- Verify CertificateVerify signatures against an SPKI directly, without an
  X.509 wrapper.
- Provide a peer-key trust hook so callers can pin/accept SPKIs (RPK has no
  CA chain).
- Preserve current X.509 behavior as the default.

## Non-Goals

- No PKI / chain validation work (X.509 path stays as-is — signature-only).
- No new ciphersuites, key exchange groups, or signature algorithms.
- No persistence of negotiated cert types beyond the active handshake.
- No DTLS 1.0 / TLS 1.2-over-TCP coverage.

## Background

Currently dimpl only handles X.509:

- `DtlsCertificate { certificate: Vec<u8> /* DER X.509 */, private_key }`
  (`src/lib.rs:249`).
- `Certificate` message carries `ArrayVec<Asn1Cert, 32>` in DTLS 1.2
  (`src/dtls12/message/certificate.rs:8`) and `ArrayVec<CertificateEntry, 32>`
  in DTLS 1.3 (`src/dtls13/message/certificate.rs:18`).
- `SignatureVerifier::verify_signature` parses an X.509 cert internally to
  extract the SPKI (`src/crypto/provider.rs:272`,
  `src/crypto/aws_lc_rs/sign.rs:193`, `src/crypto/rust_crypto/sign.rs:203`).
- `cert_named_group` parses X.509 to derive the EC curve
  (`src/crypto/provider.rs:343`).
- `ExtensionType::ClientCertificateType` / `ServerCertificateType` are listed
  but absent from `supported()` (`src/dtls12/message/extension.rs:55`,
  `src/dtls13/message/extension.rs:52`).

The CertificateVerify signing path already uses the private key directly and
needs no change. The verification path already extracts SPKI from X.509
internally — making it SPKI-native is a refactor, not a redesign.

## Design

### Cert-type model

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    X509 = 0,
    RawPublicKey = 2,
}

pub enum CertPayload {
    X509(Vec<u8>),         // DER-encoded X.509 (current behavior)
    RawPublicKey(Vec<u8>), // DER-encoded SubjectPublicKeyInfo
}
```

`DtlsCertificate` becomes:

```rust
pub struct DtlsCertificate {
    pub payload: CertPayload,
    pub private_key: Vec<u8>,
}
```

Provide a back-compat constructor `DtlsCertificate::x509(cert_der, key_der)`
to keep existing call sites tidy.

### Config

```rust
pub struct Config {
    // ...existing fields...
    pub client_cert_types: ArrayVec<CertType, 2>, // preference order
    pub server_cert_types: ArrayVec<CertType, 2>,
    pub peer_key_policy: PeerKeyPolicy,
}

pub enum PeerKeyPolicy {
    AcceptAny,                       // current X.509-style "verify sig only"
    Pinned(ArrayVec<SpkiHash, N>),   // RPK: pin by SHA-256(SPKI)
    Callback(Arc<dyn Fn(&[u8]) -> bool + Send + Sync>),
}
```

Defaults: both lists = `[X509]`, policy = `AcceptAny`.

### Crypto trait refactor (step 1, no behavior change)

`SignatureVerifier::verify_signature` currently takes `cert_der: &[u8]` and
parses X.509 internally. Make it SPKI-native and provide an X.509 helper:

```rust
pub trait SignatureVerifier: CryptoSafe {
    fn verify_signature_spki(
        &self, spki_der: &[u8], data: &[u8], signature: &[u8],
        hash_alg: HashAlgorithm, sig_alg: SignatureAlgorithm,
    ) -> Result<(), String>;
}

pub fn spki_from_x509(cert_der: &[u8]) -> Result<Vec<u8>, String>;
pub fn named_group_from_spki(spki_der: &[u8]) -> Result<NamedGroup, String>;
```

`cert_named_group` becomes a thin wrapper:
`spki_from_x509(...).and_then(named_group_from_spki)`.

Both backends (`aws_lc_rs`, `rust_crypto`) already do the SPKI extraction —
this just hoists it out of `verify_signature`.

### Extension wire-up

Add `ClientCertificateType` and `ServerCertificateType` to the `supported()`
arrays in both `src/dtls12/message/extension.rs:213` and
`src/dtls13/message/extension.rs:204`.

Define encoding helpers next to the extension module:

```rust
// ClientHello body for either extension: vector of u8 cert types.
// CertificateType cert_types<1..2^8-1>;
fn write_cert_type_list(types: &[CertType], out: &mut Buf);
fn parse_cert_type_list(input: &[u8]) -> IResult<&[u8], ArrayVec<CertType, 2>>;

// ServerHello (1.2) / EncryptedExtensions (1.3) body: single chosen u8.
fn write_cert_type_choice(t: CertType, out: &mut Buf);
fn parse_cert_type_choice(input: &[u8]) -> IResult<&[u8], CertType>;
```

### Negotiation flow

- **Client** (`handshake_create_client_hello`,
  `src/dtls12/client.rs:~1296`, `src/dtls13/client.rs:1223`): if
  `client_cert_types`/`server_cert_types` differ from `[X509]`, append the two
  extensions with the configured lists.
- **Server** (`handshake_handle_client_hello`, `src/dtls12/server.rs`,
  `src/dtls13/server.rs`): if extensions present, pick first overlapping type
  from local prefs; else fall back to `X509` (default per RFC 7250 §4.2). On
  no overlap → `unsupported_certificate` alert.
- **Server response**: echo the chosen type in ServerHello (DTLS 1.2) or
  EncryptedExtensions (DTLS 1.3).
- **Persisted state**: store `negotiated_server_cert_type` and
  `negotiated_client_cert_type` on `CryptoContext` (1.2,
  `src/dtls12/context.rs:17`) and `Engine` (1.3, `src/dtls13/engine.rs:39`).

### Certificate message emission/parsing

The wire shape is unchanged — the `opaque cert_data<1..2^24-1>` slot just
carries an SPKI instead of a cert. Branch on negotiated type at the boundary:

- Emit (`handshake_create_certificate`, `src/dtls13/client.rs:1370`; the 1.2
  equivalent in `src/dtls12/context.rs:412`): pull bytes from `CertPayload`,
  put them in the single-entry `certificate_list`. RPK MUST emit exactly one
  entry; X.509 may emit a chain.
- Parse: Certificate parser stays generic (opaque blobs). Consumers
  (`State::handshake_handle_certificate` in client/server) check the
  negotiated type and route the bytes either to X.509 validation or to the
  RPK trust hook.

### CertificateVerify

- Signing: unchanged — `SigningKey::sign` already operates on the private key.
- Verifying: call `verify_signature_spki` with bytes derived from the
  negotiated type:
  - X.509 → `spki_from_x509(cert_der)` then verify.
  - RPK → use the SPKI bytes verbatim from the Certificate message.

### Trust hook

After parsing the peer's Certificate but before completing the handshake:

```rust
match (negotiated_type, &config.peer_key_policy) {
    (CertType::X509, _)            => { /* current behavior */ }
    (CertType::RawPublicKey, p)    => p.evaluate(spki_der)?, // alert decode_error/bad_certificate on reject
}
```

`Pinned` uses constant-time compare on SHA-256(SPKI) (`subtle::ConstantTimeEq`,
already a dep).

## Implementation Phases

### Phase 1 — Crypto refactor (no behavior change)

- Add `verify_signature_spki` to `SignatureVerifier`; implement on both backends.
- Add `spki_from_x509` and `named_group_from_spki` helpers in
  `src/crypto/provider.rs`.
- Re-express `cert_named_group` and the existing `verify_signature` in terms
  of the new helpers; keep both as thin wrappers for now.
- All existing tests should pass unchanged.

### Phase 2 — Types & config

- Introduce `CertType`, `CertPayload`, `PeerKeyPolicy`.
- Migrate `DtlsCertificate` (with `::x509(...)` constructor for back-compat
  in tests).
- Add cert-type fields to `Config` (defaults preserve current behavior).
- Plumb through `Engine`/`CryptoContext` accessors.

### Phase 3 — Extension negotiation

- Add `ClientCertificateType` / `ServerCertificateType` to the `supported()`
  arrays.
- Implement extension body codec helpers.
- Emit on client; parse + select + echo on server.
- Persist negotiated types in crypto state.
- Wire alert paths (`unsupported_certificate`, `illegal_parameter`).

### Phase 4 — Certificate message branching

- DTLS 1.3 first: `handshake_create_certificate` and the 1.3 server's reuse
  of it (`src/dtls13/server.rs:39`).
- DTLS 1.2: `serialize_client_certificate` and matching server path.
- Receive-side branching in client/server `handshake_handle_certificate`.

### Phase 5 — Trust hook

- Implement `PeerKeyPolicy::evaluate(spki)` and call it post-parse, pre-Finished.
- Define alerts for reject (`bad_certificate`).

### Phase 6 — Tests

- Unit: SPKI wire roundtrip mirroring
  `src/dtls12/message/certificate.rs:69` and
  `src/dtls13/message/certificate.rs:120`.
- Negotiation matrix:
  - Both sides X.509 → X.509 (regression).
  - Both sides RPK → RPK.
  - Client `[X509, RPK]` × server `[RPK]` → RPK.
  - No overlap → `unsupported_certificate` alert.
  - Default config (no extension) on either side → X.509.
- End-to-end RPK handshake on 1.2 and 1.3 (mirror existing patterns in
  `tests/dtls12/` and `tests/dtls13/`).
- `auto`/cross-matrix variants in `tests/auto/cross_matrix.rs`.
- OpenSSL interop in `tests/ossl/`: `s_server -enable_server_rpk` and
  `s_client -enable_client_rpk` against dimpl, both directions.
- Pinned-SPKI: pin matches → connect; pin mismatches → fail with the right
  alert.

## Risks / Open Questions

- **Trust by default**: `AcceptAny` for RPK = trust-on-first-use. We should
  default RPK to *requiring* a non-`AcceptAny` policy and surface a config
  error when RPK is enabled without one — mistakenly running RPK with
  `AcceptAny` is silent insecurity. Decide before merging.
- **Mutual auth**: when both `client_cert_types` and `server_cert_types` are
  in play, we negotiate them independently per RFC 7250 — confirm CertificateRequest
  / CertificateVerify on the client side honors the negotiated *client* type.
- **Cert type in alerts**: `unsupported_certificate` (alert 43) is the right
  alert per RFC 7250 §4.4 for negotiation failure; double-check this matches
  current alert plumbing.
- **PSK interaction**: RPK is orthogonal to PSK; if PSK is selected, the
  Certificate message isn't sent and cert-type negotiation is moot. Confirm
  the auto-sense and PSK paths skip the extensions cleanly.
- **Backend coverage**: both `aws_lc_rs` and `rust_crypto` already do SPKI
  extraction internally; the refactor is mechanical, but verify P-256/P-384
  parity in `verify_signature_spki` against existing test vectors.
- **Wire-format ambiguity in 1.3**: with RPK, a `CertificateEntry`'s
  `extensions` field MUST be empty (RFC 8446 §4.4.2 + RFC 7250) — assert in
  parser when negotiated type is RPK.

## Estimated Scope

~600–900 LoC. Mostly mechanical: phase 1 is the only crypto-shape change,
phases 3–5 are wire-up, phase 6 carries the bulk of test code.
