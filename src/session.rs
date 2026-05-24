//! Session resumption types for the abbreviated DTLS 1.2 handshake (RFC 5246 §7.3).
//!
//! After every successful full handshake dimpl calls [`SessionStore::store`] with
//! the session ID and a [`StoredSession`]. On the next connection the client can
//! offer that ID in its `ClientHello`; if the server's [`SessionStore`] recognises
//! it, both sides skip the key-exchange flights and derive fresh traffic keys from
//! the cached master secret, completing the handshake in a single round-trip.

use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use crate::dtls12::message::Dtls12CipherSuite;

/// A 48-byte master secret that zeroes itself on drop.
///
/// Used inside [`StoredSession`] to hold the master secret from a completed
/// full handshake so it can be reused by an abbreviated handshake without
/// running the key-exchange again.
pub struct MasterSecret([u8; 48]);

impl MasterSecret {
    /// Create from a 48-byte slice. Returns `Err` if `bytes.len() != 48`.
    pub fn new(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 48 {
            return Err(format!(
                "MasterSecret must be 48 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Return the raw master secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        // Zero the secret on drop to limit the window of exposure.
        self.0.fill(0);
    }
}

// Intentionally omit the secret value from debug output.
impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([redacted])")
    }
}

/// A cached DTLS 1.2 session produced by a completed full handshake.
///
/// Obtain via a [`SessionStore`]; dimpl calls [`SessionStore::store`] after
/// every successful full handshake and [`SessionStore::lookup`] at the start
/// of each new handshake when a non-empty `session_id` is offered.
#[non_exhaustive]
#[derive(Debug)]
pub struct StoredSession {
    /// The 48-byte master secret from the original full handshake.
    pub master_secret: MasterSecret,
    /// The cipher suite negotiated during the original full handshake.
    pub cipher_suite: Dtls12CipherSuite,
}

/// Persist and retrieve DTLS 1.2 sessions to enable abbreviated handshakes.
///
/// Implement this trait to provide session caching. dimpl calls [`store`]
/// after every successful full handshake and [`lookup`] when a client
/// offers a non-empty `session_id` in its `ClientHello`.
///
/// The same `Arc<dyn SessionStore>` is passed to the `Config` of every
/// connection on the server so entries written by one connection task are
/// visible to future connections without additional synchronisation.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync` because one store instance is
/// shared across many concurrent connection tasks.
///
/// # Example — in-memory store
///
/// ```no_run
/// use std::collections::HashMap;
/// use std::sync::{Arc, Mutex};
/// use dimpl::{SessionStore, StoredSession};
///
/// struct MemoryStore(Mutex<HashMap<Vec<u8>, Arc<StoredSession>>>);
///
/// impl SessionStore for MemoryStore {
///     fn store(&self, id: &[u8], session: Arc<StoredSession>) {
///         self.0.lock().unwrap().insert(id.to_vec(), session);
///     }
///     fn lookup(&self, id: &[u8]) -> Option<Arc<StoredSession>> {
///         self.0.lock().unwrap().get(id).cloned()
///     }
/// }
/// ```
///
/// [`store`]: SessionStore::store
/// [`lookup`]: SessionStore::lookup
pub trait SessionStore: Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Persist a session after a successful full handshake.
    ///
    /// `id` is the `session_id` bytes from the `ServerHello` (1–32 bytes).
    fn store(&self, id: &[u8], session: Arc<StoredSession>);

    /// Retrieve a previously stored session by ID, or `None` if unknown/expired.
    ///
    /// `id` is the `session_id` bytes offered by the client in `ClientHello`.
    fn lookup(&self, id: &[u8]) -> Option<Arc<StoredSession>>;
}
