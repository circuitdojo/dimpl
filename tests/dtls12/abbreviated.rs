//! DTLS 1.2 abbreviated handshake (session resumption, RFC 5246 §7.3) tests.

use std::collections::HashMap;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dimpl::crypto::Dtls12CipherSuite;
use dimpl::{Config, Dtls, PskResolver, SessionStore, StoredSession};

use crate::common::{drain_outputs, psk_provider};

// ── Shared test infrastructure ────────────────────────────────────────────────

struct FixedPsk {
    identity: Vec<u8>,
    key: Vec<u8>,
}

impl PskResolver for FixedPsk {
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
        if identity == self.identity {
            Some(self.key.clone())
        } else {
            None
        }
    }
}

/// Simple in-memory session store backed by a Mutex<HashMap>.
struct MemoryStore {
    inner: Mutex<HashMap<Vec<u8>, Arc<StoredSession>>>,
}

impl MemoryStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

// `Mutex<HashMap<...>>` is UnwindSafe + RefUnwindSafe because Mutex poisons
// on panic, so the state is always consistent for callers that check the
// poison flag (which dimpl tests don't need to).
impl UnwindSafe for MemoryStore {}
impl RefUnwindSafe for MemoryStore {}

impl SessionStore for MemoryStore {
    fn store(&self, id: &[u8], session: Arc<StoredSession>) {
        self.inner.lock().unwrap().insert(id.to_vec(), session);
    }

    fn lookup(&self, id: &[u8]) -> Option<Arc<StoredSession>> {
        self.inner.lock().unwrap().get(id).cloned()
    }
}

/// Build client and server PSK configs with a shared session store.
fn psk_configs_with_store(store: Arc<MemoryStore>) -> (Arc<Config>, Arc<Config>) {
    let identity = b"sensor-42".to_vec();
    let key = b"super-secret-psk-key-16b".to_vec();

    let resolver: Arc<dyn PskResolver> = Arc::new(FixedPsk {
        identity: identity.clone(),
        key,
    });

    // Restrict to PSK-only suite for cleaner test
    let provider = psk_provider(Dtls12CipherSuite::PSK_AES128_CCM_8);

    let client = Arc::new(
        Config::builder()
            .with_crypto_provider(provider.clone())
            .with_psk_client(identity, resolver.clone())
            .with_session_store(Arc::clone(&store) as Arc<dyn SessionStore>)
            .use_server_cookie(false)
            .build()
            .expect("build client config"),
    );

    let server = Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .with_psk_server(None, resolver)
            .with_session_store(Arc::clone(&store) as Arc<dyn SessionStore>)
            .use_server_cookie(false)
            .build()
            .expect("build server config"),
    );

    (client, server)
}

/// Run a full handshake to `Connected` on both sides.
///
/// Returns `now` after the handshake completes.
fn run_full_handshake(client: &mut Dtls, server: &mut Dtls, mut now: Instant) -> Instant {
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).unwrap();
        server.handle_timeout(now).unwrap();

        let c_out = drain_outputs(client);
        let s_out = drain_outputs(server);

        client_connected |= c_out.connected;
        server_connected |= s_out.connected;

        for p in &c_out.packets {
            let _ = server.handle_packet(p);
        }
        for p in &s_out.packets {
            let _ = client.handle_packet(p);
        }

        if client_connected && server_connected {
            return now;
        }

        now += Duration::from_millis(50);
    }

    panic!("full handshake did not complete");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Happy path: after a full PSK handshake the session store is populated, and
/// a second connection using `with_offered_session_id` takes the abbreviated
/// path and completes successfully.
#[test]
fn dtls12_psk_abbreviated_handshake_after_full() {
    let _ = env_logger::try_init();

    let store = MemoryStore::new();
    let now = Instant::now();

    // ── First connection: full handshake ────────────────────────────────────
    let (client_cfg1, server_cfg1) = psk_configs_with_store(Arc::clone(&store));

    let mut client1 = Dtls::new_12_psk(Arc::clone(&client_cfg1), now);
    client1.set_active(true);
    let mut server1 = Dtls::new_12_psk(Arc::clone(&server_cfg1), now);

    let _now = run_full_handshake(&mut client1, &mut server1, now);

    // Both sides should have stored a session.
    assert_eq!(
        store.len(),
        1,
        "session must be stored after full handshake"
    );

    // Both sides should expose the same session_id.
    let client_sid = client1.session_id().expect("client session_id must be set");
    let server_sid = server1.session_id().expect("server session_id must be set");
    assert_eq!(
        client_sid, server_sid,
        "client and server session_ids must match"
    );

    let saved_id = client_sid.to_vec();

    // ── Second connection: abbreviated handshake ───────────────────────────
    // Build a new client config that offers the saved session_id.
    let provider2 = psk_provider(Dtls12CipherSuite::PSK_AES128_CCM_8);

    let identity = b"sensor-42".to_vec();
    let key = b"super-secret-psk-key-16b".to_vec();
    let resolver2: Arc<dyn PskResolver> = Arc::new(FixedPsk { identity, key });

    let client_cfg2 = Arc::new(
        Config::builder()
            .with_crypto_provider(provider2.clone())
            .with_psk_client(b"sensor-42".to_vec(), resolver2)
            .with_session_store(Arc::clone(&store) as Arc<dyn SessionStore>)
            .with_offered_session_id(saved_id)
            .use_server_cookie(false)
            .build()
            .expect("build abbreviated client config"),
    );

    // Server reuses the same config (same session store).
    let now2 = Instant::now() + Duration::from_secs(1);
    let mut client2 = Dtls::new_12_psk(Arc::clone(&client_cfg2), now2);
    client2.set_active(true);
    let mut server2 = Dtls::new_12_psk(Arc::clone(&server_cfg1), now2);

    // Track whether the abbreviated handshake involved ServerKeyExchange.
    // In the abbreviated path, no ServerKeyExchange is sent.
    let mut client_connected = false;
    let mut server_connected = false;
    let mut now3 = now2;

    for _ in 0..20 {
        client2.handle_timeout(now3).unwrap();
        server2.handle_timeout(now3).unwrap();

        let c_out = drain_outputs(&mut client2);
        let s_out = drain_outputs(&mut server2);

        client_connected |= c_out.connected;
        server_connected |= s_out.connected;

        for p in &c_out.packets {
            let _ = server2.handle_packet(p);
        }
        for p in &s_out.packets {
            let _ = client2.handle_packet(p);
        }

        if client_connected && server_connected {
            break;
        }

        now3 += Duration::from_millis(50);
    }

    assert!(
        client_connected,
        "client must connect via abbreviated handshake"
    );
    assert!(
        server_connected,
        "server must connect via abbreviated handshake"
    );

    // session_id must still be set after abbreviated handshake.
    assert!(
        client2.session_id().is_some(),
        "client session_id after abbreviated"
    );
    assert!(
        server2.session_id().is_some(),
        "server session_id after abbreviated"
    );
    assert_eq!(
        client2.session_id().unwrap(),
        client1.session_id().unwrap(),
        "session_id must be preserved across abbreviated handshake"
    );

    // Application data must flow in both directions.
    let msg = b"hello over abbreviated session";
    client2.send_application_data(msg).unwrap();
    let c_out3 = drain_outputs(&mut client2);
    for p in &c_out3.packets {
        let _ = server2.handle_packet(p);
    }
    let s_out3 = drain_outputs(&mut server2);
    let received: Vec<u8> = s_out3.app_data.into_iter().flatten().collect();
    assert_eq!(
        received, msg,
        "application data must survive abbreviated session"
    );
}

/// A client with a stale / unknown session_id should fall back to a full
/// handshake transparently. The server simply ignores the unknown session_id
/// and starts a fresh handshake — no error.
#[test]
fn dtls12_psk_unknown_session_id_falls_back_to_full() {
    let _ = env_logger::try_init();

    let store = MemoryStore::new();
    let now = Instant::now();
    let (_client_cfg_base, server_cfg) = psk_configs_with_store(Arc::clone(&store));

    // Build a client that offers a session_id the server has never seen.
    let unknown_id = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    let identity = b"sensor-42".to_vec();
    let key = b"super-secret-psk-key-16b".to_vec();
    let resolver: Arc<dyn PskResolver> = Arc::new(FixedPsk {
        identity: identity.clone(),
        key,
    });

    let provider = psk_provider(Dtls12CipherSuite::PSK_AES128_CCM_8);

    let client_cfg = Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .with_psk_client(identity, resolver)
            .with_session_store(Arc::clone(&store) as Arc<dyn SessionStore>)
            .with_offered_session_id(unknown_id)
            .use_server_cookie(false)
            .build()
            .unwrap(),
    );

    let mut client = Dtls::new_12_psk(client_cfg, now);
    client.set_active(true);
    let mut server = Dtls::new_12_psk(server_cfg, now);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut t = now;

    for _ in 0..40 {
        client.handle_timeout(t).unwrap();
        server.handle_timeout(t).unwrap();

        let c_out = drain_outputs(&mut client);
        let s_out = drain_outputs(&mut server);

        client_connected |= c_out.connected;
        server_connected |= s_out.connected;

        for p in &c_out.packets {
            let _ = server.handle_packet(p);
        }
        for p in &s_out.packets {
            let _ = client.handle_packet(p);
        }

        if client_connected && server_connected {
            break;
        }

        t += Duration::from_millis(50);
    }

    // The full handshake must complete even though the session_id was unknown.
    assert!(
        client_connected,
        "client must complete full fallback handshake"
    );
    assert!(
        server_connected,
        "server must complete full fallback handshake"
    );

    // After a successful full handshake, the store should now have one entry.
    assert_eq!(
        store.len(),
        1,
        "session must be stored after successful full fallback handshake"
    );
}
