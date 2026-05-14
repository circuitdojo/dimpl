//! OpenSSL DTLS 1.2 PSK harness for ECDHE-PSK interop tests.
//!
//! Self-contained (no certificate/SRTP machinery) so it can interop with
//! dimpl's `Dtls::new_12_psk` flow. Forces the cipher list to
//! `ECDHE-PSK-CHACHA20-POLY1305` so the negotiated suite matches the new
//! `Dtls12CipherSuite::ECDHE_PSK_CHACHA20_POLY1305_SHA256` (0xCCAC) on the
//! dimpl side.

use std::io::{self, Read, Write};
use std::sync::Arc;

use openssl::error::ErrorStack;
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslContextBuilder, SslMethod, SslRef,
    SslStream, SslVerifyMode,
};

use super::io_buf::{DatagramSend, IoBuffer};

/// Force ECDHE-PSK-CHACHA20-POLY1305 only.
const ECDHE_PSK_CHACHA_CIPHER: &str = "ECDHE-PSK-CHACHA20-POLY1305";

/// DTLS 1.2 PSK peer driven by OpenSSL.
pub struct OsslDtlsPsk {
    state: Option<State>,
    _ctx: SslContext,
}

enum State {
    Init(Ssl, IoBuffer),
    Mid(MidHandshakeSslStream<IoBuffer>),
    Up(SslStream<IoBuffer>),
}

/// Returns a `SslContext` configured for ECDHE-PSK DTLS 1.2 as the server.
///
/// The provided PSK is returned for *any* identity. Callers wanting an
/// identity-aware resolver should clone & extend.
pub fn psk_server_ctx(psk: Vec<u8>) -> Result<SslContext, ErrorStack> {
    let mut b = SslContextBuilder::new(SslMethod::dtls())?;
    common_setup(&mut b)?;

    let psk = Arc::new(psk);
    b.set_psk_server_callback(move |_ssl: &mut SslRef, _identity, out| {
        let n = psk.len().min(out.len());
        out[..n].copy_from_slice(&psk[..n]);
        Ok(n)
    });

    Ok(b.build())
}

/// Returns a `SslContext` configured for ECDHE-PSK DTLS 1.2 as the client.
///
/// The callback writes the configured identity (NUL-terminated, per the
/// OpenSSL contract) and the configured PSK.
pub fn psk_client_ctx(identity: Vec<u8>, psk: Vec<u8>) -> Result<SslContext, ErrorStack> {
    let mut b = SslContextBuilder::new(SslMethod::dtls())?;
    common_setup(&mut b)?;

    let identity = Arc::new(identity);
    let psk = Arc::new(psk);
    b.set_psk_client_callback(
        move |_ssl: &mut SslRef, _hint, id_buf: &mut [u8], psk_buf: &mut [u8]| {
            // Identity must fit including a trailing NUL byte.
            if identity.len() + 1 > id_buf.len() {
                return Err(ErrorStack::get());
            }
            id_buf[..identity.len()].copy_from_slice(&identity);
            id_buf[identity.len()] = 0; // NUL terminator (OpenSSL contract)

            let n = psk.len().min(psk_buf.len());
            psk_buf[..n].copy_from_slice(&psk[..n]);
            Ok(n)
        },
    );

    Ok(b.build())
}

fn common_setup(b: &mut SslContextBuilder) -> Result<(), ErrorStack> {
    // Cipher list at the TLS 1.2 layer only — this controls DTLS 1.2 cipher
    // suite negotiation (TLS 1.3 has a separate `set_ciphersuites` API).
    b.set_cipher_list(ECDHE_PSK_CHACHA_CIPHER)?;
    // No client certs, no server certs — PSK authenticates.
    b.set_verify(SslVerifyMode::NONE);
    Ok(())
}

impl OsslDtlsPsk {
    pub fn new_server(psk: Vec<u8>) -> Result<Self, ErrorStack> {
        let ctx = psk_server_ctx(psk)?;
        let ssl = Ssl::new(&ctx)?;
        Ok(Self {
            state: Some(State::Init(ssl, IoBuffer::default())),
            _ctx: ctx,
        })
    }

    pub fn new_client(identity: Vec<u8>, psk: Vec<u8>) -> Result<Self, ErrorStack> {
        let ctx = psk_client_ctx(identity, psk)?;
        let ssl = Ssl::new(&ctx)?;
        Ok(Self {
            state: Some(State::Init(ssl, IoBuffer::default())),
            _ctx: ctx,
        })
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, Some(State::Up(_)))
    }

    pub fn push_packet(&mut self, packet: &[u8]) {
        let io = match self.state.as_mut() {
            Some(State::Init(_, io)) => io,
            Some(State::Mid(m)) => m.get_mut(),
            Some(State::Up(s)) => s.get_mut(),
            None => return,
        };
        io.set_incoming(packet);
    }

    pub fn pop_packet(&mut self) -> Option<DatagramSend> {
        let io = match self.state.as_mut() {
            Some(State::Init(_, io)) => io,
            Some(State::Mid(m)) => m.get_mut(),
            Some(State::Up(s)) => s.get_mut(),
            None => return None,
        };
        io.pop_outgoing()
    }

    /// Drive the handshake forward. `active` selects connect (client) vs
    /// accept (server). Returns Ok(true) if connected, Ok(false) on
    /// WouldBlock.
    pub fn step_handshake(&mut self, active: bool) -> io::Result<bool> {
        // Already connected.
        if let Some(State::Up(_)) = self.state {
            return Ok(true);
        }

        let prev = self.state.take().expect("state");
        let result = match prev {
            State::Up(_) => unreachable!(),
            State::Init(ssl, io) => {
                if active {
                    ssl.connect(io)
                } else {
                    ssl.accept(io)
                }
            }
            State::Mid(mid) => mid.handshake(),
        };

        match result {
            Ok(stream) => {
                self.state = Some(State::Up(stream));
                Ok(true)
            }
            Err(HandshakeError::WouldBlock(m)) => {
                self.state = Some(State::Mid(m));
                Ok(false)
            }
            Err(HandshakeError::SetupFailure(e)) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput, e))
            }
            Err(HandshakeError::Failure(m)) => {
                let e = m.into_error();
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    pub fn send_app_data(&mut self, data: &[u8]) -> io::Result<usize> {
        let State::Up(s) = self.state.as_mut().expect("state") else {
            return Err(io::Error::other("not connected"));
        };
        s.write(data)
    }

    pub fn recv_app_data(&mut self) -> io::Result<Option<Vec<u8>>> {
        let State::Up(s) = self.state.as_mut().expect("state") else {
            return Ok(None);
        };
        let mut buf = vec![0u8; 4096];
        match s.read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the cipher suite OpenSSL negotiated after handshake.
    pub fn current_cipher(&self) -> Option<String> {
        if let Some(State::Up(s)) = self.state.as_ref() {
            s.ssl().current_cipher().map(|c| c.name().to_string())
        } else {
            None
        }
    }
}

impl std::panic::UnwindSafe for OsslDtlsPsk {}
