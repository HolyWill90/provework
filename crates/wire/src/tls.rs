//! TLS for the wire: self-signed coordinator certificate, generated on
//! first run, with **fingerprint pinning** on the worker side.
//!
//! Trust model: the operator copies the coordinator's `cert.der` to
//! workers alongside the worker bundle — the same trust path as the
//! code itself. A worker refuses any server whose certificate does not
//! hash to the pinned fingerprint, so a rogue coordinator (or MITM) is
//! rejected at the handshake. Worker identities remain the Ed25519
//! nonce handshake at the protocol layer — TLS here provides
//! confidentiality and server authentication, not worker auth.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::DigitallySignedStruct;

/// Generate a self-signed certificate + key (DER). The certificate is
/// its own trust anchor; workers pin its fingerprint.
pub fn generate_self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let key = rcgen::KeyPair::generate().map_err(|e| format!("rcgen key: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec!["p2pc-coordinator".to_string()])
        .map_err(|e| format!("rcgen params: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("rcgen self-sign: {e}"))?;
    Ok((
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    ))
}

/// The fingerprint a worker pins: BLAKE3 over the certificate DER —
/// the same hash family the chunk chains use.
pub fn fingerprint(cert: &CertificateDer<'_>) -> [u8; 32] {
    *blake3::hash(cert.as_ref()).as_bytes()
}

/// Fingerprint of a coordinator cert file (raw DER), for display.
pub fn fingerprint_of_file(path: &std::path::Path) -> Result<String, String> {
    let der = std::fs::read(path).map_err(|e| format!("cert: {e}"))?;
    Ok(hex(&fingerprint(&CertificateDer::from(der))))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A server-cert verifier that accepts exactly one pinned fingerprint.
/// No name checks, no chain walking: one self-signed cert, one hash.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    pinned: [u8; 32],
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate fingerprint does not match the pinned coordinator key"
                    .into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_with_provider(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_with_provider(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Install the process-level crypto provider (ring) exactly once.
/// rustls 0.23 refuses to guess when several provider features are in
/// play; we pin ours explicitly at startup.
pub fn ensure_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn verify_with_provider(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    let algorithms = provider().signature_verification_algorithms;
    rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms)
}

/// Server-side TLS config from the coordinator's DER cert + key.
pub fn server_config(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<rustls::ServerConfig, String> {
    ensure_provider();
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(key_der.to_vec().into());
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls server config: {e}"))
}

/// Client-side TLS config pinned to the coordinator's certificate.
pub fn client_config_pinned(coordinator_cert_der: &[u8]) -> Result<rustls::ClientConfig, String> {
    ensure_provider();
    let pinned = fingerprint(&CertificateDer::from(coordinator_cert_der.to_vec()));
    let verifier = Arc::new(PinnedFingerprintVerifier { pinned });
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// Wrap a connected TCP stream in the pinned-fingerprint TLS client
/// session and complete the handshake. The single entry point for
/// every client role (worker daemon, submitter) — the handshake
/// completes here so callers get a ready-to-use stream.
pub fn client_stream_pinned(
    tcp: std::net::TcpStream,
    coordinator_cert_der: &[u8],
    server_addr: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>, String> {
    let cfg = client_config_pinned(coordinator_cert_der)?;
    let server_name = rustls::pki_types::ServerName::try_from(
        server_addr.split(':').next().unwrap_or("localhost").to_string(),
    )
    .map_err(|e| format!("server name: {e}"))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), server_name)
        .map_err(|e| format!("tls: {e}"))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            return Err(format!("tls handshake failed: {e}"));
        }
    }
    Ok(tls)
}
