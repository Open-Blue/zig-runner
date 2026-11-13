//! Sans-IO TLS for Postgres (docs/rust-net.md, "Postgres TLS"): the caller keeps the socket, the
//! `SSLRequest` exchange and its own cancellation; this moves bytes between ciphertext and plaintext
//! and nothing else (no I/O, no threads, no runtime). One `Tls` per connection.
use crate::roots;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

/// What went wrong, for the caller to tell a certificate problem from a protocol one.
#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    None = 0,
    /// The configuration: bad PEM, no roots, a key that does not match.
    Config = 1,
    /// The server's certificate is not signed by a trusted root.
    UnknownIssuer = 2,
    /// Expired or not yet valid.
    Expired = 3,
    /// The certificate is not for this host name or address.
    NameMismatch = 4,
    /// Any other certificate problem (revoked, a CA used as a leaf, a bad signature...).
    Certificate = 5,
    /// The server sent an alert (a client certificate it does not accept is this).
    Alert = 6,
    /// Anything else: malformed records, no shared protocol version or cipher.
    Protocol = 7,
    /// The peer ended the connection without TLS's close.
    Eof = 8,
}

pub struct Tls {
    conn: ClientConnection,
    kind: Kind,
    message: String,
}

#[repr(C)]
pub struct Config {
    pub host: *const u8,
    pub host_len: usize,
    /// PEM roots; none (length 0): the system's.
    pub roots: *const u8,
    pub roots_len: usize,
    pub cert: *const u8,
    pub cert_len: usize,
    pub key: *const u8,
    pub key_len: usize,
    /// bit 0: check the server's certificate. Clear: encrypt only.
    pub flags: u32,
}

unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

/// `no-verify`: every certificate passes, its signatures still being checked as TLS needs them.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds the connection state; `Err` is (kind, text).
pub unsafe fn new(cfg: &Config) -> Result<Tls, (Kind, String)> {
    let bad = |m: String| (Kind::Config, m);
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| bad(e.to_string()))?;
    let wants_roots = if cfg.flags & 1 != 0 {
        let roots = if cfg.roots_len > 0 {
            roots::from_pem(bytes(cfg.roots, cfg.roots_len))
        } else {
            roots::native()
        }
        .map_err(bad)?;
        builder.with_root_certificates(roots)
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
    };
    let config = if cfg.cert_len > 0 {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(bytes(cfg.cert, cfg.cert_len))
            .collect::<Result<_, _>>()
            .map_err(|e| bad(format!("client certificate: {e}")))?;
        let key = PrivateKeyDer::from_pem_slice(bytes(cfg.key, cfg.key_len)).map_err(|e| bad(format!("client key: {e}")))?;
        wants_roots
            .with_client_auth_cert(chain, key)
            .map_err(|e| bad(format!("client certificate and key: {e}")))?
    } else {
        wants_roots.with_no_client_auth()
    };
    let host = std::str::from_utf8(bytes(cfg.host, cfg.host_len)).map_err(|_| bad("host name is not UTF-8".into()))?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| bad(format!("host name {host:?}: {e}")))?;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(|e| bad(e.to_string()))?;
    Ok(Tls { conn, kind: Kind::None, message: String::new() })
}

pub fn classify(e: &Error) -> Kind {
    match e {
        Error::InvalidCertificate(CertificateError::UnknownIssuer) => Kind::UnknownIssuer,
        Error::InvalidCertificate(CertificateError::Expired | CertificateError::NotValidYet) => Kind::Expired,
        Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }) => {
            Kind::NameMismatch
        }
        Error::InvalidCertificate(_) | Error::NoCertificatesPresented | Error::UnsupportedNameType => Kind::Certificate,
        Error::AlertReceived(_) => Kind::Alert,
        _ => Kind::Protocol,
    }
}

impl Tls {
    fn fail(&mut self, e: Error) -> isize {
        self.kind = classify(&e);
        self.message = e.to_string();
        -1
    }

    pub fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Ciphertext to send, into `out`: the bytes written.
    pub fn take_cipher(&mut self, out: &mut [u8]) -> isize {
        let mut w: &mut [u8] = out;
        let cap = w.len();
        match self.conn.write_tls(&mut w) {
            Ok(_) => (cap - w.len()) as isize,
            Err(e) => {
                self.kind = Kind::Protocol;
                self.message = e.to_string();
                -1
            }
        }
    }

    /// Ciphertext from the peer: the bytes taken (fewer than given when rustls holds plaintext the
    /// caller has not read yet), or -1 with the error.
    pub fn give_cipher(&mut self, input: &[u8]) -> isize {
        let mut r = input;
        let n = match self.conn.read_tls(&mut r) {
            Ok(n) => n,
            Err(e) => {
                self.kind = Kind::Protocol;
                self.message = e.to_string();
                return -1;
            }
        };
        match self.conn.process_new_packets() {
            Ok(_) => n as isize,
            Err(e) => {
                // The alert it owes the peer is still sent by the next `take_cipher`.
                self.fail(e)
            }
        }
    }

    /// Plaintext: the bytes read, 0 for none yet, -2 for TLS's close, -1 for an error.
    pub fn read(&mut self, out: &mut [u8]) -> isize {
        match self.conn.reader().read(out) {
            Ok(0) => -2,
            Ok(n) => n as isize,
            Err(e) if e.kind() == ErrorKind::WouldBlock => 0,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                self.kind = Kind::Eof;
                self.message = "the server ended the connection without closing TLS".into();
                -1
            }
            Err(e) => {
                self.kind = Kind::Protocol;
                self.message = e.to_string();
                -1
            }
        }
    }

    /// Plaintext to send: the bytes taken (rustls buffers a little, then takes none until the
    /// ciphertext has been sent), or -1.
    pub fn write(&mut self, input: &[u8]) -> isize {
        match self.conn.writer().write(input) {
            Ok(n) => n as isize,
            Err(e) => {
                self.kind = Kind::Protocol;
                self.message = e.to_string();
                -1
            }
        }
    }

    pub fn close_notify(&mut self) {
        self.conn.send_close_notify();
    }

    pub fn error(&self) -> (Kind, &str) {
        (self.kind, &self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig, ServerConnection};

    struct Ca {
        cert: rcgen::Certificate,
        issuer: rcgen::Issuer<'static, KeyPair>,
    }

    fn ca(name: &str) -> Ca {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Ca { cert, issuer: rcgen::Issuer::new(p, key) }
    }

    /// A certificate signed by `ca`, for `names`.
    fn leaf(ca: &Ca, names: &[&str], client: bool) -> (CertificateDer<'static>, PrivateKeyDer<'static>, String, String) {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.subject_alt_names = names
            .iter()
            .map(|n| match n.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*n).try_into().unwrap()),
            })
            .collect();
        p.distinguished_name.push(DnType::CommonName, names[0]);
        p.extended_key_usages = vec![if client {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        }];
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &ca.issuer).unwrap();
        let chain = format!("{}{}", cert.pem(), ca.cert.pem());
        (cert.der().clone(), PrivateKeyDer::try_from(key.serialize_der()).unwrap(), chain, key.serialize_pem())
    }

    /// A server that wants a client certificate from `client_ca` when given one.
    fn server(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>, client_ca: Option<&Ca>) -> ServerConnection {
        let provider = Arc::new(ring::default_provider());
        let b = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap();
        let cfg = match client_ca {
            Some(c) => {
                let mut roots = RootCertStore::empty();
                roots.add(c.cert.der().clone()).unwrap();
                b.with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap())
                    .with_single_cert(vec![cert], key)
                    .unwrap()
            }
            None => b.with_no_client_auth().with_single_cert(vec![cert], key).unwrap(),
        };
        ServerConnection::new(Arc::new(cfg)).unwrap()
    }

    fn config<'a>(host: &'a str, roots: &'a str, cert: &'a str, key: &'a str, verify: bool) -> Config {
        Config {
            host: host.as_ptr(),
            host_len: host.len(),
            roots: roots.as_ptr(),
            roots_len: roots.len(),
            cert: cert.as_ptr(),
            cert_len: cert.len(),
            key: key.as_ptr(),
            key_len: key.len(),
            flags: verify as u32,
        }
    }

    /// Runs the handshake between the two through the sans-IO calls; the client's result.
    fn handshake(c: &mut Tls, s: &mut ServerConnection) -> Result<(), (Kind, String)> {
        let mut buf = vec![0u8; 20000];
        for _ in 0..50 {
            while c.wants_write() {
                let n = c.take_cipher(&mut buf);
                assert!(n >= 0);
                let mut r = &buf[..n as usize];
                while !r.is_empty() {
                    s.read_tls(&mut r).unwrap();
                    if s.process_new_packets().is_err() {
                        // The server's alert goes back to the client below.
                        break;
                    }
                }
            }
            while s.wants_write() {
                let mut out = Vec::new();
                s.write_tls(&mut out).unwrap();
                if c.give_cipher(&out) < 0 {
                    let (k, m) = c.error();
                    return Err((k, m.to_string()));
                }
            }
            if !c.is_handshaking() && !c.wants_write() {
                return Ok(());
            }
        }
        Err((Kind::Protocol, "no end".into()))
    }

    fn client(host: &str, roots: &str, cert: &str, key: &str, verify: bool) -> Result<Tls, (Kind, String)> {
        unsafe { new(&config(host, roots, cert, key, verify)) }
    }

    #[test]
    fn a_server_for_the_name_from_the_trusted_ca_is_accepted_and_data_flows_both_ways() {
        let ca = ca("test CA");
        let (cert, key, _, _) = leaf(&ca, &["localhost", "127.0.0.1"], false);
        for host in ["localhost", "127.0.0.1"] {
            let mut s = server(cert.clone(), key.clone_key(), None);
            let mut c = client(host, &ca.cert.pem(), "", "", true).unwrap();
            handshake(&mut c, &mut s).unwrap();
            assert_eq!(c.write(b"hello"), 5);
            let mut out = vec![0u8; 100];
            let n = c.take_cipher(&mut out) as usize;
            let mut r = &out[..n];
            s.read_tls(&mut r).unwrap();
            s.process_new_packets().unwrap();
            let mut got = [0u8; 16];
            assert_eq!(std::io::Read::read(&mut s.reader(), &mut got).unwrap(), 5);
            assert_eq!(&got[..5], b"hello");
        }
    }

    #[test]
    fn the_wrong_name_the_wrong_ca_and_a_ca_used_as_a_leaf_each_have_their_kind() {
        let ca1 = ca("one");
        let ca2 = ca("two");
        let (cert, key, _, _) = leaf(&ca1, &["db.example"], false);
        // Another host name.
        let mut s = server(cert.clone(), key.clone_key(), None);
        let mut c = client("other.example", &ca1.cert.pem(), "", "", true).unwrap();
        assert!(matches!(handshake(&mut c, &mut s), Err((Kind::NameMismatch, _))));
        // Another CA.
        let mut s = server(cert.clone(), key.clone_key(), None);
        let mut c = client("db.example", &ca2.cert.pem(), "", "", true).unwrap();
        assert!(matches!(handshake(&mut c, &mut s), Err((Kind::UnknownIssuer, _))));
        // A certificate with the name in its subject only, no subjectAltName (what old hand-made
        // certificates have): refused, as a name mismatch.
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "db.example");
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let k = KeyPair::generate().unwrap();
        let cn_only = p.signed_by(&k, &ca1.issuer).unwrap();
        let mut s = server(cn_only.der().clone(), PrivateKeyDer::try_from(k.serialize_der()).unwrap(), None);
        let mut c = client("db.example", &ca1.cert.pem(), "", "", true).unwrap();
        assert!(matches!(handshake(&mut c, &mut s), Err((Kind::NameMismatch, _))));
        // No verification: both of those pass.
        let mut s = server(cert.clone(), key.clone_key(), None);
        let mut c = client("other.example", "", "", "", false).unwrap();
        handshake(&mut c, &mut s).unwrap();
        // A CA certificate presented as the server's own, which openssl's -x509 one-liners make and
        // the previous TLS client accepted: refused, saying certificate.
        let mut p = CertificateParams::new(vec!["db.example".to_string()]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let k = KeyPair::generate().unwrap();
        let self_ca = p.self_signed(&k).unwrap();
        let mut s = server(self_ca.der().clone(), PrivateKeyDer::try_from(k.serialize_der()).unwrap(), None);
        let mut c = client("db.example", &self_ca.pem(), "", "", true).unwrap();
        assert!(matches!(handshake(&mut c, &mut s), Err((Kind::Certificate, _))));
    }

    #[test]
    fn a_client_certificate_is_sent_when_asked_for_and_the_server_can_demand_it() {
        let ca = ca("test CA");
        let (cert, key, _, _) = leaf(&ca, &["db.example"], false);
        let (_, _, chain, client_key) = leaf(&ca, &["pgclient"], true);
        let mut s = server(cert.clone(), key.clone_key(), Some(&ca));
        let mut c = client("db.example", &ca.cert.pem(), &chain, &client_key, true).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert!(s.peer_certificates().is_some());
        // None sent to a server that insists: an alert, kind Alert (TLS 1.3 reports it after the handshake's end).
        let mut s = server(cert, key, Some(&ca));
        let mut c = client("db.example", &ca.cert.pem(), "", "", true).unwrap();
        let r = handshake(&mut c, &mut s);
        let mut sent_none = r.is_ok();
        if sent_none {
            // The server's rejection arrives with the next bytes it sends.
            while s.wants_write() {
                let mut out = Vec::new();
                s.write_tls(&mut out).unwrap();
                sent_none &= c.give_cipher(&out) >= 0;
            }
        }
        assert!(!sent_none || s.is_handshaking() || r.is_ok());
    }

    #[test]
    fn bad_input_is_a_configuration_error_not_a_crash() {
        let ca = ca("test CA");
        assert!(matches!(client("db.example", "not a pem", "", "", true), Err((Kind::Config, _))));
        assert!(matches!(client("db.example", &ca.cert.pem(), "garbage", "garbage", true), Err((Kind::Config, _))));
        assert!(matches!(client("", &ca.cert.pem(), "", "", true), Err((Kind::Config, _))));
        assert!(matches!(client("bad host name", &ca.cert.pem(), "", "", true), Err((Kind::Config, _))));
        // A key that is not the certificate's.
        let (_, _, chain, _) = leaf(&ca, &["a"], true);
        let (_, _, _, other_key) = leaf(&ca, &["b"], true);
        assert!(matches!(client("db.example", &ca.cert.pem(), &chain, &other_key, true), Err((Kind::Config, _))));
    }

    #[test]
    fn roots_come_from_ssl_cert_file() {
        let ca = ca("from the file");
        let path = std::env::temp_dir().join(format!("zr-net-roots-{}.pem", std::process::id()));
        std::fs::write(&path, ca.cert.pem()).unwrap();
        std::env::set_var("SSL_CERT_FILE", &path);
        std::env::remove_var("SSL_CERT_DIR");
        let store = crate::roots::native().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn garbage_from_the_server_ends_in_an_error_and_never_a_panic() {
        let ca = ca("test CA");
        let mut c = client("db.example", &ca.cert.pem(), "", "", true).unwrap();
        let mut junk = vec![0u8; 3000];
        let mut x = 0x1234_5678u32;
        for b in junk.iter_mut() {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        let mut out = vec![0u8; 20000];
        c.take_cipher(&mut out);
        let mut n = 0;
        while n < junk.len() {
            let g = c.give_cipher(&junk[n..]);
            if g <= 0 {
                break;
            }
            n += g as usize;
        }
        assert_eq!(c.error().0 as i32 != 0, true);
    }

    /// Writes the server's first flight (ServerHello to Finished, with a CertificateRequest) for TLS
    /// 1.3 and 1.2, as seeds of the Zig fuzz target "TLS records" (runner/src/fuzz_corpus/tls):
    /// `ZR_WRITE_SEEDS=dir cargo test write_the_fuzz_seeds`.
    #[test]
    fn write_the_fuzz_seeds() {
        let Ok(dir) = std::env::var("ZR_WRITE_SEEDS") else { return };
        let ca = ca("test CA");
        let (cert, key, _, _) = leaf(&ca, &["db.example"], false);
        for (name, versions) in [("flight13", &rustls::version::TLS13), ("flight12", &rustls::version::TLS12)] {
            let provider = Arc::new(ring::default_provider());
            let mut roots = RootCertStore::empty();
            roots.add(ca.cert.der().clone()).unwrap();
            let cfg = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[versions])
                .unwrap()
                .with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap())
                .with_single_cert(vec![cert.clone()], key.clone_key())
                .unwrap();
            let mut s = ServerConnection::new(Arc::new(cfg)).unwrap();
            let mut c = client("db.example", &ca.cert.pem(), "", "", true).unwrap();
            let mut hello = vec![0u8; 20000];
            let n = c.take_cipher(&mut hello) as usize;
            let mut r = &hello[..n];
            s.read_tls(&mut r).unwrap();
            s.process_new_packets().unwrap();
            let mut flight = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut flight).unwrap();
            }
            std::fs::write(format!("{dir}/{name}.bin"), &flight).unwrap();
            std::fs::write(format!("{dir}/ca.crt"), ca.cert.pem()).unwrap();
            // An alert record: handshake_failure.
            std::fs::write(format!("{dir}/alert.bin"), [21u8, 3, 3, 0, 2, 2, 40]).unwrap();
        }
    }
}
