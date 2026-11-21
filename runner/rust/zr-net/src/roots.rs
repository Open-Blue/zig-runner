//! The trusted roots, loaded once and shared by every connection: the system's (the bundle
//! `SSL_CERT_FILE` names, or `SSL_CERT_DIR`, or the usual system paths), kept for an hour and then
//! read again, so a bundle that was updated reaches a runner that has run for weeks. A PEM given
//! by the caller (`sslrootcert`) replaces them, as libpq's does.
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::RootCertStore;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KEEP: Duration = Duration::from_secs(3600);
/// The least time between two reads of the bundle that a certificate unknown to the roots may cause: a server
/// that presents a chain nobody trusts must not make every handshake read the bundle again.
const REFRESH_AFTER_UNKNOWN: Duration = Duration::from_secs(60);
static NATIVE: Mutex<Option<(Instant, Arc<RootCertStore>)>> = Mutex::new(None);

/// The roots of a PEM bundle; an error names what was wrong with it.
pub fn from_pem(pem: &[u8]) -> Result<Arc<RootCertStore>, String> {
    let mut store = RootCertStore::empty();
    let mut n = 0;
    for c in CertificateDer::pem_slice_iter(pem) {
        let c = c.map_err(|e| format!("root certificates: {e}"))?;
        store.add(c).map_err(|e| format!("root certificate: {e}"))?;
        n += 1;
    }
    if n == 0 {
        return Err("root certificates: the file holds no certificate".into());
    }
    Ok(Arc::new(store))
}

/// A handshake met a certificate whose issuer is not in the system's roots: the bundle may have been
/// updated since it was read (a CA added after the runner started, which is what the std client's
/// `renew` was for), so the next `native()` reads it again, if it was read more than a minute ago.
/// True when it will.
pub fn refresh_after_unknown_issuer() -> bool {
    refresh_if_older_than(REFRESH_AFTER_UNKNOWN)
}

fn refresh_if_older_than(age: Duration) -> bool {
    let mut slot = NATIVE.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some((at, _)) if at.elapsed() >= age => {
            *slot = None;
            true
        }
        // Never read: the next call reads it anyway.
        None => true,
        _ => false,
    }
}

/// The system's roots.
pub fn native() -> Result<Arc<RootCertStore>, String> {
    let mut slot = NATIVE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, store)) = slot.as_ref() {
        if at.elapsed() < KEEP {
            return Ok(store.clone());
        }
    }
    let loaded = rustls_native_certs::load_native_certs();
    let mut store = RootCertStore::empty();
    // Bundles hold certificates rustls refuses now and then (a negative serial): those are skipped.
    let (added, _ignored) = store.add_parsable_certificates(loaded.certs);
    if added == 0 {
        let why = loaded.errors.first().map(|e| e.to_string()).unwrap_or_default();
        return Err(format!(
            "no root certificates found (SSL_CERT_FILE, SSL_CERT_DIR, /etc/ssl/certs): {why}"
        ));
    }
    let store = Arc::new(store);
    *slot = Some((Instant::now(), store.clone()));
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_updated_after_it_was_read_is_read_again_after_an_unknown_issuer_but_not_every_time() {
        let _g = crate::runtime::test_lock();
        let dir = std::env::temp_dir().join(format!("zr-roots-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("bundle.pem");
        let ca = |name: &str| {
            let mut p = rcgen::CertificateParams::new(vec![]).expect("params");
            p.distinguished_name.push(rcgen::DnType::CommonName, name);
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let k = rcgen::KeyPair::generate().expect("key");
            p.self_signed(&k).expect("ca").pem()
        };
        let (a, b) = (ca("roots test A"), ca("roots test B"));
        std::env::set_var("SSL_CERT_FILE", &file);
        std::env::remove_var("SSL_CERT_DIR");
        std::fs::write(&file, &a).expect("write");
        *NATIVE.lock().unwrap_or_else(|e| e.into_inner()) = None;
        assert_eq!(native().expect("roots").len(), 1);
        // A CA is added to the bundle after it was read: the cache still has the old one...
        std::fs::write(&file, format!("{a}{b}")).expect("write");
        assert_eq!(native().expect("roots").len(), 1);
        // ...and an unknown issuer within the minute does not read the bundle again (a hostile server
        // could otherwise make every handshake do it)...
        assert!(!refresh_after_unknown_issuer());
        assert_eq!(native().expect("roots").len(), 1);
        // ...but one after it does.
        assert!(refresh_if_older_than(Duration::ZERO));
        assert_eq!(native().expect("roots").len(), 2);
        std::env::remove_var("SSL_CERT_FILE");
        *NATIVE.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
