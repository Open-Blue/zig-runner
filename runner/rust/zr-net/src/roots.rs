//! The trusted roots, loaded once and shared by every connection: the system's (the bundle
//! `SSL_CERT_FILE` names, or `SSL_CERT_DIR`, or the usual system paths), kept for an hour and then
//! read again, so a bundle that was updated reaches a runner that has run for weeks. A PEM given
//! by the caller (`sslrootcert`) replaces them, as libpq's does.
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::RootCertStore;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KEEP: Duration = Duration::from_secs(3600);
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
