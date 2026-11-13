//! Sans-IO TLS client for the Zig runner (pg.zig's TLS layer): Zig keeps the socket and its
//! std.Io cancellation; this only turns ciphertext into plaintext and back. C ABI, no I/O, no threads.
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::sync::Arc;

pub struct Tls { conn: ClientConnection }

unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] { if n == 0 { &[] } else { std::slice::from_raw_parts(p, n) } }

/// `ca_pem`: trusted roots (empty with `insecure` = 0 means none). `cert_pem`/`key_pem`: optional client identity.
/// Returns null on bad PEM / host name.
#[no_mangle]
pub unsafe extern "C" fn zr_tls_new(host: *const u8, host_len: usize, ca_pem: *const u8, ca_len: usize,
    cert_pem: *const u8, cert_len: usize, key_pem: *const u8, key_len: usize) -> *mut Tls {
    let mut roots = RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut bytes(ca_pem, ca_len)) { match c { Ok(c) => { let _ = roots.add(c); } Err(_) => return std::ptr::null_mut() } }
    let b = ClientConfig::builder().with_root_certificates(roots);
    let cfg = if cert_len > 0 {
        let chain: Result<Vec<_>, _> = rustls_pemfile::certs(&mut bytes(cert_pem, cert_len)).collect();
        let key = match rustls_pemfile::private_key(&mut bytes(key_pem, key_len)) { Ok(Some(k)) => k, _ => return std::ptr::null_mut() };
        match chain.ok().and_then(|c| b.with_client_auth_cert(c, key).ok()) { Some(c) => c, None => return std::ptr::null_mut() }
    } else { b.with_no_client_auth() };
    let name = match std::str::from_utf8(bytes(host, host_len)).ok().and_then(|s| s.to_string().try_into().ok()) { Some(n) => n, None => return std::ptr::null_mut() };
    match ClientConnection::new(Arc::new(cfg), name) { Ok(conn) => Box::into_raw(Box::new(Tls { conn })), Err(_) => std::ptr::null_mut() }
}

#[no_mangle] pub unsafe extern "C" fn zr_tls_free(t: *mut Tls) { if !t.is_null() { drop(Box::from_raw(t)); } }
#[no_mangle] pub unsafe extern "C" fn zr_tls_wants_write(t: *mut Tls) -> i32 { (*t).conn.wants_write() as i32 }
#[no_mangle] pub unsafe extern "C" fn zr_tls_is_handshaking(t: *mut Tls) -> i32 { (*t).conn.is_handshaking() as i32 }

/// Ciphertext to send to the peer (copied into `out`); returns bytes written (0: nothing pending).
#[no_mangle]
pub unsafe extern "C" fn zr_tls_take_cipher(t: *mut Tls, out: *mut u8, cap: usize) -> isize {
    let mut w = std::slice::from_raw_parts_mut(out, cap);
    match (*t).conn.write_tls(&mut w) { Ok(_) => { let left = w.len(); (cap - left) as isize } Err(_) => -1 }
}
/// Ciphertext received from the peer; returns bytes consumed, or -1 on a TLS error (bad cert, alert, ...).
#[no_mangle]
pub unsafe extern "C" fn zr_tls_give_cipher(t: *mut Tls, inp: *const u8, len: usize) -> isize {
    let mut r = bytes(inp, len);
    let n = match (*t).conn.read_tls(&mut r) { Ok(n) => n, Err(_) => return -1 };
    match (*t).conn.process_new_packets() { Ok(_) => n as isize, Err(_) => -1 }
}
/// Plaintext from the peer: bytes read, 0 for none yet (WouldBlock) or -2 for a clean close_notify.
#[no_mangle]
pub unsafe extern "C" fn zr_tls_read(t: *mut Tls, out: *mut u8, cap: usize) -> isize {
    match (*t).conn.reader().read(std::slice::from_raw_parts_mut(out, cap)) {
        Ok(0) => -2, Ok(n) => n as isize,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0, Err(_) => -1 }
}
#[no_mangle]
pub unsafe extern "C" fn zr_tls_write(t: *mut Tls, inp: *const u8, len: usize) -> isize {
    match (*t).conn.writer().write_all(bytes(inp, len)) { Ok(()) => len as isize, Err(_) => -1 }
}
#[no_mangle] pub unsafe extern "C" fn zr_tls_close_notify(t: *mut Tls) { (*t).conn.send_close_notify(); }
