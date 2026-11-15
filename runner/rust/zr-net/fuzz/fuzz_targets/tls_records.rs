//! What a TLS server sends the database client (`zr_net_tls_*`, rustls behind the C ABI): the
//! input is split in pieces by its first bytes and given to a client in its handshake, and what the
//! client reads, writes and reports is asked for after each. The checks are those of the C ABI: the
//! counts are within what the buffers hold, an error has a kind and a message, nothing panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zr_net::tls::Config;

fuzz_target!(|data: &[u8]| {
    let [_mode, piece, records @ ..] = data else { return };
    let host = b"db.example";
    let cfg = Config { host: host.as_ptr(), host_len: host.len(), roots: std::ptr::null(), roots_len: 0, cert: std::ptr::null(), cert_len: 0, key: std::ptr::null(), key_len: 0, flags: 0 };
    let mut t = std::ptr::null_mut();
    let mut msg = [0u8; 128];
    assert_eq!(unsafe { zr_net::zr_net_tls_new(&cfg, &mut t, msg.as_mut_ptr(), msg.len()) }, 0);
    let mut out = [0u8; 2048];
    // Its ClientHello first, as the Zig side sends it.
    while unsafe { zr_net::zr_net_tls_wants_write(t) } != 0 {
        let n = unsafe { zr_net::zr_net_tls_take_cipher(t, out.as_mut_ptr(), out.len()) };
        assert!((0..=out.len() as isize).contains(&n));
        if n == 0 {
            break;
        }
    }
    let step = 1 + *piece as usize;
    for chunk in records.chunks(step) {
        let n = unsafe { zr_net::zr_net_tls_give_cipher(t, chunk.as_ptr(), chunk.len()) };
        assert!((-1..=chunk.len() as isize).contains(&n), "consumed {n} of {}", chunk.len());
        if n < 0 {
            let mut m = [0u8; 128];
            let kind = unsafe { zr_net::zr_net_tls_error(t, m.as_mut_ptr(), m.len()) };
            assert!(kind != 0, "an error without a kind");
            break;
        }
        let r = unsafe { zr_net::zr_net_tls_read(t, out.as_mut_ptr(), out.len()) };
        assert!((-2..=out.len() as isize).contains(&r));
        let w = unsafe { zr_net::zr_net_tls_write(t, b"query".as_ptr(), 5) };
        assert!((-1..=5).contains(&w));
        let c = unsafe { zr_net::zr_net_tls_take_cipher(t, out.as_mut_ptr(), out.len()) };
        assert!((-1..=out.len() as isize).contains(&c));
        let _ = unsafe { zr_net::zr_net_tls_is_handshaking(t) };
    }
    unsafe {
        zr_net::zr_net_tls_close_notify(t);
        zr_net::zr_net_tls_free(t);
    }
});
