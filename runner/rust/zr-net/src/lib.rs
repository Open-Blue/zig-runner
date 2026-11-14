//! The runner's network stack behind a C ABI (docs/rust-net.md). Zig sees plain integers, byte
//! pointers and opaque handles; no Rust type crosses.
//!
//! R1: the library's version and the lifetime of the tokio runtime. R2: TLS for Postgres (sans-IO)
//! and the count of what Rust allocates.

mod alloc;
mod body;
mod call;
mod client;
mod proxy;
mod roots;
mod runtime;
mod tls;

#[global_allocator]
static COUNTING: alloc::Counting = alloc::Counting;

use core::ffi::c_char;

/// The crate's version, NUL-terminated, for the runner to compare with what it was built for.
#[no_mangle]
pub extern "C" fn zr_net_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Starts the runtime with `threads` workers (0: the default of 2). Idempotent: 0 when it runs
/// already or now, a negative errno-style code when it cannot start.
#[no_mangle]
pub extern "C" fn zr_net_runtime_start(threads: u32) -> i32 {
    runtime::start(threads)
}

/// Runs `n` as a task on the runtime and returns `n + 1`, proving that the worker threads and the
/// ABI work end to end. Negative when the runtime is not running.
#[no_mangle]
pub extern "C" fn zr_net_selftest(n: u32) -> i64 {
    runtime::selftest(n)
}

/// Stops the runtime and joins its threads; safe to call twice or without a start.
#[no_mangle]
pub extern "C" fn zr_net_runtime_stop() {
    runtime::stop()
}

/// Bytes Rust has allocated and not freed now.
#[no_mangle]
pub extern "C" fn zr_net_heap_bytes() -> usize {
    alloc::in_use()
}

/// The most bytes Rust ever held at once.
#[no_mangle]
pub extern "C" fn zr_net_heap_peak() -> usize {
    alloc::peak()
}

/// How many allocations Rust has made.
#[no_mangle]
pub extern "C" fn zr_net_heap_allocations() -> u64 {
    alloc::allocations()
}

unsafe fn copy_message(msg: &str, out: *mut u8, cap: usize) {
    if out.is_null() || cap == 0 {
        return;
    }
    let n = msg.len().min(cap - 1);
    std::ptr::copy_nonoverlapping(msg.as_ptr(), out, n);
    *out.add(n) = 0;
}

/// A TLS client connection for `cfg`. 0 and `*out` set, or the error's kind (see `tls::Kind`) and a
/// NUL-terminated message in `msg`.
///
/// # Safety
/// `cfg`'s pointers must be valid for their lengths; `out` for a write; `msg` for `msg_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_new(cfg: *const tls::Config, out: *mut *mut tls::Tls, msg: *mut u8, msg_cap: usize) -> i32 {
    match tls::new(&*cfg) {
        Ok(t) => {
            *out = Box::into_raw(Box::new(t));
            0
        }
        Err((kind, text)) => {
            copy_message(&text, msg, msg_cap);
            kind as i32
        }
    }
}

/// # Safety
/// `t` is from `zr_net_tls_new` and not freed before; null is allowed.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_free(t: *mut tls::Tls) {
    if !t.is_null() {
        drop(Box::from_raw(t));
    }
}

/// # Safety
/// `t` is a live handle.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_wants_write(t: *mut tls::Tls) -> i32 {
    (*t).wants_write() as i32
}

/// # Safety
/// `t` is a live handle.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_is_handshaking(t: *mut tls::Tls) -> i32 {
    (*t).is_handshaking() as i32
}

/// Ciphertext to send to the peer, copied into `out`: the bytes (0: none pending), or -1.
///
/// # Safety
/// `t` is a live handle; `out` is valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_take_cipher(t: *mut tls::Tls, out: *mut u8, cap: usize) -> isize {
    (*t).take_cipher(std::slice::from_raw_parts_mut(out, cap))
}

/// Ciphertext received from the peer: the bytes consumed, or -1 (`zr_net_tls_error` says why).
///
/// # Safety
/// `t` is a live handle; `inp` is valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_give_cipher(t: *mut tls::Tls, inp: *const u8, len: usize) -> isize {
    let input = if len == 0 { &[][..] } else { std::slice::from_raw_parts(inp, len) };
    (*t).give_cipher(input)
}

/// Plaintext from the peer: bytes read, 0 for none yet, -2 for a clean close, -1 for an error.
///
/// # Safety
/// `t` is a live handle; `out` is valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_read(t: *mut tls::Tls, out: *mut u8, cap: usize) -> isize {
    (*t).read(std::slice::from_raw_parts_mut(out, cap))
}

/// Plaintext to send: the bytes taken (0: send ciphertext first), or -1.
///
/// # Safety
/// `t` is a live handle; `inp` is valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_write(t: *mut tls::Tls, inp: *const u8, len: usize) -> isize {
    let input = if len == 0 { &[][..] } else { std::slice::from_raw_parts(inp, len) };
    (*t).write(input)
}

/// # Safety
/// `t` is a live handle.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_close_notify(t: *mut tls::Tls) {
    (*t).close_notify()
}

/// The last error's kind (`tls::Kind`) and, in `msg`, its text.
///
/// # Safety
/// `t` is a live handle; `msg` is valid for `msg_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_tls_error(t: *mut tls::Tls, msg: *mut u8, msg_cap: usize) -> i32 {
    let (kind, text) = (*t).error();
    copy_message(text, msg, msg_cap);
    kind as i32
}
