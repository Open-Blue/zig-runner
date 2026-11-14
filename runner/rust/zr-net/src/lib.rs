//! The runner's network stack behind a C ABI (docs/rust-net.md). Zig sees `include/zr_net.h`-style
//! functions with plain integers, byte pointers and opaque handles; no Rust type crosses.
//!
//! R1 exports the skeleton only: the library's version and the lifetime of the tokio runtime.

mod runtime;

/// The crate's version, NUL-terminated, for the runner to compare with what it was built for.
#[no_mangle]
pub extern "C" fn zr_net_version() -> *const core::ffi::c_char {
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
