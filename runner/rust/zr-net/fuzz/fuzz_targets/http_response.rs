//! What an HTTP server answers the client with, as the client consumes it: hyper parses the bytes
//! and our code follows redirects, keeps the headers, limits the body and copies all of it out
//! through the C ABI, whole or as a stream. The first three bytes choose how the call is made
//! (redirects allowed, the body limit, buffered or streamed); the rest is the server's answer,
//! verbatim. Checks: nothing panics or hangs, the limits hold, and what comes out is well formed
//! (see `zr_net_fuzz::run`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use zr_net_fuzz::{fixture, run, safe_response};

const LIMITS: [usize; 6] = [0, 1, 64, 4096, 1 << 20, usize::MAX];

fuzz_target!(|data: &[u8]| {
    let [mode, limit, method, response @ ..] = data else { return };
    let f = fixture();
    if !safe_response(f.port, response) {
        return;
    }
    *f.response.lock().unwrap() = response.to_vec();
    let _ = run(&zr_net_fuzz::Request {
        method: [&b"GET"[..], b"HEAD", b"POST", b"PUT"][(*method & 3) as usize],
        path: b"/dir/file?q=1",
        headers: b"accept: */*\nx-token: secret\n",
        body: if *method & 3 >= 2 { b"payload" } else { b"" },
        max_redirects: (*mode >> 1 & 3) as u32 * 2,
        max_response: LIMITS[*limit as usize % LIMITS.len()],
        stream_response: *mode & 1 != 0,
    });
});
