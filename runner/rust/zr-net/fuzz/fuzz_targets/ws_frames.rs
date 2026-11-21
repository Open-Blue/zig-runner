//! What a WebSocket server sends the feed after it accepted the upgrade, as the client consumes it:
//! tungstenite parses the bytes as frames (lengths, masks, reserved bits, fragments, control frames,
//! UTF-8) and our code answers pings, closes, queues what is received and sends what the caller
//! queued, all through the C ABI as Zig drives it. The first byte chooses what the caller does
//! (which messages it sends, whether it asks for the close); the rest is the server's bytes after the
//! upgrade, verbatim. Checks: nothing panics or hangs, queues stay within their bounds, every return
//! is one the ABI documents (see `zr_net_fuzz::ws::run`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use zr_net_fuzz::ws::{fixture, run, Plan};

fuzz_target!(|data: &[u8]| {
    let [mode, frames @ ..] = data else { return };
    let f = fixture();
    *f.after.lock().unwrap() = frames.to_vec();
    let mut sends = Vec::new();
    if mode & 1 != 0 {
        sends.push((0, b"{\"value\":[1,2,3]}".to_vec()));
    }
    if mode & 2 != 0 {
        sends.push((1, vec![7u8; 100]));
    }
    if mode & 4 != 0 {
        sends.push((2, Vec::new()));
    }
    if mode & 8 != 0 {
        // More than the queue holds, in messages bigger than a frame.
        sends.extend((0..6).map(|i| (0, vec![b'a' + i; 1500])));
    }
    run(&Plan { sends, close: mode & 16 != 0 });
});
