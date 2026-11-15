//! What the caller's request becomes on the wire: the method, the path and query, the header lines
//! (`Name: value`, `\n` apart) and the body come from the caller, who may have them from a
//! workflow's author (a URL, the `with:` of an action). The input is split at NUL bytes into
//! method, path, headers and body. Checks: a request that goes out is exactly one well-formed
//! request (a header value or a method with a line break must not split it into two), and nothing
//! panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zr_net_fuzz::{fixture, run, Request};

const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(4, |&b| b == 0);
    let (method, path, headers, body) = (parts.next().unwrap_or(b""), parts.next().unwrap_or(b""), parts.next().unwrap_or(b""), parts.next().unwrap_or(b""));
    // The address is the fixture's whatever the path says: the path starts with a slash, so
    // nothing in it is the host (`@` and `\` come after it).
    let mut path = path.to_vec();
    if path.first() != Some(&b'/') {
        path.insert(0, b'/');
    }
    let f = fixture();
    *f.response.lock().unwrap() = ANSWER.to_vec();
    f.request.lock().unwrap().clear();
    let a = run(&Request { method, path: &path, headers, body, max_redirects: 0, max_response: 1 << 16, stream_response: false });
    if a.error != 0 {
        return;
    }
    // The server has the request's head by now: the client read the answer after sending it.
    let mut head = f.request.lock().unwrap().clone();
    // The server read up to the end of the head and a little of the body, if it came with it.
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").expect("an unterminated head");
    head.truncate(end + 4);
    let text = String::from_utf8_lossy(&head);
    let lines: Vec<&str> = text.split("\r\n").collect();
    let request_line = lines[0];
    assert_eq!(request_line.split(' ').count(), 3, "the request line is `METHOD target HTTP/1.1`: {request_line:?}");
    for l in &lines[1..lines.len() - 2] {
        assert!(l.contains(':') && !l.contains('\n') && !l.contains('\r'), "a header line: {l:?}");
    }
    assert!(lines[lines.len() - 2].is_empty() && lines[lines.len() - 1].is_empty());
});
