//! What the fuzz targets share: one loopback server for the process and a driver for the C ABI of
//! the HTTP client (`zr_net::call`), used as Zig uses it (a descriptor to wait on, copies out).
//!
//! Nothing here reaches beyond the loopback interface: a request goes only to the server below
//! (`url` starts with its address), and a response that could send a redirect elsewhere is not
//! served (`safe_response`).
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use zr_net::call::*;

/// What the server answers each connection with, and the head of the last request it read.
pub struct Fixture {
    pub port: u16,
    pub response: Mutex<Vec<u8>>,
    pub request: Mutex<Vec<u8>>,
}

pub fn fixture() -> &'static Fixture {
    static F: OnceLock<&'static Fixture> = OnceLock::new();
    F.get_or_init(|| {
        assert_eq!(zr_net::zr_net_runtime_start(2), 0);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let f: &'static Fixture = Box::leak(Box::new(Fixture { port: l.local_addr().unwrap().port(), response: Mutex::new(Vec::new()), request: Mutex::new(Vec::new()) }));
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || serve(s, f));
            }
        });
        f
    })
}

/// Reads one request head, answers with the current response, and closes.
fn serve(mut s: TcpStream, f: &Fixture) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut head = Vec::new();
    let mut b = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 1 << 16 {
        match s.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&b[..n]),
        }
    }
    *f.request.lock().unwrap() = head;
    let r = f.response.lock().unwrap().clone();
    let _ = s.write_all(&r);
    let _ = s.shutdown(std::net::Shutdown::Both);
}

/// Whether a response may be served: a redirect (or any other text) could name a host of the
/// fuzzer's choosing, and the client would connect there. Every `//` in it must be the start of a
/// URL that the client's own parser (`http::Uri`) reads as the fixture's: scheme http, host
/// 127.0.0.1, this port, and no userinfo (`http://127.0.0.1:PORT@evil.example/` has the host
/// evil.example). The URL ends at the first space, control or non-ASCII byte or quote.
pub fn safe_response(port: u16, r: &[u8]) -> bool {
    let mut i = 0;
    while let Some(k) = r[i..].windows(2).position(|w| w == b"//") {
        let at = i + k;
        i = at + 2;
        if !r[..at].ends_with(b"http:") {
            return false;
        }
        let start = at - "http:".len();
        let end = r[start..].iter().position(|&b| b <= b' ' || b >= 0x7f || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'\\')).map_or(r.len(), |e| start + e);
        let Ok(text) = std::str::from_utf8(&r[start..end]) else { return false };
        let Ok(uri) = text.parse::<http::Uri>() else { return false };
        let ok = uri.scheme_str() == Some("http")
            && uri.host() == Some("127.0.0.1")
            && uri.port_u16() == Some(port)
            && uri.authority().is_some_and(|a| !a.as_str().contains('@'));
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::safe_response;

    #[test]
    fn only_the_fixtures_own_address_is_served() {
        let ok = |s: &str| safe_response(4000, s.as_bytes());
        assert!(ok("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
        assert!(ok("HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n"));
        assert!(ok("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:4000/x?y=1#z\r\n\r\n"));
        assert!(ok("Location: http://127.0.0.1:4000\r\n"));
        // Userinfo makes the host the one after the `@`.
        assert!(!ok("Location: http://127.0.0.1:4000@evil.example/\r\n"));
        assert!(!ok("Location: http://127.0.0.1:4000@evil.example\r\n"));
        assert!(!ok("Location: http://127.0.0.1:4000:80@evil.example/\r\n"));
        assert!(!ok("Location: http://a:b@127.0.0.1:4000/\r\n"));
        assert!(!ok("Location: http://127.0.0.1:40000/\r\n"));
        assert!(!ok("Location: http://127.0.0.1:4000.evil.example/\r\n"));
        assert!(!ok("Location: http://127.0.0.1/\r\n"));
        assert!(!ok("Location: https://127.0.0.1:4000/\r\n"));
        assert!(!ok("Location: //evil.example/\r\n"));
        assert!(!ok("Location: http://evil.example/\r\n"));
        assert!(!ok("Location: ftp://127.0.0.1:4000/\r\n"));
    }
}

/// One request through the C ABI.
pub struct Request<'a> {
    pub method: &'a [u8],
    /// Starts with `/`; the address is the fixture's.
    pub path: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
    pub max_redirects: u32,
    pub max_response: usize,
    pub stream_response: bool,
}

pub struct Answer {
    pub error: i32,
    pub status: u16,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub message: Vec<u8>,
}


/// Runs `r` against the fixture and checks what the library promises of any answer.
pub fn run(r: &Request) -> Answer {
    let f = fixture();
    let mut url = format!("http://127.0.0.1:{}", f.port).into_bytes();
    url.extend_from_slice(r.path);
    let cfg = ClientConfig { user_agent: std::ptr::null(), user_agent_len: 0, roots: std::ptr::null(), roots_len: 0, connect_timeout_ms: 2000, tls_timeout_ms: 2000, idle_timeout_ms: 1000, max_idle_per_host: 0, flags: 0 };
    let mut client = std::ptr::null_mut();
    assert_eq!(unsafe { zr_net_client_new(&cfg, &mut client, std::ptr::null_mut(), 0) }, 0);
    let spec = RequestSpec {
        method: r.method.as_ptr(),
        method_len: r.method.len(),
        url: url.as_ptr(),
        url_len: url.len(),
        headers: r.headers.as_ptr(),
        headers_len: r.headers.len(),
        body: r.body.as_ptr(),
        body_len: r.body.len(),
        max_redirects: r.max_redirects,
        max_response: r.max_response,
        first_byte_ms: 3000,
        read_idle_ms: 3000,
        flags: FLAG_FRESH | if r.stream_response { FLAG_STREAM_RESPONSE } else { 0 },
        total_ms: 8000,
    };
    let (mut call, mut fd) = (std::ptr::null_mut(), -1);
    let mut msg = [0u8; 256];
    let rc = unsafe { zr_net_call_start(client, &spec, &mut call, &mut fd, msg.as_mut_ptr(), msg.len()) };
    if rc != 0 {
        // Refused before it started (a bad method, URL or header): a code and a NUL-terminated message.
        assert!((1..=19).contains(&rc) || rc == 21, "start returned {rc}");
        assert!(msg.contains(&0) || msg[255] != 0, "message not terminated");
        unsafe { zr_net_client_free(client) };
        return Answer { error: rc, status: 0, headers: vec![], body: vec![], message: vec![] };
    }
    let wake = unsafe { UnixStream::from_raw_fd(fd) };
    wake.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let wait = |w: &UnixStream| {
        let mut b = [0u8; 64];
        // libFuzzer's timer signal interrupts a read: ask again.
        loop {
            match (&*w).read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("no wake within 15 s: {e}"),
                Ok(_) => return,
            }
        }
    };
    let mut info: Info = unsafe { std::mem::zeroed() };
    while unsafe { zr_net_call_result(call, &mut info) } != 0 {
        wait(&wake);
    }
    let mut a = Answer { error: info.error, status: info.status, headers: vec![0; info.headers_len], body: vec![0; info.body_len], message: vec![0; info.message_len] };
    if info.error == 0 {
        let n = unsafe { zr_net_call_copy(call, 0, a.headers.as_mut_ptr(), a.headers.len()) };
        assert_eq!(n, info.headers_len);
        if r.stream_response {
            assert_eq!(info.body_len, 0, "a streamed call's head carries no body");
            let mut total = 0usize;
            let mut buf = vec![0u8; 1 + (r.body.len() % 4096)];
            loop {
                let mut n = 0usize;
                match unsafe { zr_net_body_read(call, buf.as_mut_ptr(), buf.len(), &mut n, msg.as_mut_ptr(), msg.len()) } {
                    0 => {
                        assert!(n > 0 && n <= buf.len());
                        total += n;
                        a.body.extend_from_slice(&buf[..n]);
                    }
                    1 => wait(&wake),
                    2 => {
                        assert!(total as u64 <= r.max_response as u64, "a body of {total} bytes past the limit {}", r.max_response);
                        break;
                    }
                    rc => {
                        assert!((101..=119).contains(&rc), "body_read returned {rc}");
                        a.error = rc - 100;
                        break;
                    }
                }
            }
        } else {
            let n = unsafe { zr_net_call_copy(call, 1, a.body.as_mut_ptr(), a.body.len()) };
            assert_eq!(n, info.body_len);
            assert!(a.body.len() as u64 <= r.max_response as u64, "a body of {} bytes past the limit {}", a.body.len(), r.max_response);
        }
        assert!((100..1000).contains(&info.status), "status {}", info.status);
        assert!(info.redirects <= r.max_redirects, "{} redirects of {} allowed", info.redirects, r.max_redirects);
        for line in a.headers.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let colon = line.windows(2).position(|w| w == b": ").expect("a header line is `name: value`");
            assert!(!line[..colon].iter().any(|b| b.is_ascii_uppercase()), "header names are lower-case");
        }
    } else {
        let n = unsafe { zr_net_call_copy(call, 2, a.message.as_mut_ptr(), a.message.len()) };
        assert_eq!(n, info.message_len);
        assert!((1..=19).contains(&info.error) || info.error == 21, "error code {}", info.error);
    }
    unsafe {
        zr_net_call_free(call);
        zr_net_client_free(client);
    }
    a
}

/// The WebSocket's server side (`zr_net::ws`): a loopback server that accepts the upgrade as a real
/// server does and then sends the fuzzer's bytes, verbatim, as the frames of the connection; it
/// reads and drops what the client sends until the client goes. Only the loopback interface is
/// reached: the URL is the fixture's own address.
pub mod ws {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use zr_net::call::{zr_net_client_free, zr_net_client_new, ClientConfig};
    use zr_net::ws::*;

    pub struct Fixture {
        pub port: u16,
        /// What the server sends after the upgrade.
        pub after: Mutex<Vec<u8>>,
    }

    pub fn fixture() -> &'static Fixture {
        static F: OnceLock<&'static Fixture> = OnceLock::new();
        F.get_or_init(|| {
            assert_eq!(zr_net::zr_net_runtime_start(2), 0);
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let f: &'static Fixture = Box::leak(Box::new(Fixture { port: l.local_addr().unwrap().port(), after: Mutex::new(Vec::new()) }));
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    std::thread::spawn(move || serve(s, f));
                }
            });
            f
        })
    }

    fn serve(mut s: TcpStream, f: &Fixture) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 1 << 14 {
            match s.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => return,
            }
        }
        let text = String::from_utf8_lossy(&head);
        let key = text.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap_or("").trim().to_string();
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        let _ = s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes());
        let after = f.after.lock().unwrap().clone();
        let _ = s.write_all(&after);
        // Reads and drops what the client sends, until it goes or is silent for the timeout.
        let mut sink = [0u8; 4096];
        while let Ok(n) = s.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    }

    pub const QUEUE: u32 = 4096;
    pub const RECV: u32 = 2048;

    /// What the client is asked to do with the connection: what it sends, and whether it asks for the close.
    pub struct Plan {
        pub sends: Vec<(u32, Vec<u8>)>,
        pub close: bool,
    }

    /// One connection through the C ABI, as the Zig side drives it, with the checks the ABI promises
    /// of any peer: every return is one it documents, counts stay within what the buffers and queues
    /// hold, and a connection that ends says how.
    pub fn run(plan: &Plan) {
        let f = fixture();
        let url = format!("ws://127.0.0.1:{}/_ws/ingest.sock", f.port);
        let cfg = ClientConfig { user_agent: std::ptr::null(), user_agent_len: 0, roots: std::ptr::null(), roots_len: 0, connect_timeout_ms: 2000, tls_timeout_ms: 2000, idle_timeout_ms: 1000, max_idle_per_host: 0, flags: 0 };
        let mut client = std::ptr::null_mut();
        assert_eq!(unsafe { zr_net_client_new(&cfg, &mut client, std::ptr::null_mut(), 0) }, 0);
        let spec = WsSpec { url: url.as_ptr(), url_len: url.len(), headers: b"x-token: secret\n".as_ptr(), headers_len: 16, max_frame: 16, open_ms: 3000, close_wait_ms: 200, queue_limit: QUEUE, recv_limit: RECV };
        let (mut ws, mut fd) = (std::ptr::null_mut(), -1);
        let mut msg = [0u8; 256];
        assert_eq!(unsafe { zr_net_ws_connect(client, &spec, &mut ws, &mut fd, msg.as_mut_ptr(), msg.len()) }, 0);
        let wake = unsafe { UnixStream::from_raw_fd(fd) };
        wake.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // Waits for a wake; false when there was none in time (the caller decides what that means).
        let wait = || loop {
            let mut b = [0u8; 64];
            // libFuzzer's timer signal interrupts a read: ask again.
            match (&wake).read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) | Ok(0) => return false,
                Ok(_) => return true,
            }
        };
        let info = || {
            let mut i: WsInfo = unsafe { std::mem::zeroed() };
            unsafe { zr_net_ws_info(ws, &mut i) };
            assert!(i.state <= 3, "state {}", i.state);
            assert!(i.queued <= (QUEUE as usize).max(plan.sends.iter().map(|s| s.1.len()).max().unwrap_or(0)), "{} bytes queued", i.queued);
            assert!(i.waiting <= RECV as usize, "{} bytes waiting", i.waiting);
            i
        };
        let mut i = info();
        while i.state == 0 {
            assert!(wait(), "the upgrade neither finished nor failed");
            i = info();
        }
        if i.error != 0 {
            assert!((1..=21).contains(&i.error), "error code {}", i.error);
            let n = unsafe { zr_net_ws_message(ws, msg.as_mut_ptr(), msg.len()) };
            assert_eq!(i.message_len > 0, n > 0);
            unsafe {
                zr_net_ws_free(ws);
                zr_net_client_free(client);
            }
            return;
        }
        assert_eq!(i.status, 101);
        // From here on a wait that finds nothing is an answer (the peer is silent), not a failure.
        wake.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        for (kind, data) in &plan.sends {
            for _ in 0..8 {
                match unsafe { zr_net_ws_send(ws, *kind, data.as_ptr(), data.len()) } {
                    0 | 2 => break,
                    1 => {
                        // Full: the library wakes when the queue is below half, or the connection ends.
                        if !wait() {
                            break;
                        }
                    }
                    rc => panic!("send returned {rc}"),
                }
            }
        }
        // Takes what arrived: every message within what the inbox holds, the end with a documented code.
        let mut buf = vec![0u8; RECV as usize];
        let mut idle = 0;
        let mut ended_once = false;
        for _ in 0..64 {
            let (mut n, mut kind) = (0usize, 99u32);
            match unsafe { zr_net_ws_recv(ws, buf.as_mut_ptr(), buf.len(), &mut n, &mut kind) } {
                0 => assert!(n <= buf.len() && kind <= 1, "message of {n} bytes, kind {kind}"),
                1 => {
                    // The connection may have ended just after recv looked; asking again then must
                    // say so (the end, or a message that came before it), never "nothing yet".
                    if info().state == 3 {
                        assert!(!ended_once, "recv says nothing yet on a connection that ended");
                        ended_once = true;
                        continue;
                    }
                    idle += 1;
                    if idle > 1 || !wait() {
                        break;
                    }
                }
                2 => {
                    assert_eq!(info().state, 3);
                    break;
                }
                3 => panic!("a message of {n} bytes was taken into a buffer of {}", buf.len()),
                rc => {
                    assert!((101..=120).contains(&rc), "recv returned {rc}");
                    assert_eq!(info().state, 3);
                    break;
                }
            }
        }
        if plan.close {
            unsafe { zr_net_ws_close(ws) };
            // Over within the close wait (200 ms) and a margin, or already.
            let started = std::time::Instant::now();
            while info().state != 3 && started.elapsed() < Duration::from_secs(5) {
                wait();
            }
            assert_eq!(info().state, 3, "the close did not end the connection");
            let i = info();
            if i.error != 0 {
                assert!((1..=21).contains(&i.error), "error code {}", i.error);
            }
        }
        unsafe {
            zr_net_ws_free(ws);
            zr_net_client_free(client);
        }
    }
}
