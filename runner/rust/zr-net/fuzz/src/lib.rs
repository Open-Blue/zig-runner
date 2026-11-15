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

/// Whether a response may be served: a redirect, a refresh or any other `//` in it could name a
/// host of the fuzzer's choosing, and the client would connect there. Only the fixture's own
/// address (`http://127.0.0.1:PORT`) may follow a `//`.
pub fn safe_response(port: u16, r: &[u8]) -> bool {
    let own = format!("//127.0.0.1:{port}");
    let mut i = 0;
    while let Some(k) = r[i..].windows(2).position(|w| w == b"//") {
        let at = i + k;
        if !(r[at..].starts_with(own.as_bytes()) && r[..at].ends_with(b"http:")) {
            return false;
        }
        i = at + 2;
    }
    true
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
        assert!((1..=19).contains(&rc), "start returned {rc}");
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
        assert!((1..=19).contains(&info.error), "error code {}", info.error);
    }
    unsafe {
        zr_net_call_free(call);
        zr_net_client_free(client);
    }
    a
}
