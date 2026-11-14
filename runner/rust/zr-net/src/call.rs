//! The C ABI of the HTTP client (docs/rust-net.md, "How a Zig caller waits"): a `Client` per process,
//! a `Call` per request. `zr_net_call_start` returns at once with a descriptor that becomes readable
//! when the request has finished; the Zig side waits for it through `std.Io` (so its cancellation and
//! deadlines apply where it blocks), then reads the result. Cancelling or freeing a call drops its
//! request, which closes its connection. Everything is copied in and out: no pointer is kept.
//!
//! Streaming (R4, `body.rs`): a call may stream its response (`FLAG_STREAM_RESPONSE`: it finishes
//! when the head is there, and the body is read with `zr_net_body_read` as it arrives) and/or its
//! request body (`FLAG_STREAM_REQUEST`: `body_len` bytes written with `zr_net_body_write`). Both go
//! through queues of a fixed size, so memory does not depend on the body.
use crate::body::{DownStream, Payload, Push, Read, UpStream, Wake};
use crate::client::{header_lines, parse_headers, Client, Code, Fail, Settings, Spec, Timings, UNKNOWN};
use crate::proxy::Proxy;
use http::Method;
use hyper::body::Bytes;
use std::os::fd::IntoRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[repr(C)]
pub struct ClientConfig {
    pub user_agent: *const u8,
    pub user_agent_len: usize,
    /// PEM roots that replace the system's; none: the system's.
    pub roots: *const u8,
    pub roots_len: usize,
    pub connect_timeout_ms: u32,
    pub tls_timeout_ms: u32,
    pub idle_timeout_ms: u32,
    pub max_idle_per_host: u32,
    /// bit 0: proxy settings from the environment (HTTPS_PROXY, HTTP_PROXY, NO_PROXY).
    pub flags: u32,
}

#[repr(C)]
pub struct RequestSpec {
    pub method: *const u8,
    pub method_len: usize,
    pub url: *const u8,
    pub url_len: usize,
    /// `Name: value` lines separated by `\n`.
    pub headers: *const u8,
    pub headers_len: usize,
    pub body: *const u8,
    pub body_len: usize,
    pub max_redirects: u32,
    pub max_response: usize,
    /// 0: no limit of its own.
    pub first_byte_ms: u32,
    pub read_idle_ms: u32,
    /// `FLAG_*`.
    pub flags: u32,
    /// 0: no limit on the whole call (its body included).
    pub total_ms: u32,
}

/// The response body is read with `zr_net_body_read`; the call finishes at its head.
pub const FLAG_STREAM_RESPONSE: u32 = 1;
/// The request body is `body_len` bytes written with `zr_net_body_write`.
pub const FLAG_STREAM_REQUEST: u32 = 2;
/// A connection made for this call, not one the pool kept.
pub const FLAG_FRESH: u32 = 4;

/// What a finished call reports.
#[repr(C)]
pub struct Info {
    /// `Code`: 0, or what went wrong (the message is copied with `zr_net_call_copy`, what 2).
    pub error: i32,
    pub status: u16,
    pub http_minor: u8,
    /// 1: the connection came from the pool.
    pub reused: u8,
    pub redirects: u32,
    pub dns_ns: u64,
    pub connect_ns: u64,
    pub tls_ns: u64,
    pub ttfb_ns: u64,
    pub total_ns: u64,
    pub bytes_in: u64,
    pub headers_len: usize,
    pub body_len: usize,
    pub message_len: usize,
}

struct Finished {
    code: Code,
    message: String,
    status: u16,
    minor: u8,
    headers: Vec<u8>,
    body: Vec<u8>,
    t: Timings,
}

pub struct Call {
    task: tokio::task::JoinHandle<()>,
    done: Arc<Mutex<Option<Finished>>>,
    up: Option<Arc<UpStream>>,
    down: Option<Arc<DownStream>>,
}

/// Records the call's outcome (its head, in a streaming call; all of it otherwise), and tells the
/// writer of a request body that nothing more is wanted and the caller that there is something to read.
fn publish(slot: &Mutex<Option<Finished>>, up: &Option<Arc<UpStream>>, wake: &Wake, f: Finished) {
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    if let Some(u) = up {
        u.finish();
    }
    wake.ping();
}

fn failed(f: Fail, t: Timings) -> Finished {
    Finished { code: f.0, message: f.1, status: 0, minor: 1, headers: Vec::new(), body: Vec::new(), t }
}

/// A call that streams its response: the head is published when it is there, the body goes to `down`.
async fn stream(client: &Client, spec: Spec, down: &DownStream, slot: &Mutex<Option<Finished>>, up: &Option<Arc<UpStream>>, wake: &Wake) {
    let started = std::time::Instant::now();
    let mut t = Timings::default();
    let total = |t: &mut Timings| t.total = started.elapsed().as_nanos().min((UNKNOWN - 1) as u128) as u64;
    let head = match client.open(&spec, &mut t).await {
        Ok(h) => h,
        Err(f) => {
            total(&mut t);
            return publish(slot, up, wake, failed(f, t));
        }
    };
    let (status, minor, headers) = (head.parts.status.as_u16(), head.minor, header_lines(&head.parts));
    publish(slot, up, wake, Finished { code: Code::Ok, message: String::new(), status, minor, headers: headers.clone(), body: Vec::new(), t });
    let r = client.pump(head, &spec, down, &mut t).await;
    total(&mut t);
    if let Some(f) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        f.t = t;
    }
    match r {
        Ok(()) => down.finish(),
        Err(f) => down.fail(f),
    }
}

unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

unsafe fn copy_message(msg: &str, out: *mut u8, cap: usize) {
    if out.is_null() || cap == 0 {
        return;
    }
    let n = msg.len().min(cap - 1);
    std::ptr::copy_nonoverlapping(msg.as_ptr(), out, n);
    *out.add(n) = 0;
}

fn ms(v: u32, default: u64) -> Duration {
    Duration::from_millis(if v == 0 { default } else { v as u64 })
}

/// A client. Returns 0 and `*out`, or a `Code` and a message.
///
/// # Safety
/// The pointers in `cfg` are valid for their lengths; `out` for a write; `msg` for `msg_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_client_new(cfg: *const ClientConfig, out: *mut *mut Arc<Client>, msg: *mut u8, msg_cap: usize) -> i32 {
    let cfg = &*cfg;
    let ua = match std::str::from_utf8(bytes(cfg.user_agent, cfg.user_agent_len)) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => concat!("zig-runner-net/", env!("CARGO_PKG_VERSION")).to_string(),
    };
    let settings = Settings {
        user_agent: ua,
        connect_timeout: ms(cfg.connect_timeout_ms, 10_000),
        tls_timeout: ms(cfg.tls_timeout_ms, 10_000),
        idle_timeout: ms(cfg.idle_timeout_ms, 90_000),
        max_idle_per_host: if cfg.max_idle_per_host == 0 { 8 } else { cfg.max_idle_per_host as usize },
        proxy: if cfg.flags & 1 != 0 { Proxy::from_env() } else { Proxy::default() },
        roots_pem: bytes(cfg.roots, cfg.roots_len).to_vec(),
    };
    let _ = msg;
    let _ = msg_cap;
    *out = Box::into_raw(Box::new(Arc::new(Client::new(settings))));
    0
}

/// # Safety
/// `c` is from `zr_net_client_new`, not freed before, and no call is started on it after; null is allowed.
#[no_mangle]
pub unsafe extern "C" fn zr_net_client_free(c: *mut Arc<Client>) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

/// Starts a request: 0, `*out` the call and `*fd` the descriptor to wait on (readable once the call
/// has finished; the caller closes it), or a `Code` with a message.
///
/// # Safety
/// `c` is a live client; `spec`'s pointers are valid for their lengths; `out` and `fd` for writes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_call_start(c: *mut Arc<Client>, spec: *const RequestSpec, out: *mut *mut Call, fd: *mut i32, msg: *mut u8, msg_cap: usize) -> i32 {
    let s = &*spec;
    let fail = |code: Code, m: String| {
        copy_message(&m, msg, msg_cap);
        code as i32
    };
    let method = match Method::from_bytes(bytes(s.method, s.method_len)) {
        Ok(m) => m,
        Err(e) => return fail(Code::BadUrl, format!("method: {e}")),
    };
    let url = match std::str::from_utf8(bytes(s.url, s.url_len)) {
        Ok(u) => u.to_string(),
        Err(_) => return fail(Code::BadUrl, "URL is not UTF-8".into()),
    };
    let headers = match parse_headers(bytes(s.headers, s.headers_len)) {
        Ok(h) => h,
        Err((code, m)) => return fail(code, m),
    };
    let up_stream = s.flags & FLAG_STREAM_REQUEST != 0;
    let spec = Spec {
        method,
        url,
        headers,
        body: Payload::Bytes(if up_stream { Bytes::new() } else { Bytes::copy_from_slice(bytes(s.body, s.body_len)) }),
        max_redirects: s.max_redirects,
        max_response: if s.max_response == 0 { if s.flags & FLAG_STREAM_RESPONSE != 0 { usize::MAX } else { 16 << 20 } } else { s.max_response },
        first_byte: (s.first_byte_ms != 0).then(|| Duration::from_millis(s.first_byte_ms as u64)),
        read_idle: (s.read_idle_ms != 0).then(|| Duration::from_millis(s.read_idle_ms as u64)),
        fresh: s.flags & FLAG_FRESH != 0,
    };
    let total = (s.total_ms != 0).then(|| Duration::from_millis(s.total_ms as u64));
    let Some(rt) = crate::runtime::handle() else { return fail(Code::Config, "the runtime did not start".into()) };
    let Ok((ours, theirs)) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None) else {
        return fail(Code::Io, "no socket pair for the call".into());
    };
    let client: Arc<Client> = (*c).clone();
    let done: Arc<Mutex<Option<Finished>>> = Arc::new(Mutex::new(None));
    let slot = done.clone();
    let wake = Arc::new(Wake(ours));
    let up: Option<Arc<UpStream>> = up_stream.then(|| Arc::new(UpStream::new(s.body_len as u64, wake.clone())));
    let down: Option<Arc<DownStream>> = (s.flags & FLAG_STREAM_RESPONSE != 0).then(|| Arc::new(DownStream::new(wake.clone())));
    let mut spec = spec;
    if let Some(u) = &up {
        spec.body = Payload::Stream(u.clone());
    }
    let (task_up, task_down) = (up.clone(), down.clone());
    let task = rt.spawn(async move {
        let work = async {
            match &task_down {
                Some(d) => stream(&client, spec, d, &slot, &task_up, &wake).await,
                None => {
                    let finished = match client.run(spec).await {
                        Ok(d) => Finished { code: Code::Ok, message: String::new(), status: d.status, minor: d.minor, headers: d.headers, body: d.body, t: d.timings },
                        Err((f, t)) => failed(f, t),
                    };
                    publish(&slot, &task_up, &wake, finished);
                }
            }
        };
        match total {
            None => work.await,
            Some(limit) => {
                if tokio::time::timeout(limit, work).await.is_err() {
                    let f = (Code::Timeout, format!("the call took longer than {limit:?}"));
                    let published = slot.lock().unwrap_or_else(|e| e.into_inner()).is_some();
                    match (&task_down, published) {
                        (Some(d), true) => d.fail(f),
                        _ => publish(&slot, &task_up, &wake, failed(f, Timings::default())),
                    }
                }
            }
        }
    });
    *fd = theirs.into_raw_fd();
    *out = Box::into_raw(Box::new(Call { task, done, up, down }));
    0
}

/// Fills `info` and returns 0 when the call has finished, 1 while it has not.
///
/// # Safety
/// `call` is live; `info` is valid for a write.
#[no_mangle]
pub unsafe extern "C" fn zr_net_call_result(call: *mut Call, info: *mut Info) -> i32 {
    let guard = (*call).done.lock().unwrap_or_else(|e| e.into_inner());
    let Some(f) = guard.as_ref() else { return 1 };
    *info = Info {
        error: f.code as i32,
        status: f.status,
        http_minor: f.minor,
        reused: f.t.reused as u8,
        redirects: f.t.redirects,
        dns_ns: f.t.dns,
        connect_ns: f.t.connect,
        tls_ns: f.t.tls,
        ttfb_ns: f.t.ttfb,
        total_ns: if f.t.total == 0 { UNKNOWN } else { f.t.total },
        bytes_in: f.t.bytes_in,
        headers_len: f.headers.len(),
        body_len: f.body.len(),
        message_len: f.message.len(),
    };
    0
}

/// Copies part of a finished call's answer: `what` 0 the headers (`name: value\n`, names lower-case),
/// 1 the body, 2 the error message. Returns the bytes copied, the most `cap`.
///
/// # Safety
/// `call` is live; `out` is valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_call_copy(call: *mut Call, what: u32, out: *mut u8, cap: usize) -> usize {
    let guard = (*call).done.lock().unwrap_or_else(|e| e.into_inner());
    let Some(f) = guard.as_ref() else { return 0 };
    let src: &[u8] = match what {
        0 => &f.headers,
        1 => &f.body,
        _ => f.message.as_bytes(),
    };
    let n = src.len().min(cap);
    if n > 0 {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out, n);
    }
    n
}

/// Drops the request, closing its connection, and frees the call. Safe at any time, from any thread,
/// once.
///
/// # Safety
/// `call` is from `zr_net_call_start` and not freed before; null is allowed.
#[no_mangle]
pub unsafe extern "C" fn zr_net_call_free(call: *mut Call) {
    if call.is_null() {
        return;
    }
    let call = Box::from_raw(call);
    call.task.abort();
    if let Some(u) = &call.up {
        u.finish();
    }
}

/// Reads up to `cap` bytes of a streaming call's body into `out`: 0 and `*n` (more than 0), 1 when
/// there is nothing yet (wait on the call's descriptor and ask again), 2 at the end of the body, or
/// 100 plus a `Code` when it failed (`msg` has the text). Call `zr_net_call_result` after 2 for the
/// call's final figures.
///
/// # Safety
/// `call` is live; `out` is valid for `cap` bytes, `n` for a write, `msg` for `msg_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_body_read(call: *mut Call, out: *mut u8, cap: usize, n: *mut usize, msg: *mut u8, msg_cap: usize) -> i32 {
    let Some(down) = (*call).down.as_ref() else { return 100 + Code::Config as i32 };
    if cap == 0 {
        return 1;
    }
    match down.read(std::slice::from_raw_parts_mut(out, cap)) {
        Read::Data(k) => {
            *n = k;
            0
        }
        Read::Pending => 1,
        Read::End => 2,
        Read::Failed(code, m) => {
            copy_message(&m, msg, msg_cap);
            100 + code as i32
        }
    }
}

/// Hands `len` bytes of a streaming request body to the call: 0 and how many it took in `*taken`
/// (possibly fewer than `len`), 1 when its queue is full (wait on the descriptor and write again), 2
/// when the call is over (it answered or failed: stop, and read its result).
///
/// # Safety
/// `call` is live; `data` is valid for `len` bytes, `taken` for a write.
#[no_mangle]
pub unsafe extern "C" fn zr_net_body_write(call: *mut Call, data: *const u8, len: usize, taken: *mut usize) -> i32 {
    let Some(up) = (*call).up.as_ref() else { return 2 };
    match up.push(bytes(data, len)) {
        Push::Took(k) => {
            *taken = k;
            0
        }
        Push::Full => 1,
        Push::Over => 2,
    }
}

/// The most the response queue of a streaming call held at once (tests and the memory bound).
///
/// # Safety
/// `call` is live.
#[no_mangle]
pub unsafe extern "C" fn zr_net_body_peak(call: *mut Call) -> usize {
    (*call).down.as_ref().map_or(0, |d| d.peak())
}

#[cfg(test)]
mod tests {
    //! Streaming through the C ABI, as Zig drives it: a descriptor to wait on, reads and writes that
    //! say "pending" or "full", against servers written for each case.
    use super::*;
    use socket2::Socket;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn rt() -> tokio::runtime::Handle {
        crate::runtime::handle().expect("the runtime starts")
    }

    /// Listens on a loopback port and runs `handler(stream, index of the connection)` for each.
    fn serve<F, Fut>(handler: F) -> (u16, Arc<AtomicU32>)
    where
        F: Fn(TcpStream, u32) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_l.set_nonblocking(true).unwrap();
        let port = std_l.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicU32::new(0));
        let n = accepts.clone();
        rt().spawn(async move {
            let l = TcpListener::from_std(std_l).unwrap();
            let handler = Arc::new(handler);
            while let Ok((s, _)) = l.accept().await {
                let i = n.fetch_add(1, Ordering::SeqCst);
                let h = handler.clone();
                tokio::spawn(async move { h(s, i).await });
            }
        });
        (port, accepts)
    }

    /// A request's line, its headers (lower-case names), and the reader positioned at its body.
    async fn head(r: &mut BufReader<TcpStream>) -> Option<(String, Vec<(String, String)>)> {
        let mut first = String::new();
        if r.read_line(&mut first).await.ok()? == 0 {
            return None;
        }
        let mut h = Vec::new();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).await.ok()?;
            let l = l.trim_end();
            if l.is_empty() {
                return Some((first.trim_end().to_string(), h));
            }
            let (n, v) = l.split_once(':')?;
            h.push((n.to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    fn pattern(i: u64) -> u8 {
        (i.wrapping_mul(2654435761) >> 7) as u8
    }

    fn client() -> *mut Arc<Client> {
        let cfg = ClientConfig { user_agent: b"zr-test".as_ptr(), user_agent_len: 7, roots: std::ptr::null(), roots_len: 0, connect_timeout_ms: 0, tls_timeout_ms: 0, idle_timeout_ms: 0, max_idle_per_host: 0, flags: 0 };
        let mut out = std::ptr::null_mut();
        assert_eq!(unsafe { zr_net_client_new(&cfg, &mut out, std::ptr::null_mut(), 0) }, 0);
        out
    }

    struct Started {
        call: *mut Call,
        fd: Socket,
    }

    fn start(c: *mut Arc<Client>, method: &str, url: &str, flags: u32, body_len: usize, first_byte_ms: u32, read_idle_ms: u32, total_ms: u32, headers: &str) -> Started {
        let spec = RequestSpec {
            method: method.as_ptr(),
            method_len: method.len(),
            url: url.as_ptr(),
            url_len: url.len(),
            headers: headers.as_ptr(),
            headers_len: headers.len(),
            body: std::ptr::null(),
            body_len,
            max_redirects: 3,
            max_response: 0,
            first_byte_ms,
            read_idle_ms,
            flags,
            total_ms,
        };
        let (mut call, mut fd) = (std::ptr::null_mut(), -1);
        assert_eq!(unsafe { zr_net_call_start(c, &spec, &mut call, &mut fd, std::ptr::null_mut(), 0) }, 0);
        let sock = unsafe { <Socket as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Started { call, fd: sock }
    }

    impl Started {
        fn wait(&self) {
            let mut b = [MaybeUninit::<u8>::uninit(); 64];
            self.fd.recv(&mut b).expect("a wake within 20 s");
        }

        fn info(&self) -> Info {
            loop {
                let mut i: Info = unsafe { std::mem::zeroed() };
                if unsafe { zr_net_call_result(self.call, &mut i) } == 0 {
                    return i;
                }
                self.wait();
            }
        }

        /// Reads the body to its end: (bytes, checksum of the pattern's mismatches, end code).
        fn read_all(&self, buf: usize, pause: Duration) -> (u64, u64, i32) {
            let mut b = vec![0u8; buf];
            let (mut total, mut bad) = (0u64, 0u64);
            loop {
                let mut n = 0usize;
                match unsafe { zr_net_body_read(self.call, b.as_mut_ptr(), b.len(), &mut n, std::ptr::null_mut(), 0) } {
                    0 => {
                        for (k, x) in b[..n].iter().enumerate() {
                            if *x != pattern(total + k as u64) {
                                bad += 1;
                            }
                        }
                        total += n as u64;
                        if !pause.is_zero() {
                            std::thread::sleep(pause);
                        }
                    }
                    1 => self.wait(),
                    rc => return (total, bad, rc),
                }
            }
        }

        /// Writes `len` bytes of the pattern: how many it took before the call was over, and how often it had to wait.
        fn write_all(&self, len: u64, piece: usize) -> (u64, u32) {
            let (mut sent, mut waits) = (0u64, 0u32);
            while sent < len {
                let data: Vec<u8> = (sent..(sent + piece as u64).min(len)).map(pattern).collect();
                let mut off = 0;
                while off < data.len() {
                    let mut taken = 0usize;
                    match unsafe { zr_net_body_write(self.call, data[off..].as_ptr(), data.len() - off, &mut taken) } {
                        0 => off += taken,
                        1 => {
                            waits += 1;
                            self.wait();
                        }
                        _ => return (sent + off as u64, waits),
                    }
                }
                sent += data.len() as u64;
            }
            (sent, waits)
        }
    }

    impl Drop for Started {
        fn drop(&mut self) {
            unsafe { zr_net_call_free(self.call) };
        }
    }

    async fn serve_body(s: TcpStream, len: u64, chunked: bool) {
        let mut r = BufReader::new(s);
        while let Some((_, _)) = head(&mut r).await {
            let w = r.get_mut();
            let hdr = if chunked { "Transfer-Encoding: chunked".to_string() } else { format!("Content-Length: {len}") };
            if w.write_all(format!("HTTP/1.1 200 OK\r\n{hdr}\r\n\r\n").as_bytes()).await.is_err() {
                return;
            }
            let mut sent = 0u64;
            while sent < len {
                let n = (len - sent).min(65536);
                let chunk: Vec<u8> = (sent..sent + n).map(pattern).collect();
                let ok = if chunked { w.write_all(format!("{n:x}\r\n").as_bytes()).await.is_ok() && w.write_all(&chunk).await.is_ok() && w.write_all(b"\r\n").await.is_ok() } else { w.write_all(&chunk).await.is_ok() };
                if !ok {
                    return;
                }
                sent += n;
            }
            if chunked {
                let _ = w.write_all(b"0\r\n\r\n").await;
            }
        }
    }

    #[test]
    fn a_big_download_streams_in_bounded_memory_whichever_way_it_is_framed() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let len = 48u64 << 20;
        for chunked in [false, true] {
            let (port, accepts) = serve(move |s, _| serve_body(s, len, chunked));
            let url = format!("http://127.0.0.1:{port}/blob");
            // A slow reader: it waits before its first read, and between reads, while the server goes on.
            let s = start(c, "GET", &url, FLAG_STREAM_RESPONSE, 0, 0, 0, 0, "");
            let i = s.info();
            assert_eq!((i.error, i.status, i.body_len), (0, 200, 0));
            std::thread::sleep(Duration::from_millis(300));
            let (total, bad, end) = s.read_all(100_000, Duration::from_micros(200));
            assert_eq!((total, bad, end), (len, 0, 2), "chunked: {chunked}");
            let peak = unsafe { zr_net_body_peak(s.call) };
            assert!(peak < crate::body::QUEUE_LIMIT + 512 * 1024, "the queue held {peak} bytes of {len}");
            let i = s.info();
            assert_eq!(i.bytes_in, len);
            assert!(i.total_ns != UNKNOWN && i.ttfb_ns != UNKNOWN);
            // The connection went back to the pool: the next request rides it.
            let s2 = start(c, "GET", &url, FLAG_STREAM_RESPONSE, 0, 0, 0, 0, "");
            assert_eq!(s2.info().reused, 1);
            drop(s2);
            assert_eq!(accepts.load(Ordering::SeqCst), 1);
        }
        unsafe { zr_net_client_free(c) };
    }

    #[test]
    fn cancelling_a_download_halfway_closes_its_connection() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let closed = Arc::new(AtomicU32::new(0));
        let seen = closed.clone();
        let (port, _) = serve(move |s, _| {
            let seen = seen.clone();
            async move {
                let mut r = BufReader::new(s);
                head(&mut r).await;
                let w = r.get_mut();
                let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n").await;
                let chunk = vec![1u8; 65536];
                while w.write_all(&chunk).await.is_ok() {}
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        let s = start(c, "GET", &format!("http://127.0.0.1:{port}/endless"), FLAG_STREAM_RESPONSE, 0, 0, 0, 0, "");
        assert_eq!(s.info().status, 200);
        let mut b = vec![0u8; 4096];
        let mut n = 0usize;
        while unsafe { zr_net_body_read(s.call, b.as_mut_ptr(), b.len(), &mut n, std::ptr::null_mut(), 0) } == 1 {
            s.wait();
        }
        drop(s);
        for _ in 0..100 {
            if closed.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(closed.load(Ordering::SeqCst), 1, "the server should have seen the connection closed");
        unsafe { zr_net_client_free(c) };
    }

    #[test]
    fn a_body_that_stops_and_a_call_that_runs_too_long_end_with_their_own_error() {
        let _g = crate::runtime::test_lock();
        let c = client();
        // Head and a little body, then silence.
        let (port, _) = serve(|s, _| async move {
            let mut r = BufReader::new(s);
            head(&mut r).await;
            let w = r.get_mut();
            let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nabc").await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let url = format!("http://127.0.0.1:{port}/stall");
        let s = start(c, "GET", &url, FLAG_STREAM_RESPONSE, 0, 0, 200, 0, "");
        assert_eq!(s.info().status, 200);
        let (total, _, end) = s.read_all(100, Duration::ZERO);
        assert_eq!((total, end), (3, 100 + Code::Timeout as i32));
        let s = start(c, "GET", &url, FLAG_STREAM_RESPONSE, 0, 0, 0, 300, "");
        assert_eq!(s.info().status, 200);
        let (total, _, end) = s.read_all(100, Duration::ZERO);
        assert_eq!((total, end), (3, 100 + Code::Timeout as i32));
        // A call whose head never comes.
        let (silent, _) = serve(|s, _| async move {
            let _s = s;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let s = start(c, "GET", &format!("http://127.0.0.1:{silent}/"), FLAG_STREAM_RESPONSE, 0, 0, 0, 300, "");
        assert_eq!(s.info().error, Code::Timeout as i32);
        unsafe { zr_net_client_free(c) };
    }

    /// A server that reads a request's body slowly to its end and answers with its length and a count of bad bytes.
    async fn serve_sink(s: TcpStream, slow: bool) {
        let mut r = BufReader::new(s);
        while let Some((_, h)) = head(&mut r).await {
            let len: u64 = h.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
            let (mut got, mut bad) = (0u64, 0u64);
            let mut b = vec![0u8; 32768];
            while got < len {
                let n = r.read(&mut b[..((len - got) as usize).min(32768)]).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                for (k, x) in b[..n].iter().enumerate() {
                    if *x != pattern(got + k as u64) {
                        bad += 1;
                    }
                }
                got += n as u64;
                if slow && got < (4 << 20) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            let body = format!("{got} {bad}");
            let _ = r.get_mut().write_all(format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
        }
    }

    #[test]
    fn an_upload_streams_a_body_written_in_pieces_and_waits_when_the_queue_is_full() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let (port, accepts) = serve(|s, _| serve_sink(s, true));
        let url = format!("http://127.0.0.1:{port}/put");
        let len = 24u64 << 20;
        let s = start(c, "PUT", &url, FLAG_STREAM_REQUEST, len as usize, 0, 0, 0, "x-ms-blob-type: BlockBlob\n");
        let (sent, waits) = s.write_all(len, 300_000);
        assert_eq!(sent, len);
        assert!(waits > 0, "a slow server must have made the writer wait");
        let i = s.info();
        assert_eq!((i.error, i.status), (0, 201));
        let mut body = vec![0u8; i.body_len];
        unsafe { zr_net_call_copy(s.call, 1, body.as_mut_ptr(), body.len()) };
        assert_eq!(String::from_utf8(body).unwrap(), format!("{len} 0"));
        drop(s);
        // Again, on the same connection; and a body of no bytes at all.
        let s = start(c, "PUT", &url, FLAG_STREAM_REQUEST, 1000, 0, 0, 0, "");
        assert_eq!(s.write_all(1000, 1000).0, 1000);
        let i = s.info();
        assert_eq!((i.status, i.reused), (201, 1));
        drop(s);
        let s = start(c, "PUT", &url, FLAG_STREAM_REQUEST, 0, 0, 0, 0, "");
        assert_eq!(s.info().status, 201);
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        // `fresh` makes a connection of its own.
        let s = start(c, "PUT", &url, FLAG_STREAM_REQUEST | FLAG_FRESH, 10, 0, 0, 0, "");
        s.write_all(10, 10);
        assert_eq!((s.info().status, s.info().reused), (201, 0));
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
        unsafe { zr_net_client_free(c) };
    }

    #[test]
    fn a_server_that_answers_before_the_body_is_sent_stops_the_writer() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let (port, _) = serve(|s, _| async move {
            let mut r = BufReader::new(s);
            head(&mut r).await;
            let mut b = [0u8; 1024];
            let _ = r.read(&mut b).await;
            let _ = r.get_mut().write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbig!").await;
            // Reads what is still coming, as a server that answers early does (closing at once would
            // reset the connection and take the answer with it).
            let _ = tokio::io::copy(&mut r, &mut tokio::io::sink()).await;
        });
        let len = 512u64 << 20;
        let s = start(c, "PUT", &format!("http://127.0.0.1:{port}/put"), FLAG_STREAM_REQUEST, len as usize, 0, 0, 0, "");
        let (sent, _) = s.write_all(len, 1 << 20);
        assert!(sent < len, "the writer should have been told to stop, sent {sent}");
        let i = s.info();
        assert_eq!(i.status, 413);
        unsafe { zr_net_client_free(c) };
    }

    #[test]
    fn redirects_of_a_streamed_body_follow_303_as_a_get_and_refuse_to_repeat_it_for_307() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let (port, _) = serve(|s, _| async move {
            let mut r = BufReader::new(s);
            while let Some((first, h)) = head(&mut r).await {
                let len: usize = h.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                let mut b = vec![0u8; len];
                let _ = r.read_exact(&mut b).await;
                let path = first.split(' ').nth(1).unwrap_or("").to_string();
                let out = match path.as_str() {
                    "/303" => "HTTP/1.1 303 See Other\r\nLocation: /done\r\nContent-Length: 0\r\n\r\n".to_string(),
                    "/307" => "HTTP/1.1 307 Temporary Redirect\r\nLocation: /done\r\nContent-Length: 0\r\n\r\n".to_string(),
                    _ => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", first.len(), first),
                };
                let _ = r.get_mut().write_all(out.as_bytes()).await;
            }
        });
        let s = start(c, "POST", &format!("http://127.0.0.1:{port}/303"), FLAG_STREAM_REQUEST, 100, 0, 0, 0, "");
        s.write_all(100, 100);
        let i = s.info();
        assert_eq!((i.error, i.status, i.redirects), (0, 200, 1));
        let mut body = vec![0u8; i.body_len];
        unsafe { zr_net_call_copy(s.call, 1, body.as_mut_ptr(), body.len()) };
        assert_eq!(String::from_utf8(body).unwrap(), "GET /done HTTP/1.1");
        let s = start(c, "POST", &format!("http://127.0.0.1:{port}/307"), FLAG_STREAM_REQUEST, 100, 0, 0, 0, "");
        s.write_all(100, 100);
        assert_eq!(s.info().error, Code::Protocol as i32);
        unsafe { zr_net_client_free(c) };
    }

    #[test]
    fn credentials_do_not_follow_a_streamed_download_to_another_host() {
        let _g = crate::runtime::test_lock();
        let c = client();
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let port = Arc::new(AtomicU64::new(0));
        let p = port.clone();
        let (port_n, _) = serve(move |s, _| {
            let (log, p) = (log.clone(), p.clone());
            async move {
                let mut r = BufReader::new(s);
                while let Some((first, h)) = head(&mut r).await {
                    let auth = h.iter().find(|(n, _)| n == "authorization").map_or("-", |(_, v)| v.as_str()).to_string();
                    log.lock().unwrap().push((first.clone(), auth));
                    let out = if first.contains("/start") {
                        format!("HTTP/1.1 302 Found\r\nLocation: http://localhost:{}/blob\r\nContent-Length: 0\r\n\r\n", p.load(Ordering::SeqCst))
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()
                    };
                    let _ = r.get_mut().write_all(out.as_bytes()).await;
                }
            }
        });
        port.store(port_n as u64, Ordering::SeqCst);
        let s = start(c, "GET", &format!("http://127.0.0.1:{port_n}/start"), FLAG_STREAM_RESPONSE, 0, 0, 0, 0, "Authorization: Bearer t0k\n");
        assert_eq!(s.info().status, 200);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].1, "Bearer t0k");
        assert_eq!(seen[1].1, "-", "{seen:?}");
        unsafe { zr_net_client_free(c) };
    }
}
