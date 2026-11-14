//! The C ABI of the HTTP client (docs/rust-net.md, "How a Zig caller waits"): a `Client` per process,
//! a `Call` per request. `zr_net_call_start` returns at once with a descriptor that becomes readable
//! when the request has finished; the Zig side waits for it through `std.Io` (so its cancellation and
//! deadlines apply where it blocks), then reads the result. Cancelling or freeing a call drops its
//! request, which closes its connection. Everything is copied in and out: no pointer is kept.
use crate::client::{parse_headers, Client, Code, Settings, Spec, Timings, UNKNOWN};
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
}

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
    let spec = Spec {
        method,
        url,
        headers,
        body: Bytes::copy_from_slice(bytes(s.body, s.body_len)),
        max_redirects: s.max_redirects,
        max_response: if s.max_response == 0 { 16 << 20 } else { s.max_response },
        first_byte: (s.first_byte_ms != 0).then(|| Duration::from_millis(s.first_byte_ms as u64)),
        read_idle: (s.read_idle_ms != 0).then(|| Duration::from_millis(s.read_idle_ms as u64)),
    };
    let Some(rt) = crate::runtime::handle() else { return fail(Code::Config, "the runtime did not start".into()) };
    let Ok((ours, theirs)) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None) else {
        return fail(Code::Io, "no socket pair for the call".into());
    };
    let client: Arc<Client> = (*c).clone();
    let done: Arc<Mutex<Option<Finished>>> = Arc::new(Mutex::new(None));
    let slot = done.clone();
    let task = rt.spawn(async move {
        let finished = match client.run(spec).await {
            Ok(d) => Finished { code: Code::Ok, message: String::new(), status: d.status, minor: d.minor, headers: d.headers, body: d.body, t: d.timings },
            Err(((code, message), t)) => Finished { code, message, status: 0, minor: 1, headers: Vec::new(), body: Vec::new(), t },
        };
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(finished);
        // MSG_NOSIGNAL: a caller that closed its end already must not kill the process.
        let _ = ours.send_with_flags(&[1], 0x4000);
    });
    *fd = theirs.into_raw_fd();
    *out = Box::into_raw(Box::new(Call { task, done }));
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
}
