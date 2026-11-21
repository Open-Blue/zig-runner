//! The WebSocket client (docs/rust-net.md, "The WebSocket feed (R6)"): `tokio-tungstenite` on the
//! connection the HTTP client makes (`Client::transport`: the same proxy, roots, TLS, timeouts and
//! socket options), behind the C ABI. A `Ws` is a handle like a `Call`: `zr_net_ws_connect` returns at
//! once with a descriptor that becomes readable when something happened (the upgrade finished, the
//! send queue went below half after it was full, a message arrived, the connection ended), which the
//! Zig side waits on through `std.Io`, so its deadlines and cancel apply where it blocks.
//!
//! Ping, pong and the close handshake are the library's: a ping from the peer is answered while the
//! caller does nothing, a close from the peer is answered and ends the connection, and
//! `zr_net_ws_close` sends a close frame (code 1000) after the queued messages and waits for the
//! peer's, within `close_wait_ms`. Messages sent go through a queue of at most `queue_limit` bytes
//! (backpressure: `zr_net_ws_send` says "full" and the caller waits for the descriptor); messages
//! received wait in a queue of their own (the feed's peer sends none), and one that does not fit is
//! dropped and counted rather than stopping the reads that answer the peer's pings.
use crate::body::Wake;
use crate::client::{parse_headers, parse_url, Client, Code, Fail, Stream, UNKNOWN};
use futures_util::{Sink, Stream as FStream};
use http::{HeaderName, HeaderValue};
use hyper::body::Bytes;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::os::fd::IntoRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

/// What a message is. Text and binary are what the caller sends and gets; a ping is sent only.
pub const KIND_TEXT: u32 = 0;
pub const KIND_BINARY: u32 = 1;
pub const KIND_PING: u32 = 2;

/// The default most bytes of messages waiting to be sent.
pub const QUEUE_LIMIT: usize = 64 * 1024;
/// The default most bytes of received messages waiting to be read, and the longest message taken.
pub const RECV_LIMIT: usize = 1 << 20;
const OPEN_LIMIT: Duration = Duration::from_secs(10);
const CLOSE_WAIT: Duration = Duration::from_secs(2);

const CONNECTING: u32 = 0;
const OPEN: u32 = 1;
const CLOSING: u32 = 2;
const CLOSED: u32 = 3;

#[repr(C)]
pub struct WsSpec {
    /// `wss://` or `ws://` (`https://` and `http://` are the same).
    pub url: *const u8,
    pub url_len: usize,
    /// `Name: value` lines separated by `\n`, for the upgrade request (the job's token).
    pub headers: *const u8,
    pub headers_len: usize,
    /// A message is sent in frames of at most this many bytes (the first of its kind, the rest
    /// continuations, as actions/runner sends the feed); 0: one frame.
    pub max_frame: u32,
    /// The upgrade's limit, from connecting to the answer; 0: ten seconds.
    pub open_ms: u32,
    /// How long `zr_net_ws_close` waits for the peer's close; 0: two seconds.
    pub close_wait_ms: u32,
    /// The most bytes of messages queued to send; 0: `QUEUE_LIMIT`.
    pub queue_limit: u32,
    /// The most bytes of messages received and waiting, and the longest message; 0: `RECV_LIMIT`.
    pub recv_limit: u32,
}

/// What a `Ws` reports, any time.
#[repr(C)]
pub struct WsInfo {
    /// `Code` of the failure that ended the connection (or the upgrade), 0 when there is none.
    pub error: i32,
    /// 0 connecting, 1 open, 2 closing (our close is sent), 3 closed.
    pub state: u32,
    /// The upgrade's HTTP status (101); 0 before it, or when there was no answer.
    pub status: u16,
    /// The peer's close code, 0 when it sent none.
    pub close_code: u16,
    pub dns_ns: u64,
    pub connect_ns: u64,
    pub tls_ns: u64,
    /// From the connection being made to the upgrade's answer.
    pub ttfb_ns: u64,
    pub total_ns: u64,
    /// Payload bytes received, and sent (written to the connection).
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Bytes waiting to be sent, and messages received that no read has taken.
    pub queued: usize,
    pub waiting: usize,
    /// Messages received that did not fit the queue and were dropped.
    pub dropped: u64,
    /// Messages queued or being written when the connection ended, which were never sent.
    pub unsent: u64,
    pub message_len: usize,
}

struct Out {
    kind: u32,
    data: Bytes,
}

struct State {
    phase: u32,
    error: Option<Fail>,
    status: u16,
    close_code: u16,
    t: [u64; 5],
    bytes_in: u64,
    bytes_out: u64,
    out: VecDeque<Out>,
    out_bytes: usize,
    /// A send was told "full" and has not been woken since.
    full: bool,
    /// The task, to wake when something is queued or a close is asked.
    waker: Option<Waker>,
    close: bool,
    inbox: VecDeque<(u32, Bytes)>,
    in_bytes: usize,
    dropped: u64,
    /// A message taken from `out` that is being cut into frames and written: lost with the connection too.
    writing: u64,
    /// Messages queued or being written when the connection ended: never sent.
    unsent: u64,
    /// What the peer's close said ("closed by the peer: 1001 going away"), for the log.
    note: String,
}

struct Shared {
    st: Mutex<State>,
    wake: Arc<Wake>,
    queue_limit: usize,
    recv_limit: usize,
}

fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn new(wake: Arc<Wake>, queue_limit: usize, recv_limit: usize) -> Shared {
        Shared {
            st: Mutex::new(State {
                phase: CONNECTING,
                error: None,
                status: 0,
                close_code: 0,
                t: [UNKNOWN; 5],
                bytes_in: 0,
                bytes_out: 0,
                out: VecDeque::new(),
                out_bytes: 0,
                full: false,
                waker: None,
                close: false,
                inbox: VecDeque::new(),
                in_bytes: 0,
                dropped: 0,
                writing: 0,
                unsent: 0,
                note: String::new(),
            }),
            wake,
            queue_limit,
            recv_limit,
        }
    }

    /// The next message to send, or none (and the task's waker is kept to be woken by `push`). A
    /// caller that was told "full" is woken when the queue has gone below half.
    fn pop(&self, w: &Waker) -> Option<Out> {
        let mut g = lock(&self.st);
        match g.out.pop_front() {
            Some(m) => {
                g.out_bytes -= m.data.len();
                if g.full && g.out_bytes <= self.queue_limit / 2 {
                    g.full = false;
                    self.wake.ping();
                }
                Some(m)
            }
            None => {
                g.waker = Some(w.clone());
                None
            }
        }
    }

    /// Nothing more will be sent or received: say so, with `error` when it was not by a close.
    fn finish(&self, error: Option<Fail>) {
        let mut g = lock(&self.st);
        g.phase = CLOSED;
        g.unsent += g.out.len() as u64 + g.writing;
        if g.error.is_none() {
            g.error = error;
        }
        drop(g);
        self.wake.ping();
    }
}

pub struct Ws {
    task: tokio::task::JoinHandle<()>,
    shared: Arc<Shared>,
}

fn ns(d: Duration) -> u64 {
    d.as_nanos().min((UNKNOWN - 1) as u128) as u64
}

/// The upgrade: the connection (the client's, as a request's), then the handshake.
async fn open(client: &Client, spec: &Opened) -> Result<(WebSocketStream<Stream>, u16, [u64; 5]), Fail> {
    let started = Instant::now();
    let url = spec.url.replacen("ws", "http", 1);
    let target = parse_url(&url)?;
    let via = client.settings.proxy.for_url(target.https, &target.host, target.port).cloned();
    if via.is_some() && !target.https {
        return Err((Code::Proxy, "a ws:// URL cannot go through a proxy (wss:// can)".into()));
    }
    let (stream, (dns, connect), tls) = client.transport(&target, via.as_ref()).await?;
    let mut request = {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        spec.url.as_str().into_client_request().map_err(|e| (Code::BadUrl, format!("{}: {e}", spec.url)))?
    };
    let ua = HeaderValue::from_str(&client.settings.user_agent).map_err(|e| (Code::Config, e.to_string()))?;
    request.headers_mut().insert(http::header::USER_AGENT, ua);
    for (n, v) in &spec.headers {
        request.headers_mut().insert(n.clone(), v.clone());
    }
    // Small buffers: tungstenite's defaults (128 KiB each way) cost more than the feed's traffic needs.
    let config = WebSocketConfig::default().read_buffer_size(16 * 1024).write_buffer_size(16 * 1024).max_write_buffer_size(64 * 1024).max_message_size(Some(spec.recv_limit)).max_frame_size(Some(spec.recv_limit));
    let sent = Instant::now();
    let r = tokio::time::timeout(spec.open, tokio_tungstenite::client_async_with_config(request, stream, Some(config))).await;
    let ttfb = ns(sent.elapsed());
    let (ws, response) = match r {
        Err(_) => return Err((Code::Timeout, format!("{}: no answer to the upgrade within {:?}", spec.url, spec.open))),
        Ok(Ok(v)) => v,
        Ok(Err(WsError::Http(resp))) => {
            return Err((Code::WsRefused, format!("{}: the server answered {} to the upgrade", spec.url, resp.status())));
        }
        Ok(Err(e)) => return Err(map_error(&e, &spec.url)),
    };
    Ok((ws, response.status().as_u16(), [dns, connect, tls, ttfb, ns(started.elapsed())]))
}

fn map_error(e: &WsError, what: &str) -> Fail {
    let code = match e {
        WsError::Io(_) | WsError::ConnectionClosed | WsError::AlreadyClosed => Code::Io,
        // The peer went without a close frame: the connection is lost, not a protocol violated.
        WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => Code::Io,
        WsError::Capacity(_) => Code::BodyTooLarge,
        _ => Code::Protocol,
    };
    (code, format!("{what}: {e}"))
}

struct Opened {
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    open: Duration,
    close_wait: Duration,
    max_frame: usize,
    recv_limit: usize,
}

/// The frames a message is sent as: one, or `max_frame` bytes each, the first of its kind and the
/// rest continuations. A frame is masked as it is written (the library does that for a client).
fn frames(m: Out, max_frame: usize) -> Vec<Message> {
    let opcode = match m.kind {
        KIND_BINARY => Data::Binary,
        _ => Data::Text,
    };
    if m.kind == KIND_PING {
        return vec![Message::Ping(Bytes::new())];
    }
    if max_frame == 0 || m.data.len() <= max_frame {
        return vec![Message::Frame(Frame::message(m.data, OpCode::Data(opcode), true))];
    }
    let mut out = Vec::with_capacity(m.data.len().div_ceil(max_frame));
    let mut at = 0;
    while at < m.data.len() {
        let end = (at + max_frame).min(m.data.len());
        let kind = if at == 0 { opcode } else { Data::Continue };
        out.push(Message::Frame(Frame::message(m.data.slice(at..end), OpCode::Data(kind), end == m.data.len())));
        at = end;
    }
    out
}

/// How a connection's transfer ended.
enum End {
    /// We asked for the close, and everything queued has been written.
    Ours,
    /// The peer's stream ended (it closed, and we answered).
    Peer,
    Failed(Fail),
}

async fn transfer(ws: &mut WebSocketStream<Stream>, shared: &Shared, o: &Opened) -> End {
    let mut frames_left: VecDeque<Message> = VecDeque::new();
    let mut dirty = false;
    // The peer sent its close: it is answered (by the stream's own poll) and nothing more is sent.
    let mut peer_closed = false;
    poll_fn(|cx| {
        // The read side first: answering the peer's pings and closes happens inside the stream's
        // poll, whatever the caller is doing.
        loop {
            match Pin::new(&mut *ws).poll_next(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(End::Peer),
                Poll::Ready(Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed))) => return Poll::Ready(End::Peer),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(End::Failed(map_error(&e, "the connection"))),
                Poll::Ready(Some(Ok(m))) => {
                    let mut g = lock(&shared.st);
                    match m {
                        Message::Text(t) => received(&mut g, shared, KIND_TEXT, Bytes::from(t)),
                        Message::Binary(b) => received(&mut g, shared, KIND_BINARY, b),
                        Message::Close(f) => {
                            g.close_code = f.as_ref().map_or(0, |f| u16::from(f.code));
                            g.note = match &f {
                                Some(f) => format!("closed by the peer: {} {}", u16::from(f.code), f.reason),
                                None => "closed by the peer".to_string(),
                            };
                            g.phase = CLOSING;
                            // What is queued is not sent to a peer that closed: it is counted as lost, and
                            // nothing is written after the close (tungstenite refuses it as a protocol error).
                            if !peer_closed {
                                peer_closed = true;
                                frames_left.clear();
                                g.unsent = g.out.len() as u64 + g.writing;
                                g.writing = 0;
                                g.out.clear();
                                g.out_bytes = 0;
                                if g.full {
                                    g.full = false;
                                    shared.wake.ping();
                                }
                            }
                        }
                        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
            }
        }
        // The write side: messages from the queue, frame by frame, then the flush.
        loop {
            if peer_closed {
                break;
            }
            if frames_left.is_empty() {
                lock(&shared.st).writing = 0;
                match shared.pop(cx.waker()) {
                    Some(m) => {
                        lock(&shared.st).writing = 1;
                        frames_left.extend(frames(m, o.max_frame))
                    }
                    None => break,
                }
                continue;
            }
            match Pin::new(&mut *ws).poll_ready(cx) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(End::Failed(map_error(&e, "the connection"))),
                Poll::Ready(Ok(())) => {}
            }
            let Some(m) = frames_left.pop_front() else { break };
            let n = match &m {
                Message::Frame(f) => f.payload().len() as u64,
                _ => 0,
            };
            if let Err(e) = Pin::new(&mut *ws).start_send(m) {
                return Poll::Ready(End::Failed(map_error(&e, "the connection")));
            }
            lock(&shared.st).bytes_out += n;
            dirty = true;
        }
        if dirty {
            match Pin::new(&mut *ws).poll_flush(cx) {
                Poll::Ready(Ok(())) => dirty = false,
                Poll::Ready(Err(e)) => return Poll::Ready(End::Failed(map_error(&e, "the connection"))),
                Poll::Pending => {}
            }
        }
        let g = lock(&shared.st);
        if g.close && g.out.is_empty() && frames_left.is_empty() && !dirty {
            return Poll::Ready(End::Ours);
        }
        Poll::Pending
    })
    .await
}

fn received(g: &mut State, shared: &Shared, kind: u32, data: Bytes) {
    g.bytes_in += data.len() as u64;
    if g.in_bytes + data.len() > shared.recv_limit {
        g.dropped += 1;
        return;
    }
    g.in_bytes += data.len();
    let first = g.inbox.is_empty();
    g.inbox.push_back((kind, data));
    if first {
        shared.wake.ping();
    }
}

async fn run(client: Arc<Client>, shared: Arc<Shared>, o: Opened) {
    let (mut ws, status, t) = match open(&client, &o).await {
        Ok(v) => v,
        Err(f) => {
            return shared.finish(Some(f));
        }
    };
    {
        let mut g = lock(&shared.st);
        g.status = status;
        g.t = t;
        g.phase = OPEN;
    }
    shared.wake.ping();
    let end = transfer(&mut ws, &shared, &o).await;
    match end {
        End::Failed(f) => shared.finish(Some(f)),
        End::Peer => shared.finish(None),
        End::Ours => {
            lock(&shared.st).phase = CLOSING;
            // Our close frame (1000), then what the peer says until it ends the stream, or the limit.
            let bye = async {
                let frame = CloseFrame { code: CloseCode::Normal, reason: "".into() };
                if ws.close(Some(frame)).await.is_err() {
                    return;
                }
                while let Some(Ok(_)) = futures_util::StreamExt::next(&mut ws).await {}
            };
            let _ = tokio::time::timeout(o.close_wait, bye).await;
            shared.finish(None);
        }
    }
}

/// The state of a live handle.
unsafe fn shared_of<'a>(ws: *mut Ws) -> &'a Shared {
    let w: &Ws = &*ws;
    &w.shared
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

/// Starts connecting: 0, `*out` the handle and `*fd` the descriptor to wait on (readable when
/// something happened; the caller closes it), or a `Code` with a message. The upgrade's result is
/// `zr_net_ws_info`'s once its state is not 0.
///
/// # Safety
/// `c` is a live client (and outlives nothing: the handle holds what it needs); `spec`'s pointers
/// are valid for their lengths; `out` and `fd` for writes; `msg` for `msg_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_connect(c: *mut Arc<Client>, spec: *const WsSpec, out: *mut *mut Ws, fd: *mut i32, msg: *mut u8, msg_cap: usize) -> i32 {
    let s = &*spec;
    let fail = |code: Code, m: String| {
        copy_message(&m, msg, msg_cap);
        code as i32
    };
    let url = match std::str::from_utf8(bytes(s.url, s.url_len)) {
        Ok(u) if u.starts_with("wss://") || u.starts_with("ws://") => u.to_string(),
        Ok(u) => return fail(Code::BadUrl, format!("{u}: not a ws:// or wss:// URL")),
        Err(_) => return fail(Code::BadUrl, "URL is not UTF-8".into()),
    };
    let headers = match parse_headers(bytes(s.headers, s.headers_len)) {
        Ok(h) => h,
        Err((code, m)) => return fail(code, m),
    };
    let Some(rt) = crate::runtime::handle() else { return fail(Code::Config, "the runtime did not start".into()) };
    let Ok((ours, theirs)) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None) else {
        return fail(Code::Io, "no socket pair for the connection".into());
    };
    let or = |v: u32, d: usize| if v == 0 { d } else { v as usize };
    let (queue_limit, recv_limit) = (or(s.queue_limit, QUEUE_LIMIT), or(s.recv_limit, RECV_LIMIT));
    let opened = Opened {
        url,
        headers,
        open: if s.open_ms == 0 { OPEN_LIMIT } else { Duration::from_millis(s.open_ms as u64) },
        close_wait: if s.close_wait_ms == 0 { CLOSE_WAIT } else { Duration::from_millis(s.close_wait_ms as u64) },
        max_frame: s.max_frame as usize,
        recv_limit,
    };
    let shared = Arc::new(Shared::new(Arc::new(Wake(ours)), queue_limit, recv_limit));
    let client: Arc<Client> = (*c).clone();
    let task = rt.spawn(run(client, shared.clone(), opened));
    *fd = theirs.into_raw_fd();
    *out = Box::into_raw(Box::new(Ws { task, shared }));
    0
}

/// Fills `info` (always; nothing blocks).
///
/// # Safety
/// `ws` is live; `info` is valid for a write.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_info(ws: *mut Ws, info: *mut WsInfo) {
    let g = lock(&shared_of(ws).st);
    *info = WsInfo {
        error: g.error.as_ref().map_or(0, |e| e.0 as i32),
        state: g.phase,
        status: g.status,
        close_code: g.close_code,
        dns_ns: g.t[0],
        connect_ns: g.t[1],
        tls_ns: g.t[2],
        ttfb_ns: g.t[3],
        total_ns: g.t[4],
        bytes_in: g.bytes_in,
        bytes_out: g.bytes_out,
        queued: g.out_bytes,
        waiting: g.in_bytes,
        dropped: g.dropped,
        unsent: g.unsent,
        message_len: g.error.as_ref().map_or(g.note.len(), |e| e.1.len()),
    };
}

/// The error's message, NUL-terminated, truncated to `cap`; the bytes copied before the NUL.
///
/// # Safety
/// `ws` is live; `out` is valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_message(ws: *mut Ws, out: *mut u8, cap: usize) -> usize {
    let g = lock(&shared_of(ws).st);
    let m = match g.error.as_ref() {
        Some((_, m)) => m,
        None => &g.note,
    };
    copy_message(m, out, cap);
    m.len().min(cap.saturating_sub(1))
}

/// Queues a message (`KIND_*`; a ping has no data): 0 when it is queued, 1 when the queue is full
/// (wait on the descriptor, which is woken when it has gone below half, and send again), 2 when the
/// connection is closing or over (read `zr_net_ws_info`). A message bigger than the queue is
/// queued when the queue is empty.
///
/// # Safety
/// `ws` is live; `data` is valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_send(ws: *mut Ws, kind: u32, data: *const u8, len: usize) -> i32 {
    let sh = shared_of(ws);
    let mut g = lock(&sh.st);
    if g.phase >= CLOSING || g.close {
        return 2;
    }
    if g.out_bytes > 0 && g.out_bytes + len > sh.queue_limit {
        g.full = true;
        return 1;
    }
    g.out_bytes += len;
    g.out.push_back(Out { kind, data: Bytes::copy_from_slice(bytes(data, len)) });
    if let Some(w) = g.waker.take() {
        w.wake();
    }
    0
}

/// Takes the oldest received message into `out`: 0 and `*n` bytes, `*kind` (`KIND_*`); 1 when there
/// is none yet (wait on the descriptor); 2 when the connection ended cleanly and nothing is left; 3
/// when `cap` is too small (`*n` says how much, the message stays); 100 plus a `Code` when it
/// ended with a failure and nothing is left.
///
/// # Safety
/// `ws` is live; `out` is valid for `cap` bytes; `n` and `kind` for writes.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_recv(ws: *mut Ws, out: *mut u8, cap: usize, n: *mut usize, kind: *mut u32) -> i32 {
    let mut g = lock(&shared_of(ws).st);
    let Some((k, data)) = g.inbox.front() else {
        return match (g.phase, &g.error) {
            (CLOSED, Some((c, _))) => 100 + *c as i32,
            (CLOSED, None) => 2,
            _ => 1,
        };
    };
    if data.len() > cap {
        *n = data.len();
        return 3;
    }
    *n = data.len();
    *kind = *k;
    if !data.is_empty() {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    g.in_bytes -= *n;
    g.inbox.pop_front();
    0
}

/// Asks for the close: what is queued is sent, then a close frame (1000), then the peer's answer is
/// awaited for `close_wait_ms`; the descriptor is woken when the connection is over (state 3).
///
/// # Safety
/// `ws` is live.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_close(ws: *mut Ws) {
    let mut g = lock(&shared_of(ws).st);
    g.close = true;
    if let Some(w) = g.waker.take() {
        w.wake();
    }
}

/// Ends the connection at once (no close frame if the handshake is not done) and frees the handle.
/// Safe at any time, from any thread, once.
///
/// # Safety
/// `ws` is from `zr_net_ws_connect` and not freed before; null is allowed.
#[no_mangle]
pub unsafe extern "C" fn zr_net_ws_free(ws: *mut Ws) {
    if ws.is_null() {
        return;
    }
    let ws = Box::from_raw(ws);
    ws.task.abort();
}

#[cfg(test)]
mod tests {
    //! The WebSocket through the C ABI as Zig drives it (a descriptor to wait on, "full" and "none yet"
    //! answers), against servers written for each case: tungstenite's own server side for the
    //! protocol, raw sockets for what only the bytes show (frames, an upgrade that never answers).
    use super::*;
    use crate::call::{zr_net_client_new, ClientConfig};
    use futures_util::{SinkExt, StreamExt};
    use socket2::Socket;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    fn rt() -> tokio::runtime::Handle {
        crate::runtime::handle().expect("the runtime starts")
    }

    fn new_client(roots: &str) -> *mut Arc<Client> {
        let cfg = ClientConfig {
            user_agent: b"zr-test".as_ptr(),
            user_agent_len: 7,
            roots: roots.as_ptr(),
            roots_len: roots.len(),
            connect_timeout_ms: 0,
            tls_timeout_ms: 0,
            idle_timeout_ms: 0,
            max_idle_per_host: 0,
            flags: 0,
        };
        let mut out = std::ptr::null_mut();
        assert_eq!(unsafe { zr_net_client_new(&cfg, &mut out, std::ptr::null_mut(), 0) }, 0);
        out
    }

    /// A listening socket whose accepted connections have a small receive buffer, so that a server that
    /// does not read stops the sender after kilobytes, not megabytes.
    fn listener(small_buffers: bool) -> (std::net::TcpListener, u16) {
        let l = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).expect("socket");
        if small_buffers {
            l.set_recv_buffer_size(4096).expect("rcvbuf");
        }
        l.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().expect("addr").into()).expect("bind");
        l.listen(16).expect("listen");
        l.set_nonblocking(true).expect("nonblocking");
        let l: std::net::TcpListener = l.into();
        let port = l.local_addr().expect("addr").port();
        (l, port)
    }

    /// Accepts connections and runs `handler` for each, as a task.
    fn serve<F, Fut>(small_buffers: bool, handler: F) -> u16
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (l, port) = listener(small_buffers);
        rt().spawn(async move {
            let l = TcpListener::from_std(l).expect("listener");
            let handler = Arc::new(handler);
            while let Ok((s, _)) = l.accept().await {
                let h = handler.clone();
                tokio::spawn(async move { h(s).await });
            }
        });
        port
    }

    struct Conn {
        ws: *mut Ws,
        fd: Socket,
    }

    fn spec_with(url: &str, headers: &str, f: impl FnOnce(&mut WsSpec)) -> Conn {
        let mut s = WsSpec {
            url: url.as_ptr(),
            url_len: url.len(),
            headers: headers.as_ptr(),
            headers_len: headers.len(),
            max_frame: 0,
            open_ms: 5000,
            close_wait_ms: 0,
            queue_limit: 0,
            recv_limit: 0,
        };
        f(&mut s);
        connect_with(new_client(""), &s)
    }

    fn connect_with(c: *mut Arc<Client>, s: &WsSpec) -> Conn {
        let (mut ws, mut fd) = (std::ptr::null_mut(), -1);
        assert_eq!(unsafe { zr_net_ws_connect(c, s, &mut ws, &mut fd, std::ptr::null_mut(), 0) }, 0);
        let sock = unsafe { <Socket as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        sock.set_read_timeout(Some(Duration::from_secs(20))).expect("timeout");
        Conn { ws, fd: sock }
    }

    impl Conn {
        fn wait(&self) {
            let mut b = [MaybeUninit::<u8>::uninit(); 64];
            assert!(self.fd.recv(&mut b).expect("a wake within 20 s") > 0, "the library closed the descriptor");
        }

        fn info(&self) -> WsInfo {
            let mut i: WsInfo = unsafe { std::mem::zeroed() };
            unsafe { zr_net_ws_info(self.ws, &mut i) };
            i
        }

        fn until(&self, f: impl Fn(&WsInfo) -> bool) -> WsInfo {
            loop {
                let i = self.info();
                if f(&i) {
                    return i;
                }
                self.wait();
            }
        }

        fn open(&self) -> WsInfo {
            let i = self.until(|i| i.state != CONNECTING);
            assert_eq!(i.error, 0, "{}", self.message());
            assert_eq!(i.state, OPEN);
            i
        }

        fn message(&self) -> String {
            let mut b = [0u8; 256];
            let n = unsafe { zr_net_ws_message(self.ws, b.as_mut_ptr(), b.len()) };
            String::from_utf8_lossy(&b[..n]).into_owned()
        }

        /// Sends, waiting while the queue is full; the result of a send that was refused as over.
        fn send(&self, kind: u32, data: &[u8]) -> i32 {
            loop {
                match unsafe { zr_net_ws_send(self.ws, kind, data.as_ptr(), data.len()) } {
                    1 => self.wait(),
                    rc => return rc,
                }
            }
        }

        fn recv(&self) -> Result<(u32, Vec<u8>), i32> {
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let (mut n, mut kind) = (0usize, 0u32);
                match unsafe { zr_net_ws_recv(self.ws, buf.as_mut_ptr(), buf.len(), &mut n, &mut kind) } {
                    0 => return Ok((kind, buf[..n].to_vec())),
                    1 => self.wait(),
                    rc => return Err(rc),
                }
            }
        }
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            unsafe { zr_net_ws_free(self.ws) };
        }
    }

    /// What a server saw, in order.
    type Seen = Arc<Mutex<Vec<String>>>;

    fn describe(m: &Message) -> String {
        match m {
            Message::Text(t) => format!("T:{t}"),
            Message::Binary(b) => format!("B:{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
            Message::Ping(b) => format!("PING:{}", String::from_utf8_lossy(b)),
            Message::Pong(b) => format!("PONG:{}", String::from_utf8_lossy(b)),
            Message::Close(Some(f)) => format!("CLOSE:{}", u16::from(f.code)),
            Message::Close(None) => "CLOSE".into(),
            Message::Frame(_) => "FRAME".into(),
        }
    }

    async fn accept(s: TcpStream, headers: Seen) -> WebSocketStream<TcpStream> {
        tokio_tungstenite::accept_hdr_async(s, move |req: &Request, resp: Response| {
            let mut h = headers.lock().expect("lock");
            for n in ["authorization", "user-agent", "sec-websocket-version"] {
                h.push(format!("{n}={}", req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("")));
            }
            Ok(resp)
        })
        .await
        .expect("the upgrade is accepted")
    }

    fn url(port: u16) -> String {
        format!("ws://127.0.0.1:{port}/_ws/ingest.sock")
    }

    #[test]
    fn messages_flow_both_ways_the_peers_ping_is_answered_and_the_close_is_a_handshake() {
        let _g = crate::runtime::test_lock();
        let (seen, head): (Seen, Seen) = Default::default();
        let (s2, h2) = (seen.clone(), head.clone());
        let port = serve(false, move |s| {
            let (seen, head) = (s2.clone(), h2.clone());
            async move {
                let mut ws = accept(s, head).await;
                // Three messages from the client, then ours: a text and a ping, whose pong must come
                // although the client's caller is waiting for the text and does nothing else.
                for _ in 0..3 {
                    let m = ws.next().await.expect("a message").expect("no error");
                    seen.lock().expect("lock").push(describe(&m));
                }
                ws.send(Message::Text("back".into())).await.expect("send");
                ws.send(Message::Ping(Bytes::from_static(b"x"))).await.expect("ping");
                while let Some(Ok(m)) = ws.next().await {
                    seen.lock().expect("lock").push(describe(&m));
                    if matches!(m, Message::Close(_)) {
                        break;
                    }
                }
            }
        });
        let c = spec_with(&url(port), "Authorization: Bearer tok\n", |_| {});
        let i = c.open();
        assert_eq!(i.status, 101);
        assert!(i.total_ns != UNKNOWN && i.dns_ns < 50_000_000 && i.tls_ns == UNKNOWN, "an address needs no DNS, and ws:// no TLS");
        assert_eq!(c.send(KIND_TEXT, b"hello"), 0);
        assert_eq!(c.send(KIND_BINARY, &[1, 2, 3]), 0);
        assert_eq!(c.send(KIND_PING, b""), 0);
        assert_eq!(c.recv().expect("the text"), (KIND_TEXT, b"back".to_vec()));
        // The caller does nothing while the library answers the server's ping; a close asked first would
        // (rightly) end the connection before the ping was read.
        std::thread::sleep(Duration::from_millis(200));
        unsafe { zr_net_ws_close(c.ws) };
        let i = c.until(|i| i.state == CLOSED);
        assert_eq!(i.error, 0, "{}", c.message());
        assert_eq!(c.recv().expect_err("nothing is left"), 2);
        assert_eq!(c.send(KIND_TEXT, b"late"), 2, "nothing is sent after the close");
        let started = Instant::now();
        while seen.lock().expect("lock").len() < 5 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*seen.lock().expect("lock"), ["T:hello", "B:010203", "PING:", "PONG:x", "CLOSE:1000"]);
        assert_eq!(*head.lock().expect("lock"), ["authorization=Bearer tok", "user-agent=zr-test", "sec-websocket-version=13"]);
        assert_eq!(i.bytes_out, 5 + 3);
    }

    #[test]
    fn the_peer_closing_is_answered_and_ends_the_connection() {
        let _g = crate::runtime::test_lock();
        let port = serve(false, |s| async move {
            let mut ws = accept(s, Default::default()).await;
            let _ = ws.next().await;
            let frame = CloseFrame { code: CloseCode::Away, reason: "bye".into() };
            let _ = ws.send(Message::Text("last".into())).await;
            let _ = ws.close(Some(frame)).await;
            while let Some(Ok(_)) = ws.next().await {}
        });
        let c = spec_with(&url(port), "", |_| {});
        c.open();
        assert_eq!(c.send(KIND_TEXT, b"first"), 0);
        let i = c.until(|i| i.state == CLOSED);
        assert_eq!((i.error, i.close_code), (0, 1001), "{}", c.message());
        // What arrived before the close is still there to read; then the end.
        assert_eq!(c.recv().expect("the last message"), (KIND_TEXT, b"last".to_vec()));
        assert_eq!(c.recv().expect_err("then the end"), 2);
        assert_eq!(c.send(KIND_TEXT, b"x"), 2);
    }

    #[test]
    fn a_peer_closing_while_messages_are_queued_is_a_clean_close_with_its_code_and_the_unsent_counted() {
        let _g = crate::runtime::test_lock();
        let go = Arc::new(Notify::new());
        let g2 = go.clone();
        let port = serve(true, move |s| {
            let go = g2.clone();
            async move {
                let mut ws = accept(s, Default::default()).await;
                // Reads nothing, so the client's writer blocks with messages queued; then it closes.
                go.notified().await;
                let frame = CloseFrame { code: CloseCode::Away, reason: "going away".into() };
                let _ = ws.close(Some(frame)).await;
                while let Some(Ok(_)) = ws.next().await {}
            }
        });
        let c = spec_with(&url(port), "", |s| s.queue_limit = 8192);
        c.open();
        let msg = vec![5u8; 2048];
        // Until the kernel's buffers are full and the queue stays full: the writer is blocked.
        let (mut n, mut steady) = (0, 0);
        while steady < 40 {
            if unsafe { zr_net_ws_send(c.ws, KIND_BINARY, msg.as_ptr(), msg.len()) } == 0 {
                n += 1;
                steady = 0;
            } else {
                std::thread::sleep(Duration::from_millis(5));
                steady += 1;
            }
            assert!(n < 100_000, "never blocked");
        }
        go.notify_one();
        let i = c.until(|i| i.state == CLOSED);
        // A clean close (no protocol error from writing after it), with the peer's code and reason.
        assert_eq!((i.error, i.close_code), (0, 1001), "{}", c.message());
        assert_eq!(c.message(), "closed by the peer: 1001 going away");
        assert!(i.unsent > 0, "the queue was not counted as lost: queued {} unsent {} sent {} out {}", i.queued, i.unsent, n, i.bytes_out);
        assert_eq!(i.queued, 0);
        assert_eq!(c.send(KIND_TEXT, b"x"), 2);
    }

    #[test]
    fn a_slow_reader_stops_the_sender_at_the_queue_bound_and_the_drain_wakes_it() {
        let _g = crate::runtime::test_lock();
        const LIMIT: usize = 8 * 1024;
        let go = Arc::new(Notify::new());
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Vec<u64>>();
        let done_tx = Mutex::new(Some(done_tx));
        let g2 = go.clone();
        let port = serve(true, move |s| {
            let (go, tx) = (g2.clone(), done_tx.lock().expect("lock").take());
            async move {
                let mut ws = accept(s, Default::default()).await;
                // Reads nothing until told to.
                go.notified().await;
                let mut seqs = Vec::new();
                while let Some(Ok(m)) = ws.next().await {
                    if let Message::Binary(b) = m {
                        seqs.push(u64::from_be_bytes(b.get(..8).and_then(|x| x.try_into().ok()).unwrap_or([0; 8])));
                        if b.get(8) == Some(&255) {
                            break;
                        }
                    }
                }
                if let Some(tx) = tx {
                    let _ = tx.send(seqs);
                }
            }
        });
        let c = spec_with(&url(port), "", |s| s.queue_limit = LIMIT as u32);
        c.open();
        let msg = |n: u64, last: bool| {
            let mut m = vec![7u8; 2048];
            m[..8].copy_from_slice(&n.to_be_bytes());
            m[8] = if last { 255 } else { 0 };
            m
        };
        // Sends until the queue says "full", and checks that it never held more than its bound.
        let (mut n, mut peak) = (0u64, 0usize);
        loop {
            let m = msg(n, false);
            match unsafe { zr_net_ws_send(c.ws, KIND_BINARY, m.as_ptr(), m.len()) } {
                0 => {
                    n += 1;
                    peak = peak.max(c.info().queued);
                    assert!(peak <= LIMIT, "{peak} bytes queued of {LIMIT}");
                }
                1 => break,
                rc => panic!("send returned {rc}"),
            }
            assert!(n < 100_000, "never full: the kernel's buffers took {n} messages");
        }
        assert!(c.info().queued > 0 && n > 0);
        // The reader starts: the descriptor wakes the sender, who goes on to the end.
        let before = Instant::now();
        go.notify_one();
        let mut total = n;
        for _ in 0..50 {
            let m = msg(total, false);
            assert_eq!(c.send(KIND_BINARY, &m), 0);
            total += 1;
        }
        assert_eq!(c.send(KIND_BINARY, &msg(total, true)), 0);
        total += 1;
        let seqs = done_rx.recv_timeout(Duration::from_secs(20)).expect("the server read to the end");
        assert!(before.elapsed() < Duration::from_secs(20));
        assert_eq!(seqs, (0..total).collect::<Vec<_>>(), "every message, in order");
        assert_eq!(c.info().dropped, 0);
    }

    #[test]
    fn a_cancel_in_the_middle_of_a_send_or_a_receive_ends_the_connection_and_frees_everything() {
        let _g = crate::runtime::test_lock();
        let closed = Arc::new(AtomicBool::new(false));
        let c2 = closed.clone();
        let port = serve(true, move |s| {
            let closed = c2.clone();
            async move {
                let mut raw = s;
                // The server reads the upgrade's head, answers it, and then reads nothing but the end.
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if raw.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let key = String::from_utf8_lossy(&head).lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ").map(str::to_string)).unwrap_or_default();
                let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                let _ = raw.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await;
                // Does not read until the client is gone, then sees the end of the connection.
                tokio::time::sleep(Duration::from_millis(300)).await;
                let mut sink = vec![0u8; 1 << 16];
                loop {
                    match raw.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                closed.store(true, Ordering::SeqCst);
            }
        });
        let heap_before = crate::alloc::in_use();
        // Mid-send: the queue is full and the writer blocked on a peer that reads nothing.
        let c = spec_with(&url(port), "", |s| s.queue_limit = 4096);
        c.open();
        let big = vec![9u8; 2048];
        let mut sent = 0;
        while unsafe { zr_net_ws_send(c.ws, KIND_BINARY, big.as_ptr(), big.len()) } == 0 {
            sent += 1;
            assert!(sent < 100_000, "never full");
        }
        let fd = c.fd.try_clone().expect("clone");
        drop(c);
        // The server sees the connection end, with the message half written.
        let started = Instant::now();
        while !closed.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(closed.load(Ordering::SeqCst), "the connection was left open after the free");
        drop(fd);

        // Mid-receive: a thread waits on the descriptor for a message that never comes; the free ends
        // its wait (the library's end of the descriptor closes), as a cancelled std.Io wait ends.
        closed.store(false, Ordering::SeqCst);
        let c = spec_with(&url(port), "", |_| {});
        c.open();
        let waiter = {
            let fd = c.fd.try_clone().expect("clone");
            std::thread::spawn(move || {
                let mut b = [MaybeUninit::<u8>::uninit(); 64];
                // Drains the wake of the upgrade, then waits for what never comes.
                loop {
                    match fd.recv(&mut b) {
                        Ok(0) | Err(_) => return true,
                        Ok(_) => {}
                    }
                }
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        drop(c);
        assert!(waiter.join().expect("the waiter ends"), "the wait ended with the connection");
        let started = Instant::now();
        while crate::alloc::in_use() > heap_before + 64 * 1024 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(crate::alloc::in_use() <= heap_before + 64 * 1024, "{} bytes held after the frees, {heap_before} before", crate::alloc::in_use());
    }

    #[test]
    fn a_server_that_never_answers_the_upgrade_is_given_up_and_a_cancel_ends_it_at_once() {
        let _g = crate::runtime::test_lock();
        // Connections complete in the listener's backlog and are never answered.
        let (l, port) = listener(false);
        let started = Instant::now();
        let c = spec_with(&url(port), "", |s| s.open_ms = 300);
        let i = c.until(|i| i.state != CONNECTING);
        let took = started.elapsed();
        assert_eq!((i.error, i.state), (Code::Timeout as i32, CLOSED), "{}", c.message());
        assert!(took >= Duration::from_millis(300) && took < Duration::from_secs(10), "{took:?}");
        let c2 = spec_with(&url(port), "", |s| s.open_ms = 60_000);
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        drop(c2);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(l);
    }

    #[test]
    fn a_refused_upgrade_a_bad_url_and_a_connection_lost_are_each_their_own_error() {
        let _g = crate::runtime::test_lock();
        let refuse = serve(false, |mut s| async move {
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b).await;
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        });
        let c = spec_with(&url(refuse), "", |_| {});
        let i = c.until(|i| i.state != CONNECTING);
        assert_eq!(i.error, Code::WsRefused as i32);
        assert!(c.message().contains("403"), "{}", c.message());

        let spec = WsSpec { url: b"http://x".as_ptr(), url_len: 8, headers: std::ptr::null(), headers_len: 0, max_frame: 0, open_ms: 0, close_wait_ms: 0, queue_limit: 0, recv_limit: 0 };
        let (mut ws, mut fd) = (std::ptr::null_mut(), -1);
        let mut msg = [0u8; 64];
        let rc = unsafe { zr_net_ws_connect(new_client(""), &spec, &mut ws, &mut fd, msg.as_mut_ptr(), msg.len()) };
        assert_eq!(rc, Code::BadUrl as i32);

        // Accepts the upgrade and goes: the next thing the client learns is that the connection is
        // lost (no close frame), and what it sent is refused as over.
        let dead = serve(false, |s| async move {
            let ws = accept(s, Default::default()).await;
            drop(ws);
        });
        let c = spec_with(&url(dead), "", |_| {});
        // Whether the loss is seen before or after the upgrade's answer is the race of the server's drop.
        let i = c.until(|i| i.state == CLOSED);
        assert_eq!(i.error, Code::Io as i32, "{}", c.message());
        assert_eq!(c.send(KIND_TEXT, b"x"), 2);
        assert_eq!(c.recv().expect_err("lost"), 100 + Code::Io as i32);
    }

    #[test]
    fn a_message_is_sent_in_frames_of_the_size_asked_the_first_text_and_the_rest_continuations() {
        let _g = crate::runtime::test_lock();
        let frames: Arc<Mutex<Vec<(u8, bool, usize, bool)>>> = Default::default();
        let f2 = frames.clone();
        let port = serve(false, move |mut s| {
            let frames = f2.clone();
            async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let key = String::from_utf8_lossy(&head).lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ").map(str::to_string)).unwrap_or_default();
                let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                let _ = s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await;
                // Frames by hand: FIN and opcode, mask bit and length (7 or 16 bits), the mask, the payload.
                loop {
                    let mut h = [0u8; 2];
                    if s.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let (first, second) = (h[0], h[1]);
                    let mut len = (second & 0x7f) as usize;
                    if len == 126 {
                        let mut l = [0u8; 2];
                        if s.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        len = u16::from_be_bytes(l) as usize;
                    }
                    let mut mask = [0u8; 4];
                    if s.read_exact(&mut mask).await.is_err() {
                        return;
                    }
                    let mut payload = vec![0u8; len];
                    if s.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    for (i, p) in payload.iter_mut().enumerate() {
                        *p ^= mask.get(i % 4).copied().unwrap_or(0);
                    }
                    let opcode = first & 0x0f;
                    frames.lock().expect("lock").push((opcode, first & 0x80 != 0, len, second & 0x80 != 0));
                    if opcode == 8 {
                        // A close from the client: its status is 1000, as the std feed sent.
                        assert_eq!(payload, [0x03, 0xE8]);
                        let _ = s.write_all(&[0x88, 0x02, 0x03, 0xE8]).await;
                        return;
                    }
                }
            }
        });
        let c = spec_with(&url(port), "", |s| s.max_frame = 1024);
        c.open();
        let long: Vec<u8> = (0..2500u32).map(|i| b'a' + (i % 26) as u8).collect();
        assert_eq!(c.send(KIND_TEXT, &long), 0);
        assert_eq!(c.send(KIND_TEXT, b"short"), 0);
        assert_eq!(c.send(KIND_PING, b""), 0);
        unsafe { zr_net_ws_close(c.ws) };
        c.until(|i| i.state == CLOSED);
        // (opcode, FIN, payload length, masked): every frame from a client is masked.
        let want = [(1, false, 1024, true), (0, false, 1024, true), (0, true, 452, true), (1, true, 5, true), (9, true, 0, true), (8, true, 2, true)];
        assert_eq!(*frames.lock().expect("lock"), want);
    }

    #[test]
    fn messages_that_do_not_fit_the_inbox_are_dropped_and_counted_while_pings_are_still_answered() {
        let _g = crate::runtime::test_lock();
        let seen: Seen = Default::default();
        let s2 = seen.clone();
        let port = serve(false, move |s| {
            let seen = s2.clone();
            async move {
                let mut ws = accept(s, Default::default()).await;
                for _ in 0..4 {
                    let _ = ws.send(Message::Text("x".repeat(600).into())).await;
                }
                let _ = ws.send(Message::Ping(Bytes::from_static(b"p"))).await;
                while let Some(Ok(m)) = ws.next().await {
                    seen.lock().expect("lock").push(describe(&m));
                    if matches!(m, Message::Close(_) | Message::Pong(_)) {
                        break;
                    }
                }
                let _ = ws.close(None).await;
            }
        });
        let c = spec_with(&url(port), "", |s| s.recv_limit = 1024);
        c.open();
        let i = c.until(|i| i.dropped >= 3);
        assert_eq!((i.waiting, i.dropped), (600, 3));
        let started = Instant::now();
        while seen.lock().expect("lock").is_empty() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*seen.lock().expect("lock"), ["PONG:p"]);
        assert_eq!(c.recv().expect("the one that fitted").1.len(), 600);
    }

    mod tls {
        use super::*;
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
        use rustls::pki_types::PrivateKeyDer;

        fn acceptor(names: &[&str]) -> (tokio_rustls::TlsAcceptor, String) {
            let mut p = CertificateParams::new(vec![]).expect("params");
            p.distinguished_name.push(DnType::CommonName, "ws test CA");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca_key = KeyPair::generate().expect("key");
            let ca = p.self_signed(&ca_key).expect("ca");
            let issuer = rcgen::Issuer::new(p, ca_key);
            let mut lp = CertificateParams::new(vec![]).expect("params");
            lp.subject_alt_names = names
                .iter()
                .map(|n| match n.parse::<std::net::IpAddr>() {
                    Ok(ip) => SanType::IpAddress(ip),
                    Err(_) => SanType::DnsName((*n).try_into().expect("dns name")),
                })
                .collect();
            lp.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            let k = KeyPair::generate().expect("key");
            let cert = lp.signed_by(&k, &issuer).expect("cert");
            let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::try_from(k.serialize_der()).expect("key der"))
                .expect("config");
            (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), ca.pem())
        }

        #[test]
        fn wss_trusts_the_roots_it_was_given_and_says_why_it_does_not_trust_the_others() {
            let _g = crate::runtime::test_lock();
            let (acceptor, pem) = acceptor(&["127.0.0.1"]);
            let (l, port) = listener(false);
            rt().spawn(async move {
                let l = TcpListener::from_std(l).expect("listener");
                while let Ok((s, _)) = l.accept().await {
                    let a = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = a.accept(s).await else { return };
                        let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else { return };
                        while let Some(Ok(m)) = ws.next().await {
                            let _ = ws.send(m).await;
                        }
                    });
                }
            });
            let u = format!("wss://127.0.0.1:{port}/_ws/ingest.sock");
            let spec = WsSpec { url: u.as_ptr(), url_len: u.len(), headers: std::ptr::null(), headers_len: 0, max_frame: 0, open_ms: 5000, close_wait_ms: 0, queue_limit: 0, recv_limit: 0 };
            let c = connect_with(new_client(&pem), &spec);
            let i = c.open();
            assert!(i.tls_ns != UNKNOWN && i.connect_ns != UNKNOWN);
            assert_eq!(c.send(KIND_TEXT, b"echo"), 0);
            assert_eq!(c.recv().expect("the echo"), (KIND_TEXT, b"echo".to_vec()));
            // A name the certificate is not for: its own error, though the CA is trusted.
            let named = format!("wss://localhost:{port}/_ws/ingest.sock");
            let spec_named = WsSpec { url: named.as_ptr(), url_len: named.len(), ..spec_copy(&spec) };
            let wrong = connect_with(new_client(&pem), &spec_named);
            let i = wrong.until(|i| i.state != CONNECTING);
            assert_eq!(i.error, Code::TlsNameMismatch as i32, "{}", wrong.message());
            // The system's roots do not know this CA.
            let other = connect_with(new_client(""), &spec);
            let i = other.until(|i| i.state != CONNECTING);
            assert_eq!(i.error, Code::TlsUnknownIssuer as i32, "{}", other.message());
            drop(c);
        }

        fn spec_copy(s: &WsSpec) -> WsSpec {
            WsSpec { url: s.url, url_len: s.url_len, headers: s.headers, headers_len: s.headers_len, max_frame: s.max_frame, open_ms: s.open_ms, close_wait_ms: s.close_wait_ms, queue_limit: s.queue_limit, recv_limit: s.recv_limit }
        }

        #[test]
        fn wss_through_an_http_proxys_connect_reaches_the_server_with_the_names_of_its_certificate() {
            let _g = crate::runtime::test_lock();
            let (acceptor, pem) = acceptor(&["wss.example.test"]);
            let (l, server_port) = listener(false);
            rt().spawn(async move {
                let l = TcpListener::from_std(l).expect("listener");
                while let Ok((s, _)) = l.accept().await {
                    let a = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = a.accept(s).await else { return };
                        let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else { return };
                        while let Some(Ok(m)) = ws.next().await {
                            let _ = ws.send(m).await;
                        }
                    });
                }
            });
            // The proxy: reads CONNECT, notes its target, tunnels to the server above whatever name it was.
            let seen: Seen = Default::default();
            let seen2 = seen.clone();
            let proxy = serve(false, move |mut s| {
                let seen = seen2.clone();
                async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    seen.lock().expect("lock").push(String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string());
                    let Ok(mut up) = TcpStream::connect(("127.0.0.1", server_port)).await else { return };
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                }
            });
            // The client reads the proxy from the environment, as the runner's does (flags bit 0).
            std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"));
            std::env::remove_var("https_proxy");
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("no_proxy");
            let cfg = ClientConfig { user_agent: b"zr-test".as_ptr(), user_agent_len: 7, roots: pem.as_ptr(), roots_len: pem.len(), connect_timeout_ms: 0, tls_timeout_ms: 0, idle_timeout_ms: 0, max_idle_per_host: 0, flags: 1 };
            let mut client = std::ptr::null_mut();
            assert_eq!(unsafe { zr_net_client_new(&cfg, &mut client, std::ptr::null_mut(), 0) }, 0);
            std::env::remove_var("HTTPS_PROXY");
            let u = format!("wss://wss.example.test:{server_port}/_ws/ingest.sock");
            let spec = WsSpec { url: u.as_ptr(), url_len: u.len(), headers: std::ptr::null(), headers_len: 0, max_frame: 0, open_ms: 5000, close_wait_ms: 0, queue_limit: 0, recv_limit: 0 };
            let c = connect_with(client, &spec);
            c.open();
            assert_eq!(c.send(KIND_TEXT, b"through"), 0);
            assert_eq!(c.recv().expect("the echo"), (KIND_TEXT, b"through".to_vec()));
            assert_eq!(*seen.lock().expect("lock"), [format!("CONNECT wss.example.test:{server_port} HTTP/1.1")]);
            drop(c);
        }
    }
}
