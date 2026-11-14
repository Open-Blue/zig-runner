//! The HTTP/1.1 client (docs/rust-net.md, "HTTP semantics"): hyper's connection API under our own
//! pool, connector and timers, so the figures of the `request:` line are exact: DNS is timed around
//! the resolver, connect around the TCP connect (`TCP_NODELAY`, keepalive and `TCP_USER_TIMEOUT` set
//! there), TLS around the handshake, first byte from the request being handed to the connection to
//! the response's head. Bodies are read whole (`run`) or streamed (`open` and `pump`, R4, through
//! `body.rs`'s bounded queues). Redirects are followed here, and the credentials stay behind when
//! one leaves the origin.
use crate::body::{DownStream, Payload, ReqBody};
use crate::proxy::Proxy;
use crate::roots;
use http::{header, HeaderName, HeaderValue, Method, Uri};
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The size of the buffer a connection reads into (see `connect`).
const READ_BUF: usize = 64 * 1024;

/// A figure that was not measured.
pub const UNKNOWN: u64 = u64::MAX;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Code {
    Ok = 0,
    BadUrl = 1,
    Dns = 2,
    ConnectRefused = 3,
    ConnectTimeout = 4,
    ConnectFailed = 5,
    TlsUnknownIssuer = 6,
    TlsExpired = 7,
    TlsNameMismatch = 8,
    TlsCertificate = 9,
    TlsFailed = 10,
    Timeout = 11,
    Canceled = 12, // reported by the caller's side, which cancels
    TooManyRedirects = 13,
    BodyTooLarge = 14,
    Protocol = 15,
    Proxy = 16,
    Io = 17,
    Config = 18,
    /// A kept connection that turned out to be closed after part of a streamed body had been taken
    /// from the caller: the body cannot be repeated here, the caller sends it again.
    Stale = 19,
}

pub type Fail = (Code, String);

trait Rw: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Rw for T {}
type Stream = Box<dyn Rw>;

/// What one request measured, nanoseconds; `UNKNOWN` where nothing was.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub dns: u64,
    pub connect: u64,
    pub tls: u64,
    pub ttfb: u64,
    pub total: u64,
    pub bytes_in: u64,
    pub redirects: u32,
    pub reused: bool,
}

impl Default for Timings {
    fn default() -> Self {
        Timings { dns: UNKNOWN, connect: UNKNOWN, tls: UNKNOWN, ttfb: UNKNOWN, total: UNKNOWN, bytes_in: 0, redirects: 0, reused: false }
    }
}

pub struct Settings {
    pub user_agent: String,
    pub connect_timeout: Duration,
    pub tls_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_idle_per_host: usize,
    pub proxy: Proxy,
    /// PEM roots that replace the system's.
    pub roots_pem: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    https: bool,
    host: String,
    port: u16,
    proxy: Option<(String, u16)>,
}

struct Idle {
    sender: http1::SendRequest<ReqBody>,
    since: Instant,
    dns: u64,
    connect: u64,
    tls: u64,
}

pub struct Client {
    pub settings: Settings,
    pool: Mutex<HashMap<Key, Vec<Idle>>>,
}

pub struct Spec {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Payload,
    pub max_redirects: u32,
    pub max_response: usize,
    pub first_byte: Option<Duration>,
    pub read_idle: Option<Duration>,
    /// A connection made for this request, not one the pool kept (a streamed body sent again after a
    /// kept connection turned out to be dead).
    pub fresh: bool,
}

/// A response whose head has been read: its body is still on the connection.
pub struct Head {
    pub parts: http::response::Parts,
    pub incoming: Incoming,
    pub minor: u8,
    key: Key,
    idle: Idle,
}

pub struct Done {
    pub status: u16,
    /// `name: value` lines, names lower-case, `\n` between.
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub minor: u8,
    pub timings: Timings,
}

fn ns(d: Duration) -> u64 {
    d.as_nanos().min((UNKNOWN - 1) as u128) as u64
}

fn is_redirect(s: u16) -> bool {
    matches!(s, 301 | 302 | 303 | 307 | 308)
}

struct Target {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Target, Fail> {
    let bad = |m: &str| (Code::BadUrl, format!("{url}: {m}"));
    let uri: Uri = url.parse().map_err(|e: http::uri::InvalidUri| bad(&e.to_string()))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(bad("not an http or https URL")),
    };
    let host = uri.host().ok_or_else(|| bad("no host"))?.trim_matches(['[', ']']).to_string();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    Ok(Target { https, host, port, path: if path.is_empty() { "/".into() } else { path } })
}

impl Target {
    fn origin(&self) -> (bool, &str, u16) {
        (self.https, &self.host, self.port)
    }
    fn authority(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
    fn url(&self) -> String {
        format!("{}://{}{}", if self.https { "https" } else { "http" }, self.authority(), self.path)
    }
}

/// `location` resolved against the URL it came from (absolute, scheme-relative, absolute-path or
/// relative path), as a URL.
fn resolve(base: &Target, location: &str) -> Result<String, Fail> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let scheme = if base.https { "https" } else { "http" };
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    let path = if location.starts_with('/') {
        location.to_string()
    } else {
        let dir = base.path.split(['?', '#']).next().unwrap_or("/");
        let dir = &dir[..dir.rfind('/').map_or(0, |i| i + 1)];
        format!("{dir}{location}")
    };
    Ok(format!("{scheme}://{}{path}", base.authority()))
}

fn idempotent(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// A request that failed because the connection was closed or reset, not because of anything it said.
fn is_dead(e: &hyper::Error) -> bool {
    if e.is_closed() || e.is_incomplete_message() {
        return true;
    }
    let mut src = std::error::Error::source(e);
    while let Some(x) = src {
        if let Some(io) = x.downcast_ref::<std::io::Error>() {
            return matches!(io.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionAborted);
        }
        src = x.source();
    }
    false
}

fn tls_kind(e: &std::io::Error) -> Code {
    if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        return match crate::tls::classify(inner) {
            crate::tls::Kind::UnknownIssuer => Code::TlsUnknownIssuer,
            crate::tls::Kind::Expired => Code::TlsExpired,
            crate::tls::Kind::NameMismatch => Code::TlsNameMismatch,
            crate::tls::Kind::Certificate => Code::TlsCertificate,
            _ => Code::TlsFailed,
        };
    }
    Code::TlsFailed
}

fn tune(s: &TcpStream) {
    let _ = s.set_nodelay(true);
    let sock = socket2::SockRef::from(s);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    let _ = sock.set_tcp_keepalive(&ka);
    // The same 90 s as the keepalive's, for data sent that is never acknowledged (#100).
    let _ = sock.set_tcp_user_timeout(Some(Duration::from_secs(90)));
}

impl Client {
    pub fn new(settings: Settings) -> Client {
        Client { settings, pool: Mutex::new(HashMap::new()) }
    }

    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>, Fail> {
        let roots = if self.settings.roots_pem.is_empty() { roots::native() } else { roots::from_pem(&self.settings.roots_pem) }
            .map_err(|m| (Code::Config, m))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| (Code::Config, e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    /// TCP to `host:port`: resolved (timed), each address tried in turn (timed together).
    async fn tcp(&self, host: &str, port: u16, t: &mut (u64, u64)) -> Result<TcpStream, Fail> {
        let started = Instant::now();
        let addrs: Vec<SocketAddr> = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| (Code::Dns, format!("{host}: {e}")))?
                .collect(),
        };
        t.0 = ns(started.elapsed());
        if addrs.is_empty() {
            return Err((Code::Dns, format!("{host}: no addresses")));
        }
        let started = Instant::now();
        let mut last: Fail = (Code::ConnectFailed, String::new());
        for a in addrs {
            match tokio::time::timeout(self.settings.connect_timeout, TcpStream::connect(a)).await {
                Ok(Ok(s)) => {
                    tune(&s);
                    t.1 = ns(started.elapsed());
                    return Ok(s);
                }
                Ok(Err(e)) => {
                    let code = if e.kind() == std::io::ErrorKind::ConnectionRefused { Code::ConnectRefused } else { Code::ConnectFailed };
                    last = (code, format!("{a}: {e}"));
                }
                Err(_) => last = (Code::ConnectTimeout, format!("{a}: no answer within {:?}", self.settings.connect_timeout)),
            }
        }
        t.1 = ns(started.elapsed());
        Err(last)
    }

    /// A new connection for `key`: through the proxy when there is one, TLS when the target is https.
    async fn connect(&self, target: &Target, via: Option<&crate::proxy::Target>) -> Result<(Idle, bool), Fail> {
        let mut t = (UNKNOWN, UNKNOWN);
        let mut tls_ns = UNKNOWN;
        let mut stream: Stream = match via {
            Some(p) => Box::new(self.tcp(&p.host, p.port, &mut t).await.map_err(|(c, m)| (if c == Code::Dns || c == Code::ConnectRefused || c == Code::ConnectTimeout { c } else { Code::Proxy }, format!("proxy {}:{}: {m}", p.host, p.port)))?),
            None => Box::new(self.tcp(&target.host, target.port, &mut t).await?),
        };
        if let (Some(p), true) = (via, target.https) {
            // CONNECT: the tunnel to the target, whose TLS then runs inside it.
            let authority = target.authority();
            let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
            if let Some(a) = &p.authorization {
                req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
            }
            req.push_str("\r\n");
            stream.write_all(req.as_bytes()).await.map_err(|e| (Code::Proxy, format!("proxy: {e}")))?;
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() > 8192 || stream.read(&mut b).await.map_err(|e| (Code::Proxy, format!("proxy: {e}")))? == 0 {
                    return Err((Code::Proxy, "the proxy closed or sent no valid answer to CONNECT".into()));
                }
                head.push(b[0]);
            }
            let line = String::from_utf8_lossy(head.split(|&c| c == b'\r').next().unwrap_or(b"")).to_string();
            if line.split(' ').nth(1) != Some("200") {
                return Err((Code::Proxy, format!("the proxy refused CONNECT {authority}: {line}")));
            }
        }
        if target.https {
            let started = Instant::now();
            let cfg = self.tls_config()?;
            let name = ServerName::try_from(target.host.clone()).map_err(|e| (Code::BadUrl, format!("{}: {e}", target.host)))?;
            let handshake = tokio_rustls::TlsConnector::from(cfg).connect(name, stream);
            let tls = match tokio::time::timeout(self.settings.tls_timeout, handshake).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err((tls_kind(&e), format!("TLS to {}: {e}", target.host))),
                Err(_) => return Err((Code::Timeout, format!("TLS to {}: no handshake within {:?}", target.host, self.settings.tls_timeout))),
            };
            tls_ns = ns(started.elapsed());
            stream = Box::new(tls);
        }
        // A read buffer of one fixed size: hyper's adaptive one grows to hundreds of KiB, and each
        // chunk of that size is a fresh mapping (musl's malloc maps what is over 128 KiB), faulted in
        // and returned for every read of a big download; 64 KiB is reused from the heap.
        let (sender, conn) = http1::Builder::new()
            .read_buf_exact_size(Some(READ_BUF))
            .handshake::<_, ReqBody>(TokioIo::new(stream))
            .await
            .map_err(|e| (Code::Protocol, format!("HTTP/1.1 handshake: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((Idle { sender, since: Instant::now(), dns: t.0, connect: t.1, tls: tls_ns }, false))
    }

    fn take(&self, key: &Key) -> Option<Idle> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let list = pool.get_mut(key)?;
        while let Some(i) = list.pop() {
            if !i.sender.is_closed() && i.since.elapsed() < self.settings.idle_timeout {
                return Some(i);
            }
        }
        None
    }

    fn put(&self, key: Key, idle: Idle) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let list = pool.entry(key).or_default();
        list.retain(|i| !i.sender.is_closed());
        if list.len() < self.settings.max_idle_per_host {
            list.push(Idle { since: Instant::now(), ..idle });
        }
    }

    /// One request to one origin, no redirects: the response's head, its body still unread.
    #[allow(clippy::too_many_arguments)]
    async fn once(&self, target: &Target, method: &Method, headers: &[(HeaderName, HeaderValue)], body: &Payload, spec: &Spec, t: &mut Timings, again: bool) -> Result<Head, Fail> {
        let via = self.settings.proxy.for_url(target.https, &target.host, target.port).cloned();
        let key = Key { https: target.https, host: target.host.clone(), port: target.port, proxy: via.as_ref().map(|p| (p.host.clone(), p.port)) };
        let kept = if spec.fresh { None } else { self.take(&key) };
        let (mut idle, reused) = match kept {
            Some(i) => (i, true),
            None => self.connect(target, via.as_ref()).await?,
        };
        t.reused = reused;
        // A reused connection has no DNS, connect or TLS of its own to report.
        (t.dns, t.connect, t.tls) = if reused { (UNKNOWN, UNKNOWN, UNKNOWN) } else { (idle.dns, idle.connect, idle.tls) };

        let plain_proxy = via.is_some() && !target.https;
        let mut req = http::Request::builder().method(method.clone());
        req = req.uri(if plain_proxy { target.url() } else { target.path.clone() });
        let h = req.headers_mut().expect("a request being built has headers");
        h.insert(header::HOST, HeaderValue::from_str(&target.authority()).map_err(|e| (Code::BadUrl, e.to_string()))?);
        h.insert(header::USER_AGENT, HeaderValue::from_str(&self.settings.user_agent).map_err(|e| (Code::Config, e.to_string()))?);
        for (n, v) in headers {
            h.insert(n.clone(), v.clone());
        }
        if plain_proxy {
            if let Some(a) = via.as_ref().and_then(|p| p.authorization.as_ref()) {
                h.insert("proxy-authorization", HeaderValue::from_str(a).map_err(|e| (Code::Config, e.to_string()))?);
            }
        }
        if !body.is_empty() || matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
        let req = req.body(body.body()).map_err(|e| (Code::Protocol, e.to_string()))?;

        let sent = Instant::now();
        let ready = idle.sender.ready().await;
        if ready.is_err() && reused {
            // The kept connection was closed since: nothing was sent, so a new one is no repeat.
            return self.fresh(target, via.as_ref(), method, headers, body, spec, t, again).await;
        }
        ready.map_err(|e| (Code::Io, format!("connection: {e}")))?;
        let send = idle.sender.send_request(req);
        let resp = match spec.first_byte {
            Some(d) => tokio::time::timeout(d, send).await.map_err(|_| (Code::Timeout, format!("no answer within {d:?}")))?,
            None => send.await,
        };
        let resp = match resp {
            Ok(r) => r,
            // A connection that was closed, or is gone, when the request reached it, so that no
            // answer came: a kept one (`reused`), or a new one of a GET, which may be sent again, once.
            Err(e) if !again && is_dead(&e) && sent.elapsed() < Duration::from_millis(200) && (reused || (idempotent(method) && !body.is_stream())) => {
                // A body the caller writes has been taken from it, perhaps: it sends it again.
                if body.is_stream() {
                    return Err((Code::Stale, format!("a kept connection was closed: {e}")));
                }
                return self.fresh(target, via.as_ref(), method, headers, body, spec, t, again).await;
            }
            Err(e) => return Err((Code::Io, format!("{e}"))),
        };
        t.ttfb = ns(sent.elapsed());
        let (parts, incoming) = resp.into_parts();
        let minor = if parts.version == http::Version::HTTP_10 { 0 } else { 1 };
        Ok(Head { parts, incoming, minor, key, idle })
    }

    /// The same request on a connection made now, after a kept one turned out to be closed.
    #[allow(clippy::too_many_arguments)]
    fn fresh<'a>(&'a self, target: &'a Target, via: Option<&'a crate::proxy::Target>, method: &'a Method, headers: &'a [(HeaderName, HeaderValue)], body: &'a Payload, spec: &'a Spec, t: &'a mut Timings, _again: bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Head, Fail>> + Send + 'a>> {
        Box::pin(async move {
        // The pool entry for this key is dropped with the dead connection; a new one is made by
        // taking nothing: `once` with an empty pool would loop, so connect here and put it in.
        let key = Key { https: target.https, host: target.host.clone(), port: target.port, proxy: via.map(|p| (p.host.clone(), p.port)) };
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
        self.once(target, method, headers, body, spec, t, true).await
        })
    }

    /// Gives the connection of a response whose body was read to its end back to the pool, unless
    /// it is one that should not be reused.
    fn recycle(&self, head: Head) {
        let keep = head.parts.version != http::Version::HTTP_10
            && !head.parts.headers.get(header::CONNECTION).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"close"))
            && !head.idle.sender.is_closed();
        if keep {
            self.put(head.key, head.idle);
        }
    }

    /// The whole body of `incoming`, at most `limit` bytes.
    async fn drain(incoming: &mut Incoming, limit: usize, read_idle: Option<Duration>) -> Result<Vec<u8>, Fail> {
        let mut out = Vec::new();
        loop {
            let next = incoming.frame();
            let frame = match read_idle {
                Some(d) => tokio::time::timeout(d, next).await.map_err(|_| (Code::Timeout, format!("the body stopped for {d:?}")))?,
                None => next.await,
            };
            match frame {
                None => return Ok(out),
                Some(Err(e)) => return Err((Code::Io, format!("body: {e}"))),
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        if out.len() + d.len() > limit {
                            return Err((Code::BodyTooLarge, format!("the response is over {limit} bytes")));
                        }
                        out.extend_from_slice(d);
                    }
                }
            }
        }
    }

    pub async fn run(&self, spec: Spec) -> Result<Done, (Fail, Timings)> {
        let started = Instant::now();
        let mut t = Timings::default();
        let r = async {
            let mut head = self.follow(&spec, &mut t).await?;
            let body = Self::drain(&mut head.incoming, spec.max_response, spec.read_idle).await?;
            t.bytes_in += body.len() as u64;
            let (parts, minor) = (head.parts.clone(), head.minor);
            self.recycle(head);
            Ok::<_, Fail>((parts, body, minor))
        }
        .await;
        t.total = ns(started.elapsed());
        match r {
            Ok((parts, body, minor)) => Ok(Done { status: parts.status.as_u16(), headers: header_lines(&parts), body, minor, timings: t }),
            Err(f) => Err((f, t)),
        }
    }

    /// A request answered with its head, redirects followed: the body is read by `pump`.
    pub async fn open(&self, spec: &Spec, t: &mut Timings) -> Result<Head, Fail> {
        self.follow(spec, t).await
    }

    /// Reads the body of `head` into `down` as it arrives, at most `spec.max_response` bytes (a
    /// `usize::MAX` for none), waiting while the caller has not taken what is queued. The
    /// connection goes back to the pool when the body ended cleanly.
    pub async fn pump(&self, mut head: Head, spec: &Spec, down: &DownStream, t: &mut Timings) -> Result<(), Fail> {
        loop {
            let next = head.incoming.frame();
            let frame = match spec.read_idle {
                Some(d) => tokio::time::timeout(d, next).await.map_err(|_| (Code::Timeout, format!("the body stopped for {d:?}")))?,
                None => next.await,
            };
            match frame {
                None => break,
                Some(Err(e)) => return Err((Code::Io, format!("body: {e}"))),
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        if d.is_empty() {
                            continue;
                        }
                        t.bytes_in += d.len() as u64;
                        if t.bytes_in > spec.max_response as u64 {
                            return Err((Code::BodyTooLarge, format!("the response is over {} bytes", spec.max_response)));
                        }
                        down.push(d).await;
                    }
                }
            }
        }
        self.recycle(head);
        Ok(())
    }

    async fn follow(&self, spec: &Spec, t: &mut Timings) -> Result<Head, Fail> {
        let mut target = parse_url(&spec.url)?;
        let mut method = spec.method.clone();
        let mut headers = spec.headers.clone();
        let mut body = spec.body.clone();
        loop {
            let mut head = self.once(&target, &method, &headers, &body, spec, t, false).await?;
            let status = head.parts.status.as_u16();
            let Some(location) = head.parts.headers.get(header::LOCATION).and_then(|v| v.to_str().ok()).filter(|_| is_redirect(status)).map(str::to_string) else {
                return Ok(head);
            };
            if t.redirects >= spec.max_redirects {
                return Err((Code::TooManyRedirects, format!("more than {} redirects", spec.max_redirects)));
            }
            let next = parse_url(&resolve(&target, &location)?)?;
            if target.https && !next.https {
                return Err((Code::Protocol, "a redirect from https to http is refused".into()));
            }
            // What carries credentials stays at the origin that was given them.
            if next.origin() != target.origin() {
                for n in [header::AUTHORIZATION, header::COOKIE, header::PROXY_AUTHORIZATION] {
                    headers.retain(|(h, _)| *h != n);
                }
            }
            // 303 turns anything into GET; 301 and 302 do for POST, as browsers and curl do; 307 and
            // 308 keep the method and the body.
            if status == 303 || (matches!(status, 301 | 302) && method == Method::POST) {
                if method != Method::HEAD {
                    method = Method::GET;
                }
                body = Payload::Bytes(Bytes::new());
                headers.retain(|(h, _)| *h != header::CONTENT_TYPE && *h != header::CONTENT_LENGTH);
            } else if body.is_stream() {
                return Err((Code::Protocol, format!("a {status} redirect would send a streamed body again")));
            }
            // The redirect's own body is read (a little of it) so that its connection can be reused.
            if let Ok(_small) = Self::drain(&mut head.incoming, 64 * 1024, spec.read_idle).await {
                self.recycle(head);
            }
            target = next;
            t.redirects += 1;
        }
    }
}

/// The headers of a response as `name: value\n` lines, names lower-case.
pub fn header_lines(parts: &http::response::Parts) -> Vec<u8> {
    let mut headers = Vec::new();
    for (n, v) in parts.headers.iter() {
        headers.extend_from_slice(n.as_str().as_bytes());
        headers.extend_from_slice(b": ");
        headers.extend_from_slice(v.as_bytes());
        headers.push(b'\n');
    }
    headers
}

/// Header lines `Name: value\n...` as the caller sends them.
pub fn parse_headers(lines: &[u8]) -> Result<Vec<(HeaderName, HeaderValue)>, Fail> {
    let mut out = Vec::new();
    for line in lines.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let colon = line.iter().position(|&b| b == b':').ok_or((Code::BadUrl, "a header without a colon".to_string()))?;
        let name = HeaderName::from_bytes(&line[..colon]).map_err(|e| (Code::BadUrl, format!("header name: {e}")))?;
        let value = HeaderValue::from_bytes(line[colon + 1..].trim_ascii()).map_err(|e| (Code::BadUrl, format!("header value: {e}")))?;
        out.push((name, value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
    use rustls::pki_types::PrivateKeyDer;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    struct Server {
        port: u16,
        accepts: Arc<AtomicU32>,
        /// Delays before the TLS handshake starts and before a response, for the timing tests.
        ca_pem: String,
    }

    struct Opts {
        tls: bool,
        tls_delay: Duration,
        reply_delay: Duration,
        names: Vec<&'static str>,
    }

    fn opts() -> Opts {
        Opts { tls: false, tls_delay: Duration::ZERO, reply_delay: Duration::ZERO, names: vec!["localhost", "127.0.0.1"] }
    }

    fn tls_acceptor(names: &[&str]) -> (tokio_rustls::TlsAcceptor, String) {
        let mut p = CertificateParams::new(vec![]).unwrap();
        static N: AtomicU32 = AtomicU32::new(0);
        p.distinguished_name.push(DnType::CommonName, format!("test CA {}", N.fetch_add(1, Ordering::SeqCst)));
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = p.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(p, ca_key);
        let mut lp = CertificateParams::new(vec![]).unwrap();
        lp.subject_alt_names = names
            .iter()
            .map(|n| match n.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*n).try_into().unwrap()),
            })
            .collect();
        lp.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let k = KeyPair::generate().unwrap();
        let cert = lp.signed_by(&k, &issuer).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::try_from(k.serialize_der()).unwrap())
            .unwrap();
        (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), ca.pem())
    }

    /// Reads one request: its line, its headers (lower-case names) and its body.
    async fn read_request<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
        let mut line = String::new();
        if r.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let mut parts = line.split_whitespace();
        let (m, p) = (parts.next()?.to_string(), parts.next()?.to_string());
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            r.read_line(&mut h).await.ok()?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let (n, v) = h.split_once(':')?;
            headers.push((n.to_ascii_lowercase(), v.trim().to_string()));
        }
        let len: usize = headers.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await.ok()?;
        Some((m, p, headers, body))
    }

    async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(stream: S, o: Arc<Opts>, port: u16) {
        let mut r = BufReader::new(stream);
        while let Some((m, p, h, body)) = read_request(&mut r).await {
            tokio::time::sleep(o.reply_delay).await;
            let auth = h.iter().find(|(n, _)| n == "authorization").map(|(_, v)| v.as_str()).unwrap_or("-");
            let ua = h.iter().find(|(n, _)| n == "user-agent").map(|(_, v)| v.as_str()).unwrap_or("-");
            let (status, extra, body): (&str, String, Vec<u8>) = match p.as_str() {
                "/echo" => ("200 OK", String::new(), format!("{m} {auth} {} ua={ua}", String::from_utf8_lossy(&body)).into_bytes()),
                "/same" => ("302 Found", format!("Location: http://127.0.0.1:{port}/echo\r\n"), vec![]),
                "/other" => ("302 Found", format!("Location: http://localhost:{port}/echo\r\n"), vec![]),
                "/relative" => ("302 Found", "Location: /echo\r\n".into(), vec![]),
                "/see-other" => ("303 See Other", "Location: /echo\r\n".into(), vec![]),
                "/temporary" => ("307 Temporary Redirect", "Location: /echo\r\n".into(), vec![]),
                "/loop" => ("302 Found", "Location: /loop\r\n".into(), vec![]),
                "/to-http" => ("302 Found", format!("Location: http://127.0.0.1:{port}/echo\r\n"), vec![]),
                "/big" => ("200 OK", String::new(), vec![b'x'; 100_000]),
                "/close" => ("200 OK", "Connection: close\r\n".into(), b"bye".to_vec()),
                "/nothing" => ("204 No Content", String::new(), vec![]),
                _ => ("404 Not Found", String::new(), b"{\"message\":\"Not Found\"}".to_vec()),
            };
            let head = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nX-Test: a\r\n\r\n", body.len());
            let w = r.get_mut();
            if status.starts_with("204") {
                let _ = w.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            } else {
                let _ = w.write_all(head.as_bytes()).await;
                let _ = w.write_all(&body).await;
            }
            let _ = w.flush().await;
            if p == "/close" {
                break;
            }
        }
    }

    async fn server(o: Opts) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicU32::new(0));
        let (acceptor, ca_pem) = tls_acceptor(&o.names);
        let o = Arc::new(o);
        let n = accepts.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                n.fetch_add(1, Ordering::SeqCst);
                let (o, acceptor) = (o.clone(), acceptor.clone());
                tokio::spawn(async move {
                    if o.tls {
                        tokio::time::sleep(o.tls_delay).await;
                        if let Ok(t) = acceptor.accept(s).await {
                            serve_conn(t, o, port).await;
                        }
                    } else {
                        serve_conn(s, o, port).await;
                    }
                });
            }
        });
        Server { port, accepts, ca_pem }
    }

    fn client(roots: &str, proxy: Proxy) -> Client {
        Client::new(Settings {
            user_agent: "zr-test/1".into(),
            connect_timeout: Duration::from_secs(5),
            tls_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_idle_per_host: 4,
            proxy,
            roots_pem: roots.as_bytes().to_vec(),
        })
    }

    fn spec(method: Method, url: String) -> Spec {
        Spec { method, url, headers: vec![], body: Payload::Bytes(Bytes::new()), max_redirects: 3, max_response: 1 << 20, first_byte: None, read_idle: None, fresh: false }
    }

    fn auth() -> Vec<(HeaderName, HeaderValue)> {
        vec![(header::AUTHORIZATION, HeaderValue::from_static("Bearer t0k"))]
    }

    fn text(d: &Done) -> String {
        String::from_utf8_lossy(&d.body).into_owned()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_post_user_agent_headers_and_a_kept_connection() {
        let s = server(opts()).await;
        let c = client("", Proxy::default());
        let url = |p: &str| format!("http://127.0.0.1:{}{p}", s.port);
        let d = c.run(spec(Method::GET, url("/echo"))).await.ok().unwrap();
        assert_eq!((d.status, text(&d).as_str()), (200, "GET -  ua=zr-test/1"));
        assert!(String::from_utf8_lossy(&d.headers).contains("x-test: a\n"));
        assert!(!d.timings.reused);
        // The second request rides the first one's connection, which has no DNS or connect of its own.
        let mut sp = spec(Method::POST, url("/echo"));
        sp.headers = auth();
        sp.body = Payload::Bytes(Bytes::from_static(b"payload"));
        let d = c.run(sp).await.ok().unwrap();
        assert_eq!(text(&d), "POST Bearer t0k payload ua=zr-test/1");
        assert!(d.timings.reused && d.timings.connect == UNKNOWN && d.timings.dns == UNKNOWN);
        assert_eq!(s.accepts.load(Ordering::SeqCst), 1);
        // 204, 404 with a body, and a response that closes the connection: the next one is new.
        assert_eq!(c.run(spec(Method::GET, url("/nothing"))).await.ok().unwrap().status, 204);
        let d = c.run(spec(Method::GET, url("/missing"))).await.ok().unwrap();
        assert_eq!((d.status, text(&d).as_str()), (404, "{\"message\":\"Not Found\"}"));
        assert_eq!(c.run(spec(Method::GET, url("/close"))).await.ok().unwrap().status, 200);
        let d = c.run(spec(Method::GET, url("/echo"))).await.ok().unwrap();
        assert!(!d.timings.reused);
        assert_eq!(s.accepts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redirects_keep_credentials_at_their_origin_only() {
        let s = server(opts()).await;
        let c = client("", Proxy::default());
        let url = |h: &str, p: &str| format!("http://{h}:{}{p}", s.port);
        let go = |p: &'static str| {
            let mut sp = spec(Method::GET, url("127.0.0.1", p));
            sp.headers = auth();
            c.run(sp)
        };
        // Same origin (also through a relative Location): the token goes along.
        assert_eq!(text(&go("/same").await.ok().unwrap()), "GET Bearer t0k  ua=zr-test/1");
        assert_eq!(text(&go("/relative").await.ok().unwrap()), "GET Bearer t0k  ua=zr-test/1");
        // Another host name (localhost): it does not.
        let d = go("/other").await.ok().unwrap();
        assert_eq!(text(&d), "GET -  ua=zr-test/1");
        assert_eq!(d.timings.redirects, 1);
        // 303 makes a POST a GET without its body; 307 keeps both.
        let mut sp = spec(Method::POST, url("127.0.0.1", "/see-other"));
        sp.body = Payload::Bytes(Bytes::from_static(b"data"));
        assert_eq!(text(&c.run(sp).await.ok().unwrap()), "GET -  ua=zr-test/1");
        let mut sp = spec(Method::POST, url("127.0.0.1", "/temporary"));
        sp.body = Payload::Bytes(Bytes::from_static(b"data"));
        assert_eq!(text(&c.run(sp).await.ok().unwrap()), "POST - data ua=zr-test/1");
        // A loop ends at the limit, with its own error; 0 redirects returns the 302 itself.
        let Err(((code, _), t)) = c.run(spec(Method::GET, url("127.0.0.1", "/loop"))).await else { panic!() };
        assert_eq!((code, t.redirects), (Code::TooManyRedirects, 3));
        let mut sp = spec(Method::GET, url("127.0.0.1", "/same"));
        sp.max_redirects = 0;
        assert_eq!(c.run(sp).await.err().map(|e| e.0 .0), Some(Code::TooManyRedirects));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_trusts_the_given_roots_and_says_why_it_does_not() {
        let s = server(Opts { tls: true, ..opts() }).await;
        let url = format!("https://localhost:{}/echo", s.port);
        let d = client(&s.ca_pem, Proxy::default()).run(spec(Method::GET, url.clone())).await.ok().unwrap();
        assert_eq!(text(&d), "GET -  ua=zr-test/1");
        assert!(d.timings.tls != UNKNOWN);
        // An address the certificate names.
        let d = client(&s.ca_pem, Proxy::default()).run(spec(Method::GET, format!("https://127.0.0.1:{}/echo", s.port))).await;
        assert!(d.is_ok());
        // Another CA's roots: unknown issuer.
        let other = server(Opts { tls: true, ..opts() }).await;
        let Err(((code, m), _)) = client(&other.ca_pem, Proxy::default()).run(spec(Method::GET, url)).await else { panic!() };
        assert_eq!(code, Code::TlsUnknownIssuer, "{m}");
        // A name the certificate does not have.
        let names = server(Opts { tls: true, names: vec!["db.example"], ..opts() }).await;
        let Err(((code, _), _)) = client(&names.ca_pem, Proxy::default()).run(spec(Method::GET, format!("https://localhost:{}/echo", names.port))).await else { panic!() };
        assert_eq!(code, Code::TlsNameMismatch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_phase_is_measured_where_it_happens() {
        let s = server(Opts { tls: true, tls_delay: Duration::from_millis(150), reply_delay: Duration::from_millis(100), ..opts() }).await;
        let c = client(&s.ca_pem, Proxy::default());
        let d = c.run(spec(Method::GET, format!("https://localhost:{}/echo", s.port))).await.ok().unwrap();
        let t = d.timings;
        let ms = |n: u64| n as f64 / 1e6;
        // The handshake waited 150 ms before the server began it; the answer 100 ms after the request.
        assert!((150.0..400.0).contains(&ms(t.tls)), "tls {} ms", ms(t.tls));
        assert!((100.0..300.0).contains(&ms(t.ttfb)), "ttfb {} ms", ms(t.ttfb));
        // DNS and connect are the loopback's: small. And none of the others is counted in them.
        assert!(ms(t.dns) < 50.0 && ms(t.connect) < 50.0, "dns {} connect {}", ms(t.dns), ms(t.connect));
        assert!(ms(t.total) >= ms(t.tls) + ms(t.ttfb));
        assert!(ms(t.total) < ms(t.dns) + ms(t.connect) + ms(t.tls) + ms(t.ttfb) + 100.0);
        // The next one rides the same connection: no phase of its own but the first byte.
        let d = c.run(spec(Method::GET, format!("https://localhost:{}/echo", s.port))).await.ok().unwrap();
        assert!(d.timings.reused && d.timings.tls == UNKNOWN && d.timings.ttfb != UNKNOWN);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sockets_have_nodelay_keepalive_and_a_limit_on_unacked_data() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        tune(&s);
        assert!(s.nodelay().unwrap());
        let sock = socket2::SockRef::from(&s);
        assert!(sock.keepalive().unwrap());
        assert_eq!(sock.tcp_user_timeout().unwrap(), Some(Duration::from_secs(90)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn limits_and_timeouts_end_a_request_with_their_own_error() {
        let s = server(Opts { reply_delay: Duration::from_millis(400), ..opts() }).await;
        let c = client("", Proxy::default());
        let url = |p: &str| format!("http://127.0.0.1:{}{p}", s.port);
        let mut sp = spec(Method::GET, url("/echo"));
        sp.first_byte = Some(Duration::from_millis(100));
        assert_eq!(c.run(sp).await.err().map(|e| e.0 .0), Some(Code::Timeout));
        let fast = server(opts()).await;
        let mut sp = spec(Method::GET, format!("http://127.0.0.1:{}/big", fast.port));
        sp.max_response = 1000;
        assert_eq!(c.run(sp).await.err().map(|e| e.0 .0), Some(Code::BodyTooLarge));
        // Nothing listens there.
        let free = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        assert_eq!(c.run(spec(Method::GET, format!("http://127.0.0.1:{free}/"))).await.err().map(|e| e.0 .0), Some(Code::ConnectRefused));
        assert_eq!(c.run(spec(Method::GET, "ftp://x/".into())).await.err().map(|e| e.0 .0), Some(Code::BadUrl));
        let r = client("", Proxy::default()).run(spec(Method::GET, "http://no-such-host.invalid/".into())).await;
        assert_eq!(r.err().map(|e| e.0 .0), Some(Code::Dns));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxies_carry_http_requests_and_tunnel_https_ones() {
        // The proxy: reads a request or a CONNECT, forwards it to the origin it names, and counts.
        let origin = server(Opts { tls: true, names: vec!["origin.test"], ..opts() }).await;
        let plain = server(opts()).await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pport = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let (oport, pport_plain) = (origin.port, plain.port);
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let log = log.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let text = String::from_utf8_lossy(&head).to_string();
                    let first = text.lines().next().unwrap_or("").to_string();
                    log.lock().unwrap().push(format!("{first} | {}", text.lines().filter(|l| l.to_ascii_lowercase().starts_with("proxy-authorization")).collect::<String>()));
                    if first.starts_with("CONNECT") {
                        let Ok(mut up) = TcpStream::connect(("127.0.0.1", oport)).await else { return };
                        let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    } else {
                        // An absolute-form request: forwarded to the plain origin as an origin-form one.
                        let Ok(mut up) = TcpStream::connect(("127.0.0.1", pport_plain)).await else { return };
                        let rewritten = text.replacen(&first, "GET /echo HTTP/1.1", 1);
                        let _ = up.write_all(rewritten.as_bytes()).await;
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                });
            }
        });
        let proxy = Proxy::new(&format!("http://u:p@127.0.0.1:{pport}"), &format!("http://u:p@127.0.0.1:{pport}"), "");
        let c = client(&origin.ca_pem, proxy);
        // https: a CONNECT to the origin's name, then TLS inside it.
        let d = c.run(spec(Method::GET, format!("https://origin.test:{}/echo", origin.port))).await;
        let d = d.ok().unwrap();
        assert_eq!(text(&d), "GET -  ua=zr-test/1");
        // http: the request line is absolute-form and the proxy's credentials ride in the head.
        let d = c.run(spec(Method::GET, format!("http://origin.test:{}/echo", plain.port))).await.ok().unwrap();
        assert_eq!(d.status, 200);
        let seen = seen.lock().unwrap().clone();
        let auth = format!("proxy-authorization: Basic {}", crate::proxy::base64(b"u:p"));
        assert_eq!(seen[0], format!("CONNECT origin.test:{} HTTP/1.1 | Proxy-Authorization: Basic {}", origin.port, crate::proxy::base64(b"u:p")), "{seen:?}");
        assert!(seen[1].starts_with(&format!("GET http://origin.test:{}/echo HTTP/1.1", plain.port)) && seen[1].ends_with(&auth), "{seen:?}");
        // A proxy that refuses CONNECT is its own error.
        let refuse = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rport = refuse.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = refuse.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                });
            }
        });
        let c = client(&origin.ca_pem, Proxy::new("", &format!("http://127.0.0.1:{rport}"), ""));
        let Err(((code, m), _)) = c.run(spec(Method::GET, "https://origin.test:1/".into())).await else { panic!() };
        assert_eq!(code, Code::Proxy, "{m}");
    }
}
