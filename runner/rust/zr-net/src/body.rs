//! Streaming bodies (docs/rust-net.md, "Streaming (R4)"): a response whose body the caller reads as it
//! arrives, and a request body the caller writes as it is sent, each through a queue of a fixed size
//! (`QUEUE_LIMIT`) so that memory never depends on the size of the body: a full queue stops the
//! reader of the socket (TCP's window does the rest) or tells the writer to wait. Nothing here blocks
//! a thread: the caller waits on the call's descriptor through `std.Io`, which this side writes one
//! byte to (`Wake`) when something it may be waiting for happens.
use crate::client::{Code, Fail};
use http_body_util::Full;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::Notify;

/// The most a queue holds before whoever fills it waits: a chunk more than that may be in flight, and a
/// chunk is at most one read of hyper's (its buffer is at most about 400 KiB).
pub const QUEUE_LIMIT: usize = 1 << 20;

/// The Zig side's end of the call's descriptor.
pub struct Wake(pub socket2::Socket);

impl Wake {
    /// One byte, without blocking and without a signal: a caller that closed its end, or one that
    /// has a full descriptor of unread wakes already, loses nothing.
    pub fn ping(&self) {
        // MSG_NOSIGNAL | MSG_DONTWAIT
        let _ = self.0.send_with_flags(&[1], 0x4000 | 0x40);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// --- the request body ---

/// What a request sends: bytes held, or a body of a known length that the caller writes.
#[derive(Clone)]
pub enum Payload {
    Bytes(Bytes),
    Stream(Arc<UpStream>),
}

impl Payload {
    pub fn len(&self) -> u64 {
        match self {
            Payload::Bytes(b) => b.len() as u64,
            Payload::Stream(s) => s.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_stream(&self) -> bool {
        matches!(self, Payload::Stream(_))
    }

    pub fn body(&self) -> ReqBody {
        match self {
            Payload::Bytes(b) => ReqBody::Bytes(Full::new(b.clone())),
            Payload::Stream(s) => ReqBody::Stream(s.clone()),
        }
    }
}

/// The body type of every request the client sends.
pub enum ReqBody {
    Bytes(Full<Bytes>),
    Stream(Arc<UpStream>),
}

impl Body for ReqBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.get_mut() {
            ReqBody::Bytes(f) => Pin::new(f).poll_frame(cx).map(|o| o.map(|r| r.map_err(|e| match e {}))),
            ReqBody::Stream(s) => s.poll(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ReqBody::Bytes(f) => f.is_end_stream(),
            ReqBody::Stream(s) => s.len == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ReqBody::Bytes(f) => f.size_hint(),
            ReqBody::Stream(s) => SizeHint::with_exact(s.len),
        }
    }
}

struct UpInner {
    q: VecDeque<Bytes>,
    queued: usize,
    pushed: u64,
    taken: u64,
    waker: Option<Waker>,
    /// The call is over (answered, failed or dropped): nothing more is wanted.
    over: bool,
}

/// A request body of `len` bytes that the caller pushes (`push`) and the connection takes.
pub struct UpStream {
    pub len: u64,
    wake: Arc<Wake>,
    inner: Mutex<UpInner>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Push {
    /// This many bytes were queued.
    Took(usize),
    /// The queue is full: wait on the descriptor and push again.
    Full,
    /// The call is over (or the body is complete): stop writing and ask for its result.
    Over,
}

impl UpStream {
    pub fn new(len: u64, wake: Arc<Wake>) -> UpStream {
        UpStream { len, wake, inner: Mutex::new(UpInner { q: VecDeque::new(), queued: 0, pushed: 0, taken: 0, waker: None, over: false }) }
    }

    pub fn push(&self, data: &[u8]) -> Push {
        let mut g = lock(&self.inner);
        if g.over || g.pushed >= self.len {
            return Push::Over;
        }
        let room = QUEUE_LIMIT.saturating_sub(g.queued).min((self.len - g.pushed).min(usize::MAX as u64) as usize);
        let n = room.min(data.len());
        if n == 0 {
            return if data.is_empty() { Push::Took(0) } else { Push::Full };
        }
        g.q.push_back(Bytes::copy_from_slice(&data[..n]));
        g.queued += n;
        g.pushed += n as u64;
        if let Some(w) = g.waker.take() {
            w.wake();
        }
        Push::Took(n)
    }

    /// The call has ended: a connection waiting for more is told it will not come, and the writer's
    /// next push says `Over`.
    pub fn finish(&self) {
        let mut g = lock(&self.inner);
        g.over = true;
        if let Some(w) = g.waker.take() {
            w.wake();
        }
    }

    /// The most the queue held at once (tests).
    #[cfg(test)]
    pub fn queued(&self) -> usize {
        lock(&self.inner).queued
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let mut g = lock(&self.inner);
        if let Some(b) = g.q.pop_front() {
            let before = g.queued;
            g.queued -= b.len();
            g.taken += b.len() as u64;
            drop(g);
            // A writer waiting for room is told once the queue is half empty.
            if before > QUEUE_LIMIT / 2 {
                self.wake.ping();
            }
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        if g.taken >= self.len {
            return Poll::Ready(None);
        }
        if g.over {
            return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the request ended before its body did"))));
        }
        g.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

// --- the response body ---

struct DownInner {
    q: VecDeque<Bytes>,
    queued: usize,
    /// Of the front chunk, already read.
    front: usize,
    end: bool,
    err: Option<Fail>,
    peak: usize,
}

/// A response body that the connection fills (`push`) and the caller reads (`read`).
pub struct DownStream {
    wake: Arc<Wake>,
    space: Notify,
    inner: Mutex<DownInner>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    Data(usize),
    /// Nothing yet: wait on the descriptor.
    Pending,
    End,
    Failed(Code, String),
}

impl DownStream {
    pub fn new(wake: Arc<Wake>) -> DownStream {
        DownStream { wake, space: Notify::new(), inner: Mutex::new(DownInner { q: VecDeque::new(), queued: 0, front: 0, end: false, err: None, peak: 0 }) }
    }

    /// Queues a chunk, waiting while the queue is full.
    pub async fn push(&self, b: Bytes) {
        loop {
            {
                let mut g = lock(&self.inner);
                if g.queued < QUEUE_LIMIT {
                    let was_empty = g.q.is_empty();
                    g.queued += b.len();
                    g.peak = g.peak.max(g.queued);
                    g.q.push_back(b);
                    drop(g);
                    if was_empty {
                        self.wake.ping();
                    }
                    return;
                }
            }
            // A permit stored by a read between the check and here is not lost.
            self.space.notified().await;
        }
    }

    pub fn finish(&self) {
        lock(&self.inner).end = true;
        self.wake.ping();
    }

    pub fn fail(&self, f: Fail) {
        lock(&self.inner).err = Some(f);
        self.wake.ping();
    }

    /// The most the queue held at once.
    pub fn peak(&self) -> usize {
        lock(&self.inner).peak
    }

    pub fn read(&self, out: &mut [u8]) -> Read {
        let mut g = lock(&self.inner);
        if g.q.is_empty() {
            if let Some((c, m)) = &g.err {
                return Read::Failed(*c, m.clone());
            }
            return if g.end { Read::End } else { Read::Pending };
        }
        let mut n = 0;
        while n < out.len() {
            let front = g.front;
            let Some(chunk) = g.q.front() else { break };
            let take = (chunk.len() - front).min(out.len() - n);
            out[n..n + take].copy_from_slice(&chunk[front..front + take]);
            n += take;
            let done = front + take == chunk.len();
            if done {
                g.front = 0;
                g.q.pop_front();
            } else {
                g.front += take;
            }
        }
        g.queued -= n;
        drop(g);
        self.space.notify_one();
        Read::Data(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wake() -> Arc<Wake> {
        let (a, _b) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        Arc::new(Wake(a))
    }

    #[test]
    fn a_queue_reads_what_was_pushed_in_pieces_and_ends_after_its_data() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let d = DownStream::new(wake());
        rt.block_on(async {
            d.push(Bytes::from_static(b"hello ")).await;
            d.push(Bytes::from_static(b"world")).await;
        });
        d.finish();
        let mut b = [0u8; 4];
        let mut got = Vec::new();
        while let Read::Data(n) = d.read(&mut b) {
            got.extend_from_slice(&b[..n]);
        }
        assert_eq!(got, b"hello world");
        assert_eq!(d.read(&mut b), Read::End);
    }

    #[test]
    fn an_error_comes_after_the_data_that_preceded_it() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let d = DownStream::new(wake());
        rt.block_on(d.push(Bytes::from_static(b"abc")));
        d.fail((Code::Io, "reset".into()));
        let mut b = [0u8; 8];
        assert_eq!(d.read(&mut b), Read::Data(3));
        assert_eq!(d.read(&mut b), Read::Failed(Code::Io, "reset".into()));
    }

    #[test]
    fn an_upload_queue_takes_what_fits_and_says_full_and_over() {
        let u = UpStream::new((QUEUE_LIMIT + 10) as u64, wake());
        let data = vec![7u8; QUEUE_LIMIT + 10];
        assert_eq!(u.push(&data), Push::Took(QUEUE_LIMIT));
        assert_eq!(u.push(&data[..10]), Push::Full);
        assert_eq!(u.queued(), QUEUE_LIMIT);
        u.finish();
        assert_eq!(u.push(&data[..10]), Push::Over);
    }
}
