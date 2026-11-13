// hyper + hyper-util + hyper-rustls benchmark with per-phase hooks:
// bench_hyper <url> <warm|cold|conc> <n> [workers] [h2]
// Phases: DNS (custom resolver), TCP connect (inner HttpConnector minus DNS), TLS (outer minus inner).
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::{dns::Name, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

static DNS_NS: AtomicU64 = AtomicU64::new(0);
static TCP_NS: AtomicU64 = AtomicU64::new(0); // dns+tcp (inner connector)
static ALL_NS: AtomicU64 = AtomicU64::new(0); // dns+tcp+tls (outer)
static CONNS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct TimedResolver;
impl tower_service::Service<Name> for TimedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
    fn call(&mut self, name: Name) -> Self::Future {
        Box::pin(async move {
            let t = Instant::now();
            let r = tokio::task::spawn_blocking(move || (name.as_str(), 0).to_socket_addrs()).await.unwrap();
            DNS_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
            r
        })
    }
}

#[derive(Clone)]
struct Timed<S>(S, &'static AtomicU64);
impl<S, R> tower_service::Service<R> for Timed<S>
where S: tower_service::Service<R> + Clone + Send + 'static, S::Future: Send + 'static, R: Send + 'static {
    type Response = S::Response; type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;
    fn poll_ready(&mut self, c: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { self.0.poll_ready(c) }
    fn call(&mut self, r: R) -> Self::Future {
        let f = self.0.call(r); let a = self.1;
        Box::pin(async move { let t = Instant::now(); let o = f.await; a.fetch_add(t.elapsed().as_nanos() as u64, Relaxed); o })
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (url, mode, n) = (a[1].clone(), a[2].clone(), a[3].parse::<usize>().unwrap());
    let workers: usize = a.get(4).map(|s| s.parse().unwrap()).unwrap_or(1);
    let h2 = a.len() > 5;
    let host: String = a[1].split("//").nth(1).unwrap().split(|c| c == '/' || c == ':').next().unwrap().to_string();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async move {
        let mut roots = rustls::RootCertStore::empty();
        let pem = std::fs::read(std::env::var("CA_FILE").unwrap_or("/home/lement/projects/zig-runner-http-client/bench/http-client/certs/cert.pem".into())).unwrap();
        for c in rustls_pemfile::certs(&mut &pem[..]) { roots.add(c.unwrap()).unwrap(); }
        let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let mut http = HttpConnector::new_with_resolver(TimedResolver);
        http.enforce_http(false);
        http.set_nodelay(true);
        let inner = Timed(http, &TCP_NS);
        let b = HttpsConnectorBuilder::new().with_tls_config(cfg).https_only().with_server_name_resolver(
            hyper_rustls::FixedServerNameResolver::new(host.clone().try_into().unwrap()));
        let https = if h2 { b.enable_all_versions().wrap_connector(inner) } else { b.enable_http1().wrap_connector(inner) };
        let https = Timed(https, &ALL_NS);
        let mut cb = Client::builder(TokioExecutor::new());
        if mode == "cold" { cb.pool_max_idle_per_host(0); }
        let client = Arc::new(cb.build::<_, Empty<Bytes>>(https));
        let uri: hyper::Uri = url.parse().unwrap();
        let once = |c: Arc<_>, u: hyper::Uri| async move {
            let t = Instant::now();
            let c: Arc<Client<_, Empty<Bytes>>> = c;
            let r = c.get(u).await.unwrap();
            let ok = r.status().is_success();
            let _ = r.into_body().collect().await.unwrap();
            (t.elapsed().as_nanos() as u64, ok)
        };
        let t0 = Instant::now();
        let mut lat: Vec<u64> = Vec::new(); let mut fails = 0;
        if mode == "conc" {
            let per = n / workers; let mut hs = vec![];
            for _ in 0..workers { let c = client.clone(); let u = uri.clone();
                hs.push(tokio::spawn(async move { let mut v = vec![]; for _ in 0..per { v.push(once(c.clone(), u.clone()).await); } v })); }
            for h in hs { for (l, ok) in h.await.unwrap() { lat.push(l); if !ok { fails += 1; } } }
        } else {
            for _ in 0..n { let (l, ok) = once(client.clone(), uri.clone()).await; lat.push(l); if !ok { fails += 1; } }
        }
        let wall = t0.elapsed();
        lat.sort(); let m = lat.len(); let mean = lat.iter().sum::<u64>() / m as u64;
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let cpu = (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000 + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1000;
        print!("hyper{} {} n={} p50={} p99={} mean={} wall_ms={} cpu_ms={} rss_kb={} fails={}", if h2 {"-h2"} else {""}, mode, m,
            lat[m/2]/1000, lat[m*99/100]/1000, mean/1000, wall.as_millis(), cpu, ru.ru_maxrss, fails);
        let conns = ALL_NS.load(Relaxed); let _ = CONNS.load(Relaxed);
        if mode == "cold" {
            let (d, t, all) = (DNS_NS.load(Relaxed), TCP_NS.load(Relaxed), conns);
            print!(" phases_us[dns,tcp,tls]={},{},{}", d/m as u64/1000, (t-d)/m as u64/1000, (all-t)/m as u64/1000);
        }
        println!();
    });
}
