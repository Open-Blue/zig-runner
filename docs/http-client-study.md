# Should the runner replace std.http.Client? (study, 2026-11-13)

Branch `perf/http-client-study`, harness in `bench/http-client/`. Nothing here touches the runner's code.
Question: replace std's HTTP client for GitHub/Gitea calls with a Rust or C client that has per-phase hooks, and is it faster?
Also (scope addition): could the same TLS stack serve `pg.zig`, so the runner carries one?

## Answer in four lines

1. Not faster where it matters. Warm requests (what the runner mostly does: long-poll, uploads) are as fast or faster on std
   (p50 80-170 us vs curl 114-220, hyper 146-230). Only new connections differ (hyper ~3x quicker than std's TLS), and against
   GitHub a handshake is 60-100 ms of network, so 2 ms of crypto is noise.
2. A real, cheap win was found instead: **std never sets TCP_NODELAY**. A new TLS connection to a peer that does not speak
   right after our Finished stalls ~40 ms (Nagle vs delayed ACK): cold request p50 45 ms -> 2.2 ms with one setsockopt, applied
   in the Io wrapper `net_hooks.zig` already has (`netConnectIp`). Against api.github.com 4 samples showed no stall
   (std 178 ms vs 159 ms with nodelay: RTT noise), so GitHub's gain is unproven; Gitea/Forgejo behind other proxies, and
   local servers, can hit it.
3. Hooks: libcurl gives exact phases for free; hyper can with ~60 lines (resolver + two timing layers); std's hooks are
   exact for connect, approximate for DNS and TLS (as PR #530 documents). Exactness alone is not worth a second HTTP stack.
4. Recommendation: **keep std for HTTP now, add TCP_NODELAY.** If one TLS stack is the goal, a sans-IO rustls shim (prototyped,
   mTLS works, both arches) can replace tls.zig for pg; do it only together with a decision to move HTTP to hyper.

## Measurements (local TLS server, Go net/http, TLS 1.3, ECDSA P-256, 2 KiB body; client and server on cowbird)

Cowbird balanced profile, load average 2.9-5 on 12 cores (other work running: numbers are noisy, 3 repetitions shown as ranges;
`bench/http-client/results.txt` has every run). latency in us from request start to body end; cpu = user+sys of the process.

| mode | client | p50 us | p99 us | cpu ms | RSS MB |
|---|---|---|---|---|---|
| warm, 1 conn, 2000 req | std | 83-170 | 164-329 | 114-196 | 2.3 |
| | std + nodelay | 79-132 | 160-304 | 107-192 | 2.3 |
| | libcurl 8.18 (OpenSSL) h1 | 114-221 | 294-391 | 159-266 | 13.7 |
| | hyper 1.12 + rustls (ring) h1 | 146-200 | 308-416 | 218-288 | 5.2 |
| | libcurl h2 / hyper h2 | 258-488 / 199-384 | 547-627 / 445-516 | 295-501 / 277-458 | 13.8 / 5.2 |
| cold, new conn each, 300 req | std | **45000-46000** | 47000-60000 | 1127-1372 | 2.7 |
| | std + nodelay | 2205-3305 | 3916-6416 | 574-816 | 2.9 |
| | libcurl | 1606-2124 | 3043-19222 | 389-801 | 13.8 |
| | hyper (tcp 150 us, tls 620 us, dns 87 us) | 742-1087 | 1202-2075 | 173-258 | 5.3 |
| conc 16 workers, 3200 req, h1 | std | 516-626 | 2358-3928 | 456-508 | 11.4 |
| | std + nodelay | 519-624 | 2117-2887 | 426-482 | 11.4 |
| | libcurl (multi) | 892-1120 | 4497-6686 | 248-353 | 15.4 |
| | hyper (2 worker threads) | 326-350 | 1299-1715 | 154-160 | 6.2 |
| conc 16, h2 multiplexed | libcurl / hyper | 1323-1575 / 671-758 | 2578-2868 / 1593-2064 | 300-361 / 159-194 | 15.8 / 5.7 |

Throughput under 16-way concurrency (wall for 3200 req): hyper 80 ms, std 190-213 ms, curl 243-347 ms. h2 is slower than h1 here
(one connection, one core's worth of crypto) and the runner talks to GitHub mostly one request at a time, so h2 buys nothing now.
std's per-connection memory is ~0.6 MB (16 conns = +9 MB), hyper ~0.07 MB, curl ~0.1 MB; curl's 13 MB base is OpenSSL + libcurl init.

api.github.com/zen, unauthenticated, 4 cold and 5 warm requests each (`results-github.txt`; ~25 of the 60/h limit used):
cold std 178 ms p50, std+nodelay 159, curl 94 (its phases: dns 7, tcp 34, tls 63 cumulative = 63 ms of handshake), warm std ~21-30 ms.
Too few samples to rank; the lesson is the scale (tens of ms of network vs ~1-3 ms of client). The hyper row there is invalid:
no User-Agent was sent, so GitHub answered 403 (all 9 "fails"). The runner sets its own.

## Candidates

| | std (as is) | libcurl (C) | hyper + hyper-util + rustls (Rust) |
|---|---|---|---|
| per-phase timing | connect exact; DNS approximate and TLS inferred (net_hooks wrap); no first-byte hook (head time known, send time not) | all exact: NAMELOOKUP, CONNECT, APPCONNECT, PRETRANSFER, STARTTRANSFER, plus NUM_CONNECTS/CONN_ID for reuse | DNS exact (custom `Resolve` service), TCP = inner connector minus DNS, TLS = outer minus inner (prototype, 60 lines); first byte = own timer around the request future; `HttpInfo`/`Connected` extensions per connection |
| reuse / HTTP/2 | h1 keep-alive pool, no h2 (and the pool-stale-clock problem `http.zig renew` works around: std fixes `now` at first TLS use) | pool + h2 multiplexing via nghttp2 | pool + h2 (hyper-util legacy client) |
| websocket (feed) | feed.zig upgrades a std request by hand | `CURLOPT_CONNECT_ONLY=2` + `curl_ws_send/recv` (still marked experimental in some builds: verify before relying) | `hyper::upgrade` yields the raw IO; framing in Zig (as now) or a crate |
| proxy / CA | `Client.http_proxy`/`https_proxy` fields; CA from fixed system paths only, **no SSL_CERT_FILE/CAINFO**, no custom CA (my bench had to inject into `ca_bundle`) | env proxies (`HTTPS_PROXY`, `NO_PROXY`), `CURLOPT_CAINFO`/CAPATH, system store | rustls needs roots passed in: Zig reads the PEM bundle (one loader shared with pg), proxy = connector layer to write (hyper-util has a proxy connector but extra dependency) |
| static musl, both arches | n/a | only with a TLS backend compiled for musl (OpenSSL, mbedTLS or wolfSSL via zig cc) and nghttp2, zlib: **not built here**, headers+.so only; most work of the three | **built**: x86_64 and aarch64 `-musl` via `zig cc` as CC and linker (wrapper drops `--target=`, `--fix-cortex-a53-843419`; `-C link-self-contained=no`), static ELF; staticlib needs `-lc -lunwind` at the Zig link |
| size added | est. 0.8-1.5 MB with mbedTLS, 3+ MB with OpenSSL (estimate) | | whole bench exe 2.34 MB (x86_64) / 2.0 MB (aarch64), stripped, with tokio, h1+h2, ring; as a staticlib in a Zig exe ~1.2-1.4 MB (tls shim only) |
| build time / CI | seconds | build curl+TLS from source per arch: not measured, minutes | cold `cargo build --release` 39 s (glibc), 29-39 s each musl arch on 12 cores; needs rustup + 2 targets in CI, cached `~/.cargo`; one more toolchain beside Zig and Go |
| cancellation / timeouts | native std.Io (`http.within` cancels blocked reads) | blocking easy handle on a thread: cancel by `CURLOPT_XFERINFOFUNCTION` returning nonzero or wakeup of multi; does not compose with std.Io | tokio futures: drop to cancel, but a second scheduler (2+ threads) beside std.Io; timeouts per request easy; bridging = a thread + channel per call, or an eventfd-woken Zig future |
| memory / conn | ~0.6 MB (TLS buffers) | ~0.1 MB | ~0.07 MB |
| FFI surface | none | wide API, but the easy/multi subset is ~15 calls and stable for 20 years; callbacks (write, xferinfo) need `callconv(.c)` shims | none exists: we design a C ABI over a tokio runtime: submit(request) -> id, poll/wait fd or callback, result struct with timings, cancel(id), plus the websocket upgrade; ~10 functions and ownership rules for buffers; panics must be `abort` |
| extra risk | stale-clock renew hack stays | CVE flow of a big C library, backend divergence | Rust panics across FFI, tokio threads under `ProcessCgroup`/seccomp, two allocators |

Others considered, not built: `ureq` (sync Rust, no runtime, easy cancellation by closing the fd, no per-phase hooks, no h2),
`reqwest` (hyper plus much more; its `dns_resolver` hook is the same resolver hook as the prototype, bigger binary),
libcurl with rustls backend (smaller TLS than OpenSSL but more build complexity), BoringSSL/h2o-style stacks (too big),
and **keeping Zig end-to-end with ianic's tls.zig** (already linked for pg, supports client certificates and TLS 1.3): an HTTP/1.1
layer of ~400 lines on top of it would give exact phase hooks, SSL_CERT_FILE, one TLS stack, native std.Io cancellation and no new toolchain.
Its handshake speed is not measured here (it is Zig crypto like std's, so expect std-like handshake CPU, 2-3 ms).
This is the option I would study next if the one-stack goal stays.

## pg.zig TLS: can the same stack serve it?

pg.zig upgrades after a plaintext SSLRequest on the same socket and holds std.Io readers/writers. libcurl is out: it owns the
socket (`CURLOPT_CONNECT_ONLY` with `CURLOPT_USE_SSL` cannot start from an existing fd after the app wrote protocol bytes; the only
fit is `CURLOPT_OPENSOCKETFUNCTION` + a non-TLS handshake, not supported for pg's SSLRequest). hyper is out for the same reason
(it speaks HTTP). **rustls itself fits well in sans-IO form**, prototyped in `bench/http-client/tls-ffi/` (`src/lib.rs`, 10 C functions:
`zr_tls_new`, `zr_tls_take_cipher`, `zr_tls_give_cipher`, `zr_tls_read`, `zr_tls_write`, `zr_tls_wants_write`, `zr_tls_is_handshaking`,
`zr_tls_close_notify`, `zr_tls_free`) and driven from Zig in `bench/http-client/tls_ffi_test.zig`:

- Zig keeps the socket and cancellation; the shim only moves bytes (no threads, no I/O, no tokio). The SSLRequest/'S' exchange stays
  exactly where it is, then pg.zig swaps its reader/writer for ones that call take_cipher/give_cipher (what `tls.Connection.Reader/Writer`
  do now). pg's protocol code does not change.
- Client certificates: tested against a Go server with `RequireAndVerifyClientCert` (port 8445): with `client.pem` + key the request
  returns `200`; without, the handshake fails with `TlsError` (the alert), as pg.zig needs for Tiger Data. ECDSA keys worked; PKCS8/SEC1 PEM accepted
  by `rustls_pemfile::private_key`. RSA client keys not tested.
- CA bundle: the shim takes PEM bytes; the same Zig loader (system bundle, `SSL_CERT_FILE`, a configured file) would feed pg and the HTTP side.
  Certificate checking uses rustls-webpki, stricter than std (it rejected an openssl `-x509` self-signed CA-flagged leaf with `CaUsedAsEndEntity`,
  which std and curl accepted): good, but test every user's private CA.
- Cost: `libzrtls.a` 10.1-11.8 MB (before dead-stripping) and +1.2-1.4 MB in a stripped static musl Zig exe on both arches (built; aarch64 not run,
  no qemu here), a cargo build (~20 s per target) in `build.zig`/CI, `-lc -lunwind`. tls.zig today: a pinned git dependency, no toolchain.
- Verdict: technically a clean replacement, but it trades a small pure-Zig dependency for a Rust toolchain and ~1.3 MB. It earns that only if
  HTTP moves to hyper/rustls too; otherwise pg should stay on tls.zig.

## Recommendation

1. Now (tiny PR, minor-version bump as every PR): set TCP_NODELAY in `net_hooks.zig`'s `connect` wrapper (and anywhere else the Io is
   unwrapped: `zig_release.zig`, the feed's local client), with a test that a cold connection to a local Nagle-sensitive server takes ms, not 40 ms.
   Move the wrap out of the "request log only" role so it is always on.
2. Keep std for HTTP. Keep PR #530's approximate phases; if exactness for DNS/TLS is wanted, patch std's hook points (std is not untouchable)
   or add a first-byte timestamp in `http.zig`, not a second client.
3. For the one-TLS-stack goal, study next: an HTTP/1.1 layer over tls.zig (pure Zig, one stack, exact hooks). Only if that disappoints
   (handshake CPU on the Pi, h2 need), move to hyper+rustls with the plan below.
4. Do not pick libcurl: widest FFI, hardest static build, no memory or speed edge, wrong cancellation model.

## Migration plan if hyper/rustls is chosen later (order of call sites, safest first)

1. `pg.zig` TLS through the sans-IO shim (self-contained, tested, reversible with a build flag `-Dtls=rustls`).
2. `auth.zig`/`app.zig` `http.fetch` (GitHub App/OAuth): short, no keep-alive needs, no websocket; a blocking `zr_fetch` first.
3. `zig_release.zig` downloads and `results.zig` uploads (large bodies: streaming callbacks; compare CPU on the Pi).
4. `runservice.zig`, then `broker.zig` long-poll (cancellation and the 17-minute dead-connection lesson of #100: keep `http.within`
   semantics via eventfd + cancel(id), and TCP keepalive options on the connector).
5. `feed.zig` websocket last (`hyper::upgrade` or keep framing in Zig over a raw upgraded stream).
Gate each step on the repo's smoke test on the laptop pool and razorbill (arm64, SD card) before the next.

## Risks

- Rust panics across FFI (set `panic=abort`), double allocators and RSS accounting (`proc_stats.heap` sees only Zig's), tokio threads inside job cgroups.
- A third toolchain in CI and the release build (`build-binaries.sh`): rustup, two musl targets, the zig-cc linker wrapper above (fragile flags).
- Merge with the other agent's `build.zig` C-library work: both would add link inputs (`-lc`, `-lunwind` for Rust staticlibs; check duplicate libc/compiler-rt symbols).
- rustls strictness may reject certificates std accepted (private CAs); no `SSL_CERT_FILE` in std today either, so behavior must be specified.
- Benchmarks are loopback and noisy (load avg 3-5); aarch64 and Pi numbers were not taken; GitHub samples are tiny.
- Unmeasured: libcurl static size/build time, tls.zig handshake speed, 24-hour memory growth of any candidate.
