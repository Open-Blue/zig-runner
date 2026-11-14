# One network stack in Rust (design)

Status: R1 (build, skeleton, ABI smoke test) is in this pull request; R2 to R6 follow, each after review.
Origin: the HTTP client study (`docs/http-client-study.md` on `perf/http-client-study`, 2026-11-13) and the user's decision
to move all of the runner's HTTP, the live WebSocket feed and the database's TLS to Rust (hyper + rustls), so that the
runner has **one network and TLS stack with real hooks and no shims**: no `net_hooks.zig` wrapper around `std.Io`, no
retired-client list, no stale-clock `renew`, no second TLS implementation for Postgres.

## Decisions that need the user first

1. **The runner links musl from R1 on.** Everything below depends on it. See "libc" (next section): +0.77 MB (+17%) on
   x86_64 and +0.47 MB (+12%) on aarch64 for the skeleton alone, with the runner's startup and hardening unchanged, and the
   full stack will add about 1.3-1.5 MB more. The alternative, a Rust that links no libc, does not exist for tokio and
   rustls. If this is not acceptable, the series stops here, before R2.
2. The runtime's threads (2 by default) live in the runner's own cgroup and are never in a job's. Confirmed by how the
   runner places processes ("Threads and cgroups"). Nothing to decide, but it constrains where the runtime may start.
3. The std client stays as an oracle (tests only) until R6, then goes. Between R3 and R6 the runner carries both stacks
   in the binary (the std one is dead code in production but compiled).
4. Toolchain policy: Rust 1.99.1 pinned, unpacked without rustup from checksummed tarballs (`install-rust.sh`), about
   1 GB on disk and 45 s on first use per machine (the Pi included: see "Build"). A self-hosted runner must be able to
   afford that once.
5. TLS provider: `ring` (built by `zig cc`, used by the study) rather than `aws-lc-rs` (needs cmake and more C).
   ring is x86_64/aarch64 only, which is the runner's whole target list ("Linux only").

## The libc question

The runner links no libc today (`std.os.linux` syscalls, Zig's `std.Io`, the vendored C of #532/#533 compiled
`-ffreestanding` with a shim directory in place of headers). Rust's standard library on `*-unknown-linux-musl` calls libc
(`pthread_create`, `malloc`, `getaddrinfo`, `epoll_*`...), and tokio is built on std. A `#![no_std]` network stack would
mean giving up tokio, hyper's runtime glue, and `std::net`; not an option.

What R1 does: `runner/build.zig` sets `link_libc = true` on the runner module and links `libunwind`, both Zig's bundled
(musl built from source by Zig and cached: no system libc and no cross toolchain). The Rust
staticlib is an ordinary archive (`libzr_net.a`) added as a link object. Rust is built with `panic = "abort"`, but its
precompiled `std` still references `_Unwind_*`, hence `-lunwind`.

Alignment with #532 and #533: they compile their C with `-ffreestanding` and need no libc; that stays valid with libc
linked (freestanding C does not call it), and the new link inputs are additive: `zig_zr_net_args` appends `-lc -lunwind
libzr_net.a` to `modules`, after their `libzstd_args`/`libzlibng_args`. Both PRs edit the same `modules=(...)` line in
`.github/scripts/zig-modules.sh` and add `zig_target_arch` (R1 carries the same text, so Git merges it without conflict
if their function is byte for byte identical; whoever lands second resolves the one `modules=` line). `build.zig` gets
`addZrNet` next to their `addLibzstd`/`addLibzlibng`. Nothing in their flags needs to change. The one thing to watch
is symbol clashes between zlib-ng/zstd (`ZSTD_*`, `zng_*`) and musl or Rust: none seen, since their names are prefixed.

Measured (cowbird, Zig 0.17.0, `-Doptimize=ReleaseSafe -Dstrip`, static PIE, `zig build` and `build-binaries.sh` produce
byte-identical x86_64 binaries):

| binary | x86_64 | aarch64 |
|---|---|---|
| main (no libc) | 4,444,720 | 3,798,352 |
| R1 as merged here (libc + unwind + archive linked, runtime not yet called from the runner) | 5,062,392 (+618 KB, +13.9%) | 4,270,080 (+472 KB, +12.4%) |
| libc only, no Rust archive (variant) | 4,718,440 (+274 KB, +6.2%) | not built |
| R1 plus the runner calling `start`/`stop` (the tokio skeleton fully linked, variant for R2) | 5,214,712 (+770 KB, +17.3%) | not built |

The libc alone is +274 KB (musl's code that Zig's start-up, `std.Io`'s threads and `std.c` paths now pull in). Rust std
and tokio are the rest. The full stack (hyper, h2, rustls, ring, webpki, tungstenite) was measured in the study at
+1.2-1.4 MB as a stripped staticlib in a static musl Zig executable for the TLS shim alone; expect the final binary near
6.5-7 MB on x86_64.

Startup: `runner --version` p50 1.93 ms (main), 1.18 ms (libc, no archive), 1.13 ms (tokio skeleton called): no regression
(300 runs each; the difference is noise and musl's smaller relocation work). Peak RSS of that command 1.6 MB, 1.3 MB, 1.7 MB.
Hardening (`checksec.sh`: static PIE, full RELRO, NX, W^X) still passes on the libc build.

Behaviour changes to know about, none of which is a deliberate decision of this series:

- **`std.Io`'s syscall layer.** With libc linked, `std` routes its POSIX wrappers through musl (`std.c.*`) instead of raw
  `std.os.linux` syscalls (errno via libc, `pread`/`openat` wrappers, thread creation via `pthread_create`). This is the
  largest change to code that has been exercised only without libc. The oracle is the test suite, run with libc linked:
  see "Validation". R1's CI run is that evidence: every existing test now runs on the libc build.
- **Direct `clone`/`unshare`/`vfork` in the native backend** (`native/sandbox.zig`, `cgroup.zig`, `net.zig`) use
  `std.os.linux` raw syscalls, which stay raw. A raw `clone` in a process with musl bypasses musl's bookkeeping (cached
  thread id, atfork handlers, malloc locks). That is safe only because every such child either execs or runs
  async-signal-safe code; the runtime must therefore never be started before one of those forks, and must not
  be started in the `native-step`, `userns` and health helper subcommands. Rule: the runtime starts lazily on the first
  network call, which none of those helpers makes (R3 adds a test that the helper subcommands never load it).
- **Allocator.** Zig's `smp_allocator` and `page_allocator` are unchanged. Rust allocates with musl's `malloc`
  (mallocng): a second heap. `proc_stats.heap` sees only Zig's, as the study warned. R2 adds a counter for Rust's
  allocations through a `#[global_allocator]` wrapper reporting bytes in use over the ABI, so RSS accounting stays honest.
- **Signals and `abort`.** `panic = "abort"` calls musl's `abort()` (SIGABRT): the runner dies, and its service manager
  restarts it; the job in flight is lost as with any crash, which is the behaviour a Zig panic already has.
- **TSan**: see "Validation".

**CI's tests now build for musl too.** Until R1, `zig test` and `zig build test` used the machine's own libc setting (native: no libc, so
nothing to mismatch). With a musl-built Rust archive in a binary linked against the host's **glibc**, 36 tests failed (`Thread.spawn` with a 256 KiB stack
returned EINVAL, `unreachable` in std, in `native/Store.zig`'s sync threads): two libcs in one process. So `zig-modules.sh` adds
`-target native-native-musl` (the machine's CPU and OS, musl ABI) when a caller gives no target, and `build.zig`'s default target has `abi = .musl`;
the tests then run what ships. With that: the whole non-root suite on cowbird is 1038 passed, 139 skipped, 0 failed (the native backend's tests skip here:
user namespaces are refused by AppArmor on this laptop; they are CI's `Native tests as root` job's to run on the libc build, and that run is the real
evidence for the `clone`-related point below).

Not required and not planned: switching Zig's own allocator to `c_allocator`, using libc's `getaddrinfo` from Zig, or
using glibc. Rust's resolver call is `getaddrinfo` in musl (blocking, on a runtime blocking thread); it honours
`/etc/resolv.conf` and `/etc/hosts` like the std client's own lookup, with musl's behaviour (no `nsswitch`, queries
all nameservers in parallel). The study measured DNS at 87 us on loopback; see "Hooks" for how it is timed exactly.

## Crate layout

```
runner/rust/
  rust-toolchain.toml      Rust 1.99.1, both musl targets (what rustup follows on a developer's machine)
  deny.toml                cargo-deny: licenses, advisories, sources, bans
  zr-net/
    Cargo.toml, Cargo.lock   (lock committed; builds are --locked)
    src/lib.rs             the C ABI, nothing else; every export is a thin wrapper
    src/runtime.rs         the one tokio runtime
    (R2) src/tls.rs        sans-IO rustls for Postgres
    (R3) src/client.rs     hyper client, pool, resolver and timing layers; src/proxy.rs; src/roots.rs
    (R4) src/body.rs       streaming bodies
    (R6) src/ws.rs         WebSocket
runner/src/zr_net.zig      the Zig side: externs, error mapping, typed wrappers; the only file with `extern fn`
```

One crate, `staticlib` (for Zig) and `rlib` (for `cargo test`). No workspace until a second crate earns it. Names:
every export is `zr_net_*`; no Rust type, `Vec`, `String` or `Result` crosses; Zig never frees Rust memory itself
(it calls the matching `zr_net_*_free`) and Rust never frees Zig's. Release profile: `opt-level = "s"`, `lto = true`,
`codegen-units = 1`, `strip`, `panic = "abort"` (the study's profile; R3 measures `s` against `3` on the Pi with
the request benchmark before settling).

### ABI rules

- C types only: `u8`/`u32`/`i64`/`usize`, `*const u8` + length pairs (never NUL-terminated input), opaque handles
  (`*mut Client`, `*mut Request`, `*mut Tls`, `*mut Ws`: declared `opaque {}` in Zig).
- A handle has one owner and one `free`; `free` on a handle with work in flight cancels it first and returns after
  the Rust side has stopped using any Zig-provided buffer.
- Results are small structs (`extern struct`, `#[repr(C)]`, explicit sizes, versioned by a `size` first field so
  fields append without breaking), filled by Rust into caller memory; strings returned by Rust (error text) are
  copied into a caller buffer.
- Callbacks into Zig exist in one shape only: "wake" (an eventfd write, below), so Rust never runs Zig code and Zig
  code never needs to be reentrant from a tokio thread. Body data moves by explicit read/write calls on handles.
- `zr_net_version()` is compared with the version Zig was built for at runtime start: a mismatched archive is a
  build mistake that aborts at startup with the two versions printed.
- Every export is `catch_unwind`-free by design: the profile is `panic = "abort"`, so a panic ends the process
  (see "libc" on signals) instead of unwinding across the boundary.

### Error mapping

Rust returns negative `i32` codes from one `#[repr(i32)]` enum (`ZrError`) and, for details, writes a short UTF-8 message
into a caller buffer. `zr_net.zig` maps them to Zig error sets that match what call sites handle today:
`Dns`, `ConnectionRefused`, `ConnectionTimedOut`, `ConnectionReset`, `TlsCertificate` (unknown issuer, expired, name
mismatch, each with its text), `TlsHandshake`, `Timeout`, `Canceled`, `TooManyRedirects`, `BodyTooLarge`,
`Protocol` (HTTP framing), `Proxy`, `Io(errno)`, `Internal`. `http.staleClock` disappears with the renew machinery
(rustls takes the time per handshake, from `SystemTime`, never from a client created earlier).

## Threading and the runtime

- **One runtime per process**, `Builder::new_multi_thread`, worker threads named `zr-net` (visible in `ps -L`,
  `/proc/*/comm`), **2 workers by default** (the study's concurrency bench: 2 workers served 16 concurrent connections
  at 80 ms for 3200 requests, faster than std). Configurable through `RUNNER_NET_THREADS` and a
  config field later; the runner on a Pi 4 uses 2. `max_blocking_threads` is capped at 4 (getaddrinfo only).
- **Started lazily** by the first network call (`zr_net_runtime_start` is idempotent and thread-safe), **stopped at
  exit** by `zr_net_runtime_stop` from the runner's shutdown path, which drops the runtime, cancels all tasks and
  joins workers (5 s timeout, then abandoned: the process is exiting). Tests start and stop it repeatedly (R1's test
  does).
- **Never in a forked child that does not exec.** See "libc".

### How a Zig caller waits through `std.Io`

Each request handle owns an **eventfd** (one per in-flight request, from a free list; 8 bytes of kernel state).
Rust writes to it when the request's state changes (headers ready, body chunk available, finished, error). The Zig
side waits for it with `io`'s own readiness primitive (`std.Io` poll/`await` on that fd, so the waiting thread is
cancelable by `std.Io` like any blocked read), then asks the handle what happened (`zr_net_poll`) and loops. A Zig
fiber/thread therefore blocks exactly where it blocks today, and `http.within`'s semantics are kept: the deadline and
the cancel watch work on the wait, not inside Rust.

- **Cancellation.** When the Zig wait returns `error.Canceled`, `zr_net_request_cancel(handle)` is called (it is also
  what `free` does): Rust drops the request future, which closes the connection (or, on h2, resets the stream). No
  Rust code needs to know about `std.Io`: the cancel is a plain function. The call is safe from any thread and
  idempotent. A dropped future cannot leave a half-written body: the connection is not returned to the pool.
- **Timeouts.** Four, all Rust-side so they are exact and uniform: connect (default 10 s), TLS handshake (10 s),
  time to first byte after the request is sent (per call, as `http.within`'s deadline is now), and idle between body
  chunks (read timeout, per call). The total deadline stays in Zig's `within` (it already covers everything and cancels).
  TCP keepalive (idle 30 s, interval 10 s, 3 probes) and `TCP_USER_TIMEOUT` are set by the connector with
  `socket2`, replacing `http.keepAlive`; that is the #100 lesson (a dead connection hung 17 minutes). `TCP_NODELAY` is always set.
- **Backpressure.** Request/response bodies move through a bounded `tokio::sync::mpsc` channel (depth 4 chunks of 64 KiB)
  per direction, so a slow disk stalls the socket, not memory.

### Threads and cgroups

The runner places a *process*, not itself, in a job's cgroup: `sandbox.joinCgroup` writes `0` to `cgroup.procs` in the
step helper (`native-step`), a child of the runner, and `cgroup.zig` creates job leaves under the runner's own cgroup and
moves job pids there. The runner's threads, tokio's included, are created from the runner process and stay in its own
cgroup (`/runner`); they cannot enter a job's cgroup unless the runner process itself is moved, which nothing does. A fork of the
runner copies only the calling thread, so a forked helper never contains tokio workers. Consequence: network time is
accounted to the runner, as the std client's is. Two rules keep that true: the runtime never starts inside a helper
subcommand, and no code calls `joinCgroup` in the runner's main process (a check in R3's tests: `/proc/self/task/*/cgroup`
of every thread equals the runner's cgroup after a request).

## Hooks: the `request:` line (PR #530)

The Rust client must produce the same line as #530's `net_hooks.zig`, with exact numbers. hyper-util's `legacy::Client` +
a custom connector gives all of them, as the study's bench showed (60 lines):

| field | measured where |
|---|---|
| `dns` | a custom `Resolve` service: time around `getaddrinfo` (cached: 0 when the host's addresses are reused on a pooled connection) |
| `connect` | the inner `TcpStream::connect` future, minus nothing (DNS is outside it): exact; `TCP_NODELAY`, keepalive and `TCP_USER_TIMEOUT` are set on the socket here |
| `tls` | the TLS wrapper layer minus the inner connect: handshake only, exact; resumed sessions are marked `resumed` |
| `ttfb` | from the request being fully written to the response head parsed: a timer around hyper's `send_request` future |
| `reused` | hyper-util's `Connected`/`HttpInfo` extension: whether the connection came from the pool |
| `bytes` in/out, `status`, `http` version | from the response and the body wrapper's counters |

The same function formats the line from a `Timings` struct that Rust fills (`zr_net_request_timings`); #530's formatting
stays in Zig so the line is identical byte for byte (R3 shares #530's golden test of the format, and a server that
delays each phase by a known amount, asserting each reported phase within 20% of the delay). The approximations #530
documents (DNS approximate, TLS inferred) go away with the wrapper.

## HTTP semantics

- **Streaming both ways.** `zr_net_request_new(client, method, url, headers...)` creates a handle. The body is either
  whole bytes (small), or streamed: Zig writes chunks with `zr_net_body_write` (returns "would block" and arms the eventfd when the
  channel is full) and ends with `zr_net_body_finish`; the response body is read with `zr_net_body_read` into a Zig-owned
  buffer. Results uploads (blocks), layer blobs and the Zig tarball therefore stream to and from disk with 64 KiB
  chunks and a bounded memory, as today. `Content-Length` is used when known, chunked otherwise. A `limit` field bounds a
  response read into memory (`BodyTooLarge`).
- **Redirects.** Followed in Rust, up to 5 (std's behaviour with `.unhandled` today in the registry; others use std's default 3: R3
  keeps each call site's current limit as a parameter). 301/302/303 change POST to GET, 307/308 keep the method and need a replayable
  body (a streamed body is not replayed: the redirect is returned to the caller as a response, flagged
  `redirect_not_followed`). **Header privacy:** on any redirect to a different origin (scheme, host or port) `Authorization`,
  `Cookie` and `Proxy-Authorization` are removed, as std 0.17's fix in `registry.zig` does by hand today ("std 0.17's
  client keeps `headers.authorization` across a redirect to another host": that quirk disappears, and the registry code
  keeps only the 401 challenge dance). Same-origin redirects keep them. A redirect from https to http is refused.
- **Proxy.** `HTTPS_PROXY`/`https_proxy`, `HTTP_PROXY`/`http_proxy`, `NO_PROXY`/`no_proxy` (host suffixes, CIDRs, `*`), read once
  at runtime start by a ~150-line `proxy.rs` (HTTP CONNECT tunnelling for https URLs, with `user:pass@` as Basic
  `Proxy-Authorization`; SOCKS is out). `NO_PROXY` matches `localhost`/loopback by default. The same logic is a pure
  function with its own test table (curl's documented cases). The std client has only the fields `http_proxy`/`https_proxy`
  set by hand: this is a feature gain, announced in the changelog of R3.
- **CA bundle.** Loaded **once per process** by `rustls-native-certs` (it honours `SSL_CERT_FILE` and `SSL_CERT_DIR`, and
  reads the system locations: `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, ...), then an
  optional extra PEM path from the runner's config (`RUNNER_CA_FILE`, new) is added. The same loaded roots serve HTTP
  and Postgres. Reloaded when a request's TLS fails with `UnknownIssuer` and the bundle's mtime changed (replaces the 15-minute `renew`).
  No built-in webpki roots: a runner with no system store fails with a message naming the paths searched.
- **Pooling.** hyper-util's pool keyed by (scheme, host, port, proxy): idle timeout 90 s, at most 8 idle per host,
  `pool_max_idle_per_host` set low because the runner is mostly one request at a time; a connection that failed is never
  returned. The pool lives in the process-wide client (one `Client` handle, created at start, torn down at stop); no
  per-request clients, no retired list.
- **HTTP/2.** Enabled by ALPN for `https` hosts, h1 for plain http and proxies by default: the study found h2 slower than
  h1 for one request at a time (199-384 us vs 146-200 us warm) and equal in concurrency; it matters for upload fan-out to
  one host. Policy: **h1 by default, h2 allowed per call site** (R3 sets it off for everything; R4 turns it on for results
  block uploads if the Pi benchmark shows a gain). `Connection: close` handling and h1 keep-alive as std's.
- **User-Agent.** One string, set by the client, not by each call site: `zig-runner/<version> (linux; <arch>)`, with the
  value from `zr_net.start(.{.user_agent = ...})`. GitHub rejects requests with none (the study's hyper rows all got 403); a call
  site can still override per request (GitHub's results service wants its own).
- **Compression.** `Accept-Encoding` is not set unless the call asks (blob downloads must see the compressed bytes: layers
  are already compressed). No automatic decompression.
- **Cookies, auth, retries.** None in the client. Retries stay where they are (call sites know what is idempotent).

## The HTTP client (R3, as built)

`runner/src/net_client.zig` is the Zig side (`fetch(arena, io, options)`), `rust/zr-net/src/client.rs`, `proxy.rs` and `call.rs` the library's.

- **API.** `zr_net_client_new` makes the process's client (user agent `zig-runner/<version>`, proxies from the environment, the pool); `zr_net_call_start`
  takes a request (method, URL, header lines, body, redirect limit, response limit, first-byte and idle limits), copies it, starts it on the runtime and returns a call
  and a descriptor (the Zig end of a socket pair; the library keeps the other and writes one byte with `MSG_NOSIGNAL` when the call has finished, so a caller that
  closed its end first costs nothing). Zig waits with `Io.File.readStreaming` on it: the wait is std.Io's, so the deadline (`http.within`, 30 s) and cancellation
  apply where it blocks, and both free the call, which drops the request and closes its connection (tested: a request to a server that never answers ends at its
  deadline, and a cancel ends it at once). `zr_net_call_result` fills a struct (status, error code, timings, lengths); `zr_net_call_copy` copies headers, body or the error text.
  Whole bodies up to `max_response`; streaming is R4 (below).
- **Pool and connections.** hyper's `http1` connection API under our own pool (per scheme, host, port and proxy; 8 idle per host, 90 s): a kept connection that turns out to be
  closed is replaced silently when nothing had been sent (what `HttpConnectionClosing` retries did). HTTP/1.1 only, as decided; HTTP/2 is per call site later.
- **Exact phases.** DNS is timed around `getaddrinfo` (an address needs none), connect around the TCP connect (each address in turn, 10 s each), TLS around the handshake,
  first byte from handing the request to the connection until its head is parsed, total around everything. A reused connection reports no DNS, connect or TLS of its own.
  With redirects the phases are the last hop's and the total is the whole. `TCP_NODELAY`, keepalive (60 s idle, 10 s apart, 3 probes) and `TCP_USER_TIMEOUT` (90 s) are set on
  every socket the library connects (tested). The cargo test `each_phase_is_measured_where_it_happens` has a server that waits 150 ms before its handshake and 100 ms before
  answering and asserts the TLS time is 150-400 ms and the first byte 100-300 ms, DNS and connect small, and the total consistent.
- **The `request:` line**: one implementation, `github/request_log.zig` (#530's: format, redaction `redactPath` with its query cut and secret-shaped segments `*`, rate-limit fields, the
  golden tests of the line and of the redaction). R3 first carried a copy of it (`request_line.zig`) so that the bytes could not drift while #530 was open; this PR includes #530 (merged into the branch), the copy
  is gone, and `net_client.zig` writes through `request_log.Line` and `emit` as `broker.zig` and `http.zig` do (through its `Probe`, which measures std's client by wrapping its Io and approximates; the library's figures
  are exact). `RUNNER_LOG_REQUESTS` is now the one switch for both (before, the copy had a switch of its own that `main` did not set). Emitted by every `net_client.fetch`.
- **Proxies** (`proxy.rs`, pure and tested table): `HTTPS_PROXY`/`HTTP_PROXY` (lower case wins), `NO_PROXY` as curl documents it (names with subdomains, `*`, IPs, CIDR, ports; loopback
  never proxied), `http://user:pass@host:port` proxies with Basic `Proxy-Authorization`; https targets are tunnelled with CONNECT and TLS runs inside it, http targets use the
  absolute form. Tested against in-process proxies, including one that refuses CONNECT (its own error). No SOCKS, no https proxies.
- **Roots**: `roots::native()` (`SSL_CERT_FILE`, `SSL_CERT_DIR`, system paths), shared with the database's TLS; a PEM in the client's settings replaces them (tests).
- **Redirects**: up to `max_redirects` (3 for the moved call sites); `Authorization`, `Cookie` and `Proxy-Authorization` are dropped when the origin (scheme, host, port) changes; 303 (and 301/302 for a POST)
  turn the request into a GET without its body, 307/308 keep both; https to http is refused.
- **Moved to it**: `auth.zig` (the OAuth token), `app.zig` (the App's installation and token calls), `jitconfig.zig` (generate-jitconfig). Their tests run through it against `testserver.zig`.
- **The oracle** (`net_oracle.zig`): 12 cases against `testserver.zig` through std's client and the library: status and body must match, except where a case writes the difference down. It found two,
  both now documented in the cases: std keeps `Authorization` across a redirect to another host (the library drops it), and std hands a 303 for a POST back instead of following it (the library follows it as a GET).
  Also: the request line's figures for a plain request, and the deadline and cancel behaviour.
- **Validation of R3**: 18 cargo tests (client against in-process plain and TLS servers: keep-alive and reuse, redirects and credentials, CA/name errors by kind, the phases, socket options, limits and timeouts, proxies, the proxy
  table); the oracle; a fuzz target `fuzz: HTTP responses` (what a server answers, byte for byte; in the nightly matrix and in the analysis scope; seeded with normal, chunked, redirecting, malformed and non-HTTP answers);
  TSan: the Rust archive is built instrumented for TSan builds ("ThreadSanitizer" below), so there is no blanket suppression; `.github/tsan.supp` holds the one report that is not a race; Valgrind over the new tests.
- **Not in R3**: the std client's other users (registry, release downloads, uploads: R4, below; run service, broker, Gitea: R5; the feed: R6), `http.zig`'s renew/retire machinery (still needed by those), HTTP/2, streaming.

## Streaming: downloads, uploads, the registry (R4, as built)

- **What moved.** `zig_release.zig` (the Zig tarballs), `github/results.zig`'s blob upload (`putBlob`: the step and job logs) and `native/oci/registry.zig` (manifests, blobs, the token service; `image.zig` and `Backend.zig` lose
  the std client they carried). No other std client user is in R4's scope: tool and action downloads happen inside the Dagger engine or the jobs' own steps, not in the runner, and the artifact and cache uploads are
  the jobs' actions' own. What is left for std: `broker.zig` (the run service, the broker's long poll, the Dagger engine's queries, whose `Body` type is now `net_client.Body`) and `gitea/` (R5), `feed.zig` (R6),
  and `http.zig`'s renew/retire machinery with them.
- **The library's side** (`rust/zr-net/src/body.rs`, `call.rs`): two bounded queues, 1 MiB each (`QUEUE_LIMIT`; a chunk more may be in flight, at most one read of hyper's, about 400 KiB). *Response*: `FLAG_STREAM_RESPONSE` makes the call
  finish when the head is there; the task goes on reading the body into a queue and waits while it is full (so TCP's window stops the server), the caller takes bytes with `zr_net_body_read`, which says "data", "pending" (wait on
  the call's descriptor, as for the head), "end" or a `Code`. `Wake` writes one byte to the descriptor when a queue goes from empty to non-empty (or, for a request body, half empty), at an end, or on an error; a
  descriptor full of unread wakes loses nothing (`MSG_DONTWAIT`). *Request*: `FLAG_STREAM_REQUEST` and `body_len`: the caller writes with `zr_net_body_write` ("took n", "full", "over": the call has answered or failed, stop writing)
  and hyper takes chunks from the queue (`ReqBody`); Content-Length is the declared length (a short or failing writer ends the call with `UploadFailed`, never a hung request). Both are cancelled by `zr_net_call_free`
  (the connection is dropped). `total_ms` bounds the whole call, body included, `read_idle_ms` a body that stops, `first_byte_ms` the head.
- **Connections.** A response read to its end puts its connection back in the pool (before the end is announced, so the next request finds it); one not read to its end is dropped. A kept connection found closed or reset
  before an answer is replaced by a new one (bytes bodies and GETs: unseen by the caller, the library's; a streamed body cannot be taken back from hyper, so that call fails with `Stale` and the caller writes it again with
  `fresh`, which `putBlob` does, as `broker.request` did for #100). A GET (or HEAD) that met a closed connection, new or kept, is sent once more. Redirects follow the R3 rules for credentials and methods; a streamed request body
  cannot be repeated, so a 307 or 308 for it is an error (`Protocol`), and a 301, 302 or 303 turns it into a GET as before.
- **`net_client.zig`.** `open(arena, io, options)` returns a `Stream` (status, headers, `read`, `discard`, `close`, `timings`): the head wait is `http.withinClosing`'s (a deadline or cancel frees the call), each wait inside `read` is
  std.Io's readiness wait on the descriptor, which cancels. `Options.upload` (a `Body`: a length and a writer, the shape `broker.Body` had) writes through the queue from the caller's thread; `fetch` takes the same option, so
  the results upload still gets its small answer whole. One `request:` line per stream, when the body ends or the stream is closed, with the whole body's `bytes_in` and the final total (the head's figures stay exact).
- **Zig seeds.** `zig_release.download` streams the tarball into BLAKE2b-512 (for `minisign.verifyDigest`) and SHA-256 (the digest handed to the seed build) and keeps neither the tarball nor a copy: the ~50 MB per version no longer
  exist in the runner's memory at startup.
- **Registry.** `registry.Client` has an `io` where it had the std client; a request is `net_client.open` with up to five redirects done by the library (which drops `Authorization` at another origin: the hand-written
  `sameOrigin` and redirect loop are deleted), 60 s for a head and for a silence in a body; the token request is `fetch` without redirects. `Body.take` reads the stream into the blob's file and its hash as before. A 401's small
  body is read so that its connection serves the token request and the retry.
- **Differences from std**, each in `net_oracle.zig`: a redirect to another host takes the token away (std keeps it, the R3 difference; seen on downloads too: a CDN's signed URL refuses it with 403 from std);
  the User-Agent is `zig-runner/<version>` where the registry's was `zig-runner`; a token service that redirects is an error (`TooManyRedirects`, with 0 redirects allowed) where std handed back the 3xx, and the pull says
  "the token service: TooManyRedirects" instead of "answered HTTP 302"; the registry's stale-connection retry counts (`staleRetries + 1` tries) become the library's one repeat; errors are `net_client.Error`'s names (a registry that closes every
  connection unanswered is `NetworkIo`, not `HttpConnectionClosing`).
- **Measured** (cowbird, loopback server in the same process, 512 MiB, ReleaseSafe, `net_oracle.zig`'s `bench:` tests, three alternating runs; load average 2.8 for the last set, 6-8 for the first):
  | | wall | CPU (process, server thread included) | peak RSS |
  |---|---|---|---|
  | tarball, std, whole body in memory (the old `zig_release`) | 445-527 ms (970-1150 MiB/s) | 0.82-0.96 s | 526 MB |
  | tarball, library stream, hashed as it arrives | 478-540 ms (950-1070 MiB/s) | 0.99-1.10 s | 3.9 MB |
  | blob into a file and SHA-256, std (the old registry) | 590-603 ms (850-870 MiB/s) | 1.06-1.10 s | 1.8 MB |
  | blob, library stream (the new registry's `Body.take`) | 586-693 ms (740-870 MiB/s) | 1.49-1.73 s | 4.9 MB |
  So: equal wall time within noise on a 1 GiB/s loopback, 100-250 ms (tarball) and 400-600 ms (blob) more CPU per 512 MiB, and 500 MB less memory for a tarball. The CPU is the hop between
  the runtime's thread and the caller's (one wake and one read per burst of the connection). The first run was twice as slow: hyper's adaptive read buffer allocates a block of hundreds of KiB per read and musl maps and
  unmaps each one, so the connection now reads into a fixed 64 KiB (`READ_BUF`) and `alloc.rs` keeps up to 16 freed blocks of 32-512 KiB for reuse (CPU 2.2-2.5 s before, 1.5-1.7 s after, for the blob). Not measured: the
  Raspberry Pi (disk streaming vs std; planned in the R4 row below), a real registry or ziglang.org (network-bound; the loopback isolates the client), HTTP/2 (the client is h1 only; no gain was shown to justify it).
- **Validation.** Cargo: 7 new tests through the C ABI as Zig drives it (48 MiB streamed plain and chunked with a slow reader and the queue's peak asserted below 1.5 MiB, reuse after a stream, a cancel halfway closes the
  connection at the server, a stalled body and a call over its total each have their own error, a 24 MiB upload through a slow server with the writer made to wait, a server that answers a 512 MiB upload at once stops the writer,
  303 and 307 for a streamed body, the token left behind at a redirect), and queue unit tests. Zig: the oracle's download (five sizes up to 24 MiB, three read sizes, hashed on both sides), redirect, upload
  (std's `broker.request` against the library), short and failing writers, request line and early close cases; `fuzz: HTTP streams` (the HTTP responses' seeds, read in pieces of any size, and an upload of any size
  into a server that may answer before it and close; nightly matrix and analysis scope, as `HTTP responses`); the registry's tests (token auth, CDN redirect without the token, digest mismatch, stale and reset) on the
  library. TSan (cargo and the whole Zig suite) and Valgrind clean.

## The WebSocket feed (R6)

`feed.zig` upgrades a std request by hand and frames in Zig. The Rust side uses `tokio-tungstenite` (rustls via the
shared `ClientConfig`, so the same CA/proxy policy) behind `Ws` handles: `zr_net_ws_connect` (handle, same timings and
`request:` line for the upgrade), `zr_net_ws_send` (text/binary, bounded queue, wake when drained), `zr_net_ws_recv`
into a caller buffer, `zr_net_ws_close`; ping/pong and close handshakes inside Rust; the same eventfd wait and
cancel as requests. The feed is send-mostly (log lines), so send backpressure matters, receive is only control messages. The framing
code in `feed.zig` (and its fuzz target) is deleted in R6; the std path stays as an oracle until then.
Alternative considered: `hyper::upgrade` yielding the raw IO and keeping framing in Zig (zero new crates). Rejected because the point is one stack
with real hooks and fewer lines of protocol in Zig; the decision is cheap to revisit in R6 if `tokio-tungstenite` adds more than
~150 KB.

## Postgres TLS (R2, as built)

Zig keeps the socket, the `SSLRequest` exchange and `std.Io` cancellation (`pg.zig`, `startTls`). After the `S`, `runner/src/tls_stream.zig` opens a `Stream` over
the sans-IO handle (`rust/zr-net/src/tls.rs`: no I/O, no threads, no tokio; `zr_net_tls_*`, 12 functions) and gives `pg.zig` an `Io.Reader` and `Io.Writer` that
call `take_cipher`/`give_cipher`, so the protocol code is untouched. The handshake runs inside `open`, on the caller's thread, so a timeout or cancel of the
connect (`http.withinClosing`) ends it where it blocks. Errors come back with a kind (`unknown_issuer`, `name_mismatch`, `expired`, `certificate`, `alert`,
`protocol`, `eof`, `config`) and the library's text, logged as `pg: TLS to <host>: TLS unknown_issuer: invalid peer certificate: UnknownIssuer`.

- **Configuration** (libpq's names): `sslmode=require` (checks chain and name, as before; also `verify-full` and `verify-ca`), `no-verify`, `disable`;
  `sslrootcert`, `sslcert`, `sslkey` in the URL, or `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`. Without `sslkey` the key is looked for in `sslcert`'s file.
- **Client certificates**: PEM chain and key, read by Zig and handed over whole. Tested live against a Postgres that demands them: ECDSA (PKCS#8 and SEC1) and RSA
  (PKCS#8 and PKCS#1) keys; no certificate at all is refused by the server and reported. Before R2 the client could not send one: it answered a request with an empty
  Certificate message, which Tiger Data accepts. It still does when none is configured.
- **Roots**: the system's, loaded once per process and again after an hour (`rustls-native-certs`: `SSL_CERT_FILE` or `SSL_CERT_DIR` if set, else the usual
  system paths), shared by every connection; `sslrootcert` replaces them (a private CA's file). `std.crypto.Certificate.Bundle`, its rescan and its clock
  (`now`) are gone from `pg.zig`.
- **Differences to know about (private CAs).** rustls-webpki is stricter than std and tls.zig. Measured here (cargo tests against an in-process server and
  the live server): a **CA certificate presented as the server's own** (`CaUsedAsEndEntity`, what openssl's `-x509` one-liners make) is refused as `certificate`;
  a certificate with the name **in the subject only and no subjectAltName** is refused as `name_mismatch`; a wrong CA is `unknown_issuer`; a name that is
  an IP address needs an IP SAN. A database that works today with such a hand-made certificate stops working with that message; `sslmode=no-verify` is unaffected and
  `.github/scripts/pg-tls-fixture.sh` shows an acceptable CA, server and client set (an `openssl req -x509` with `-addext subjectAltName=...` and `basicConstraints=CA:FALSE`
  for the leaf).
- **Memory.** The sans-IO state is small (about 40 KB of Rust heap per connection with TLS 1.3, none after `close`: a test connects and closes 50 times and the Rust heap
  is within 16 KiB of where it started). Rust's allocator is counted (`zr_net_heap_bytes`) and shown as `rust=` in `health: proc` and the job-end stats.
- **Removed from every build:** `tls.zig` (as a dependency of the runner's build: `zig_package_hash` and the fetch of it in `zig-modules.sh`, the SBOM entry; the SBOM now
  lists the crates of `Cargo.lock`, musl and libunwind). It stays in `build.zig.zon` as a **lazy** dependency (`.lazy = true`, pinned by commit, with its Renovate entries) that
  only the oracle below fetches.
- **The old TLS client as an oracle.** `zig build test-tls-oracle -Dtls-oracle` (`runner/tls_oracle.zig`, with `runner/tools/tls_oracle/pg_old.zig`: main's `pg.zig` as of 3516c49 on tls.zig,
  its tests removed, three edits: a path for one import, and `sslrootcert` so that it can trust the fixture's CA) runs the old and the new client against the same servers, and fails if either does
  anything but what a table of cases says; a difference between the two must carry its reason (`why`). A lazy dependency is fetched when the build script asks for it, and the configure phase does
  not know which step was named, so the request is behind `-Dtls-oracle`: `zig build`, `zig build test` and CI's direct-compiler paths never fetch, hash or compile tls.zig. Servers: the Database
  job's Postgres (private CA, client certificates; `pg-tls-fixture.sh`) and, for certificates Postgres does not have, the test's own endpoint (it answers the SSLRequest with `S` and
  proxies to `openssl s_server` on a Unix socket), where "outcome" is how far each client got. CI runs it in a job of its own, "TLS oracle", beside the Database tests job (same database, started by the same script; not a required check), and the analysis scope of
  `ci-scope.sh` includes its files. Measured (laptop, TimescaleDB container, same as CI's):

  | case | old | new |
  |---|---|---|
  | Postgres, private CA, verified; no-verify | connected | connected |
  | a CA nobody trusts; system roots only | handshake failed | handshake failed (`unknown_issuer`) |
  | a client certificate, user only by certificate | refused (no client certificates) | connected (**intended**: the old client answered with an empty Certificate) |
  | a certificate-only user and no certificate | refused | refused |
  | `s_server`, TLS 1.3 and TLS 1.2, name in subjectAltName | handshake done | handshake done |
  | a CA certificate (CA:TRUE) as the server's own | handshake done | handshake failed (**intended**: `CaUsedAsEndEntity`) |
  | the name only in the subject | handshake done | handshake failed (**intended**: `name_mismatch`) |
  | the server answers `S`, then plain text | handshake failed | handshake failed (`protocol`) |
  | the server answers `S`, then hangs up | handshake failed | `ConnectionClosed` (**difference**, both fail; the library says the connection ended) |

  The same statements through both clients over TLS (verified and no-verify) give the same results byte for byte: `current_user` and `pg_stat_ssl`, 20,000 rows with NULLs and non-ASCII text
  (same SHA-256), an 8 MiB field, the server's errors (`22012`, `42P01`, `42601`: same class and text, the connection usable after), COPY of 4,096 rows and 4 MiB. Cost: the
  TLS oracle job compiles Zig's build system (about 100 s cold on a hosted runner) and tls.zig, and runs for about 20 s.
- **Validation brought by R2**: the live TLS tests (7, in `pg.zig`, run by the Database tests job against a container started by `ci-database.sh` with
  `pg-tls-fixture.sh`'s CA and users; they skip locally unless `ZIG_TEST_PG_TLS_DIR` is set, and fail without it where `ZIG_TEST_REQUIRE_DB` is); 8 cargo tests (`cargo-test.sh`, now a CI step:
  the TLS state machine, kinds of failure, bad input, `SSL_CERT_FILE`, garbage from a server); the fuzz target `fuzz: TLS records` (what a TLS server sends, in any chunks, held to
  no panic and bounded memory, seeded with real first flights for TLS 1.3 and 1.2; 300K runs clean locally; in the nightly matrix and in the analysis scope of `ci-scope.sh`:
  `runner/rust/*`, `tls_stream.zig`, the corpus); the allocation counter above; Valgrind over the live tests (clean after one suppression, in `.github/valgrind.supp`, for ring's
  ECDSA nonce code, with why); the whole suite under TSan in the Database job (the TLS side is single-threaded: no Rust thread is involved).

## Build

- **Cargo from `build.zig`** (`addZrNet`, R1): a `Run` step running `.github/scripts/build-zr-net.sh <arch> <out>`, whose output is a
  `LazyPath` linked into the module with `-lc -lunwind`. The same script is run by `zig-modules.sh` (`zig_zr_net_args`: the
  direct-compiler path of CI's tests, Valgrind, TSan, coverage, e2e, and `build-binaries.sh`, the release), so there is one
  implementation of "how Rust is built here" and `zig build` and `build-binaries.sh` give byte-identical x86_64 binaries
  (checked here with `cmp`; release.yml's "Binaries (same as zig build)" compares them).
- **Both arches.** `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`; cross builds on either host. A staticlib is never linked by
  rustc, so the only toolchain Rust needs for the target is a C compiler for crates with C or assembly (ring, later). `zig-cc.sh` is that
  C compiler (`zig cc -target <arch>-linux-musl`), dropping the two flags the study found Zig's driver rejects (`--target=...`
  and `--fix-cortex-a53-843419`, the study's wrapper). No `-C link-self-contained=no` was needed for a staticlib.
- **`Cargo.lock` committed; `--locked` always.** A stale lock is a build error, not a silent update. Renovate keeps crates current (it supports
  cargo; one grouped weekly PR, reviewed like any other).
- **Vendoring / offline.** Policy: **no `cargo vendor` in the repository** (megabytes of third-party source in diffs and Zig-style
  vendoring does not fit crates; #532/#533 vendor C because it is a few hundred KB). Instead: crates.io is fetched with the lock's checksums
  (cargo verifies every crate against `Cargo.lock`), through the sparse index, cached in `~/.cargo` (CI: cache keyed on `Cargo.lock`
  and the toolchain's version). If an offline build is needed (the image build, the provisioned image), `cargo vendor` is run in that build
  from the lock and not stored. Revisit at R3 when the dependency count is real (about 90 crates for hyper + rustls + tungstenite).
- **Toolchain without rustup.** `install-rust.sh`: cargo, rustc and rust-std (host plus both musl targets) tarballs from
  static.rust-lang.org, each SHA-256 pinned from the release manifest (`channel-rust-1.99.1.toml`), unpacked to `RUNNER_TOOL_CACHE/rust/1.99.1/<arch>` (or
  `~/.cache/zig-runner-rust`), once per version, and **the tree is checked against a pinned digest of its 292 files** every run (0.7 s), as `install-zig.sh` does for Zig, so a job that wrote
  the tool cache cannot swap the compiler. Nothing else is cached there on purpose: a shared `target/` or `CARGO_HOME/registry/src` is not verified by cargo and would let one job's bytes into another's release. `build-zr-net.sh` calls it itself when the machine's `cargo` is not 1.99.1, so
  no workflow job had to change (every job that builds the runner already goes through `zig-modules.sh`). A developer with rustup gets the
  same version from `rust-toolchain.toml` (`targets = [...]`). Cost, measured here: **45 s and 969 MB on disk** on first use per
  machine. GitHub's hosted runners have rustup; the script does not use it so that hosted and self-hosted builds are the same bytes.
  On razorbill (SD card) the one-time 1 GB write is the cost to watch (R2 measures it, and may drop `rust-docs`-class components
  if any sneak in: none are installed now).
- **Cost (measured, cowbird, 12 cores, load average 3-5).** Cargo for the tokio-only skeleton: cold 3.4 s (x86_64) and 4.8 s (aarch64), warm
  0.02-0.09 s (a no-op check). `build-binaries.sh` for both arches (zig-runner's own two compiles run in parallel): 2:37 wall with the skeleton against
  2:01 on main, same machine, back to back, load average about 4-5 (the 36 s is the libc build and the serial cargo step, not the tokio skeleton:
  noisy, repeat at R2). The study's full stack (hyper, h2, rustls, ring) builds cold in 29-39 s per musl arch: expected to add about
  35 s to a release build (the two arches run in parallel after the Rust step, which is serial per arch in `zig_modules` today and parallel
  later if it matters) and 0 for a warm cache. CI jobs that build the runner on a cold GitHub runner pay the cold figure once each (no job shares a cache today:
  the cargo cache action keyed on `Cargo.lock` + toolchain version is R2's CI change, measured then).
- **Supply chain.** `deny.toml` (licenses allow-list: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, ISC, BSD-3-Clause, Unicode-3.0, Zlib; advisories; crates.io
  only; wildcards denied), run by `.github/scripts/cargo-deny.sh` in `security.yml` ("Rust dependencies": on pull requests and weekly for new advisories), tarball pinned by
  SHA-256 as gitleaks is. GitHub's dependency review reads `Cargo.lock` for free. `docs/THIRD_PARTY.md` lists direct dependencies and
  the license policy; transitive ones are listed by `cargo deny list` (R2 adds the generated table once the set is real; `ring`'s mixed
  licence needs a `deny.toml` exception then, which is a decision to record there).

## Validation (the user's principle: the validation tooling lets us move to Rust and C without losing safety)

Each PR brings its own checks; none is left to "later".

1. **The std client as an oracle until R6.** Tests drive the same request script (method, headers, streamed body, redirects,
   chunked and content-length responses, 1xx/204/304, big headers, HEAD, early server close, slow server) against
   `github/testserver.zig` through both clients and assert **identical status, headers (minus ones that
   legitimately differ: `User-Agent`, `Connection`) and body bytes**. The harness is `src/net_oracle.zig`, added in R3 and kept to R6, where
   it is deleted with the std client. Every later PR extends the script with its call sites' shapes (R4 uploads and downloads, R5 long-poll, R6 WebSocket
   frames against `feed.zig`'s own framing).
2. **Fuzz targets for every parser Rust runs on network bytes that crosses the ABI.** hyper, h2, httparse, tungstenite and rustls parse
   untrusted bytes entirely inside Rust, so the fuzz boundary is the ABI: targets feed arbitrary bytes as the *server's side* of a connection
   (a socketpair/in-memory transport handle exported only in test builds) into `zr_net_request` and `zr_net_ws`, and ciphertext
   into `zr_net_tls_give_cipher`, asserting no crash and bounded memory. They live beside the existing fuzz targets (`zig-fuzz.sh`, `src/fuzz.zig`)
   with corpora under `src/fuzz_corpus/`. They are **wired into the analysis scope in `.github/scripts/ci-scope.sh`** (as the zstd decoder is), so a change
   to `runner/rust/*` or `zr_net.zig` is fuzzed before it merges, not only at night: R1 already adds `runner/rust/*`, `runner/src/zr_net.zig`
   and the build scripts to that case. Rust's own `cargo fuzz` (libFuzzer) is not used: Zig's fuzzer is the one in CI, and the shared ABI is the
   boundary that matters to the runner. R2 brings the TLS one, R3 HTTP head and header parsing, R6 WebSocket frames.
3. **Valgrind clean on the Zig tests that call into Rust.** `zig-valgrind.sh` already runs every test through the module graph, which
   now includes the archive, so tests that start the runtime run under memcheck: R1's does, with **no reports** (done: `the runtime starts...` passes
   under `zig-valgrind.sh` with no suppression). Limits, to know what that proves: a static musl binary hides `malloc` from Valgrind's
   replacement, so memcheck sees uninitialised reads and bad accesses of Rust code but cannot track Rust heap blocks (no leak or
   use-after-free of Rust allocations); Zig-side buffers handed to Rust (body chunks, `read` targets) are fully checked. Rust's heap is covered by
   the allocation counter from "libc" (leak at runtime stop is an assertion in the tests: bytes in use is 0 after `stop`) and
   by `cargo test` under Miri on the pure functions (proxy matching, redirect policy, URL handling).
4. **ThreadSanitizer (as built after R3's review).** An uninstrumented Rust archive in a TSan binary is invisible to TSan: it reported
   false races at the hand-over of memory between Zig and tokio threads, and (the reason R3's first answer, a blanket `race:*::*`, was
   wrong) it also could not report a real race in or across Rust. Measured with a deliberate race (a `static mut` counter incremented by two
   Rust threads, and a word written by a Zig thread and a Rust thread): the uninstrumented archive reported neither; the instrumented one
   reported both, with both stacks. So TSan builds link an **instrumented** archive: `build-zr-net.sh ... tsan` builds the gnu target
   (TSan's runtime needs glibc's loader; musl is the release's) with a pinned nightly (`install-rust-nightly.sh`: 2026-11-10, rustc
   1.102.0-nightly, dated tarballs with checked SHA-256, rust-src included; no rustup) and `-Zsanitizer=thread -Zbuild-std=std,panic_abort`, so
   std's atomics and locks, tokio's and ours are all seen. `zig-modules.sh` (CI's tests, e2e) and `build.zig` (`-Dsanitize-thread`) choose it
   whenever the Zig side is built with `-fsanitize-thread`. Not instrumented: the C of ring (assembly and C routines that work on
   buffers the caller owns); a race inside them would be missed. Cost: a 36-45 s cold build of the std and the crates (about 2 min more for the one-time
   nightly install on a runner with an empty tool cache); `cargo-test.sh tsan` runs the crate's tests under it too (the Database tests job; 17 of
   18 tests: the one asserting wall-clock bounds on each phase is not run, `getaddrinfo` took 262 ms once under TSan against a bound of 50).
   With the archive visible, the whole suite showed what the blanket suppression had been hiding, and what the sharded runner had never
   shown (`test_shards.zig` ignored a shard's stderr and exit status, so a TSan report in a passing test was lost; it now fails the test
   that printed it and any shard that exits with a failing status): a race in a test fake (`dagger.zig`'s `FakeWarn.n`, polled by the test
   thread while the watch thread wrote it; fixed with an atomic) and one pattern in tokio: a socket's `ScheduledIo` is written by
   `RegistrationSet::allocate` and registered with epoll with a pointer as the event's data; the driver thread receives that pointer from
   `epoll_wait` and reads the struct. The kernel orders the two and TSan cannot model epoll_ctl to epoll_wait, so it reports a race at every
   registration. That one frame is suppressed (`.github/tsan.supp`, with this reason); and a thread-leak report at a test process's end for a tokio blocking-pool thread (the `getaddrinfo` ones) that went idle and left before the process ended, its handle held by a runtime that lives as long as the process (suppressed by the stack that created the thread, with its reason). Nothing else. The whole suite passes under it
   (1042 passed, 0 failed), and `cargo test` too.
   What is still not covered: `loom` for the lock-free structures we write ourselves (small: none yet), and the Zig side of the ABI
   exercised by the stress job. Race-freedom of hyper and tokio themselves is not re-proved here beyond what TSan sees running our tests.
5. **Existing tooling, now over Rust too**: coverage (`cargo llvm-cov` for the crate in `analysis.yml`, reported next to Zig's, from R3),
   mutation testing on the glue (`cargo mutants` scoped to `src/proxy.rs` and the redirect policy, a manual job first), `cargo clippy -D warnings` and `cargo fmt --check`
   in the Zig-less "Workflows"-style job (R2), `cargo deny` (R1), and the e2e job (a real runner job over the new stack) plus the pre-release smoke test on the laptop pool.
6. **R1's own checks**: `cargo test` in the crate (starts, tasks, stops, twice); the Zig test `the runtime starts, runs a task through the ABI and stops`
   in the normal suite (it runs in every test job and under Valgrind); `build-binaries.sh` output byte-compared with `zig build`; `checksec.sh` on the libc build;
   the whole existing test suite on the libc build.

## The series

| PR | Brings | Deletes | Version | Checks it brings |
|---|---|---|---|---|
| **R1** (this) | `runner/rust/zr-net` skeleton, `build.zig` `addZrNet`, `build-zr-net.sh`, `zig-cc.sh`, `install-rust.sh`, `zig-modules.sh` link inputs, `zr_net.zig` + test, cargo-deny, this document | nothing | minor | Zig test, `cargo test`, Valgrind, byte-identical builds, checksec, cargo-deny |
| **R2** | `src/tls.rs` sans-IO rustls, `tls_stream.zig`, `pg.zig` on it, client certs (`sslcert`, `sslkey`, `sslrootcert`), roots loader, allocation counter, `cargo test` in CI | `tls.zig` dependency, `build.zig.zon` tls entry, `zig_package_hash` and the tls fetch in `zig-modules.sh`, `ca_bundle` in `pg.zig` | minor | TLS fuzz target, live pg client-cert and private-CA tests, in-process rustls tests |
| **R3** | the client API (`net_client.zig`; pool, proxy, redirects, h1, exact timings), `request:` lines through #530's `request_log.zig`, `auth.zig`, `app.zig`, `jitconfig.zig` fetches on it; oracle harness | their std client use (`http.fetch` there) | minor | oracle against `testserver.zig`, HTTP head fuzz, phase-delay test, cgroup-of-threads test, TSan suppressions |
| **R4** (built: "Streaming", above) | streaming bodies; `zig_release.zig` download, `results.zig` uploads, `native/oci/registry.zig` (redirect privacy tests) | `registry.zig`'s hand-written redirect/authorization workaround, `zig_release`'s std path | minor | streamed oracle cases, memory bound test; the Pi disk-streaming benchmark vs std is not run yet (laptop numbers in the PR) |
| **R5** | `runservice.zig`, `broker.zig` long-poll (cancel, keepalive, #100's dead-connection test), `gitea/client.zig` | `http.within`'s client coupling, `http.keepAlive` | minor | long-poll oracle and kill-the-network test, Gitea job diff tool |
| **R6** | `feed.zig` on tokio-tungstenite | std client use everywhere, `net_hooks.zig`, `http.zig`'s retired list and `renew`, the oracle harness, feed framing | minor | WebSocket fuzz target, feed oracle until deleted |

Every PR bumps the version (changie `Added` or `Changed`, minor), runs the pre-release smoke test on the laptop pool before release, and is checked on
main's own CI (self-hosted overlayfs/arm64 job), not only the PR's.

## Open items found while building R1

- **`runner/Dockerfile` has no from-source stage any more** (decided with R1): the image is built from the release's binaries (`prebuilt`), and `deploy/compose.yaml`
  pulls the published image (`ZIG_RUNNER_IMAGE` overrides) instead of building `../runner`.
- **The root native tests** (`Native tests as root`, `Native tests as root (in a container)`...) are the real check of the raw `clone`/`unshare` paths on the libc build:
  they cannot run on this laptop (user namespaces are refused by AppArmor for the test process), so R1's CI run is their first result.
- **`zig_target_arch` and `modules=`** in `zig-modules.sh` are also in #533's diff; the second PR to merge resolves a small textual conflict.

## Risks

- A second heap and two schedulers' worth of threads in a 4-5 MB process; mitigated by the allocation counter, 2 workers, and measuring RSS on
  razorbill at R3 (the study's std was ~0.6 MB per TLS connection, hyper ~0.07 MB).
- Binary growth (see table) and the 1 GB toolchain on the Pi's SD card.
- rustls's strictness (private CAs) and no built-in roots: both give precise errors and are documented in R2's changelog entry.
- Rust panics abort the runner: every `unwrap` in the crate is a decision; clippy's `unwrap_used`, `expect_used` and `indexing_slicing` are denied from R2.
- Two languages in one build: the Zig-only developer needs `cargo` (or `install-rust.sh`, run automatically).
- The `zig_modules` parallelism: Rust builds serialise per arch in `build-binaries.sh` (cargo's own lock on a shared target dir); fixed if it shows.
