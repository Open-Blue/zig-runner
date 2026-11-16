//! A Docker-compatible API for one native job (issue #448): a unix socket in the job's directory,
//! bound into every step at `/var/run/docker.sock`, and a thread of the runner that answers on it.
//!
//! Stage 1a is the skeleton, so that a step's `docker` CLI finds a server, says what it is and
//! learns plainly what is not there yet; stage 1b makes `docker build` work through it, answered
//! by the job's `Handler` (`Backend.zig`, the native Dockerfile builder):
//!
//!   GET|HEAD /_ping      `OK`, with `API-Version`, `Builder-Version: 1` and `OSType: linux`
//!   GET /version, /info  JSON a real `docker version` and `docker info` print
//!   POST /build          the classic builder: a tar context in the body, the build's output
//!                        streamed back as JSON lines (`Handler.buildFn`); without a handler 501
//!   GET /images/{name}/json, POST /images/{name}/tag, DELETE /images/{name}
//!                        over the job's tag index (`Handler.imageFn`)
//!   /grpc, /session, /build?version=2
//!                        501 with the BuildKit hint (the classic builder is the first stage)
//!   anything else        501 `{"message":"not supported by zig-runner yet: <METHOD> <path>"}`
//!
//! **The gate.** A request is answered only while a step's process may be running (`openGate`,
//! `closeGate`, which `Backend.runIn` calls around every sandbox that has the socket): a request
//! found with the gate closed is told 503 and counted, and `closeGate` cancels what is in flight
//! (a build), waits for it to end and takes in what the dead clients had sent, so every request is
//! counted against the step that made it, and a build never runs on after its step.
//!
//! An optional `/v1.NN` prefix is stripped (1.24 to 1.52 are served; others get Docker's own 400).
//!
//! The server never hangs and never trusts the client: a connection is one thread (at most
//! `Limits.max_connections` at a time, the next is told 503), every wait is a `poll` with a
//! deadline (a request's head must arrive within `header_ms` of its first byte, a kept connection
//! may idle `idle_ms`, a write may take `write_ms`), a request head is at most `header_bytes`, a
//! malformed one gets 400 and a closed connection, and the body of a request is never held: it is
//! read and dropped (up to `drain_bytes` or `drain_ms`) after the answer, which closes the
//! connection. `stop` wakes every thread through one eventfd and joins them all.
//!
//! The socket is made `0666`: a step's user is another one of the host's (a user namespace's), and
//! what protects it is that only the job's own steps have it in their root, and the job's
//! directory (`Store.secure`) is not the host's to walk.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;
const docker_build = @import("docker_build.zig");

/// The newest API version served, answered as `API-Version`.
pub const api_version = "1.52";
/// The oldest one a request's `/vX.Y` prefix may name, as Docker 29's daemon accepts.
pub const min_api_version = "1.24";
const newest_minor = 52;
const oldest_minor = 24;

/// Where the socket is bound inside every step.
pub const socket_at = "/var/run/docker.sock";
/// What the job's steps get in their environment (a workflow's own `env:` wins).
pub const env_host = "unix://" ++ socket_at;

pub const buildkit_hint = "BuildKit is not supported by zig-runner yet; DOCKER_BUILDKIT=0 is set " ++
    "for you, and docker buildx / docker/build-push-action need a later stage";
/// `POST /build` with no handler to build it.
pub const build_unavailable = "not supported by zig-runner yet: POST /build";
/// What a request finds between steps.
pub const gate_closed = "no step of the job is running: its Docker API answers only to a step's own " ++
    "processes, while the step runs";

pub const Limits = struct {
    /// The most bytes of a request's line and headers.
    header_bytes: usize = 16 * 1024,
    /// The longest target (path and query) of a request line.
    target_bytes: usize = 4096,
    /// From a request's first byte to the end of its head.
    header_ms: u32 = 10_000,
    /// A connection kept open between requests.
    idle_ms: u32 = 15_000,
    /// One write of an answer, every wait in it together.
    write_ms: u32 = 10_000,
    /// What of a request's body is read and dropped after the answer, and how long that may take.
    drain_bytes: usize = 8 * 1024 * 1024,
    drain_ms: u32 = 2_000,
    /// Requests answered on one connection.
    max_requests: u32 = 1000,
    max_connections: usize = 8,
    /// Requests a second the job's API answers, and how many it takes in a burst: a request that
    /// finds none left is 429. The server's work is the runner's, outside the job's CPU limit.
    rate_per_s: u32 = 100,
    burst: u32 = 200,
    /// What a request over the budget waits before it is answered 429 and the connection closed.
    deny_delay_ms: u32 = 100,
    /// How long `settle` waits for the connections to take in what they were sent.
    settle_ms: u32 = 2000,
    /// A build's context as the client sends it: its bytes (the tar's own, a little over what
    /// `docker_build.Limits.bytes` allows the files), how long a read may wait for more and how
    /// long the whole upload may take.
    body_bytes: u64 = (1 << 30) + (1 << 28),
    body_idle_ms: u32 = 30_000,
    body_ms: u32 = 10 * 60_000,
    /// Builds a job may make, and how many at once (one: they share the job's build directories).
    max_builds: u32 = 32,
    /// What a job's uploaded contexts may add up to (the tar files spooled in its directory).
    spool_budget: u64 = 4 << 30,
    /// What a build's context may hold once unpacked.
    context: docker_build.Limits = .{},
};

/// The answer of `Handler.imageFn`.
pub const ImageAnswer = struct { status: u16, body: []const u8 };

pub const ImageOp = union(enum) {
    /// `GET /images/{name}/json`.
    inspect: []const u8,
    /// `POST /images/{name}/tag?repo=&tag=`.
    tag: struct { name: []const u8, repo: []const u8, tag: []const u8 },
    /// `DELETE /images/{name}`.
    remove: struct { name: []const u8, force: bool },
};

/// Where a build writes what the client reads: JSON lines (`docker_build.streamLine`).
pub const Sink = struct {
    server: *Server,
    fd: linux.fd_t,
    lock: std.atomic.Mutex = .unlocked,
    /// A write failed (the client is gone or too slow): the build should stop.
    failed: std.atomic.Value(bool) = .init(false),

    /// One chunk of the response. After a failure it writes nothing.
    pub fn write(k: *Sink, bytes: []const u8) void {
        if (bytes.len == 0 or k.failed.load(.acquire)) return;
        while (!k.lock.tryLock()) {
            if (std.Thread.yield()) {} else |_| {} // spinning is the fallback
        }
        defer k.lock.unlock();
        if (k.failed.load(.acquire)) return;
        var head: [24]u8 = undefined;
        const h = std.fmt.bufPrint(&head, "{x}\r\n", .{bytes.len}) catch return;
        const lim = k.server.cfg.limits;
        // The frame in one write when it is small: one syscall for a line of output.
        var small: [1024]u8 = undefined;
        if (h.len + bytes.len + 2 <= small.len) {
            @memcpy(small[0..h.len], h);
            @memcpy(small[h.len..][0..bytes.len], bytes);
            @memcpy(small[h.len + bytes.len ..][0..2], "\r\n");
            sendAll(k.server, k.fd, small[0 .. h.len + bytes.len + 2], lim.write_ms) catch {
                k.failed.store(true, .release);
            };
            return;
        }
        sendAll(k.server, k.fd, h, lim.write_ms) catch {
            k.failed.store(true, .release);
            return;
        };
        sendAll(k.server, k.fd, bytes, lim.write_ms) catch {
            k.failed.store(true, .release);
            return;
        };
        sendAll(k.server, k.fd, "\r\n", lim.write_ms) catch k.failed.store(true, .release);
    }

    pub fn gone(k: *const Sink) bool {
        return k.failed.load(.acquire);
    }
};

/// One `POST /build` for the handler.
pub const BuildCall = struct {
    /// Freed when the call ends.
    arena: Allocator,
    query: docker_build.Query,
    /// The tar the client sent, a file of the job's directory that the server removes after.
    tar_path: []const u8,
    /// Its size.
    tar_bytes: u64,
    /// A name for the build, unique in the job: a directory name.
    id: u32,
    /// What the unpacked context may hold.
    limits: docker_build.Limits,
    sink: *Sink,
};

/// What answers for the job: the Docker API's effects. An implementation embeds it as a field and
/// recovers itself from the pointer with `@fieldParentPtr`.
pub const Handler = struct {
    /// Runs the build and streams its output to `call.sink`, ending with the aux ID or an
    /// `errorDetail`. Called on a thread of its own, so that the connection's can watch the client.
    buildFn: *const fn (h: *Handler, call: *BuildCall) void,
    imageFn: *const fn (h: *Handler, arena: Allocator, op: ImageOp) ImageAnswer,
    /// Stops the build `id` (a `BuildCall.id`) if it is the one in flight; with null, whichever is,
    /// and any that starts before `resetFn` (the gate's close).
    cancelFn: *const fn (h: *Handler, id: ?u32) void,
    resetFn: *const fn (h: *Handler) void,
};

pub const Config = struct {
    /// The job's id (its directory's name), `ID` in `/info` and what tells two jobs' APIs apart.
    job: []const u8,
    /// The job's own hostname (`--hostname`), `Name` in `/info`; "" for a neutral one.
    hostname: []const u8 = "",
    /// The runner's version, as `--version` prints it.
    version: []const u8,
    limits: Limits = .{},
    /// What answers `POST /build` and `/images`; without it they are 501.
    handler: ?*Handler = null,
    /// A directory of the job's, where a build's context is kept while it is read: its own files
    /// `api-<n>.tar`. Required with a handler.
    work_dir: []const u8 = "",
    /// Tests only: how long a request waits before it is routed and counted, so that a test can
    /// end a step with its request still unread (`settle`).
    test_route_delay_ms: u32 = 0,
};

/// What a job did with its API, said once when the job ends (`Server.stop`).
pub const Stats = struct {
    connections: u32 = 0,
    requests: u32 = 0,
    /// Answered 501: the endpoint is not there yet.
    unsupported: u32 = 0,
    /// Answered 4xx: malformed, too large, too slow, a version out of range.
    refused: u32 = 0,
    /// The ones of those that were a timeout.
    timeouts: u32 = 0,
    /// Turned away for want of a free connection.
    busy: u32 = 0,
    /// Answered 429: over the job's request budget.
    limited: u32 = 0,
    /// Requests that were anything but a 200 (`/_ping`, `/version`, `/info`) answered: those that
    /// would have an effect once there are any (1b), which the step cache must not replay.
    beyond: u32 = 0,
    /// Builds started (`POST /build` with a context read).
    builds: u32 = 0,
    /// Turned away because no step was running (the gate was closed).
    gated: u32 = 0,
};

pub const Server = struct {
    gpa: Allocator,
    cfg: Config,
    path: []const u8,
    listen_fd: linux.fd_t,
    /// Readable for good once `stop` is called.
    wake_fd: linux.fd_t,
    thread: std.Thread = undefined,
    slots: []Slot,
    /// `/version` and `/info`, made once at the start: a client asking again costs a copy.
    version_body: []const u8,
    info_body: []const u8,
    /// Readable for good while `settle` waits: a connection with nothing more to read says so.
    settle_fd: linux.fd_t,
    settle_epoch: std.atomic.Value(u32) = .init(0),
    /// The request budget: milli-tokens in the high half, the `nowMs` of the last refill below.
    bucket: std.atomic.Value(u64),
    counters: struct {
        connections: std.atomic.Value(u32) = .init(0),
        requests: std.atomic.Value(u32) = .init(0),
        unsupported: std.atomic.Value(u32) = .init(0),
        refused: std.atomic.Value(u32) = .init(0),
        timeouts: std.atomic.Value(u32) = .init(0),
        busy: std.atomic.Value(u32) = .init(0),
        limited: std.atomic.Value(u32) = .init(0),
        beyond: std.atomic.Value(u32) = .init(0),
        builds: std.atomic.Value(u32) = .init(0),
        gated: std.atomic.Value(u32) = .init(0),
    } = .{},
    /// The gate: the high bit says it is closed, the rest counts the requests in flight.
    gate: std.atomic.Value(u32) = .init(0),
    /// A build (its upload and its run) is in hand: one at a time per job.
    building: std.atomic.Value(bool) = .init(false),
    /// What the job's uploads have spooled so far.
    spooled: std.atomic.Value(u64) = .init(0),

    const Slot = struct {
        thread: ?std.Thread = null,
        done: std.atomic.Value(bool) = .init(false),
        /// A connection is being served in it, and which one (a slot is reused).
        live: std.atomic.Value(bool) = .init(false),
        generation: std.atomic.Value(u32) = .init(0),
        /// The `settle` this connection last answered.
        ack: std.atomic.Value(u32) = .init(0),
        server: *Server = undefined,
        fd: linux.fd_t = -1,
    };

    /// Listens on a socket made at `path` (made `0666`) and answers on a thread of its own. The
    /// socket's file is removed by `stop`.
    pub fn start(gpa: Allocator, path: []const u8, cfg: Config) !*Server {
        const lfd = try listenAt(path);
        errdefer {
            _ = linux.close(lfd);
            unlinkPath(path);
        }
        const wfd = try fdOf(linux.eventfd(0, linux.EFD.CLOEXEC));
        errdefer _ = linux.close(wfd);
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        const slots = try gpa.alloc(Slot, cfg.limits.max_connections);
        errdefer gpa.free(slots);
        const owned = try gpa.dupe(u8, path);
        errdefer gpa.free(owned);
        var own_cfg = cfg;
        own_cfg.job = try gpa.dupe(u8, cfg.job);
        errdefer gpa.free(own_cfg.job);
        own_cfg.version = try gpa.dupe(u8, cfg.version);
        errdefer gpa.free(own_cfg.version);
        own_cfg.hostname = try gpa.dupe(u8, cfg.hostname);
        errdefer gpa.free(own_cfg.hostname);
        own_cfg.work_dir = try gpa.dupe(u8, cfg.work_dir);
        errdefer gpa.free(own_cfg.work_dir);
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const version_body = try gpa.dupe(u8, try versionJson(arena.allocator(), own_cfg));
        errdefer gpa.free(version_body);
        const info_body = try gpa.dupe(u8, try infoJson(arena.allocator(), own_cfg));
        errdefer gpa.free(info_body);
        const sfd = try fdOf(linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK));
        errdefer _ = linux.close(sfd);
        for (slots) |*sl| sl.* = .{};
        s.* = .{
            .gpa = gpa,
            .cfg = own_cfg,
            .path = owned,
            .listen_fd = lfd,
            .wake_fd = wfd,
            .slots = slots,
            .settle_fd = sfd,
            .version_body = version_body,
            .info_body = info_body,
            .bucket = .init(@as(u64, cfg.limits.burst) * 1000 << 32 | (nowMs() & 0xffff_ffff)),
        };
        s.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, acceptLoop, .{s});
        return s;
    }

    /// Wakes and joins every thread, removes the socket and frees the server. What the job did.
    pub fn stop(s: *Server) Stats {
        const one: u64 = 1;
        _ = linux.write(s.wake_fd, std.mem.asBytes(&one).ptr, @sizeOf(u64));
        s.thread.join();
        const st = s.stats();
        _ = linux.close(s.listen_fd);
        _ = linux.close(s.wake_fd);
        _ = linux.close(s.settle_fd);
        unlinkPath(s.path);
        const gpa = s.gpa;
        gpa.free(s.path);
        gpa.free(s.cfg.job);
        gpa.free(s.cfg.version);
        gpa.free(s.cfg.hostname);
        gpa.free(s.cfg.work_dir);
        gpa.free(s.version_body);
        gpa.free(s.info_body);
        gpa.free(s.slots);
        gpa.destroy(s);
        return st;
    }

    pub fn stats(s: *const Server) Stats {
        const c = &s.counters;
        return .{
            .connections = c.connections.load(.acquire),
            .requests = c.requests.load(.acquire),
            .unsupported = c.unsupported.load(.acquire),
            .refused = c.refused.load(.acquire),
            .timeouts = c.timeouts.load(.acquire),
            .busy = c.busy.load(.acquire),
            .limited = c.limited.load(.acquire),
            .beyond = c.beyond.load(.acquire),
            .builds = c.builds.load(.acquire),
            .gated = c.gated.load(.acquire),
        };
    }

    /// Takes one request from the budget: null when there was one, else the milliseconds until
    /// there is.
    fn admit(s: *Server) ?u32 {
        return takeToken(&s.bucket, s.cfg.limits, realClock);
    }

    /// Returns once every connection has taken in what its client had sent before this call (a
    /// step's processes are gone when the runner asks), so that what the step asked of the API is
    /// counted (`Stats.beyond`) before anything reads the count. Each connection is asked, at its
    /// next wait for a request, whether it has more to read: one that does reads it first. At most
    /// `settle_ms`.
    pub fn settle(s: *Server) void {
        const deadline = nowMs() + s.cfg.limits.settle_ms;
        // A connection still in the listen queue is taken first.
        while (nowMs() < deadline) {
            var queue = [_]linux.pollfd{.{ .fd = s.listen_fd, .events = linux.POLL.IN, .revents = 0 }};
            var wake = [_]linux.pollfd{.{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 }};
            const queued = linux.poll(&queue, 1, 0) > 0 and queue[0].revents & linux.POLL.IN != 0;
            if (!queued) break;
            if (linux.poll(&wake, 1, 1) > 0 and wake[0].revents != 0) return;
        }
        // And the one just taken is given a slot.
        _ = waitStop(s, 2);
        var live: [32]struct { slot: *Slot, generation: u32 } = undefined;
        var n: usize = 0;
        for (s.slots) |*sl| {
            if (n == live.len) break;
            if (sl.live.load(.acquire)) {
                live[n] = .{ .slot = sl, .generation = sl.generation.load(.acquire) };
                n += 1;
            }
        }
        if (n == 0) return;
        const epoch = s.settle_epoch.fetchAdd(1, .acq_rel) +% 1;
        const one: u64 = 1;
        _ = linux.write(s.settle_fd, std.mem.asBytes(&one).ptr, @sizeOf(u64));
        while (nowMs() < deadline) {
            var all = true;
            for (live[0..n]) |l| {
                const gone = !l.slot.live.load(.acquire) or l.slot.generation.load(.acquire) != l.generation;
                if (!gone and l.slot.ack.load(.acquire) != epoch) all = false;
            }
            if (all) break;
            var wake = [_]linux.pollfd{.{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 }};
            if (linux.poll(&wake, 1, 1) > 0 and wake[0].revents != 0) break;
        }
        var drained: u64 = 0;
        _ = linux.read(s.settle_fd, std.mem.asBytes(&drained).ptr, @sizeOf(u64));
    }

    const gate_closed_bit: u32 = 1 << 31;

    /// Lets requests in: a step's processes may run now.
    pub fn openGate(s: *Server) void {
        if (s.cfg.handler) |h| h.resetFn(h);
        _ = s.gate.fetchAnd(~gate_closed_bit, .acq_rel);
    }

    /// Turns requests away (503) from now on, cancels what is in flight, waits for it to end
    /// (without a limit: the builder and unpacker see the cancel between their steps) and then takes
    /// in what clients had sent before they went (`settle`), which is told 503 and counted. Returns
    /// false only when the server was stopped meanwhile.
    pub fn closeGate(s: *Server) bool {
        const before = s.gate.fetchOr(gate_closed_bit, .acq_rel);
        var clean = true;
        if (before & ~gate_closed_bit != 0) {
            if (s.cfg.handler) |h| h.cancelFn(h, null);
            // Until it has ended, whatever it takes: a build that kept running into the next step
            // would be counted against it (the builder and the unpacker look at the cancel
            // between their steps). Only the server's stop ends this wait early.
            var rounds: u32 = 0;
            while (s.gate.load(.acquire) & ~gate_closed_bit != 0) {
                if (!waitStop(s, 1)) {
                    clean = false;
                    break;
                }
                // The cancel again now and then: a sandbox that began after the first one is
                // stopped by it too.
                rounds += 1;
                if (rounds % 100 == 0) if (s.cfg.handler) |h| h.cancelFn(h, null);
            }
        }
        // A request that did not end in time is one the step's count cannot be trusted about.
        if (!clean) s.bump("beyond");
        s.settle();
        return clean;
    }

    /// A request is let in, or told the gate is closed.
    fn enter(s: *Server) bool {
        var cur = s.gate.load(.acquire);
        while (true) {
            if (cur & gate_closed_bit != 0) return false;
            cur = s.gate.cmpxchgWeak(cur, cur + 1, .acq_rel, .acquire) orelse return true;
        }
    }

    fn leave(s: *Server) void {
        _ = s.gate.fetchSub(1, .acq_rel);
    }

    fn bump(s: *Server, comptime field: []const u8) void {
        _ = @field(s.counters, field).fetchAdd(1, .acq_rel);
    }

    fn acceptLoop(s: *Server) void {
        defer for (s.slots) |*sl| if (sl.thread) |t| {
            t.join();
            sl.thread = null;
        };
        while (true) {
            var fds = [_]linux.pollfd{
                .{ .fd = s.listen_fd, .events = linux.POLL.IN, .revents = 0 },
                .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
            };
            const rc = linux.poll(&fds, fds.len, -1);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return,
            }
            if (fds[1].revents != 0) return;
            if (fds[0].revents & linux.POLL.IN == 0) {
                if (fds[0].revents != 0) return;
                continue;
            }
            // A refusal (a connection that went, no descriptors left) is tried again when the next
            // one arrives.
            const fd = fdOf(linux.accept4(s.listen_fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK)) catch {
                // Out of descriptors or memory: the connection stays queued and the poll above
                // would return at once, so wait a moment (or for the stop) instead of spinning.
                var wake = [_]linux.pollfd{.{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 }};
                if (linux.poll(&wake, 1, accept_backoff_ms) > 0 and wake[0].revents != 0) return;
                continue;
            };
            s.bump("connections");
            const slot = s.freeSlot() orelse {
                s.bump("busy");
                s.bump("refused");
                // One short write into a fresh socket's buffer: it cannot block.
                if (sendAll(s, fd, busy_answer, 100)) {} else |_| {} // the peer going is no matter
                _ = linux.close(fd);
                // A connect-and-close loop gets no more than this many a second of the runner's
                // time: the wait is the cost of being refused.
                if (!waitStop(s, busy_delay_ms)) return;
                continue;
            };
            // Field by field: `settle` reads the atomic ones from another thread.
            slot.server = s;
            slot.fd = fd;
            slot.done.store(false, .release);
            slot.ack.store(0, .release);
            slot.generation.store(slot.generation.load(.monotonic) +% 1, .release);
            slot.live.store(true, .release);
            slot.thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, connection, .{slot}) catch {
                // No thread will clear it: a `settle` would wait for a connection that is not.
                slot.live.store(false, .release);
                _ = linux.close(fd);
                continue;
            };
        }
    }

    /// A slot with no thread, after the finished ones were joined.
    fn freeSlot(s: *Server) ?*Slot {
        var free: ?*Slot = null;
        for (s.slots) |*sl| {
            if (sl.thread) |t| if (sl.done.load(.acquire)) {
                t.join();
                sl.thread = null;
            };
            if (sl.thread == null and free == null) free = sl;
        }
        if (free) |f| f.done.store(false, .release);
        return free;
    }
};

const accept_backoff_ms = 100;
/// `POLLRDHUP`: the peer shut its end of the socket.
const poll_rdhup: i16 = 0x2000;
const busy_delay_ms = 10;

const Clock = *const fn () u32;

fn realClock() u32 {
    return @truncate(nowMs());
}

/// Takes a token from `bucket` (milli-tokens above, the clock's last refill below): null when it
/// did, else the milliseconds until one is due. The clock is read in every round of the loop, so a
/// thread that lost the race does not refill from a reading older than the bucket's; a reading
/// behind the bucket's own refills nothing and moves nothing back.
fn takeToken(bucket: *std.atomic.Value(u64), lim: Limits, clock: Clock) ?u32 {
    var old = bucket.load(.acquire);
    while (true) {
        const now = clock();
        const tokens: u64 = old >> 32;
        const last: u32 = @truncate(old);
        const since = now -% last;
        const behind = since > (1 << 31);
        const refill: u64 = if (behind) 0 else @as(u64, since) * lim.rate_per_s;
        const have = @min(@as(u64, lim.burst) * 1000, tokens + refill);
        if (have < 1000) {
            const rate = @max(lim.rate_per_s, 1);
            return std.math.lossyCast(u32, @max(1, (1000 - have + rate - 1) / rate));
        }
        const next = (have - 1000) << 32 | (if (behind) last else now);
        old = bucket.cmpxchgWeak(old, next, .acq_rel, .acquire) orelse return null;
    }
}

const limited_body = "{\"message\":\"too many requests to this job's Docker API: slow down\"}\n";
/// A 429, ready to send: no request is parsed or answered at this cost.
const limited_answer = std.fmt.comptimePrint(
    "HTTP/1.1 429 Too Many Requests\r\nApi-Version: " ++ api_version ++ "\r\nContent-Type: application/json\r\n" ++
        "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
    .{ limited_body.len, limited_body },
);

const busy_answer = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n" ++
    "Content-Length: 46\r\nConnection: close\r\n\r\n" ++
    "{\"message\":\"too many connections to the API\"}\n";

// --- the socket ---

/// The descriptor a syscall returned, or its failure.
fn fdOf(rc: usize) error{Syscall}!linux.fd_t {
    if (linux.errno(rc) != .SUCCESS) return error.Syscall;
    return std.math.cast(linux.fd_t, rc) orelse error.Syscall;
}

/// A socket address as `bind` takes it (`sockaddr`) and as it is made (`sockaddr.un`).
const Addr = extern union { base: linux.sockaddr, un: linux.sockaddr.un };

/// A listening unix socket at `path`, `0666`. A path past `sun_path` is bound through the
/// directory's descriptor (`/proc/self/fd/N/name`).
fn listenAt(path: []const u8) !linux.fd_t {
    const fd = try fdOf(linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0));
    errdefer _ = linux.close(fd);
    var guard: DirFd = .{};
    defer guard.close();
    const addr = try unixAddr(path, &guard);
    const as_base: Addr = .{ .un = addr };
    switch (linux.errno(linux.bind(fd, &as_base.base, @sizeOf(linux.sockaddr.un)))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Bind,
    }
    errdefer unlinkPath(path);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = zpath(&buf, "{s}", .{path}) catch return error.NameTooLong;
    if (linux.errno(linux.chmod(z, 0o666)) != .SUCCESS) return error.Chmod;
    if (linux.errno(linux.listen(fd, 16)) != .SUCCESS) return error.Listen;
    return fd;
}

/// An O_PATH descriptor of a socket's directory, held while a long path is used through it.
const DirFd = struct {
    fd: linux.fd_t = -1,

    fn close(g: *DirFd) void {
        if (g.fd >= 0) _ = linux.close(g.fd);
        g.fd = -1;
    }
};

fn unixAddr(path: []const u8, guard: *DirFd) !linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len < addr.path.len) {
        @memcpy(addr.path[0..path.len], path);
        return addr;
    }
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.NameTooLong;
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = zpath(&dir_buf, "{s}", .{if (slash == 0) "/" else path[0..slash]}) catch
        return error.NameTooLong;
    guard.fd = fdOf(linux.open(dir, .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0)) catch
        return error.NameTooLong;
    const via = std.fmt.bufPrint(&addr.path, "/proc/self/fd/{d}/{s}", .{ guard.fd, path[slash + 1 ..] }) catch
        return error.NameTooLong;
    addr.path[via.len] = 0;
    return addr;
}

/// `text` in `buf`, null-terminated.
fn zpath(buf: []u8, comptime fmt: []const u8, args: anytype) ![:0]u8 {
    const s = try std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

fn unlinkPath(path: []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = zpath(&buf, "{s}", .{path}) catch return;
    _ = linux.unlink(z);
}

/// A connection to the socket at `path`, blocking: for the runner's tests, and a client's probe.
pub fn connect(path: []const u8) !linux.fd_t {
    const fd = try fdOf(linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0));
    errdefer _ = linux.close(fd);
    var guard: DirFd = .{};
    defer guard.close();
    const addr = try unixAddr(path, &guard);
    if (linux.errno(linux.connect(fd, &addr, @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.Connect;
    return fd;
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return std.math.lossyCast(u64, ts.sec) * 1000 + std.math.lossyCast(u64, ts.nsec) / 1_000_000;
}

const Wait = enum { ready, timeout, stopped, gone };

/// Waits `ms` or until the stop: false when it was the stop.
fn waitStop(s: *const Server, ms: u32) bool {
    var wake = [_]linux.pollfd{.{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 }};
    return !(linux.poll(&wake, 1, std.math.lossyCast(i32, ms)) > 0 and wake[0].revents != 0);
}

/// `waitFor` the connection to be readable, which also answers a `settle` once the connection has
/// nothing to read: a poll that finds data takes it first.
fn waitHead(s: *const Server, slot: *Server.Slot, deadline: u64) Wait {
    const fd = slot.fd;
    // Set once a `settle` in progress has been answered: its eventfd stays readable until it ends,
    // so it is left out of the next poll, which then does not wait long.
    var answered = false;
    while (true) {
        const now = nowMs();
        if (now >= deadline) return .timeout;
        var fds = [_]linux.pollfd{
            .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
            // Always in the poll otherwise: an idle connection hears of a settle at once.
            .{ .fd = if (answered) -1 else s.settle_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const left = std.math.lossyCast(i32, deadline - now);
        const rc = linux.poll(&fds, fds.len, if (answered) @min(left, 2) else left);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return .gone,
        }
        if (fds[1].revents != 0) return .stopped;
        if (fds[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0) return .ready;
        answered = false;
        if (fds[2].revents != 0) {
            const epoch = s.settle_epoch.load(.acquire);
            if (slot.ack.load(.acquire) != epoch) slot.ack.store(epoch, .release) else answered = true;
        }
    }
}

/// Waits for `fd` to be readable (or writable) until `deadline` (milliseconds of `nowMs`), or for
/// the server's stop.
fn waitFor(s: *const Server, fd: linux.fd_t, events: i16, deadline: u64) Wait {
    while (true) {
        const now = nowMs();
        if (now >= deadline) return .timeout;
        var fds = [_]linux.pollfd{
            .{ .fd = fd, .events = events, .revents = 0 },
            .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const left = std.math.lossyCast(i32, deadline - now);
        const rc = linux.poll(&fds, fds.len, left);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return .gone,
        }
        if (fds[1].revents != 0) return .stopped;
        if (fds[0].revents & (events | linux.POLL.HUP | linux.POLL.ERR) != 0) return .ready;
    }
}

/// All of `bytes`, in `write_ms`.
fn sendAll(s: *Server, fd: linux.fd_t, bytes: []const u8, write_ms: u32) error{ Timeout, Gone }!void {
    const deadline = nowMs() + write_ms;
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.sendto(fd, bytes[off..].ptr, bytes.len - off, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => {},
            .AGAIN => switch (waitFor(s, fd, linux.POLL.OUT, deadline)) {
                .ready => {},
                .timeout => return error.Timeout,
                .stopped, .gone => return error.Gone,
            },
            else => return error.Gone,
        }
    }
}

// --- one connection ---

fn connection(slot: *Server.Slot) void {
    const s = slot.server;
    defer {
        _ = linux.close(slot.fd);
        slot.live.store(false, .release);
        slot.done.store(true, .release);
    }
    var arena: std.heap.ArenaAllocator = .init(s.gpa);
    defer arena.deinit();
    serve(s, slot, &arena);
}

fn serve(s: *Server, slot: *Server.Slot, arena: *std.heap.ArenaAllocator) void {
    const fd = slot.fd;
    const lim = s.cfg.limits;
    const head_buf = s.gpa.alloc(u8, lim.header_bytes) catch return;
    defer s.gpa.free(head_buf);
    var have: usize = 0;
    var served: u32 = 0;
    while (served < lim.max_requests) {
        _ = arena.reset(.retain_capacity);
        // The head: to its blank line, in `header_ms` from its first byte (`idle_ms` for that).
        var deadline = nowMs() + lim.idle_ms;
        var started = have > 0;
        if (started) deadline = nowMs() + lim.header_ms;
        const end = while (true) {
            if (std.mem.indexOf(u8, head_buf[0..have], "\r\n\r\n")) |i| break i + 4;
            if (have == head_buf.len) {
                s.bump("refused");
                _ = reply(s, fd, arena.allocator(), 431, error_json(arena.allocator(), "request header too large"), false, false);
                return;
            }
            switch (waitHead(s, slot, deadline)) {
                .ready => {},
                .timeout => {
                    if (started) {
                        s.bump("timeouts");
                        s.bump("refused");
                        _ = reply(s, fd, arena.allocator(), 408, error_json(arena.allocator(), "request timeout"), false, false);
                    }
                    return;
                },
                .stopped, .gone => return,
            }
            const rc = linux.recvfrom(fd, head_buf[have..].ptr, head_buf.len - have, linux.MSG.DONTWAIT, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return,
            }
            if (rc == 0) return;
            have += rc;
            if (!started) {
                started = true;
                deadline = nowMs() + lim.header_ms;
            }
        };
        const a = arena.allocator();
        const req = parseHead(head_buf[0..end], lim) catch |e| {
            s.bump("refused");
            _ = s.counters.requests.fetchAdd(1, .acq_rel);
            const status: u16 = if (e == error.TargetTooLong) 414 else 400;
            _ = reply(s, fd, a, status, error_json(a, switch (e) {
                error.TargetTooLong => "request target too long",
                else => "malformed HTTP request",
            }), false, false);
            return;
        };
        s.bump("requests");
        served += 1;
        const has_body = req.chunked or (req.content_length orelse 0) > 0;
        if (s.admit() != null) {
            // Over the budget: the client waits, is told once, and is let go. Nothing is parsed
            // further or allocated, so a flood costs the runner little and a thread's time is the
            // flooder's to wait.
            s.bump("limited");
            s.bump("refused");
            s.bump("beyond");
            _ = waitStop(s, lim.deny_delay_ms);
            if (sendAll(s, fd, limited_answer, lim.write_ms)) {} else |_| {}
            return;
        }
        if (!s.enter()) {
            // Between steps (or after the step's processes are gone): nothing of the job is
            // there to ask. Counted, so a step that sent it is not stored; the connection closes.
            s.bump("gated");
            s.bump("refused");
            s.bump("beyond");
            _ = reply(s, fd, a, 503, error_json(a, gate_closed), req.head_only, false);
            if (has_body) drain(s, fd, lim);
            return;
        }
        const keep_open = dispatch(s, slot, arena, req, head_buf[end..have], has_body, served);
        s.leave();
        if (!keep_open) return;
        // What came after the head (a pipelined request) stays for the next round.
        std.mem.copyForwards(u8, head_buf[0 .. have - end], head_buf[end..have]);
        have -= end;
    }
}

/// One admitted request, answered. False when the connection is to be closed.
fn dispatch(
    s: *Server,
    slot: *Server.Slot,
    arena: *std.heap.ArenaAllocator,
    req: Request,
    after_head: []const u8,
    has_body: bool,
    served: u32,
) bool {
    const fd = slot.fd;
    const lim = s.cfg.limits;
    const a = arena.allocator();
    if (s.cfg.test_route_delay_ms > 0) _ = waitStop(s, s.cfg.test_route_delay_ms);
    const routed = route(a, s, req.method, req.target) catch Routed{ .answer = Answer.oom };
    const answer = switch (routed) {
        .answer => |ans| ans,
        .build => |query| {
            s.bump("beyond");
            serveBuild(s, slot, arena, req, after_head, query);
            return false;
        },
        .image => |op| img: {
            s.bump("beyond");
            const h = s.cfg.handler.?;
            const got = h.imageFn(h, a, op);
            break :img Answer{ .status = got.status, .body = got.body };
        },
    };
    switch (answer.status) {
        200 => {},
        501 => {
            s.bump("unsupported");
            s.bump("beyond");
        },
        400...428, 430...499 => {
            s.bump("refused");
            s.bump("beyond");
        },
        else => s.bump("beyond"),
    }
    // A request with a body is answered and the connection closed: the body is not kept.
    const keep = req.keep_alive and !has_body and served < lim.max_requests;
    if (!reply(s, fd, a, answer.status, answer, req.head_only, keep)) return false;
    if (!keep) {
        if (has_body) drain(s, fd, lim);
        return false;
    }
    return true;
}

/// Reads and drops what the client is still sending, so that closing does not reset the
/// connection with our answer unread (the CLI sends a build's context while reading the answer).
fn drain(s: *Server, fd: linux.fd_t, lim: Limits) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
    const deadline = nowMs() + lim.drain_ms;
    var left = lim.drain_bytes;
    var junk: [4096]u8 = undefined;
    while (left > 0) {
        if (waitFor(s, fd, linux.POLL.IN, deadline) != .ready) return;
        const rc = linux.recvfrom(fd, &junk, junk.len, linux.MSG.DONTWAIT, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return,
        }
        if (rc == 0) return;
        left -|= rc;
    }
}

// --- requests ---

const Request = struct {
    method: []const u8,
    target: []const u8,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool = true,
    head_only: bool = false,
};

const ParseError = error{ Malformed, TargetTooLong };

/// The request line and headers of `head` (to and with its blank line). The slices are in `head`.
fn parseHead(head: []const u8, lim: Limits) ParseError!Request {
    var lines = std.mem.splitSequence(u8, head[0 .. head.len - 4], "\r\n");
    const line = lines.next().?;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next().?;
    const target = parts.next() orelse return error.Malformed;
    const version = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;
    if (method.len == 0 or method.len > 16) return error.Malformed;
    for (method) |ch| if (!std.ascii.isUpper(ch)) return error.Malformed;
    if (target.len == 0 or target[0] != '/') return error.Malformed;
    if (target.len > lim.target_bytes) return error.TargetTooLong;
    for (target) |ch| if (ch <= ' ' or ch == 127) return error.Malformed;
    const http11 = std.mem.eql(u8, version, "HTTP/1.1");
    if (!http11 and !std.mem.eql(u8, version, "HTTP/1.0")) return error.Malformed;
    var req: Request = .{
        .method = method,
        .target = target,
        .keep_alive = http11,
        .head_only = std.mem.eql(u8, method, "HEAD"),
    };
    var host = false;
    while (lines.next()) |h| {
        // No folded lines, no bare line feeds or control characters: a smuggler's tools.
        for (h) |ch| if ((ch < ' ' and ch != '\t') or ch == 127) return error.Malformed;
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.Malformed;
        const name = h[0..colon];
        if (name.len == 0) return error.Malformed;
        for (name) |ch| if (!isTokenChar(ch)) return error.Malformed;
        const value = std.mem.trim(u8, h[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const n = std.fmt.parseInt(u64, value, 10) catch return error.Malformed;
            if (req.content_length) |old| if (old != n) return error.Malformed;
            req.content_length = n;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.Malformed;
            req.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.findIgnoreCase(value, "close") != null) req.keep_alive = false;
            if (!http11 and std.ascii.findIgnoreCase(value, "keep-alive") != null) req.keep_alive = true;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            host = true;
        }
    }
    if (req.chunked and req.content_length != null) return error.Malformed;
    // Docker's client sends one; HTTP/1.1 requires it.
    if (http11 and !host) return error.Malformed;
    return req;
}

fn isTokenChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", ch) != null;
}

// --- answers ---

const Answer = struct {
    status: u16,
    body: []const u8,
    content_type: []const u8 = "application/json",
    /// Only on /_ping: Docker's headers (the others carry them too, as the daemon's do).
    const oom: Answer = .{ .status = 500, .body = "{\"message\":\"out of memory\"}\n" };
};

fn error_json(a: Allocator, message: []const u8) Answer {
    return .{ .status = 0, .body = jsonMessage(a, message) catch "{\"message\":\"error\"}\n" };
}

/// `{"message":<message>}` and a newline, as Docker's daemon writes its errors.
fn jsonMessage(a: Allocator, message: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    try out.writer.writeAll("{\"message\":");
    try std.json.Stringify.value(message, .{}, &out.writer);
    try out.writer.writeAll("}\n");
    return out.written();
}

fn failure(a: Allocator, status: u16, message: []const u8) !Answer {
    return .{ .status = status, .body = try jsonMessage(a, message) };
}

fn reasonOf(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        408 => "Request Timeout",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        else => "Error",
    };
}

/// The prefix `/vMAJOR.MINOR` of `path`, if it has one: its version, and the path after it.
const Versioned = struct { major: u32, minor: u32, rest: []const u8 };

const Prefix = union(enum) { none, malformed, ok: Versioned };

/// A number as Docker's clients write one: one to three digits, no sign, no leading zero.
fn canonical(text: []const u8) ?u32 {
    if (text.len == 0 or text.len > 3) return null;
    if (text.len > 1 and text[0] == '0') return null;
    for (text) |ch| if (!std.ascii.isDigit(ch)) return null;
    return std.fmt.parseInt(u32, text, 10) catch null;
}

/// `/v` and a digit start a version; a segment that starts one and is not `N.N` canonically (`/v1.+40`,
/// `/v01.052`, `/v1.99999`) is `.malformed`, any other path has none.
fn versionPrefix(path: []const u8) Prefix {
    if (path.len < 3 or path[0] != '/' or path[1] != 'v' or !std.ascii.isDigit(path[2])) return .none;
    const end = std.mem.indexOfScalarPos(u8, path, 1, '/') orelse path.len;
    const ver = path[2..end];
    const dot = std.mem.indexOfScalar(u8, ver, '.') orelse return .none;
    const major = canonical(ver[0..dot]) orelse return .malformed;
    const minor = canonical(ver[dot + 1 ..]) orelse return .malformed;
    return .{ .ok = .{ .major = major, .minor = minor, .rest = path[end..] } };
}

/// `text` as UTF-8 for a JSON string: a byte that is not part of a valid sequence becomes U+FFFD,
/// and what is past `max` bytes is cut at a character boundary.
fn cleanText(a: Allocator, text: []const u8, max: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
        const valid = n > 0 and i + n <= text.len and std.unicode.utf8ValidateSlice(text[i .. i + n]);
        const piece: []const u8 = if (valid) text[i .. i + n] else "\u{FFFD}";
        if (out.items.len + piece.len > max) break;
        try out.appendSlice(a, piece);
        i += if (valid) n else 1;
    }
    return out.items;
}

/// What a request comes to: an answer made at once, or work for the handler.
const Routed = union(enum) {
    answer: Answer,
    /// `POST /build`, with the query's text.
    build: []const u8,
    image: ImageOp,
};

/// What `method target` is answered, for the server's config. A status of 0 in an `Answer` the
/// caller makes itself (`error_json`) stands for the one it gives.
fn route(a: Allocator, s: *const Server, method: []const u8, target: []const u8) !Routed {
    const q = std.mem.indexOfScalar(u8, target, '?');
    var path = target[0 .. q orelse target.len];
    const query = if (q) |i| target[i + 1 ..] else "";
    switch (versionPrefix(path)) {
        .none => {},
        .malformed => return .{ .answer = try failure(a, 400, "invalid API version prefix: a version is /v1.NN, with no sign or leading zero") },
        .ok => |v| {
            if (v.major != 1 or v.minor > newest_minor) return .{ .answer = try failure(a, 400, try std.fmt.allocPrint(
                a,
                "client version {d}.{d} is too new. Maximum supported API version is " ++ api_version,
                .{ v.major, v.minor },
            )) };
            if (v.minor < oldest_minor) return .{ .answer = try failure(a, 400, try std.fmt.allocPrint(
                a,
                "client version {d}.{d} is too old. Minimum supported API version is " ++
                    min_api_version ++ ", please upgrade your client to a newer version",
                .{ v.major, v.minor },
            )) };
            path = if (v.rest.len == 0) "/" else v.rest;
        },
    }
    const is_get = std.mem.eql(u8, method, "GET");
    if ((is_get or std.mem.eql(u8, method, "HEAD")) and std.mem.eql(u8, path, "/_ping"))
        return .{ .answer = .{ .status = 200, .body = "OK", .content_type = "text/plain; charset=utf-8" } };
    if (is_get and std.mem.eql(u8, path, "/version")) return .{ .answer = .{ .status = 200, .body = s.version_body } };
    if (is_get and std.mem.eql(u8, path, "/info")) return .{ .answer = .{ .status = 200, .body = s.info_body } };
    // `docker buildx build` looks for its builder's container (`buildx_buildkit_<name>`) first.
    if (std.mem.eql(u8, path, "/grpc") or std.mem.eql(u8, path, "/session") or
        std.mem.startsWith(u8, path, "/containers/buildx_buildkit"))
        return .{ .answer = try failure(a, 501, buildkit_hint) };
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/build")) {
        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |p| if (std.mem.eql(u8, p, "version=2"))
            return .{ .answer = try failure(a, 501, buildkit_hint) };
        if (s.cfg.handler == null) return .{ .answer = try failure(a, 501, build_unavailable) };
        return .{ .build = query };
    }
    if (s.cfg.handler != null) if (try imageRoute(a, method, path, query)) |r| return r;
    return .{ .answer = try failure(a, 501, try std.fmt.allocPrint(
        a,
        "not supported by zig-runner yet: {s} {s}",
        .{ try cleanText(a, method, 16), try cleanText(a, path, 200) },
    )) };
}

/// `/images/{name}/json`, `/images/{name}/tag` and `/images/{name}` (the name may hold slashes and
/// be percent-encoded); null for any other path.
fn imageRoute(a: Allocator, method: []const u8, path: []const u8, query: []const u8) !?Routed {
    const prefix = "/images/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const rest = path[prefix.len..];
    const is_get = std.mem.eql(u8, method, "GET");
    const is_post = std.mem.eql(u8, method, "POST");
    const is_delete = std.mem.eql(u8, method, "DELETE");
    var name_enc: []const u8 = "";
    if (is_get and std.mem.endsWith(u8, rest, "/json")) {
        name_enc = rest[0 .. rest.len - "/json".len];
    } else if (is_post and std.mem.endsWith(u8, rest, "/tag")) {
        name_enc = rest[0 .. rest.len - "/tag".len];
    } else if (is_delete) {
        name_enc = rest;
    } else return null;
    // `/images/json` and `/images/search` are the list and the search, not an image.
    if (name_enc.len == 0) return null;
    const name = (try docker_build.pathDecode(a, name_enc)) orelse
        return .{ .answer = try failure(a, 400, "invalid image name: a bad percent escape") };
    if (is_get) return .{ .image = .{ .inspect = name } };
    var repo: []const u8 = "";
    var tag: []const u8 = "";
    var force = false;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |part| {
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse part.len;
        const k = (try docker_build.percentDecode(a, part[0..eq])) orelse continue;
        const v = (try docker_build.percentDecode(a, if (eq < part.len) part[eq + 1 ..] else "")) orelse continue;
        if (std.mem.eql(u8, k, "repo")) repo = v else if (std.mem.eql(u8, k, "tag")) tag = v else if (std.mem.eql(u8, k, "force")) force = docker_build.boolValue(v);
    }
    if (is_post) return .{ .image = .{ .tag = .{ .name = name, .repo = repo, .tag = tag } } };
    return .{ .image = .{ .remove = .{ .name = name, .force = force } } };
}

/// `{}` where a struct's field must be an object and an empty tuple would be `[]`.
const empty_object = struct {}{};

fn archName() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    };
}

fn kernelOf() struct { release: [64:0]u8, host: [64:0]u8 } {
    var u: linux.utsname = undefined;
    if (linux.errno(linux.uname(&u)) != .SUCCESS) return .{ .release = @splat(0), .host = @splat(0) };
    return .{ .release = u.release, .host = u.nodename };
}

fn cstr(buf: *const [64:0]u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

fn versionJson(a: Allocator, cfg: Config) ![]const u8 {
    const k = kernelOf();
    const kernel = cstr(&k.release);
    const version = std.mem.trimStart(u8, cfg.version, "v");
    const details = .{
        .ApiVersion = api_version,
        .Arch = archName(),
        .BuildTime = "",
        .Experimental = "false",
        .GitCommit = "",
        .GoVersion = "",
        .KernelVersion = kernel,
        .MinAPIVersion = min_api_version,
        .Os = "linux",
    };
    var out: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{
        .Platform = .{ .Name = "zig-runner" },
        .Components = .{.{ .Name = "Engine", .Version = version, .Details = details }},
        .Version = version,
        .ApiVersion = api_version,
        .MinAPIVersion = min_api_version,
        .GitCommit = "",
        .GoVersion = "",
        .Os = "linux",
        .Arch = archName(),
        .KernelVersion = kernel,
        .BuildTime = "",
    }, .{}, &out.writer);
    try out.writer.writeByte('\n');
    return out.written();
}

fn infoJson(a: Allocator, cfg: Config) ![]const u8 {
    const k = kernelOf();
    var si: linux.Sysinfo = undefined;
    const mem: u64 = if (linux.errno(linux.sysinfo(&si)) == .SUCCESS) @as(u64, si.totalram) * si.mem_unit else 0;
    const cpus: usize = std.Thread.getCpuCount() catch 1;
    const version = std.mem.trimStart(u8, cfg.version, "v");
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const secs: std.time.epoch.EpochSeconds = .{ .secs = std.math.lossyCast(u64, ts.sec) };
    const day = secs.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const clock = secs.getDaySeconds();
    const now_text = try std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        day.year,                month.month.numeric(),      month.day_index + 1,
        clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute(),
    });
    var out: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{
        .ID = cfg.job,
        .Containers = 0,
        .ContainersRunning = 0,
        .ContainersPaused = 0,
        .ContainersStopped = 0,
        .Images = 0,
        .Driver = "overlay2",
        .DriverStatus = [_][2][]const u8{},
        .Plugins = .{
            .Volume = [_][]const u8{"local"},
            .Network = [_][]const u8{ "bridge", "host", "null" },
            .Authorization = null,
            .Log = [_][]const u8{"local"},
        },
        .MemoryLimit = true,
        .SwapLimit = false,
        .CpuCfsPeriod = true,
        .CpuCfsQuota = true,
        .CPUShares = true,
        .CPUSet = true,
        .PidsLimit = true,
        .IPv4Forwarding = true,
        .Debug = false,
        .NFd = 0,
        .OomKillDisable = true,
        .NGoroutines = 0,
        .SystemTime = now_text,
        .LoggingDriver = "local",
        .CgroupDriver = "cgroupfs",
        .CgroupVersion = "2",
        .NEventsListener = 0,
        .KernelVersion = cstr(&k.release),
        .OperatingSystem = "zig-runner",
        .OSVersion = "",
        .OSType = "linux",
        .Architecture = if (builtin.cpu.arch == .x86_64) "x86_64" else if (builtin.cpu.arch == .aarch64) "aarch64" else archName(),
        .IndexServerAddress = "https://index.docker.io/v1/",
        .RegistryConfig = .{
            .InsecureRegistryCIDRs = [_][]const u8{"127.0.0.0/8"},
            .IndexConfigs = empty_object,
            .Mirrors = null,
        },
        .NCPU = cpus,
        .MemTotal = mem,
        .GenericResources = null,
        .DockerRootDir = "/var/lib/docker",
        .HttpProxy = "",
        .HttpsProxy = "",
        .NoProxy = "",
        .Name = if (cfg.hostname.len > 0) cfg.hostname else "zig-runner",
        .Labels = [_][]const u8{},
        .ExperimentalBuild = false,
        .ServerVersion = version,
        .Runtimes = .{ .@"io.containerd.runc.v2" = .{ .path = "runc" }, .runc = .{ .path = "runc" } },
        .DefaultRuntime = "runc",
        .Swarm = .{
            .NodeID = "",
            .NodeAddr = "",
            .LocalNodeState = "inactive",
            .ControlAvailable = false,
            .Error = "",
            .RemoteManagers = null,
        },
        .LiveRestoreEnabled = false,
        .Isolation = "",
        .InitBinary = "docker-init",
        .SecurityOptions = [_][]const u8{ "name=seccomp,profile=builtin", "name=cgroupns" },
        .Warnings = [_][]const u8{
            "zig-runner serves a Docker-compatible API for this job; only /_ping, /version and /info are implemented so far (a build comes with stage 1b)",
        },
    }, .{}, &out.writer);
    try out.writer.writeByte('\n');
    return out.written();
}

/// Writes `answer` (a status of 0 for an `error_json`, the one it was made for: 400). Returns
/// false when the connection is gone.
fn reply(s: *Server, fd: linux.fd_t, a: Allocator, status: u16, answer: Answer, head_only: bool, keep: bool) bool {
    const code = if (answer.status == 0) status else answer.status;
    var out: std.Io.Writer.Allocating = .init(a);
    out.writer.print(
        "HTTP/1.1 {d} {s}\r\nApi-Version: " ++ api_version ++ "\r\nBuilder-Version: 1\r\n" ++
            "Docker-Experimental: false\r\nOstype: linux\r\nServer: zig-runner (linux)\r\n" ++
            "Content-Type: {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n",
        .{
            code,
            reasonOf(code),
            answer.content_type,
            answer.body.len,
            if (keep) "keep-alive" else "close",
        },
    ) catch return false;
    if (!head_only) out.writer.writeAll(answer.body) catch return false;
    sendAll(s, fd, out.written(), s.cfg.limits.write_ms) catch |e| {
        if (e == error.Timeout) s.bump("timeouts");
        return false;
    };
    return true;
}

// --- POST /build ---

const BodyEnd = enum { ok, too_large, timeout, gone, malformed, disk };

/// The request's body written to `out_fd`: `after_head` is what came behind the head already.
/// Content-Length or chunked, at most `max` bytes, each wait `idle_ms`, the whole `total_ms`.
fn readBody(
    s: *Server,
    fd: linux.fd_t,
    req: Request,
    after_head: []const u8,
    out_fd: linux.fd_t,
    max: u64,
    written: *u64,
) BodyEnd {
    const lim = s.cfg.limits;
    const total_deadline = nowMs() + lim.body_ms;
    var dec: BodyDecoder = .{ .out = out_fd, .max = max, .chunked = req.chunked, .remaining = req.content_length orelse 0 };
    if (!req.chunked and (req.content_length orelse 0) > max) return .too_large;
    var buf: [32 * 1024]u8 = undefined;
    var first = after_head;
    while (true) {
        const got: []const u8 = if (first.len > 0) blk: {
            const g = first;
            first = "";
            break :blk g;
        } else blk: {
            const deadline = @min(total_deadline, nowMs() + lim.body_idle_ms);
            switch (waitFor(s, fd, linux.POLL.IN, deadline)) {
                .ready => {},
                .timeout => return .timeout,
                .stopped, .gone => return .gone,
            }
            const rc = linux.recvfrom(fd, &buf, buf.len, linux.MSG.DONTWAIT, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return .gone,
            }
            if (rc == 0) return .gone;
            break :blk buf[0..rc];
        };
        switch (dec.feed(got)) {
            .more => {},
            .done => {
                written.* = dec.total;
                return .ok;
            },
            .too_large => return .too_large,
            .malformed => return .malformed,
            .disk => return .disk,
        }
    }
}

/// Decodes a body, whole or chunked, into a file.
const BodyDecoder = struct {
    out: linux.fd_t,
    max: u64,
    chunked: bool,
    /// Bytes of the body, or of the chunk in hand, still to come.
    remaining: u64,
    total: u64 = 0,
    state: enum { size, data, data_end, trailer } = .size,
    line: [80]u8 = undefined,
    line_len: usize = 0,
    /// A chunk's `\r\n`: how much of it was seen.
    crlf: u8 = 0,
    /// The last chunk was seen (`0`): the trailers' lines follow.
    last: bool = false,

    const Step = enum { more, done, too_large, malformed, disk };

    fn feed(d: *BodyDecoder, bytes: []const u8) Step {
        if (!d.chunked) {
            const n = std.math.lossyCast(usize, @min(d.remaining, bytes.len));
            if (!d.write(bytes[0..n])) return .disk;
            d.remaining -= n;
            return if (d.remaining == 0) .done else .more;
        }
        var i: usize = 0;
        while (i < bytes.len) {
            switch (d.state) {
                .size, .trailer => {
                    const c = bytes[i];
                    i += 1;
                    if (c != '\n') {
                        if (d.line_len == d.line.len) return .malformed;
                        d.line[d.line_len] = c;
                        d.line_len += 1;
                        continue;
                    }
                    const line = std.mem.trimEnd(u8, d.line[0..d.line_len], "\r");
                    d.line_len = 0;
                    if (d.state == .trailer) {
                        // The blank line ends the message.
                        if (line.len == 0) return .done;
                        continue;
                    }
                    const hex = line[0 .. std.mem.indexOfScalar(u8, line, ';') orelse line.len];
                    if (hex.len == 0 or hex.len > 12) return .malformed;
                    const n = std.fmt.parseInt(u64, std.mem.trim(u8, hex, " \t"), 16) catch return .malformed;
                    if (n == 0) {
                        d.state = .trailer;
                    } else {
                        if (n > d.max - d.total) return .too_large;
                        d.remaining = n;
                        d.state = .data;
                    }
                },
                .data => {
                    const n = std.math.lossyCast(usize, @min(d.remaining, bytes.len - i));
                    if (!d.write(bytes[i..][0..n])) return .disk;
                    i += n;
                    d.remaining -= n;
                    if (d.remaining == 0) {
                        d.state = .data_end;
                        d.crlf = 0;
                    }
                },
                .data_end => {
                    const want: u8 = if (d.crlf == 0) '\r' else '\n';
                    if (bytes[i] != want) return .malformed;
                    i += 1;
                    d.crlf += 1;
                    if (d.crlf == 2) d.state = .size;
                },
            }
        }
        return .more;
    }

    fn write(d: *BodyDecoder, bytes: []const u8) bool {
        if (bytes.len > d.max - d.total) return false;
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = linux.write(d.out, bytes[off..].ptr, bytes.len - off);
            switch (linux.errno(rc)) {
                .SUCCESS => off += rc,
                .INTR => {},
                else => return false,
            }
        }
        d.total += bytes.len;
        return true;
    }
};

/// The thread a build runs on, so that the connection's can watch for the client leaving.
const Worker = struct {
    h: *Handler,
    call: *BuildCall,
    done_fd: linux.fd_t,
    fn run(w: *Worker) void {
        w.h.buildFn(w.h, w.call);
        const one: u64 = 1;
        _ = linux.write(w.done_fd, std.mem.asBytes(&one).ptr, @sizeOf(u64));
    }
};

fn buildError(s: *Server, a: Allocator, fd: linux.fd_t, status: u16, message: []const u8) void {
    s.bump("refused");
    _ = reply(s, fd, a, status, error_json(a, message), false, false);
}

/// `POST /build`: the query read and the context received (before a byte of it is built), then the
/// build streamed. The connection is closed after.
fn serveBuild(
    s: *Server,
    slot: *Server.Slot,
    arena: *std.heap.ArenaAllocator,
    req: Request,
    after_head: []const u8,
    query: []const u8,
) void {
    const fd = slot.fd;
    const lim = s.cfg.limits;
    const a = arena.allocator();
    const h = s.cfg.handler.?;
    const has_body = req.chunked or (req.content_length orelse 0) > 0;
    const q = switch (docker_build.parseQuery(a, query) catch return buildError(s, a, fd, 500, "out of memory")) {
        .ok => |ok| ok,
        .bad => |m| return finishEarly(s, fd, a, 400, m, has_body),
        .unsupported => |m| return finishEarly(s, fd, a, 501, m, has_body),
    };
    if (!has_body) return buildError(s, a, fd, 400, "the build needs a context: a tar in the request's body");
    // One at a time: a second upload would hold another context's worth of disk and a thread.
    if (s.building.cmpxchgStrong(false, true, .acq_rel, .acquire) != null)
        return finishEarly(s, fd, a, 429, "another build of this job is in progress: one at a time", has_body);
    defer s.building.store(false, .release);
    const n = s.counters.builds.fetchAdd(1, .acq_rel);
    if (n >= lim.max_builds)
        return finishEarly(s, fd, a, 429, "too many builds in this job", has_body);
    const spooled = s.spooled.load(.acquire);
    if (spooled >= lim.spool_budget)
        return finishEarly(s, fd, a, 413, "this job's uploaded contexts have used what the runner allows one job", has_body);
    const tar_path = std.fmt.allocPrint(a, "{s}/api-{d}.tar", .{ s.cfg.work_dir, n }) catch
        return buildError(s, a, fd, 500, "out of memory");
    defer if (unlinkPathA(a, tar_path)) {} else |_| {};
    const out_rc = linux.open(a.dupeSentinel(u8, tar_path, 0) catch return, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o600);
    if (linux.errno(out_rc) != .SUCCESS)
        return buildError(s, a, fd, 500, "the job's directory cannot hold the build's context");
    const out_fd = fdOf(out_rc) catch
        return buildError(s, a, fd, 500, "the job's directory cannot hold the build's context");
    var got: u64 = 0;
    const end = readBody(s, fd, req, after_head, out_fd, @min(lim.body_bytes, lim.spool_budget - spooled), &got);
    _ = linux.close(out_fd);
    _ = s.spooled.fetchAdd(got, .acq_rel);
    switch (end) {
        .ok => {},
        .too_large => return buildError(s, a, fd, 413, std.fmt.allocPrint(
            a,
            "the build context is larger than {d} MiB",
            .{lim.body_bytes >> 20},
        ) catch "the build context is too large"),
        .timeout => return buildError(s, a, fd, 408, "the build context was not sent in time"),
        .malformed => return buildError(s, a, fd, 400, "the build context's chunked encoding is malformed"),
        .disk => return buildError(s, a, fd, 500, "the build context could not be stored (disk full?)"),
        .gone => return,
    }
    // From here the answer is 200 and what goes wrong is told in the stream, as Docker's does.
    const head = "HTTP/1.1 200 OK\r\nApi-Version: " ++ api_version ++ "\r\nBuilder-Version: 1\r\n" ++
        "Docker-Experimental: false\r\nOstype: linux\r\nServer: zig-runner (linux)\r\n" ++
        "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    sendAll(s, fd, head, lim.write_ms) catch return;
    var sink: Sink = .{ .server = s, .fd = fd };
    var call: BuildCall = .{ .arena = a, .query = q, .tar_path = tar_path, .tar_bytes = got, .id = n, .limits = lim.context, .sink = &sink };
    const done_rc = linux.eventfd(0, linux.EFD.CLOEXEC);
    if (linux.errno(done_rc) != .SUCCESS) {
        sink.write(docker_build.errorLine(a, "the runner has no file descriptor left for the build") catch "");
        if (sendAll(s, fd, "0\r\n\r\n", lim.write_ms)) {} else |_| {} // the peer going is no matter
        return;
    }
    const done_fd = fdOf(done_rc) catch return;
    defer _ = linux.close(done_fd);
    var worker: Worker = .{ .h = h, .call = &call, .done_fd = done_fd };
    const thread = std.Thread.spawn(.{ .stack_size = 16 * 1024 * 1024 }, Worker.run, .{&worker}) catch {
        sink.write(docker_build.errorLine(a, "the runner could not start the build") catch "");
        if (sendAll(s, fd, "0\r\n\r\n", lim.write_ms)) {} else |_| {} // the peer going is no matter
        return;
    };
    // Until the build ends: if the client goes (the step was stopped, `docker build` killed) or the
    // server stops, the build is cancelled, and waited for.
    var cancelled = false;
    while (true) {
        var fds = [_]linux.pollfd{
            .{ .fd = done_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (cancelled) -1 else fd, .events = linux.POLL.IN | poll_rdhup, .revents = 0 },
        };
        const rc = linux.poll(&fds, fds.len, 200);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (fds[0].revents != 0) break;
        // A client too slow to read (the sink's write timed out) is as good as gone.
        if (!cancelled and sink.gone()) {
            cancelled = true;
            h.cancelFn(h, n);
            continue;
        }
        if (!cancelled) {
            var gone = fds[1].revents != 0 or sink.gone();
            if (fds[2].revents & (linux.POLL.HUP | linux.POLL.ERR | poll_rdhup) != 0) gone = true;
            if (fds[2].revents & linux.POLL.IN != 0) {
                // A client has nothing more to say: bytes are junk, EOF is leaving.
                var junk: [512]u8 = undefined;
                const r = linux.recvfrom(fd, &junk, junk.len, linux.MSG.DONTWAIT, null, null);
                if (linux.errno(r) == .SUCCESS and r == 0) gone = true;
            }
            if (gone) {
                cancelled = true;
                // A build still queued for the job's one builder never starts.
                sink.failed.store(true, .release);
                h.cancelFn(h, n);
            }
        } else if (fds[1].revents != 0) {
            // Stopping: the cancel is made; wait for the build in a short sleep loop.
            var again = [_]linux.pollfd{.{ .fd = done_fd, .events = linux.POLL.IN, .revents = 0 }};
            _ = linux.poll(&again, 1, 10);
        }
    }
    thread.join();
    if (sendAll(s, fd, "0\r\n\r\n", lim.write_ms)) {} else |_| {} // the peer going is no matter
}

/// A refusal before the context is read: answered, and what the client is sending dropped.
fn finishEarly(s: *Server, fd: linux.fd_t, a: Allocator, status: u16, message: []const u8, has_body: bool) void {
    s.bump("refused");
    _ = reply(s, fd, a, status, error_json(a, message), false, false);
    if (has_body) drain(s, fd, s.cfg.limits);
}

fn unlinkPathA(a: Allocator, path: []const u8) !void {
    const z = try a.dupeSentinel(u8, path, 0);
    _ = linux.unlink(z);
}

// --- tests ---

const testing = std.testing;

fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    const out = comptime blk: {
        @setEvalBranchQuota(200_000);
        var o: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(o[i * s.len ..][0..s.len], s);
        break :blk o;
    };
    return &out;
}

const test_cfg: Config = .{ .job = "0123456789abcdef", .version = "v9.9.9-test" };

/// A server on a socket in a fresh temporary directory.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    path: []const u8,
    server: *Server,

    fn start(cfg: Config) !Fixture {
        var f: Fixture = .{ .tmp = std.testing.tmpDir(.{}), .path = "", .server = undefined };
        errdefer f.tmp.cleanup();
        const dir = try f.tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
        defer testing.allocator.free(dir);
        f.path = try std.fmt.allocPrint(testing.allocator, "{s}/docker.sock", .{dir});
        errdefer testing.allocator.free(f.path);
        f.server = try Server.start(testing.allocator, f.path, cfg);
        return f;
    }

    fn finish(f: *Fixture) Stats {
        const st = f.server.stop();
        testing.allocator.free(f.path);
        f.tmp.cleanup();
        return st;
    }
};

/// Sends `request` and reads until the server closes or `ms` pass with nothing more.
/// Returns what came, and whether the server closed the connection.
const Heard = struct { text: []u8, closed: bool };

fn ask(path: []const u8, request: []const u8, ms: u32) !Heard {
    const fd = try connect(path);
    defer _ = linux.close(fd);
    return askOn(fd, request, ms);
}

fn askOn(fd: linux.fd_t, request: []const u8, ms: u32) !Heard {
    if (request.len > 0) _ = linux.sendto(fd, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0);
    var got: std.ArrayList(u8) = .empty;
    errdefer got.deinit(testing.allocator);
    var closed = false;
    const end = nowMs() + ms;
    while (nowMs() < end) {
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const left = std.math.lossyCast(i32, end - nowMs());
        if (linux.poll(&fds, 1, left) == 0) break;
        var buf: [8192]u8 = undefined;
        const rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            closed = true;
            break;
        }
        try got.appendSlice(testing.allocator, buf[0..rc]);
        // An answer with its whole body is enough when the server keeps the connection.
        if (completeAnswer(got.items) and std.mem.indexOf(u8, got.items, "Connection: close") == null) break;
    }
    return .{ .text = try got.toOwnedSlice(testing.allocator), .closed = closed };
}

fn completeAnswer(text: []const u8) bool {
    const head_end = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return false;
    const key = "Content-Length: ";
    const at = std.mem.indexOf(u8, text[0..head_end], key) orelse return false;
    const stop = std.mem.indexOfScalarPos(u8, text, at, '\r') orelse return false;
    const n = std.fmt.parseInt(usize, text[at + key.len .. stop], 10) catch return false;
    if (std.mem.startsWith(u8, text, "HEAD")) return true;
    return text.len == head_end + 4 + n;
}

fn bodyOf(text: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return "";
    return text[i + 4 ..];
}

fn statusOf(text: []const u8) u16 {
    if (text.len < 12) return 0;
    return std.fmt.parseInt(u16, text[9..12], 10) catch 0;
}

fn get(path: []const u8, target: []const u8) ![]u8 {
    const req = try std.fmt.allocPrint(testing.allocator, "GET {s} HTTP/1.1\r\nHost: docker\r\n\r\n", .{target});
    defer testing.allocator.free(req);
    const r = try ask(path, req, 3000);
    return r.text;
}

fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, hay, needle) == null) {
        std.debug.print("ERROR: {s} is not in:\n{s}\n", .{ needle, hay });
        return error.TestExpectedContains;
    }
}

test "docker api: /_ping answers OK with Docker's headers, with and without a version prefix" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    for ([_][]const u8{ "/_ping", "/v1.24/_ping", "/v1.41/_ping", "/v1.52/_ping" }) |target| {
        const text = try get(f.path, target);
        defer testing.allocator.free(text);
        try testing.expectEqual(@as(u16, 200), statusOf(text));
        try testing.expectEqualStrings("OK", bodyOf(text));
        try expectContains(text, "Api-Version: 1.52\r\n");
        try expectContains(text, "Builder-Version: 1\r\n");
        try expectContains(text, "Ostype: linux\r\n");
        try expectContains(text, "Content-Length: 2\r\n");
    }
}

test "docker api: HEAD /_ping has the headers and no body" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const r = try ask(f.path, "HEAD /_ping HTTP/1.1\r\nHost: docker\r\n\r\n", 300);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(@as(u16, 200), statusOf(r.text));
    try expectContains(r.text, "Content-Length: 2\r\n");
    try testing.expectEqualStrings("", bodyOf(r.text));
}

test "docker api: /version and /info are the JSON the docker CLI reads" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const v = try get(f.path, "/v1.45/version");
    defer testing.allocator.free(v);
    try testing.expectEqual(@as(u16, 200), statusOf(v));
    try expectContains(v, "Content-Type: application/json\r\n");
    var pv = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(v), .{});
    defer pv.deinit();
    const vo = pv.value.object;
    try testing.expectEqualStrings("zig-runner", vo.get("Platform").?.object.get("Name").?.string);
    try testing.expectEqualStrings("9.9.9-test", vo.get("Version").?.string);
    try testing.expectEqualStrings("1.52", vo.get("ApiVersion").?.string);
    try testing.expectEqualStrings("1.24", vo.get("MinAPIVersion").?.string);
    try testing.expectEqualStrings("linux", vo.get("Os").?.string);
    try testing.expect(vo.get("Arch").?.string.len > 0);
    const comp = vo.get("Components").?.array.items[0].object;
    try testing.expectEqualStrings("Engine", comp.get("Name").?.string);
    try testing.expectEqualStrings("1.52", comp.get("Details").?.object.get("ApiVersion").?.string);

    const i = try get(f.path, "/info");
    defer testing.allocator.free(i);
    try testing.expectEqual(@as(u16, 200), statusOf(i));
    var pi = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(i), .{});
    defer pi.deinit();
    const io = pi.value.object;
    try testing.expectEqualStrings("0123456789abcdef", io.get("ID").?.string);
    try testing.expectEqualStrings("linux", io.get("OSType").?.string);
    try testing.expectEqualStrings("9.9.9-test", io.get("ServerVersion").?.string);
    try testing.expectEqualStrings("zig-runner", io.get("OperatingSystem").?.string);
    try testing.expect(io.get("NCPU").?.integer >= 1);
    try testing.expect(io.get("MemTotal").?.integer > 0);
    try testing.expect(io.get("Plugins").?.object.get("Volume") != null);
    try testing.expect(io.get("Swarm").?.object.get("LocalNodeState") != null);
    for ([_][]const u8{ "Driver", "DockerRootDir", "Name", "Architecture", "KernelVersion", "Runtimes", "DefaultRuntime" }) |k|
        try testing.expect(io.get(k) != null);
}

fn expectMessage(f: *Fixture, method: []const u8, target: []const u8, status: u16, message: []const u8) !void {
    const req = try std.fmt.allocPrint(testing.allocator, "{s} {s} HTTP/1.1\r\nHost: docker\r\n\r\n", .{ method, target });
    defer testing.allocator.free(req);
    const r = try ask(f.path, req, 3000);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(status, statusOf(r.text));
    var p = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(r.text), .{});
    defer p.deinit();
    try testing.expectEqualStrings(message, p.value.object.get("message").?.string);
}

test "docker api: every other endpoint is 501 naming the method and the path" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const prefix = "not supported by zig-runner yet: ";
    try expectMessage(&f, "GET", "/containers/json", 501, prefix ++ "GET /containers/json");
    try expectMessage(&f, "POST", "/v1.43/containers/create?name=x", 501, prefix ++ "POST /containers/create");
    try expectMessage(&f, "DELETE", "/images/alpine", 501, prefix ++ "DELETE /images/alpine");
    try expectMessage(&f, "GET", "/v1.52/images/json", 501, prefix ++ "GET /images/json");
    try expectMessage(&f, "POST", "/_ping", 501, prefix ++ "POST /_ping");
    try expectMessage(&f, "GET", "/", 501, prefix ++ "GET /");
    try expectMessage(&f, "GET", "/v1.30", 501, prefix ++ "GET /");
    // A path with quotes and slashes stays valid JSON.
    try expectMessage(&f, "GET", "/a\"b\\c", 501, prefix ++ "GET /a\"b\\c");
}

test "docker api: BuildKit's endpoints get the hint, the classic /build says it is not built without a handler" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    try expectMessage(&f, "POST", "/grpc", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/v1.47/session", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/build?version=2&t=x", 501, buildkit_hint);
    try expectMessage(&f, "GET", "/v1.52/containers/buildx_buildkit_default/json", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/v1.41/build?t=x&dockerfile=Dockerfile", 501, build_unavailable);
    try expectMessage(&f, "POST", "/build", 501, build_unavailable);
    try testing.expect(std.mem.indexOf(u8, buildkit_hint, "DOCKER_BUILDKIT=0 is set for you") != null);
}

test "docker api: a version out of 1.24 to 1.52 is Docker's 400" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    try expectMessage(&f, "GET", "/v1.53/_ping", 400, "client version 1.53 is too new. Maximum supported API version is 1.52");
    try expectMessage(&f, "GET", "/v1.23/_ping", 400, "client version 1.23 is too old. Minimum supported API version is 1.24, please upgrade your client to a newer version");
    try expectMessage(&f, "GET", "/v2.0/_ping", 400, "client version 2.0 is too new. Maximum supported API version is 1.52");
    // Not a version prefix: just an unknown path.
    try expectMessage(&f, "GET", "/vault/x", 501, "not supported by zig-runner yet: GET /vault/x");
}

test "docker api: requests are kept alive and pipelined requests are all answered" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const one = try askOn(fd, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 3000);
    defer testing.allocator.free(one.text);
    try testing.expectEqual(@as(u16, 200), statusOf(one.text));
    try testing.expect(!one.closed);
    try expectContains(one.text, "Connection: keep-alive");
    const both = "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\nGET /nope HTTP/1.1\r\nHost: d\r\n\r\n";
    // The two answers may come in one read or in two: until both are in, or three seconds.
    var heard: std.ArrayList(u8) = .empty;
    defer heard.deinit(testing.allocator);
    const until = nowMs() + 3000;
    var first_round = true;
    while (std.mem.count(u8, heard.items, "HTTP/1.1 ") < 2 and nowMs() < until) {
        const part = try askOn(fd, if (first_round) both else "", 100);
        defer testing.allocator.free(part.text);
        first_round = false;
        try heard.appendSlice(testing.allocator, part.text);
    }
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, heard.items, "HTTP/1.1 "));
    try expectContains(heard.items, "GET /nope");
    const st = f.server.stats();
    try testing.expectEqual(@as(u32, 3), st.requests);
    try testing.expectEqual(@as(u32, 1), st.unsupported);
    try testing.expectEqual(@as(u32, 1), st.connections);
}

test "docker api: Connection: close and HTTP/1.0 close after the answer" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const a = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n", 3000);
    defer testing.allocator.free(a.text);
    try testing.expectEqual(@as(u16, 200), statusOf(a.text));
    try expectContains(a.text, "Connection: close");
    const b = try ask(f.path, "GET /_ping HTTP/1.0\r\n\r\n", 3000);
    defer testing.allocator.free(b.text);
    try testing.expectEqual(@as(u16, 200), statusOf(b.text));
    try expectContains(b.text, "Connection: close");
}

test "docker api: malformed requests are 400 and closed, never a crash" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const bad = [_][]const u8{
        "this is not http\r\n\r\n",
        "GET\r\n\r\n",
        "GET /_ping\r\n\r\n",
        "GET /_ping HTTP/1.1 extra\r\nHost: d\r\n\r\n",
        "get /_ping HTTP/1.1\r\nHost: d\r\n\r\n",
        "GET _ping HTTP/1.1\r\nHost: d\r\n\r\n",
        "GET /_ping HTTP/2.0\r\nHost: d\r\n\r\n",
        "GET /_ping HTTP/1.1\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nno colon here\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\n folded: x\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nBad Name: x\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nX: a\x00b\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: abc\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: gzip\r\n\r\n",
        "GET /_ping HTTP/1.1\nHost: d\n\n\r\n\r\n",
    };
    for (bad) |req| {
        const r = try ask(f.path, req, 3000);
        defer testing.allocator.free(r.text);
        errdefer std.debug.print("ERROR request {any}\n", .{req});
        try testing.expectEqual(@as(u16, 400), statusOf(r.text));
        try expectContains(bodyOf(r.text), "malformed HTTP request");
        try testing.expect(r.closed or std.mem.indexOf(u8, r.text, "Connection: close") != null);
    }
    // Binary noise, and a connection that sends nothing and goes: the server is still there.
    const noise = try ask(f.path, "\xff\xfe\x00\x01\r\n\r\n", 3000);
    defer testing.allocator.free(noise.text);
    try testing.expectEqual(@as(u16, 400), statusOf(noise.text));
    const fd = try connect(f.path);
    _ = linux.close(fd);
    const ok = try get(f.path, "/_ping");
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
}

test "docker api: an oversized head is 431 and an oversized target 414" {
    var cfg = test_cfg;
    cfg.limits.header_bytes = 1024;
    cfg.limits.target_bytes = 100;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    const big = try std.fmt.allocPrint(testing.allocator, "GET /_ping HTTP/1.1\r\nHost: d\r\nX-Fill: {s}\r\n\r\n", .{repeat("a", 2000)});
    defer testing.allocator.free(big);
    const a = try ask(f.path, big, 3000);
    defer testing.allocator.free(a.text);
    try testing.expectEqual(@as(u16, 431), statusOf(a.text));
    // No end to the head at all: the same, without waiting for one.
    const endless = try ask(f.path, "GET /_ping HTTP/1.1\r\n" ++ comptime repeat("X: b\r\n", 400), 3000);
    defer testing.allocator.free(endless.text);
    try testing.expectEqual(@as(u16, 431), statusOf(endless.text));
    const long = try std.fmt.allocPrint(testing.allocator, "GET /{s} HTTP/1.1\r\nHost: d\r\n\r\n", .{repeat("p", 200)});
    defer testing.allocator.free(long);
    const b = try ask(f.path, long, 3000);
    defer testing.allocator.free(b.text);
    try testing.expectEqual(@as(u16, 414), statusOf(b.text));
}

test "docker api: a head that stalls is 408 and a silent connection is closed, within the limits" {
    var cfg = test_cfg;
    cfg.limits.header_ms = 200;
    cfg.limits.idle_ms = 300;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    var t0 = nowMs();
    const slow = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\n", 3000);
    defer testing.allocator.free(slow.text);
    try testing.expectEqual(@as(u16, 408), statusOf(slow.text));
    try testing.expect(slow.closed);
    try testing.expect(nowMs() - t0 < 1500);
    t0 = nowMs();
    const idle = try ask(f.path, "", 3000);
    defer testing.allocator.free(idle.text);
    try testing.expect(idle.closed);
    try testing.expectEqualStrings("", idle.text);
    try testing.expect(nowMs() - t0 < 1500);
    // A kept connection that goes quiet after an answer is closed too.
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const one = try askOn(fd, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    defer testing.allocator.free(one.text);
    try testing.expectEqual(@as(u16, 200), statusOf(one.text));
    t0 = nowMs();
    const after = try askOn(fd, "", 3000);
    defer testing.allocator.free(after.text);
    try testing.expect(after.closed);
    try testing.expect(nowMs() - t0 < 1500);
    try testing.expect(f.server.stats().timeouts >= 1);
}

test "docker api: a request with a body is answered at once, then its body is dropped and the connection closed" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const head = "POST /v1.41/build?t=x HTTP/1.1\r\nHost: d\r\nContent-Length: 1000000\r\n\r\n";
    _ = linux.sendto(fd, head.ptr, head.len, linux.MSG.NOSIGNAL, null, 0);
    // The answer comes before the body is sent.
    var got = try askOn(fd, "", 3000);
    try testing.expectEqual(@as(u16, 501), statusOf(got.text));
    try expectContains(got.text, build_unavailable);
    try expectContains(got.text, "Connection: close");
    testing.allocator.free(got.text);
    // And the client may still send all of it: it is read, not reset.
    const chunk = repeat("x", 65536);
    var sent: usize = 0;
    while (sent < 1_000_000) {
        const n = @min(chunk.len, 1_000_000 - sent);
        const rc = linux.sendto(fd, chunk.ptr, n, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) != .SUCCESS) break;
        sent += rc;
    }
    try testing.expectEqual(@as(usize, 1_000_000), sent);
    got = try askOn(fd, "", 3000);
    defer testing.allocator.free(got.text);
    try testing.expect(got.closed);
}

test "docker api: a client that sends a body forever is let go after the drain limit" {
    var cfg = test_cfg;
    cfg.limits.drain_bytes = 100_000;
    cfg.limits.drain_ms = 300;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const head = "POST /containers/create HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n";
    const r = try askOn(fd, head, 3000);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(@as(u16, 501), statusOf(r.text));
    const t0 = nowMs();
    const more = try askOn(fd, "", 3000);
    defer testing.allocator.free(more.text);
    try testing.expect(more.closed);
    try testing.expect(nowMs() - t0 < 1500);
}

test "docker api: with every connection busy the next is 503, and stop does not wait for them" {
    var cfg = test_cfg;
    cfg.limits.max_connections = 2;
    var f = try Fixture.start(cfg);
    const a = try connect(f.path);
    defer _ = linux.close(a);
    const b = try connect(f.path);
    defer _ = linux.close(b);
    // Each holds a connection open and silent (the default idle limit is long).
    const one = try askOn(a, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(one.text);
    const two = try askOn(b, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(two.text);
    const third = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 3000);
    defer testing.allocator.free(third.text);
    try testing.expectEqual(@as(u16, 503), statusOf(third.text));
    const kept_path = try testing.allocator.dupe(u8, f.path);
    defer testing.allocator.free(kept_path);
    const t0 = nowMs();
    const st = f.finish();
    try testing.expect(nowMs() - t0 < 1000);
    try testing.expectEqual(@as(u32, 1), st.busy);
    try testing.expectEqual(@as(u32, 3), st.connections);
    // The socket's file is gone with the server.
    try testing.expectError(error.Connect, connect(kept_path));
}

test "docker api: a socket path past sun_path is bound through its directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    var dir: std.ArrayList(u8) = .empty;
    defer dir.deinit(testing.allocator);
    try dir.appendSlice(testing.allocator, root);
    while (dir.items.len < 130) {
        try dir.appendSlice(testing.allocator, "/long-directory-name");
        try tmp.dir.createDirPath(testing.io, dir.items[root.len + 1 ..]);
    }
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/docker.sock", .{dir.items});
    defer testing.allocator.free(path);
    const server = try Server.start(testing.allocator, path, test_cfg);
    defer _ = server.stop();
    const text = try get(path, "/_ping");
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(u16, 200), statusOf(text));
    const st = try tmp.dir.statFile(testing.io, path[root.len + 1 ..], .{});
    try testing.expect(st.kind == .unix_domain_socket);
}

test "docker api: the socket is 0666 and a second server on the same path is refused" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try zpath(&buf, "{s}", .{f.path});
    var stx: linux.Statx = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(linux.AT.FDCWD, z, 0, .{ .MODE = true }, &stx)));
    try testing.expectEqual(@as(u16, 0o666), stx.mode & 0o7777);
    try testing.expectError(error.AddressInUse, Server.start(testing.allocator, f.path, test_cfg));
}

test "docker api: the log line's counts" {
    var f = try Fixture.start(test_cfg);
    const a = try get(f.path, "/_ping");
    testing.allocator.free(a);
    const b = try get(f.path, "/images/json");
    testing.allocator.free(b);
    const c = try ask(f.path, "junk\r\n\r\n", 3000);
    testing.allocator.free(c.text);
    const st = f.finish();
    try testing.expectEqual(Stats{ .connections = 3, .requests = 3, .unsupported = 1, .refused = 1, .beyond = 1 }, st);
}

// For recording a real `docker` CLI's traffic (`testdata/docker_api/`): with
// `ZIG_TEST_DOCKER_API_SERVE=<socket path>` the server runs there until `<socket path>.stop` is
// made (`touch`), and a CLI with `DOCKER_HOST=unix://<path>` talks to it. Skipped otherwise.
test "docker api: serve for a real CLI (ZIG_TEST_DOCKER_API_SERVE=<socket>, ends when <socket>.stop exists)" {
    var env = try std.testing.environ.createMap(testing.allocator);
    defer env.deinit();
    const path = env.get("ZIG_TEST_DOCKER_API_SERVE") orelse return error.SkipZigTest;
    const server = try Server.start(testing.allocator, path, .{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = server.stop();
    const stop = try std.fmt.allocPrint(testing.allocator, "{s}.stop", .{path});
    defer testing.allocator.free(stop);
    const dir = std.fs.path.dirname(path) orelse ".";
    const ino = try fdOf(linux.inotify_init1(linux.IN.CLOEXEC));
    defer _ = linux.close(ino);
    var dir_z: [std.fs.max_path_bytes]u8 = undefined;
    const dz = try zpath(&dir_z, "{s}", .{dir});
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.inotify_add_watch(ino, dz, linux.IN.CREATE | linux.IN.MOVED_TO)));
    var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
    while (true) {
        std.Io.Dir.cwd().access(testing.io, stop, .{}) catch {
            const rc = linux.read(ino, &buf, buf.len);
            if (linux.errno(rc) == .INTR) continue;
            continue;
        };
        break;
    }
}

// --- a real docker CLI's traffic, recorded (testdata/docker_api/, cli-transcript.txt) ---

const Capture = struct { name: []const u8, request: []const u8, response: []const u8 };

/// What the docker CLI 29.9.3 sent the server of this stage, and what it answered, as a proxy
/// between the two wrote it down (`docker version`, `docker info`, `docker build .` of the legacy
/// builder with and without `-t`, `--build-arg` and `--target`, a BuildKit build's `/grpc` and its
/// builder's inspect, `docker ps`, `docker images`).
const captures = [_]Capture{
    .{ .name = "version", .request = @embedFile("testdata/docker_api/01-version.req"), .response = @embedFile("testdata/docker_api/01-version.resp") },
    .{ .name = "info", .request = @embedFile("testdata/docker_api/02-info.req"), .response = @embedFile("testdata/docker_api/02-info.resp") },
    .{ .name = "build", .request = @embedFile("testdata/docker_api/03-build.req"), .response = @embedFile("testdata/docker_api/03-build.resp") },
    .{ .name = "build with args", .request = @embedFile("testdata/docker_api/04-build-args.req"), .response = @embedFile("testdata/docker_api/04-build-args.resp") },
    .{ .name = "grpc", .request = @embedFile("testdata/docker_api/05-grpc.req"), .response = @embedFile("testdata/docker_api/05-grpc.resp") },
    .{ .name = "buildx builder", .request = @embedFile("testdata/docker_api/06-buildx-builder.req"), .response = @embedFile("testdata/docker_api/06-buildx-builder.resp") },
    .{ .name = "ps", .request = @embedFile("testdata/docker_api/07-ps.req"), .response = @embedFile("testdata/docker_api/07-ps.resp") },
    .{ .name = "images", .request = @embedFile("testdata/docker_api/08-images.req"), .response = @embedFile("testdata/docker_api/08-images.resp") },
};

/// The methods of the requests in `stream`, up to the first one that has a body.
fn methodsOf(a: Allocator, stream: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var rest = stream;
    while (std.mem.indexOf(u8, rest, "\r\n\r\n")) |end| {
        const head = rest[0..end];
        try out.append(a, head[0 .. std.mem.indexOfScalar(u8, head, ' ') orelse head.len]);
        if (std.ascii.findIgnoreCase(head, "transfer-encoding:") != null or
            std.ascii.findIgnoreCase(head, "content-length: ") != null and
                std.ascii.findIgnoreCase(head, "content-length: 0") == null) break;
        rest = rest[end + 4 ..];
    }
    return out.items;
}

const Response = struct { head: []const u8, body: []const u8 };

/// The responses in `stream`, `methods` being the requests' (a HEAD's has no body). A last one cut
/// short is left out.
fn responsesOf(a: Allocator, stream: []const u8, methods: []const []const u8) ![]const Response {
    var out: std.ArrayList(Response) = .empty;
    var rest = stream;
    for (methods) |m| {
        const end = std.mem.indexOf(u8, rest, "\r\n\r\n") orelse break;
        const head = rest[0..end];
        var n: usize = 0;
        if (std.ascii.findIgnoreCase(head, "content-length: ")) |i| {
            const from = i + "content-length: ".len;
            const to = std.mem.indexOfScalarPos(u8, head, from, '\r') orelse head.len;
            n = try std.fmt.parseInt(usize, head[from..to], 10);
        }
        if (std.mem.eql(u8, m, "HEAD")) n = 0;
        if (rest.len < end + 4 + n) break;
        try out.append(a, .{ .head = head, .body = rest[end + 4 ..][0..n] });
        rest = rest[end + 4 + n ..];
    }
    return out.items;
}

/// The lines of `head` but the ones that name this machine or this body's length, sorted.
fn stableHead(a: Allocator, head: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |l| {
        if (std.ascii.startsWithIgnoreCase(l, "server:") or std.ascii.startsWithIgnoreCase(l, "content-length:")) continue;
        try out.append(a, l);
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.less);
    return out.items;
}

/// Whether `got` is what `want` is, as JSON: the same keys and kinds of value all the way down,
/// what a machine's values differ in left alone (a `message` must be the same text).
fn sameShape(want: std.json.Value, got: std.json.Value, key: []const u8) bool {
    if (std.meta.activeTag(want) != std.meta.activeTag(got)) return false;
    switch (want) {
        .object => |wo| {
            if (wo.count() != got.object.count()) return false;
            var it = wo.iterator();
            while (it.next()) |e| {
                const g = got.object.get(e.key_ptr.*) orelse return false;
                if (!sameShape(e.value_ptr.*, g, e.key_ptr.*)) return false;
            }
            return true;
        },
        .array => |wa| {
            if (wa.items.len == 0 or got.array.items.len == 0) return wa.items.len == got.array.items.len;
            return sameShape(wa.items[0], got.array.items[0], key);
        },
        .string => |s| return !std.mem.eql(u8, key, "message") or std.mem.eql(u8, s, got.string),
        .bool => |b| return b == got.bool,
        else => return true,
    }
}

test "docker api: a real docker CLI's traffic, replayed, is answered as it was (version, info, build, BuildKit, ps, images)" {
    var f = try Fixture.start(.{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = f.finish();
    for (captures) |c| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        errdefer std.debug.print("ERROR capture {s}\n", .{c.name});
        const methods = try methodsOf(a, c.request);
        const want = try responsesOf(a, c.response, methods);
        try testing.expectEqual(methods.len, want.len);
        // Everything the CLI sent, at once, as the CLI sent it; then what comes back.
        const fd = try connect(f.path);
        defer _ = linux.close(fd);
        var got_bytes: std.ArrayList(u8) = .empty;
        var sent = false;
        const end = nowMs() + 3000;
        var got: []const Response = &.{};
        while (nowMs() < end and got.len < want.len) {
            const heard = try askOn(fd, if (sent) "" else c.request, 100);
            defer testing.allocator.free(heard.text);
            sent = true;
            try got_bytes.appendSlice(a, heard.text);
            got = try responsesOf(a, got_bytes.items, methods);
            if (heard.closed) break;
        }
        try testing.expectEqual(want.len, got.len);
        for (want, got) |w, g| {
            try testing.expectEqualDeep(try stableHead(a, w.head), try stableHead(a, g.head));
            if (std.mem.indexOf(u8, w.head, "application/json") != null) {
                const pw = try std.json.parseFromSliceLeaky(std.json.Value, a, w.body, .{});
                const pg = try std.json.parseFromSliceLeaky(std.json.Value, a, g.body, .{});
                try testing.expect(sameShape(pw, pg, ""));
            } else try testing.expectEqualStrings(w.body, g.body);
        }
    }
}

test "docker api: a path of bytes that are not UTF-8 or too long still makes a JSON message" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const bad = try get(f.path, "/\xff\xfe");
    defer testing.allocator.free(bad);
    try testing.expectEqual(@as(u16, 501), statusOf(bad));
    var p = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(bad), .{});
    defer p.deinit();
    try testing.expectEqualStrings("not supported by zig-runner yet: GET /\u{FFFD}\u{FFFD}", p.value.object.get("message").?.string);
    // 300 bytes of a three-byte character: cut between characters, not inside one.
    const long = try get(f.path, "/" ++ comptime repeat("\xe2\x82\xac", 100));
    defer testing.allocator.free(long);
    var q = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(long), .{});
    defer q.deinit();
    const msg = q.value.object.get("message").?.string;
    try testing.expect(std.unicode.utf8ValidateSlice(msg));
    try testing.expect(std.mem.indexOf(u8, msg, "\u{FFFD}") == null);
    try testing.expect(msg.len <= "not supported by zig-runner yet: GET ".len + 200);
}

test "docker api: only canonical version prefixes are accepted" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const prefix_error = "invalid API version prefix: a version is /v1.NN, with no sign or leading zero";
    for ([_][]const u8{ "/v1.+40/_ping", "/v1.-40/_ping", "/v01.52/_ping", "/v1.052/_ping", "/v1.99999/_ping", "/v1234.1/_ping", "/v1./_ping", "/v1.4x/_ping" }) |target| {
        errdefer std.debug.print("ERROR target {s}\n", .{target});
        try expectMessage(&f, "GET", target, 400, prefix_error);
    }
    const ok = try get(f.path, "/v1.40/_ping");
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
}

test "docker api: the Server header names no version, /info's Name is the job's hostname or a neutral one" {
    var cfg = test_cfg;
    cfg.hostname = "ci-box";
    var f = try Fixture.start(cfg);
    const ping = try get(f.path, "/_ping");
    defer testing.allocator.free(ping);
    try expectContains(ping, "Server: zig-runner (linux)\r\n");
    try testing.expect(std.mem.indexOf(u8, ping, "9.9.9") == null);
    const info = try get(f.path, "/info");
    defer testing.allocator.free(info);
    try expectContains(info, "\"Name\":\"ci-box\"");
    _ = f.finish();
    var g = try Fixture.start(test_cfg);
    defer _ = g.finish();
    const info2 = try get(g.path, "/info");
    defer testing.allocator.free(info2);
    try expectContains(info2, "\"Name\":\"zig-runner\"");
}

var test_now: u32 = 0;
fn testClock() u32 {
    return test_now;
}

test "docker api: the budget refills with the clock, and a stale reading refills and moves nothing" {
    const lim: Limits = .{ .rate_per_s = 20, .burst = 5 };
    test_now = 1_000;
    var bucket: std.atomic.Value(u64) = .init(@as(u64, lim.burst) * 1000 << 32 | test_now);
    // The burst, then none: the wait is the time to the next token (50 ms at 20 a second).
    for (0..5) |_| try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
    try testing.expectEqual(@as(?u32, 50), takeToken(&bucket, lim, testClock));
    test_now += 25;
    try testing.expectEqual(@as(?u32, 25), takeToken(&bucket, lim, testClock));
    test_now += 25;
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
    try testing.expectEqual(@as(?u32, 50), takeToken(&bucket, lim, testClock));
    // A long quiet refills to the burst and no further.
    test_now += 60_000;
    for (0..5) |_| try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
    try testing.expect(takeToken(&bucket, lim, testClock) != null);
    // A reading older than the bucket's last refill (a thread that read the clock, lost a race and
    // retried): not the 2^32 milliseconds that `now -% last` would make it, and `last` stays.
    const before = bucket.load(.acquire);
    test_now -= 40;
    try testing.expect(takeToken(&bucket, lim, testClock) != null);
    try testing.expectEqual(before, bucket.load(.acquire));
    test_now += 40 + 50;
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
    // The clock wrapping round is no jump back either.
    test_now = 5;
    bucket.store(@as(u64, 2) * 1000 << 32 | 0xffff_fff0, .release);
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, testClock));
}

var racing_calls: u32 = 0;
/// A clock that reads late the first time: the thread that took the reading was passed by another.
fn racingClock() u32 {
    racing_calls += 1;
    return if (racing_calls == 1) 100 else 900;
}

test "docker api: a retry reads the clock again, so a stale first reading refills nothing" {
    const lim: Limits = .{ .rate_per_s = 1000, .burst = 3 };
    // Another thread refilled at 500 and took a token: 1.5 tokens left.
    var bucket: std.atomic.Value(u64) = .init(@as(u64, 1500) << 32 | 500);
    racing_calls = 0;
    // 100 is behind 500: nothing to refill from, 1.5 tokens, so one is taken at once; the next
    // reading (900) is the one that counts for what follows.
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, racingClock));
    try testing.expectEqual(@as(u64, 500), bucket.load(.acquire) >> 32);
    try testing.expectEqual(@as(u32, 500), @as(u32, @truncate(bucket.load(.acquire))));
}

test "docker api: over its budget a job's API is told 429 once, after a wait, and let go; the rest is counted" {
    var cfg = test_cfg;
    cfg.limits.rate_per_s = 1;
    cfg.limits.burst = 5;
    cfg.limits.deny_delay_ms = 50;
    var f = try Fixture.start(cfg);
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const batch = comptime repeat("GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 12);
    var heard: std.ArrayList(u8) = .empty;
    defer heard.deinit(testing.allocator);
    const until = nowMs() + 3000;
    var first = true;
    var closed = false;
    while (!closed and nowMs() < until) {
        const part = try askOn(fd, if (first) batch else "", 100);
        defer testing.allocator.free(part.text);
        first = false;
        closed = part.closed;
        try heard.appendSlice(testing.allocator, part.text);
    }
    // Five answered at the rate of the burst, the sixth refused and the connection closed: the
    // other six were never read.
    try testing.expect(closed);
    try testing.expectEqual(@as(usize, 5), std.mem.count(u8, heard.items, "HTTP/1.1 200 "));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, heard.items, "HTTP/1.1 429 "));
    try expectContains(heard.items, "too many requests to this job's Docker API");
    const st = f.finish();
    try testing.expectEqual(@as(u32, 1), st.limited);
    try testing.expect(st.beyond >= 1);
}

test "docker api: settle waits for what a client sent before it went to be counted" {
    var cfg = test_cfg;
    cfg.test_route_delay_ms = 300;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    {
        // A request written and the client gone without reading the answer, as a step ends.
        const fd = try connect(f.path);
        const req = "GET /images/json HTTP/1.1\r\nHost: d\r\n\r\n";
        _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
        _ = linux.close(fd);
    }
    try testing.expectEqual(@as(u32, 0), f.server.stats().beyond);
    const t0 = nowMs();
    f.server.settle();
    // The request was routed and counted by the time it returned, though it was held 300 ms.
    try testing.expectEqual(@as(u32, 1), f.server.stats().beyond);
    try testing.expect(nowMs() - t0 >= 250);
    // With nothing sent, nothing to wait for, and an idle kept connection answers at once.
    const keep = try connect(f.path);
    defer _ = linux.close(keep);
    const one = try askOn(keep, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(one.text);
    const t1 = nowMs();
    f.server.settle();
    try testing.expect(nowMs() - t1 < 250);
    try testing.expectEqual(@as(u32, 1), f.server.stats().beyond);
}

test "docker api: an oversized head is counted as refused, a stalled one as a timeout and refused" {
    var cfg = test_cfg;
    cfg.limits.header_bytes = 256;
    cfg.limits.header_ms = 150;
    var f = try Fixture.start(cfg);
    const big = try ask(f.path, "GET /_ping HTTP/1.1\r\nX: " ++ comptime repeat("a", 400) ++ "\r\n\r\n", 3000);
    testing.allocator.free(big.text);
    const slow = try ask(f.path, "GET /_ping HTTP/1.1\r\n", 3000);
    testing.allocator.free(slow.text);
    const st = f.finish();
    try testing.expectEqual(@as(u32, 2), st.refused);
    try testing.expectEqual(@as(u32, 1), st.timeouts);
}

test "docker api: /version and /info are made once" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const a = try get(f.path, "/info");
    defer testing.allocator.free(a);
    const b = try get(f.path, "/info");
    defer testing.allocator.free(b);
    try testing.expectEqualStrings(bodyOf(a), bodyOf(b));
}

var hook_bucket: *std.atomic.Value(u64) = undefined;
var hook_calls: u32 = 0;
/// A clock that, on its first reading, is also another thread: it refills the bucket and takes a
/// token between the loop's load and its swap, so that the swap fails and the loop goes round again.
fn interferingClock() u32 {
    hook_calls += 1;
    if (hook_calls == 1) {
        hook_bucket.store(@as(u64, 1000) << 32 | 900, .release);
        return 150;
    }
    return 950;
}

test "docker api: a compare-and-swap that loses goes round again with a new reading and the new bucket" {
    const lim: Limits = .{ .rate_per_s = 10, .burst = 5 };
    var bucket: std.atomic.Value(u64) = .init(@as(u64, 3000) << 32 | 100);
    hook_bucket = &bucket;
    hook_calls = 0;
    try testing.expectEqual(@as(?u32, null), takeToken(&bucket, lim, interferingClock));
    try testing.expectEqual(@as(u32, 2), hook_calls);
    // 1000 left by the other thread at 900, 50 ms to 950 at 10 a second: 500 more, one taken.
    try testing.expectEqual(@as(u64, 500), bucket.load(.acquire) >> 32);
    try testing.expectEqual(@as(u32, 950), @as(u32, @truncate(bucket.load(.acquire))));
}

test "docker api: settle returns at once for an idle connection opened before the first settle, and for one that answered one" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const idle = try connect(f.path);
    defer _ = linux.close(idle);
    const one = try askOn(idle, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(one.text);
    // A connection that has not said a word, too.
    const silent = try connect(f.path);
    defer _ = linux.close(silent);
    var round: usize = 0;
    while (round < 4) : (round += 1) {
        errdefer std.debug.print("ERROR settle round {d}\n", .{round});
        const t0 = nowMs();
        f.server.settle();
        try testing.expect(nowMs() - t0 < 300);
    }
    // Still served after them.
    const again = try askOn(idle, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    defer testing.allocator.free(again.text);
    try testing.expectEqual(@as(u16, 200), statusOf(again.text));
}

// --- POST /build and /images, the gate (stage 1b), with a handler that builds nothing ---

/// A handler that records what it was asked and answers as a build would.
const Fake = struct {
    tmp_dir: []const u8,
    iface: Handler = .{ .buildFn = build, .imageFn = image, .cancelFn = cancel, .resetFn = reset },
    mu: std.atomic.Mutex = .unlocked,
    tags_len: usize = 0,
    arg_name: [8]u8 = undefined,
    arg_len: usize = 0,
    tar: []u8 = &.{},
    builds: std.atomic.Value(u32) = .init(0),
    cancels: std.atomic.Value(u32) = .init(0),
    resets: std.atomic.Value(u32) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),
    /// The build waits for a cancel (or 5 s) before it ends, as a long RUN does.
    hang: bool = false,
    last_image_op: ?[]const u8 = null,

    /// What the handler wrote is read by the test thread after `sync`: the lock is the order
    /// ThreadSanitizer sees (the socket's is not one it knows).
    fn sync(f: *Fake) void {
        while (!f.mu.tryLock()) {}
        f.mu.unlock();
    }

    fn build(h: *Handler, call: *BuildCall) void {
        const f: *Fake = @fieldParentPtr("iface", h);
        _ = f.builds.fetchAdd(1, .acq_rel);
        const data = std.Io.Dir.cwd().readFileAlloc(testing.io, call.tar_path, testing.allocator, .limited(64 << 20)) catch "";
        while (!f.mu.tryLock()) {}
        defer f.mu.unlock();
        f.tar = @constCast(data);
        f.tags_len = call.query.tags.len;
        if (call.query.build_args.len > 0) {
            const n = call.query.build_args[0].name;
            f.arg_len = @min(n.len, f.arg_name.len);
            @memcpy(f.arg_name[0..f.arg_len], n[0..f.arg_len]);
        }
        call.sink.write("{\"stream\":\"Step 1/1 : FROM scratch\\n\"}\n");
        if (f.hang) {
            const end = nowMs() + 5000;
            while (!f.cancelled.load(.acquire) and !call.sink.gone() and nowMs() < end) {
                var ts: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
                _ = linux.nanosleep(&ts, null);
            }
            call.sink.write("{\"errorDetail\":{\"message\":\"cancelled\"},\"error\":\"cancelled\"}\n");
            return;
        }
        call.sink.write("{\"aux\":{\"ID\":\"sha256:abc\"}}\n");
    }

    fn image(h: *Handler, a: Allocator, op: ImageOp) ImageAnswer {
        const f: *Fake = @fieldParentPtr("iface", h);
        while (!f.mu.tryLock()) {}
        defer f.mu.unlock();
        switch (op) {
            .inspect => |n| f.last_image_op = std.fmt.allocPrint(testing.allocator, "inspect {s}", .{n}) catch "",
            .tag => |t| f.last_image_op = std.fmt.allocPrint(testing.allocator, "tag {s} {s} {s}", .{ t.name, t.repo, t.tag }) catch "",
            .remove => |r| f.last_image_op = std.fmt.allocPrint(testing.allocator, "remove {s} {}", .{ r.name, r.force }) catch "",
        }
        _ = a;
        return .{ .status = 200, .body = "{}\n" };
    }

    fn cancel(h: *Handler, id: ?u32) void {
        _ = id;
        const f: *Fake = @fieldParentPtr("iface", h);
        _ = f.cancels.fetchAdd(1, .acq_rel);
        f.cancelled.store(true, .release);
    }

    fn reset(h: *Handler) void {
        const f: *Fake = @fieldParentPtr("iface", h);
        _ = f.resets.fetchAdd(1, .acq_rel);
        f.cancelled.store(false, .release);
    }
};

/// A fixture whose server has `fake` as its handler and a directory for contexts.
fn startBuilding(fake: *Fake, cfg_in: Config) !Fixture {
    var f: Fixture = .{ .tmp = std.testing.tmpDir(.{}), .path = "", .server = undefined };
    errdefer f.tmp.cleanup();
    const dir = try f.tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(dir);
    var cfg = cfg_in;
    cfg.work_dir = dir;
    cfg.handler = &fake.iface;
    fake.tmp_dir = "";
    f.path = try std.fmt.allocPrint(testing.allocator, "{s}/docker.sock", .{dir});
    errdefer testing.allocator.free(f.path);
    f.server = try Server.start(testing.allocator, f.path, cfg);
    return f;
}

/// `data` as a chunked body of `size`-byte chunks.
fn chunked(data: []const u8, size: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    var i: usize = 0;
    while (i < data.len) : (i += size) {
        const part = data[i..@min(i + size, data.len)];
        try out.print(testing.allocator, "{x}\r\n", .{part.len});
        try out.appendSlice(testing.allocator, part);
        try out.appendSlice(testing.allocator, "\r\n");
    }
    try out.appendSlice(testing.allocator, "0\r\n\r\n");
    return out.toOwnedSlice(testing.allocator);
}

/// The JSON lines a chunked response carries, joined.
fn dechunk(a: Allocator, text: []const u8) ![]const u8 {
    const body = bodyOf(text);
    var out: std.ArrayList(u8) = .empty;
    var rest = body;
    while (true) {
        const nl = std.mem.indexOf(u8, rest, "\r\n") orelse return error.BadChunk;
        const n = try std.fmt.parseInt(usize, rest[0..nl], 16);
        if (n == 0) return out.items;
        if (rest.len < nl + 2 + n + 2) return error.BadChunk;
        try out.appendSlice(a, rest[nl + 2 ..][0..n]);
        rest = rest[nl + 2 + n + 2 ..];
    }
}

const build_head = "POST /v1.52/build?dockerfile=Dockerfile&t=x%3A1&t=y&buildargs=%7B%22A%22%3A%221%22%7D&version=1 HTTP/1.1\r\n" ++
    "Host: api.moby.localhost\r\nUser-Agent: Docker-Client/29.9.3 (linux)\r\nTransfer-Encoding: chunked\r\n" ++
    "Content-Type: application/x-tar\r\nX-Registry-Config: e30=\r\n\r\n";

test "docker api: POST /build reads a chunked context, hands it to the handler and streams its lines" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, test_cfg);
    const context = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(context);
    for (context, 0..) |*c, i| c.* = @truncate(i *% 31);
    const body = try chunked(context, 512);
    defer testing.allocator.free(body);
    const req = try std.mem.concat(testing.allocator, u8, &.{ build_head, body });
    defer testing.allocator.free(req);
    const got = try ask(f.path, req, 5000);
    defer testing.allocator.free(got.text);
    try testing.expect(got.closed);
    fake.sync();
    try testing.expectEqual(@as(u16, 200), statusOf(got.text));
    try expectContains(got.text, "Transfer-Encoding: chunked\r\n");
    try expectContains(got.text, "Content-Type: application/json\r\n");
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const lines = try dechunk(arena.allocator(), got.text);
    try testing.expectEqualStrings("{\"stream\":\"Step 1/1 : FROM scratch\\n\"}\n{\"aux\":{\"ID\":\"sha256:abc\"}}\n", lines);
    // The handler had the whole context, and what the query asked.
    try testing.expectEqualSlices(u8, context, fake.tar);
    testing.allocator.free(fake.tar);
    try testing.expectEqual(@as(usize, 2), fake.tags_len);
    try testing.expectEqualStrings("A", fake.arg_name[0..fake.arg_len]);
    // The context's file is gone once the build is.
    const st = f.server.stats();
    try testing.expectEqual(@as(u32, 1), st.builds);
    try testing.expect(st.beyond >= 1);
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(testing.io, "api-0.tar", .{}));
    _ = f.finish();
}

test "docker api: POST /build takes a Content-Length body too, and a context in one piece with the head" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, test_cfg);
    defer _ = f.finish();
    const head = "POST /build?t=z HTTP/1.1\r\nHost: d\r\nContent-Length: 11\r\n\r\n";
    const got = try ask(f.path, head ++ "hello world", 5000);
    defer testing.allocator.free(got.text);
    try testing.expectEqual(@as(u16, 200), statusOf(got.text));
    fake.sync();
    try testing.expectEqualStrings("hello world", fake.tar);
    testing.allocator.free(fake.tar);
}

test "docker api: POST /build refuses what it cannot build before reading the context" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, test_cfg);
    defer _ = f.finish();
    const Case = struct { target: []const u8, status: u16, message: []const u8 };
    const cases = [_]Case{
        .{ .target = "/build?buildargs=nope", .status = 400, .message = "not a JSON object" },
        .{ .target = "/build?t=UPPER", .status = 200, .message = "" },
        .{ .target = "/build?platform=linux%2Farm64x", .status = 400, .message = "is not supported by zig-runner" },
        .{ .target = "/build?networkmode=host", .status = 501, .message = "--network=host" },
        .{ .target = "/build?squash=1", .status = 501, .message = "--squash" },
        .{ .target = "/build?remote=https%3A%2F%2Fx", .status = 501, .message = "remote build context" },
        .{ .target = "/build?version=2", .status = 501, .message = "BuildKit" },
    };
    for (cases) |c| {
        const req = try std.fmt.allocPrint(testing.allocator, "POST {s} HTTP/1.1\r\nHost: d\r\nContent-Length: 3\r\n\r\nabc", .{c.target});
        defer testing.allocator.free(req);
        const got = try ask(f.path, req, 3000);
        defer testing.allocator.free(got.text);
        testing.expectEqual(c.status, statusOf(got.text)) catch |e| {
            std.debug.print("case {s}: {s}\n", .{ c.target, got.text });
            return e;
        };
        if (c.message.len > 0) try expectContains(got.text, c.message);
    }
    // A build with no context at all.
    const none = try ask(f.path, "POST /build HTTP/1.1\r\nHost: d\r\n\r\n", 3000);
    defer testing.allocator.free(none.text);
    try testing.expectEqual(@as(u16, 400), statusOf(none.text));
    try expectContains(none.text, "needs a context");
    fake.sync();
    if (fake.tar.len > 0) testing.allocator.free(fake.tar);
}

test "docker api: a context over the limit is 413, a broken chunk 400, a slow upload 408" {
    var fake: Fake = .{ .tmp_dir = "" };
    var cfg = test_cfg;
    cfg.limits.body_bytes = 1000;
    cfg.limits.body_idle_ms = 300;
    var f = try startBuilding(&fake, cfg);
    defer _ = f.finish();
    {
        const got = try ask(f.path, "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 5000\r\n\r\n", 3000);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(u16, 413), statusOf(got.text));
    }
    {
        const big: [2000]u8 = @splat('x');
        const body = try chunked(&big, 400);
        defer testing.allocator.free(body);
        const req = try std.mem.concat(testing.allocator, u8, &.{ "POST /build HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n", body });
        defer testing.allocator.free(req);
        const got = try ask(f.path, req, 3000);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(u16, 413), statusOf(got.text));
    }
    {
        const got = try ask(f.path, "POST /build HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n", 3000);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(u16, 400), statusOf(got.text));
    }
    {
        const got = try ask(f.path, "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 10\r\n\r\nabc", 3000);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(u16, 408), statusOf(got.text));
    }
    try testing.expectEqual(@as(u32, 0), fake.builds.load(.acquire));
}

test "docker api: a client that leaves cancels its build, and the build is waited for" {
    var fake: Fake = .{ .tmp_dir = "", .hang = true };
    var f = try startBuilding(&fake, test_cfg);
    const fd = try connect(f.path);
    const req = "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 2\r\n\r\nhi";
    _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
    // The build has started (its first line is there), then the client goes.
    var buf: [4096]u8 = undefined;
    var seen: usize = 0;
    const t0 = nowMs();
    while (nowMs() - t0 < 3000 and std.mem.indexOf(u8, buf[0..seen], "FROM scratch") == null) {
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 100) > 0) seen += linux.read(fd, buf[seen..].ptr, buf.len - seen);
    }
    try testing.expect(std.mem.indexOf(u8, buf[0..seen], "FROM scratch") != null);
    _ = linux.close(fd);
    const t1 = nowMs();
    while (fake.cancels.load(.acquire) == 0 and nowMs() - t1 < 3000) {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    try testing.expect(fake.cancels.load(.acquire) >= 1);
    // stop joins the connection, which joined the build.
    _ = f.finish();
    testing.allocator.free(fake.tar);
}

test "docker api: closing the gate cancels the build in flight, waits for it, and turns requests away" {
    var fake: Fake = .{ .tmp_dir = "", .hang = true };
    var f = try startBuilding(&fake, test_cfg);
    defer _ = f.finish();
    f.server.openGate();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const req = "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 2\r\n\r\nhi";
    _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
    const t0 = nowMs();
    while (fake.builds.load(.acquire) == 0 and nowMs() - t0 < 3000) {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    try testing.expectEqual(@as(u32, 1), fake.builds.load(.acquire));
    const t1 = nowMs();
    try testing.expect(f.server.closeGate());
    // Cancelled and ended well before the build's own 5 s.
    try testing.expect(nowMs() - t1 < 3000);
    try testing.expect(fake.cancels.load(.acquire) >= 1);
    fake.sync();
    // Closed: the next request is 503 and counted, whichever it is.
    const got = try get(f.path, "/_ping");
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(u16, 503), statusOf(got));
    try expectContains(got, "no step of the job is running");
    try testing.expect(f.server.stats().gated >= 1);
    // Open again: the handler is told to forget the cancel, and the ping answers.
    const resets = fake.resets.load(.acquire);
    f.server.openGate();
    try testing.expect(fake.resets.load(.acquire) > resets);
    const ok = try get(f.path, "/_ping");
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
    testing.allocator.free(fake.tar);
}

test "docker api: a request from a client that has gone is counted by the step that made it, and none by the next" {
    var fake: Fake = .{ .tmp_dir = "" };
    var cfg = test_cfg;
    // Held in the connection's thread after it was read, as a late-admitted request is.
    cfg.test_route_delay_ms = 200;
    var f = try startBuilding(&fake, cfg);
    defer _ = f.finish();
    f.server.openGate();
    {
        const fd = try connect(f.path);
        const req = "GET /images/x/json HTTP/1.1\r\nHost: d\r\n\r\n";
        _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
        _ = linux.close(fd);
    }
    // The step ends with its request in flight (read, and held by the test's delay): the gate
    // waits for it, and it is counted.
    const t0 = nowMs();
    while (f.server.stats().requests == 0 and nowMs() - t0 < 3000) {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    try testing.expect(f.server.closeGate());
    try testing.expectEqual(@as(u32, 1), f.server.stats().beyond);
    const before = f.server.stats().beyond;
    // A request after the end finds the gate closed: it cannot be in flight in the next step's
    // window, and it is 503 whenever it is read.
    {
        const fd = try connect(f.path);
        const req = "GET /images/y/json HTTP/1.1\r\nHost: d\r\n\r\n";
        _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
        _ = linux.close(fd);
    }
    f.server.settle();
    try testing.expect(f.server.stats().gated >= 1);
    // It reached no handler: the image op the handler saw last is the first request's.
    fake.sync();
    try testing.expectEqualStrings("inspect x", fake.last_image_op.?);
    testing.allocator.free(fake.last_image_op.?);
    try testing.expect(f.server.stats().beyond > before);
}

test "docker api: the image routes reach the handler with the name decoded" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, test_cfg);
    defer _ = f.finish();
    const Case = struct { method: []const u8, target: []const u8, op: []const u8 };
    const cases = [_]Case{
        .{ .method = "GET", .target = "/v1.52/images/x:1/json", .op = "inspect x:1" },
        .{ .method = "GET", .target = "/images/myorg/app:2/json", .op = "inspect myorg/app:2" },
        .{ .method = "GET", .target = "/images/sha256%3Aabcd/json", .op = "inspect sha256:abcd" },
        .{ .method = "POST", .target = "/images/x/tag?repo=y&tag=2", .op = "tag x y 2" },
        .{ .method = "POST", .target = "/images/x/tag?repo=reg.io%2Fy", .op = "tag x reg.io/y " },
        .{ .method = "DELETE", .target = "/images/x:1", .op = "remove x:1 false" },
        .{ .method = "DELETE", .target = "/images/x?force=1&noprune=0", .op = "remove x true" },
    };
    for (cases) |c| {
        const req = try std.fmt.allocPrint(testing.allocator, "{s} {s} HTTP/1.1\r\nHost: d\r\n\r\n", .{ c.method, c.target });
        defer testing.allocator.free(req);
        const got = try ask(f.path, req, 3000);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(u16, 200), statusOf(got.text));
        fake.sync();
        try testing.expectEqualStrings(c.op, fake.last_image_op.?);
        testing.allocator.free(fake.last_image_op.?);
        fake.last_image_op = null;
    }
    // The list and the search are not an image.
    const list = try get(f.path, "/images/json");
    defer testing.allocator.free(list);
    try testing.expectEqual(@as(u16, 501), statusOf(list));
}

test "docker api: the docker CLI's own build requests (recorded) reach the handler with their context whole" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, .{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = f.finish();
    for ([_]usize{ 2, 3 }) |which| {
        const c = captures[which];
        errdefer std.debug.print("ERROR capture {s}\n", .{c.name});
        // The CLI sent a ping, then the build, on one connection.
        const got = try ask(f.path, c.request, 5000);
        defer testing.allocator.free(got.text);
        try expectContains(got.text, "HTTP/1.1 200 OK");
        try expectContains(got.text, "Transfer-Encoding: chunked");
        fake.sync();
        try testing.expect(fake.tar.len > 1024);
        // What it sent is a tar with a Dockerfile in it, which unpacks.
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "ctx.tar", .data = fake.tar });
        try tmp.dir.createDirPath(testing.io, "out");
        const base = try tmp.dir.realPathFileAlloc(testing.io, ".", arena.allocator());
        var why: []const u8 = "";
        const out = try docker_build.unpack(arena.allocator(), testing.io, try std.fmt.allocPrint(arena.allocator(), "{s}/out", .{base}), try std.fmt.allocPrint(arena.allocator(), "{s}/ctx.tar", .{base}), .{}, null, &why);
        try testing.expect(out.entries >= 1);
        const df = try tmp.dir.readFileAlloc(testing.io, "out/Dockerfile", arena.allocator(), .limited(1 << 16));
        try testing.expect(std.mem.startsWith(u8, df, "FROM "));
        testing.allocator.free(fake.tar);
        fake.tar = &.{};
    }
    fake.sync();
    try testing.expectEqual(@as(usize, 1), fake.arg_len);
}

test "docker api: the docker CLI's own image requests (recorded) are the routes the handler gets" {
    var fake: Fake = .{ .tmp_dir = "" };
    var f = try startBuilding(&fake, .{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = f.finish();
    const Case = struct { req: []const u8, op: []const u8 };
    const cases = [_]Case{
        .{ .req = @embedFile("testdata/docker_api/09-image-inspect.req"), .op = "inspect myorg/app:1.2" },
        .{ .req = @embedFile("testdata/docker_api/10-image-tag.req"), .op = "tag myorg/app:1.2 reg.io/y 2" },
        .{ .req = @embedFile("testdata/docker_api/11-image-rmi.req"), .op = "remove reg.io/y:2 false" },
        .{ .req = @embedFile("testdata/docker_api/12-image-inspect-id.req"), .op = "inspect sha256:0123456789ab" },
        .{ .req = @embedFile("testdata/docker_api/13-image-rmi-force.req"), .op = "remove 0123abcd true" },
    };
    for (cases) |c| {
        errdefer std.debug.print("ERROR request for {s}\n", .{c.op});
        // The CLI's ping, then its request, on one connection: both answered.
        const got = try ask(f.path, c.req, 300);
        defer testing.allocator.free(got.text);
        try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got.text, "HTTP/1.1 "));
        fake.sync();
        try testing.expectEqualStrings(c.op, fake.last_image_op.?);
        testing.allocator.free(fake.last_image_op.?);
        fake.last_image_op = null;
    }
}

test "docker api: one build at a time, a job's uploads are budgeted" {
    var fake: Fake = .{ .tmp_dir = "", .hang = true };
    var cfg = test_cfg;
    cfg.limits.spool_budget = 100;
    var f = try startBuilding(&fake, cfg);
    defer _ = f.finish();
    f.server.openGate();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const req = "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 2\r\n\r\nhi";
    _ = linux.sendto(fd, req.ptr, req.len, linux.MSG.NOSIGNAL, null, 0);
    const t0 = nowMs();
    while (fake.builds.load(.acquire) == 0 and nowMs() - t0 < 3000) {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 2_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    // A second build while the first is in hand is told so, without being read.
    const second = try ask(f.path, req, 2000);
    defer testing.allocator.free(second.text);
    try testing.expectEqual(@as(u16, 429), statusOf(second.text));
    try expectContains(second.text, "one at a time");
    try testing.expect(f.server.closeGate());
    fake.sync();
    testing.allocator.free(fake.tar);
    fake.tar = &.{};
    // The budget: 100 bytes of uploads in all.
    f.server.openGate();
    const big = "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 90\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    fake.hang = false;
    const one = try ask(f.path, big, 3000);
    defer testing.allocator.free(one.text);
    try testing.expectEqual(@as(u16, 200), statusOf(one.text));
    fake.sync();
    testing.allocator.free(fake.tar);
    fake.tar = &.{};
    const two = try ask(f.path, big, 3000);
    defer testing.allocator.free(two.text);
    try testing.expectEqual(@as(u16, 413), statusOf(two.text));
}
