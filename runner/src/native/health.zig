//! When a native service is ready (docs/native-backend.md, P6), decided in its sandbox's helper
//! (`sandbox.runStep`), which already holds the service's first process as its child: so the
//! process a health check joins can never be another one that took its pid, and a check runs in
//! the service's namespaces with nothing but a `fork`.
//!
//! A service is ready, as on GitHub, when its health check passes: `options: --health-cmd ...`,
//! or the image's own `HEALTHCHECK` (`healthFor`). Without one, it is ready when each of its
//! `ports:` accepts a connection, as the Dagger path's `start` waits; with neither, once it has
//! started. The helper writes the answer once to a file of the job's (`Ready.status`), which the
//! runner reads (`services.zig`); the service cannot reach that file, which is outside its root.
//!
//! Docker counts a health check's failure once per interval, after the start period, and calls
//! the container unhealthy after `retries` of them in a row. The helper keeps that count, but
//! tries sooner in between (from 10 ms, doubling up to the interval), so a database that is up
//! after two seconds is ready after two seconds, not at the first interval's end.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox.zig");

const Allocator = std.mem.Allocator;

/// What the helper is told of a service, besides its sandbox (`sandbox.Spec.service`).
pub const Ready = struct {
    /// Where the helper writes its answer: a file of the job's, empty until then; one line,
    /// `ready` or `unhealthy <why>`, written once.
    status: []const u8,
    health: ?Health = null,
    /// Without a health check: the ports that must accept a connection on the job's loopback.
    ports: []const u16 = &.{},
    ports_timeout_ms: u32 = default_ports_timeout_ms,
};

/// How long a service with ports and no health check may take to accept connections on them.
pub const default_ports_timeout_ms = 5 * 60 * 1000;

/// A health check, as Docker's `HEALTHCHECK` and `--health-*` options give it.
pub const Health = struct {
    /// `CMD-SHELL` (and `--health-cmd`): `/bin/sh -c <cmd>`; `CMD`: the arguments, the first
    /// looked up in the service's PATH (`search`).
    argv: []const []const u8,
    search: bool = false,
    interval_ms: u32 = default_interval_ms,
    timeout_ms: u32 = default_interval_ms,
    retries: u32 = default_retries,
    start_period_ms: u32 = 0,
};

/// Docker's defaults: a check every 30 s, given 30 s, unhealthy after 3 failures.
pub const default_interval_ms = 30_000;
pub const default_retries = 3;

/// The first try's delay (doubled after each failure, up to the interval), and how often ports
/// are tried at most.
const first_delay_ms = 10;
const ports_delay_ms = 250;

/// The status file, opened for the helper's one write (`report`). It is made, empty, by the
/// runner.
pub fn openStatus(arena: Allocator, path: []const u8) linux.fd_t {
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CLOEXEC = true };
    const fd = linux.open(sandbox.z(arena, path), flags, 0);
    sandbox.check("open the service's status file", fd);
    return @intCast(fd);
}

fn report(fd: linux.fd_t, line: []const u8) void {
    var done: usize = 0;
    while (done < line.len) {
        const rc = linux.pwrite(fd, line[done..].ptr, line.len - done, @intCast(done));
        if (linux.errno(rc) != .SUCCESS) return;
        done += rc;
    }
}

/// `sandbox.superviseStep` for a service: waits for its first process (`pid`) until the lifeline
/// closes or the process ends, and meanwhile decides once whether it is ready (see the file's
/// comment), writing the answer to `status`. The wait status.
pub fn supervise(
    arena: Allocator,
    spec: sandbox.Spec,
    ready: Ready,
    pid: linux.pid_t,
    root: linux.fd_t,
    status: linux.fd_t,
    env: []const []const u8,
) u32 {
    const pidfd_rc = linux.pidfd_open(pid, 0);
    sandbox.check("watch the service", pidfd_rc);
    const pidfd: linux.fd_t = @intCast(pidfd_rc);
    var decided = false;
    if (ready.health == null and ready.ports.len == 0) {
        report(status, "ready\n");
        decided = true;
    }
    const start = nowMs();
    const cap: u64 = if (ready.health) |h| @max(h.interval_ms, first_delay_ms) else ports_delay_ms;
    var delay: u64 = first_delay_ms;
    var next_at = start + first_delay_ms;
    var failures: u32 = 0;
    var last_counted = start;
    var check: ?Check = null;
    while (true) {
        var timeout: i32 = -1;
        if (!decided) {
            const until = if (check) |c| c.deadline else next_at;
            timeout = @intCast(@min(until -| nowMs(), std.math.maxInt(i32)));
        }
        var fds = [_]linux.pollfd{
            .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (check) |c| c.pidfd else -1, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&fds, fds.len, timeout);
        if (linux.errno(rc) == .INTR) continue;
        sandbox.check("wait for the service or its stop", rc);
        if (fds[0].revents != 0) {
            _ = linux.kill(pid, .KILL);
            break;
        }
        if (fds[1].revents != 0) break;
        if (decided) continue;
        const now = nowMs();
        var outcome: ?bool = null;
        if (check) |c| {
            if (fds[2].revents != 0) {
                outcome = c.finish() == 0;
                check = null;
            } else if (now >= c.deadline) {
                _ = linux.kill(c.pid, .KILL);
                _ = c.finish();
                outcome = false;
                check = null;
            }
        } else if (now >= next_at) {
            if (ready.health) |h| {
                check = startCheck(arena, spec, h, root, env, now);
                if (check == null) outcome = false;
            } else outcome = portsOpen(ready.ports);
        }
        const ok = outcome orelse continue;
        if (ok) {
            report(status, "ready\n");
            decided = true;
            continue;
        }
        if (ready.health) |h| {
            // Counted as Docker counts: once an interval, after the start period.
            if (now >= start + h.start_period_ms and now >= last_counted + h.interval_ms) {
                failures += 1;
                last_counted = now;
            }
            if (failures >= h.retries) {
                var buf: [96]u8 = undefined;
                report(status, std.fmt.bufPrint(&buf, "unhealthy its health check failed {d} " ++
                    "times in a row\n", .{failures}) catch "unhealthy\n");
                decided = true;
                continue;
            }
        } else if (now >= start + ready.ports_timeout_ms) {
            var buf: [128]u8 = undefined;
            report(status, std.fmt.bufPrint(&buf, "unhealthy its ports did not accept " ++
                "connections within {d} s\n", .{ready.ports_timeout_ms / 1000}) catch
                "unhealthy\n");
            decided = true;
            continue;
        }
        delay = @min(delay * 2, cap);
        next_at = now + delay;
    }
    if (check) |c| {
        _ = linux.kill(c.pid, .KILL);
        _ = c.finish();
    }
    _ = linux.close(pidfd);
    var st: i32 = 0;
    while (true) {
        const w = linux.waitpid(pid, &st, 0);
        if (linux.errno(w) == .INTR) continue;
        sandbox.check("wait for the service", w);
        break;
    }
    return @bitCast(st);
}

/// A health check running: its process, watched through a pidfd, and when it must have ended.
const Check = struct {
    pid: linux.pid_t,
    pidfd: linux.fd_t,
    deadline: u64,

    /// Reaps it: its exit code, or 128 + its signal.
    fn finish(c: Check) u32 {
        _ = linux.close(c.pidfd);
        var st: i32 = 0;
        while (true) {
            const w = linux.waitpid(c.pid, &st, 0);
            if (linux.errno(w) == .INTR) continue;
            if (linux.errno(w) != .SUCCESS) return 128;
            break;
        }
        const s: u32 = @bitCast(st);
        if (linux.W.IFEXITED(s)) return linux.W.EXITSTATUS(s);
        return 128;
    }
};

/// Starts one health check as a step is started, but inside the running service: a child of the
/// helper, so in the service's PID namespace (the helper unshared it; a fork fails once the
/// service's first process is gone), its mount, UTS, IPC and network namespaces and user, with
/// the service's root as its own, Docker's capabilities, the seccomp filter and the service's
/// user and environment. Its output is dropped, as Docker keeps it out of the container's log.
/// Null when it could not be started, which counts as a failure.
fn startCheck(
    arena: Allocator,
    spec: sandbox.Spec,
    h: Health,
    root: linux.fd_t,
    env: []const []const u8,
    now: u64,
) ?Check {
    if (h.argv.len == 0) return null;
    const argv = sandbox.zList(arena, h.argv);
    const envp = sandbox.zList(arena, env);
    const workdir = sandbox.z(arena, spec.workdir);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return null;
    if (pid == 0) {
        _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0);
        sandbox.check("enter the service's root", linux.fchdir(root));
        sandbox.check("chroot to the service's root", linux.chroot("."));
        if (linux.errno(linux.chdir(workdir)) != .SUCCESS) _ = linux.chdir("/");
        sandbox.dropCapabilities();
        sandbox.installSeccomp();
        if (spec.uid != 0 or spec.gid != 0) {
            sandbox.check("setgroups", linux.setgroups(0, sandbox.no_groups));
            sandbox.check("setgid", linux.setgid(spec.gid));
            sandbox.check("setuid", linux.setuid(spec.uid));
        }
        if (spec.userns != .mapped or spec.uid == 0)
            sandbox.check("no_new_privs", linux.prctl(
                @backingInt(linux.PR.SET_NO_NEW_PRIVS),
                1,
                0,
                0,
                0,
            ));
        const devnull = linux.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(devnull) == .SUCCESS) {
            for ([_]i32{ 0, 1, 2 }) |fd| _ = linux.dup2(@intCast(devnull), fd);
        }
        const path = if (h.search) sandbox.lookPath(arena, h.argv[0], env) else argv[0].?;
        _ = linux.execve(path, argv, envp);
        linux.exit_group(127);
    }
    const fd = linux.pidfd_open(@intCast(pid), 0);
    if (linux.errno(fd) != .SUCCESS) {
        _ = linux.kill(@intCast(pid), .KILL);
        var st: i32 = 0;
        _ = linux.waitpid(@intCast(pid), &st, 0);
        return null;
    }
    return .{ .pid = @intCast(pid), .pidfd = @intCast(fd), .deadline = now + h.timeout_ms };
}

/// Whether every port accepts a connection on the loopback of the helper's network namespace,
/// which is the job's, shared with the service.
fn portsOpen(ports: []const u16) bool {
    for (ports) |p| if (!accepts(p)) return false;
    return true;
}

fn accepts(port: u16) bool {
    const v4 = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(v4) == .SUCCESS) {
        defer _ = linux.close(@intCast(v4));
        var sa: linux.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        const rc = linux.connect(@intCast(v4), @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
        if (linux.errno(rc) == .SUCCESS) return true;
    }
    // A server listening on ::1 alone.
    const v6 = linux.socket(linux.AF.INET6, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(v6) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(v6));
    var sa6: linux.sockaddr.in6 = .{
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .scope_id = 0,
    };
    const rc = linux.connect(@intCast(v6), @ptrCast(&sa6), @sizeOf(linux.sockaddr.in6));
    return linux.errno(rc) == .SUCCESS;
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

// --- the runner's side: a service's health check from its options and its image ---

/// A health check as the image's configuration gives it (`HEALTHCHECK`): `Test` is `["NONE"]`,
/// `["CMD", args...]` or `["CMD-SHELL", command]`; the times are nanoseconds, 0 for Docker's
/// default.
pub const ImageCheck = struct {
    test_cmd: []const []const u8 = &.{},
    interval_ns: u64 = 0,
    timeout_ns: u64 = 0,
    start_period_ns: u64 = 0,
    retries: u32 = 0,
};

/// The service's health check: `--health-cmd` and the other `--health-*` options over the image's
/// `HEALTHCHECK`, none with `--no-healthcheck` or `NONE`, as `docker create` decides it. An
/// option that cannot be read is in `bad`, for the log, and leaves Docker's default.
pub fn healthFor(
    arena: Allocator,
    options: []const u8,
    image: ?ImageCheck,
    bad: *std.ArrayList([]const u8),
) !?Health {
    var h: Health = .{ .argv = &.{} };
    var have = false;
    if (image) |ic| if (ic.test_cmd.len > 0) {
        const kind = ic.test_cmd[0];
        if (std.mem.eql(u8, kind, "CMD-SHELL") and ic.test_cmd.len >= 2) {
            h.argv = try arena.dupe([]const u8, &.{ "/bin/sh", "-c", ic.test_cmd[1] });
            have = true;
        } else if (std.mem.eql(u8, kind, "CMD") and ic.test_cmd.len >= 2) {
            h.argv = ic.test_cmd[1..];
            h.search = true;
            have = true;
        }
        if (ic.interval_ns > 0) h.interval_ms = nsToMs(ic.interval_ns);
        if (ic.timeout_ns > 0) h.timeout_ms = nsToMs(ic.timeout_ns);
        if (ic.start_period_ns > 0) h.start_period_ms = nsToMs(ic.start_period_ns);
        if (ic.retries > 0) h.retries = ic.retries;
    };
    const words = try splitOptions(arena, options);
    var i: usize = 0;
    while (i < words.len) : (i += 1) {
        const w = words[i];
        if (std.mem.eql(u8, w, "--no-healthcheck")) return null;
        if (!std.mem.startsWith(u8, w, "--health-")) continue;
        var name = w;
        var value: []const u8 = "";
        if (std.mem.indexOfScalar(u8, w, '=')) |eq| {
            name = w[0..eq];
            value = w[eq + 1 ..];
        } else if (i + 1 < words.len) {
            i += 1;
            value = words[i];
        }
        if (std.mem.eql(u8, name, "--health-cmd")) {
            if (value.len == 0) continue;
            h.argv = try arena.dupe([]const u8, &.{ "/bin/sh", "-c", value });
            h.search = false;
            have = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--health-retries")) {
            h.retries = std.fmt.parseInt(u32, value, 10) catch {
                try bad.append(arena, w);
                continue;
            };
            continue;
        }
        const ms = parseDurationMs(value) orelse {
            try bad.append(arena, w);
            continue;
        };
        if (std.mem.eql(u8, name, "--health-interval")) {
            h.interval_ms = ms;
        } else if (std.mem.eql(u8, name, "--health-timeout")) {
            h.timeout_ms = ms;
        } else if (std.mem.eql(u8, name, "--health-start-period")) {
            h.start_period_ms = ms;
        }
        // `--health-start-interval` is Docker's pace during the start period, which the
        // helper's quicker tries already cover.
    }
    if (!have) return null;
    // Docker takes 0 for its default.
    if (h.interval_ms == 0) h.interval_ms = default_interval_ms;
    if (h.timeout_ms == 0) h.timeout_ms = default_interval_ms;
    if (h.retries == 0) h.retries = default_retries;
    return h;
}

fn nsToMs(ns: u64) u32 {
    return @intCast(@min(ns / std.time.ns_per_ms, std.math.maxInt(u32)));
}

/// `options:` split into words as a shell splits them: quotes group, a backslash escapes in
/// double quotes and outside them.
pub fn splitOptions(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var word: std.ArrayList(u8) = .empty;
    var in_word = false;
    var quote: ?u8 = null;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (quote) |q| {
            if (c == q) {
                quote = null;
            } else if (q == '"' and c == '\\' and i + 1 < text.len) {
                i += 1;
                try word.append(arena, text[i]);
            } else try word.append(arena, c);
            continue;
        }
        switch (c) {
            ' ', '\t', '\n', '\r' => if (in_word) {
                try out.append(arena, try word.toOwnedSlice(arena));
                in_word = false;
            },
            '"', '\'' => {
                quote = c;
                in_word = true;
            },
            '\\' => {
                in_word = true;
                if (i + 1 < text.len) {
                    i += 1;
                    try word.append(arena, text[i]);
                }
            },
            else => {
                in_word = true;
                try word.append(arena, c);
            },
        }
    }
    if (in_word) try out.append(arena, try word.toOwnedSlice(arena));
    return out.items;
}

/// A Go duration (`10s`, `1m30s`, `500ms`, `1.5s`), as Docker reads `--health-*` times, in
/// milliseconds; null when it is not one. A unit is required, as in Go, except for `0`.
pub fn parseDurationMs(text: []const u8) ?u32 {
    if (std.mem.eql(u8, text, "0")) return 0;
    if (text.len == 0) return null;
    var total: f64 = 0;
    var i: usize = 0;
    while (i < text.len) {
        const num_start = i;
        while (i < text.len and (std.ascii.isDigit(text[i]) or text[i] == '.')) : (i += 1) {}
        if (i == num_start) return null;
        const n = std.fmt.parseFloat(f64, text[num_start..i]) catch return null;
        const unit_start = i;
        while (i < text.len and !std.ascii.isDigit(text[i]) and text[i] != '.') : (i += 1) {}
        const unit = text[unit_start..i];
        const ms_per: f64 = if (std.mem.eql(u8, unit, "ns"))
            1e-6
        else if (std.mem.eql(u8, unit, "us") or std.mem.eql(u8, unit, "µs"))
            1e-3
        else if (std.mem.eql(u8, unit, "ms"))
            1
        else if (std.mem.eql(u8, unit, "s"))
            1000
        else if (std.mem.eql(u8, unit, "m"))
            60_000
        else if (std.mem.eql(u8, unit, "h"))
            3_600_000
        else
            return null;
        total += n * ms_per;
    }
    if (total > std.math.maxInt(u32)) return null;
    return @intFromFloat(total);
}

test "a service's health check: its options over the image's, as docker create decides" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var bad: std.ArrayList([]const u8) = .empty;
    const pg = (try healthFor(arena, "--health-cmd \"pg_isready -U postgres\" " ++
        "--health-interval 10s --health-timeout=5s --health-retries 5", null, &bad)).?;
    try std.testing.expectEqualStrings("/bin/sh", pg.argv[0]);
    try std.testing.expectEqualStrings("pg_isready -U postgres", pg.argv[2]);
    try std.testing.expect(!pg.search);
    try std.testing.expectEqual(@as(u32, 10_000), pg.interval_ms);
    try std.testing.expectEqual(@as(u32, 5_000), pg.timeout_ms);
    try std.testing.expectEqual(@as(u32, 5), pg.retries);
    // The image's HEALTHCHECK, its times in nanoseconds, the CMD form looked up in PATH.
    const image: ImageCheck = .{
        .test_cmd = &.{ "CMD", "redis-cli", "ping" },
        .interval_ns = 2 * std.time.ns_per_s,
        .retries = 7,
    };
    const img = (try healthFor(arena, "--shm-size 1g", image, &bad)).?;
    try std.testing.expectEqualStrings("redis-cli", img.argv[0]);
    try std.testing.expect(img.search);
    try std.testing.expectEqual(@as(u32, 2_000), img.interval_ms);
    try std.testing.expectEqual(@as(u32, default_interval_ms), img.timeout_ms);
    try std.testing.expectEqual(@as(u32, 7), img.retries);
    // Options win over the image; --no-healthcheck and NONE turn it off; nothing is nothing.
    const over = (try healthFor(arena, "--health-cmd='redis-cli -p 7000 ping'", image, &bad)).?;
    try std.testing.expectEqualStrings("redis-cli -p 7000 ping", over.argv[2]);
    try std.testing.expectEqual(@as(u32, 2_000), over.interval_ms);
    try std.testing.expect(try healthFor(arena, "--no-healthcheck", image, &bad) == null);
    const none: ImageCheck = .{ .test_cmd = &.{"NONE"} };
    try std.testing.expect(try healthFor(arena, "", none, &bad) == null);
    try std.testing.expect(try healthFor(arena, "--health-interval 2s", null, &bad) == null);
    try std.testing.expectEqual(@as(usize, 0), bad.items.len);
    const unreadable = "--health-cmd true --health-interval soon --health-retries x";
    _ = try healthFor(arena, unreadable, null, &bad);
    try std.testing.expectEqual(@as(usize, 2), bad.items.len);
}

test "durations as Docker reads them, and options split as a shell splits them" {
    try std.testing.expectEqual(@as(?u32, 10_000), parseDurationMs("10s"));
    try std.testing.expectEqual(@as(?u32, 90_000), parseDurationMs("1m30s"));
    try std.testing.expectEqual(@as(?u32, 500), parseDurationMs("500ms"));
    try std.testing.expectEqual(@as(?u32, 1_500), parseDurationMs("1.5s"));
    try std.testing.expectEqual(@as(?u32, 0), parseDurationMs("0"));
    for ([_][]const u8{ "", "10", "s", "10x", "1..5s" }) |t|
        try std.testing.expect(parseDurationMs(t) == null);
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const words = try splitOptions(a.allocator(), "--health-cmd \"redis-cli \\\"ping\\\"\" " ++
        "--x='a b' c\\ d  ");
    try std.testing.expectEqual(@as(usize, 4), words.len);
    try std.testing.expectEqualStrings("redis-cli \"ping\"", words[1]);
    try std.testing.expectEqualStrings("--x=a b", words[2]);
    try std.testing.expectEqualStrings("c d", words[3]);
}
