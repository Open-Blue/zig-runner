//! One `step-end:` line per step, for finding where a job's time and resources go:
//!
//!   step-end: job=<check_run_id> step=<n> name='<display name>' result=<success|failure|cancelled|
//!   skipped> wall_ms=<..> cpu_ms=<..> mem_peak=<..> io_read=<..> io_write=<..> majflt=<..>
//!   minflt=<..> spawn_ms=<..> namespaces_ms=<..> overlay_ms=<..> binds_ms=<..> root_ms=<..>
//!   exit_ms=<..>
//!
//! (on one line). `key=value`, space separated; sizes in bytes, times in milliseconds to a tenth,
//! `?` for what could not be read; the name in single quotes, a quote or a control character in it
//! replaced. A native step's figures are what its cgroup (the job's `steps` child, where every
//! step's helper joins) gained between the step's start and its end: `cpu.stat`'s `usage_usec`,
//! `io.stat`'s `rbytes` and `wbytes`, `memory.stat`'s `pgmajfault` and `pgfault`, and
//! `memory.peak`, which is reset when the step starts where the kernel allows (Linux 6.12: a write
//! resets it for the file descriptor that wrote it, which is kept to the step's end); otherwise
//! it is the peak since the job's start, and `peak_scope=job` follows the line. The set-up fields
//! are the step's samples of the same phases as `native phases` (`native/phases.zig`). A Dagger
//! step has its time and its result only. `Meter` is the observer that measures the steps; the
//! lines go to `Options.step_ends`, which the caller writes out with the job's other lines.

const std = @import("std");
const linux = std.os.linux;
const dagger = @import("../dagger.zig");
const phases = @import("../native/phases.zig");
const admission = @import("../admission.zig");

/// A step's figures, as the line shows them. Null is `?`.
pub const Figures = struct {
    job: u64,
    step: u32,
    name: []const u8,
    result: []const u8,
    wall_ns: u64,
    cpu_us: ?u64 = null,
    mem_peak: ?u64 = null,
    io_read: ?u64 = null,
    io_write: ?u64 = null,
    majflt: ?u64 = null,
    minflt: ?u64 = null,
    /// The set-up phases, in microseconds.
    spawn_us: ?u64 = null,
    namespaces_us: ?u64 = null,
    overlay_us: ?u64 = null,
    binds_us: ?u64 = null,
    root_us: ?u64 = null,
    exit_us: ?u64 = null,
    /// `mem_peak` is the job's, not the step's.
    peak_job_scope: bool = false,

    pub fn write(f: Figures, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("step-end: job={d} step={d} name='", .{ f.job, f.step });
        for (f.name) |c| try w.writeByte(if (c == '\'') '"' else if (c < 0x20 or c == 0x7f) ' ' else c);
        try w.print("' result={s} wall_ms=", .{f.result});
        try tenths(w, f.wall_ns / 1000);
        try w.writeAll(" cpu_ms=");
        try tenths(w, f.cpu_us);
        for ([_]struct { []const u8, ?u64 }{
            .{ "mem_peak", f.mem_peak },
            .{ "io_read", f.io_read },
            .{ "io_write", f.io_write },
            .{ "majflt", f.majflt },
            .{ "minflt", f.minflt },
        }) |v| {
            try w.print(" {s}=", .{v[0]});
            if (v[1]) |n| try w.print("{d}", .{n}) else try w.writeByte('?');
        }
        for ([_]struct { []const u8, ?u64 }{
            .{ "spawn_ms", f.spawn_us },
            .{ "namespaces_ms", f.namespaces_us },
            .{ "overlay_ms", f.overlay_us },
            .{ "binds_ms", f.binds_us },
            .{ "root_ms", f.root_us },
            .{ "exit_ms", f.exit_us },
        }) |v| {
            try w.print(" {s}=", .{v[0]});
            try tenths(w, v[1]);
        }
        if (f.peak_job_scope) try w.writeAll(" peak_scope=job");
        try w.writeByte('\n');
    }
};

/// Microseconds as milliseconds to a tenth; `?` for null.
fn tenths(w: *std.Io.Writer, us: anytype) std.Io.Writer.Error!void {
    const n: u64 = switch (@typeInfo(@TypeOf(us))) {
        .optional => us orelse return w.writeByte('?'),
        else => us,
    };
    const t = n / 100;
    try w.print("{d}.{d}", .{ t / 10, t % 10 });
}

/// What a cgroup has counted so far; null for a file that could not be read.
pub const Counters = struct {
    cpu_us: ?u64 = null,
    io_read: ?u64 = null,
    io_write: ?u64 = null,
    majflt: ?u64 = null,
    minflt: ?u64 = null,

    pub fn read(io: std.Io, dir: []const u8) Counters {
        var c: Counters = .{};
        var buf: [4096]u8 = undefined;
        if (readFile(io, dir, "cpu.stat", &buf)) |t| c.cpu_us = admission.parseStat(t, "usage_usec");
        if (readFile(io, dir, "memory.stat", &buf)) |t| {
            c.majflt = admission.parseStat(t, "pgmajfault");
            c.minflt = admission.parseStat(t, "pgfault");
        }
        // One line per device: `8:0 rbytes=1 wbytes=2 rios=3 ...`. No file, where the io
        // controller is not enabled for the cgroup.
        if (readFile(io, dir, "io.stat", &buf)) |t| {
            var read_bytes: u64 = 0;
            var written: u64 = 0;
            var lines = std.mem.splitScalar(u8, t, '\n');
            while (lines.next()) |line| {
                var fields = std.mem.tokenizeScalar(u8, line, ' ');
                while (fields.next()) |field| {
                    if (std.mem.startsWith(u8, field, "rbytes="))
                        read_bytes += std.fmt.parseInt(u64, field[7..], 10) catch 0;
                    if (std.mem.startsWith(u8, field, "wbytes="))
                        written += std.fmt.parseInt(u64, field[7..], 10) catch 0;
                }
            }
            c.io_read = read_bytes;
            c.io_write = written;
        }
        return c;
    }

    fn delta(now: ?u64, before: ?u64) ?u64 {
        return (now orelse return null) -| (before orelse return null);
    }
};

fn readFile(io: std.Io, dir: []const u8, name: []const u8, buf: []u8) ?[]const u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name }) catch return null;
    return std.Io.Dir.cwd().readFile(io, path, buf) catch null;
}

/// `memory.peak` of a cgroup, from a file descriptor kept open from the step's start: where the
/// kernel lets a write reset it, the reset is for that descriptor, so it reads the most memory
/// the cgroup held since.
const Peak = struct {
    fd: ?linux.fd_t = null,
    /// Whether the descriptor was reset: the peak is the step's.
    reset: bool = false,

    fn open(dir: []const u8) Peak {
        var path_buf: [std.Io.Dir.max_path_bytes:0]u8 = undefined;
        const path = std.fmt.bufPrintSentinel(&path_buf, "{s}/memory.peak", .{dir}, 0) catch return .{};
        const rw = linux.open(path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        if (linux.errno(rw) == .SUCCESS) {
            const fd: linux.fd_t = std.math.cast(linux.fd_t, rw) orelse return .{};
            if (linux.errno(linux.write(fd, "1", 1)) == .SUCCESS) return .{ .fd = fd, .reset = true };
            // Open for writing but not resettable: the job's peak, read at the end.
            return .{ .fd = fd };
        }
        const ro = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(ro) != .SUCCESS) return .{};
        return .{ .fd = std.math.cast(linux.fd_t, ro) };
    }

    fn read(p: Peak) ?u64 {
        const fd = p.fd orelse return null;
        var buf: [64]u8 = undefined;
        const n = linux.pread(fd, &buf, buf.len, 0);
        if (linux.errno(n) != .SUCCESS) return null;
        return std.fmt.parseInt(u64, std.mem.trim(u8, buf[0..n], " \n"), 10) catch null;
    }

    fn close(p: Peak) void {
        if (p.fd) |fd| _ = linux.close(fd);
    }
};

/// The observer that writes a `step-end:` line as each step finishes, and passes everything on to
/// `inner`. Steps run one at a time, so one step is under measurement at a time.
pub const Meter = struct {
    inner: ?dagger.Observer,
    io: std.Io,
    out: *std.Io.Writer.Allocating,
    job: u64,
    /// The native backend's phases, and the cgroup its steps run in; both null for Dagger.
    timings: ?*const phases.Phases = null,
    cgroup: ?[]const u8 = null,
    // The step under measurement.
    began: ?u64 = null,
    mark: phases.Phases.Mark = undefined,
    counters: Counters = .{},
    peak: Peak = .{},

    pub fn observer(m: *Meter) dagger.Observer {
        // The extras and the post count are passed on only when the inner observer takes them.
        const i = m.inner;
        return .{
            .ptr = m,
            .startedFn = started,
            .finishedFn = finished,
            .extraStartedFn = if (i != null and i.?.extraStartedFn != null) extraStarted else null,
            .extraFinishedFn = if (i != null and i.?.extraFinishedFn != null) extraFinished else null,
            .postsFn = if (i != null and i.?.postsFn != null) posts else null,
        };
    }

    /// The observer's `ptr` is the meter: the one place the erased pointer is given back its type.
    fn self(ptr: *anyopaque) *Meter {
        return @ptrCast(@alignCast(ptr));
    }

    fn started(ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void {
        const m = self(ptr);
        m.begin();
        if (m.inner) |i| i.startedFn(i.ptr, number, name, started_ms);
    }

    fn finished(ptr: *anyopaque, number: u32, res: dagger.StepResult) void {
        const m = self(ptr);
        m.end(number, res);
        if (m.inner) |i| i.finishedFn(i.ptr, number, res);
    }

    fn extraStarted(ptr: *anyopaque, kind: dagger.ExtraKind, log_step: u32, name: []const u8, started_ms: i64) void {
        const m = self(ptr);
        const i = m.inner.?;
        i.extraStartedFn.?(i.ptr, kind, log_step, name, started_ms);
    }

    fn extraFinished(ptr: *anyopaque, e: dagger.ExtraStep) void {
        const m = self(ptr);
        const i = m.inner.?;
        i.extraFinishedFn.?(i.ptr, e);
    }

    fn posts(ptr: *anyopaque, n: u32, stop: bool) void {
        const m = self(ptr);
        const i = m.inner.?;
        i.postsFn.?(i.ptr, n, stop);
    }

    /// A step starts: the clock, the phases' mark and the cgroup's counters are taken, and the
    /// peak reset.
    pub fn begin(m: *Meter) void {
        m.peak.close();
        m.peak = .{};
        m.began = phases.now();
        if (m.timings) |t| m.mark = t.mark();
        if (m.cgroup) |dir| {
            m.counters = .read(m.io, dir);
            m.peak = .open(dir);
        }
    }

    /// A step ends (or was skipped, never begun): its line is written.
    pub fn end(m: *Meter, number: u32, res: dagger.StepResult) void {
        defer {
            m.peak.close();
            m.peak = .{};
            m.began = null;
        }
        var f: Figures = .{
            .job = m.job,
            .step = number,
            .name = res.name,
            .result = switch (res.outcome) {
                .success => "success",
                .failure => "failure",
                .cancelled => "cancelled",
                .skipped, .not_run => "skipped",
            },
            .wall_ns = if (m.began) |b| phases.now() -| b else 0,
        };
        if (m.began != null) {
            if (m.timings) |t| {
                f.spawn_us = t.sinceMark(m.mark, .spawn);
                f.namespaces_us = t.sinceMark(m.mark, .namespaces);
                f.overlay_us = t.sinceMark(m.mark, .overlay);
                f.binds_us = t.sinceMark(m.mark, .binds);
                f.root_us = t.sinceMark(m.mark, .root);
                f.exit_us = t.sinceMark(m.mark, .exit);
            }
            if (m.cgroup) |dir| {
                const now: Counters = .read(m.io, dir);
                f.cpu_us = Counters.delta(now.cpu_us, m.counters.cpu_us);
                f.io_read = Counters.delta(now.io_read, m.counters.io_read);
                f.io_write = Counters.delta(now.io_write, m.counters.io_write);
                f.majflt = Counters.delta(now.majflt, m.counters.majflt);
                f.minflt = Counters.delta(now.minflt, m.counters.minflt);
                f.mem_peak = m.peak.read();
                f.peak_job_scope = f.mem_peak != null and !m.peak.reset;
            }
        }
        f.write(&m.out.writer) catch |e| std.log.warn("step-end line not kept: {t}", .{e});
    }
};

test "the line: exact text for fixed figures, `?` for what was not read, and a name that cannot break it" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (Figures{
        .job = 77,
        .step = 3,
        .name = "Build it's \"x\"\nrm",
        .result = "success",
        .wall_ns = 12_345_678,
        .cpu_us = 9_876_543,
        .mem_peak = 123456789,
        .io_read = 4096,
        .io_write = 8192,
        .majflt = 2,
        .minflt = 1500,
        .spawn_us = 1_234,
        .namespaces_us = 2_000,
        .overlay_us = 3_999,
        .binds_us = 0,
        .root_us = 50_000,
        .exit_us = 100,
    }).write(&w);
    try std.testing.expectEqualStrings(
        "step-end: job=77 step=3 name='Build it\"s \"x\" rm' result=success wall_ms=12.3 " ++
            "cpu_ms=9876.5 mem_peak=123456789 io_read=4096 io_write=8192 majflt=2 minflt=1500 " ++
            "spawn_ms=1.2 namespaces_ms=2.0 overlay_ms=3.9 binds_ms=0.0 root_ms=50.0 exit_ms=0.1\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try (Figures{ .job = 1, .step = 2, .name = "x", .result = "failure", .wall_ns = 1_000_000, .peak_job_scope = true }).write(&w);
    try std.testing.expectEqualStrings(
        "step-end: job=1 step=2 name='x' result=failure wall_ms=1.0 cpu_ms=? mem_peak=? io_read=? " ++
            "io_write=? majflt=? minflt=? spawn_ms=? namespaces_ms=? overlay_ms=? binds_ms=? " ++
            "root_ms=? exit_ms=? peak_scope=job\n",
        w.buffered(),
    );
}

fn fakeCgroup(tmp: *std.testing.TmpDir, cpu: u64, majflt: u64, minflt: u64, rb: u64, wb: u64) !void {
    var buf: [512]u8 = undefined;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cpu.stat", .data = try std.fmt.bufPrint(&buf, "usage_usec {d}\nuser_usec 1\n", .{cpu}) });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "memory.stat", .data = try std.fmt.bufPrint(&buf, "anon 5\npgfault {d}\npgmajfault {d}\n", .{ minflt, majflt }) });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "io.stat", .data = try std.fmt.bufPrint(&buf, "8:0 rbytes={d} wbytes={d} rios=1 wios=1\n8:16 rbytes=10 wbytes=20 rios=1\n", .{ rb, wb }) });
}

test "a step's deltas come from its cgroup's counters between its start and its end, against a fake cgroup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = path_buf[0..try tmp.dir.realPathFile(std.testing.io, ".", &path_buf)];
    try fakeCgroup(&tmp, 1_000_000, 1, 100, 1000, 2000);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "memory.peak", .data = "5000\n" });

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var timings: phases.Phases = .{};
    defer for (&timings.samples) |*s| s.deinit(std.testing.allocator);
    var m: Meter = .{ .inner = null, .io = std.testing.io, .out = &out, .job = 9, .timings = &timings, .cgroup = dir };
    m.begin();
    // What the step did: the counters moved, and its sandbox's phases were sampled.
    try fakeCgroup(&tmp, 1_250_000, 3, 600, 5000, 2500);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "memory.peak", .data = "123456\n" });
    timings.add(std.testing.allocator, .spawn, 2_000_000);
    timings.add(std.testing.allocator, .root, 7_300_000);
    m.end(2, .{ .name = "Run tests", .outcome = .failure });
    const text = out.written();
    // The two devices' bytes add up; the reset wrote "1" into the fake's peak file, then the test
    // set it, as the kernel's would have counted.
    try std.testing.expect(std.mem.indexOf(u8, text, "step-end: job=9 step=2 name='Run tests' result=failure wall_ms=") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, " cpu_ms=250.0 mem_peak=123456 io_read=4000 io_write=500 majflt=2 minflt=500 spawn_ms=2.0 namespaces_ms=0.0 overlay_ms=0.0 binds_ms=0.0 root_ms=7.3 exit_ms=0.0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "peak_scope") == null);

    // A step that never began (skipped) has a time of 0 and nothing else.
    out.clearRetainingCapacity();
    m.end(3, .{ .name = "Later", .outcome = .skipped });
    try std.testing.expectEqualStrings(
        "step-end: job=9 step=3 name='Later' result=skipped wall_ms=0.0 cpu_ms=? mem_peak=? io_read=? io_write=? majflt=? minflt=? spawn_ms=? namespaces_ms=? overlay_ms=? binds_ms=? root_ms=? exit_ms=?\n",
        out.written(),
    );

    // Without a cgroup (Dagger): the time and the result.
    out.clearRetainingCapacity();
    var plain: Meter = .{ .inner = null, .io = std.testing.io, .out = &out, .job = 9 };
    plain.begin();
    plain.end(1, .{ .name = "s", .outcome = .success });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), " result=success wall_ms=") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), " cpu_ms=? mem_peak=? io_read=?") != null);
}
