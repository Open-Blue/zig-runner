//! Uploads step and job logs to GitHub's results service so the Actions UI can show them.
//!
//! Flow per log (names from `actions/runner`; verified live, see SPEC §3): ask the service for a
//! signed blob URL (Twirp JSON, authorized with the job-scoped token), PUT the log text to that
//! URL, then register the upload with a metadata call. Blob lines are `<ISO timestamp, 7 digits>
//! <text>`. Failures never block job completion: callers log the returned detail and carry on.
//! A failure that may pass (`transientError`, `transientStatus`) is tried again within `Retry`.
const std = @import("std");
const broker = @import("broker.zig");
const http = @import("http.zig");
const net_client = @import("../net_client.zig");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const timefmt = @import("../timefmt.zig");

const Allocator = std.mem.Allocator;

pub const service = "results.services.receiver.Receiver";

pub const Blob = struct {
    text: []const u8 = "",
    line_count: usize,
    /// Written out as it is uploaded, in place of `text` (`KeptBlob`).
    stream: ?broker.Body = null,

    fn len(b: Blob) usize {
        return if (b.stream) |s| s.len else b.text.len;
    }

    /// The blob's text, written out if it is streamed: for tests, which look at what went up.
    pub fn textAlloc(b: Blob, arena: Allocator) ![]const u8 {
        const s = b.stream orelse return b.text;
        var aw: std.Io.Writer.Allocating = .init(arena);
        try s.writeFn(s.ptr, &aw.writer);
        return aw.written();
    }
};

/// Lines of one step (`step` set) or of the whole job (`step` null), in arrival order.
pub fn formatBlob(
    arena: Allocator,
    lines: []const sink.CollectedLine,
    step: ?u32,
) Allocator.Error!Blob {
    var aw: std.Io.Writer.Allocating = .init(arena);
    var n: usize = 0;
    for (lines) |l| {
        if (step) |s| if (l.step != s) continue;
        var ts_buf: [64]u8 = undefined;
        const ts = timefmt.isoTime7Buf(&ts_buf, l.ts_ms);
        aw.writer.print("{s} {s}\n", .{ ts, l.text }) catch return error.OutOfMemory;
        n += 1;
    }
    return .{ .text = aw.written(), .line_count = n };
}

/// One step's log (`step` set) or the whole job's (`step` null) as `formatBlob` writes it, read
/// from the job's kept log (`sink.Kept`) as it is uploaded rather than held: the job's is up to
/// the 64 MiB the log keeps, and with a step's beside it, both formatted in memory, a 200 MB log
/// grew the runner by over 1 GB at the job's end.
pub const KeptBlob = struct {
    kept: *const sink.Kept,
    io: std.Io,
    step: ?u32,
    /// Read buffer, at least a spool record's header (`Kept.iterate`).
    buf: []u8,
    /// The bytes it writes (`count`).
    len: usize,

    /// Each step's line count, text bytes and blob size, and the whole job's (`all`), in one read
    /// of the log. `steps.len` is the number of log steps; a line of a step past it counts only in
    /// `all`.
    pub fn count(kept: *const Kept, io: std.Io, buf: []u8, steps: []Size) !Size {
        @memset(steps, .{});
        var all: Size = .{};
        var it = kept.iterate(io, buf);
        while (try it.next()) |l| {
            var ts_buf: [64]u8 = undefined;
            const size: Size = .{
                .lines = 1,
                .text_bytes = it.textLen(),
                .bytes = timefmt.isoTime7Buf(&ts_buf, l.ts_ms).len + 1 + it.textLen() + 1,
            };
            all.add(size);
            if (l.step < steps.len) steps[l.step].add(size);
        }
        return all;
    }

    pub const Size = struct {
        lines: usize = 0,
        /// The lines' text alone, as `StepLogs` counts it.
        text_bytes: usize = 0,
        /// The blob: each line's timestamp, a space, its text and a newline.
        bytes: usize = 0,

        fn add(s: *Size, o: Size) void {
            s.lines += o.lines;
            s.text_bytes += o.text_bytes;
            s.bytes += o.bytes;
        }
    };

    pub fn blob(b: *const KeptBlob, line_count: usize) Blob {
        return .{
            .line_count = line_count,
            .stream = .{ .len = b.len, .ptr = b, .writeFn = write },
        };
    }

    fn write(ptr: *const anyopaque, w: *std.Io.Writer) anyerror!void {
        const b: *const KeptBlob = @ptrCast(@alignCast(ptr));
        var it = b.kept.iterate(b.io, b.buf);
        var written: usize = 0;
        while (try it.next()) |l| {
            if (b.step) |s| if (l.step != s) continue;
            var ts_buf: [64]u8 = undefined;
            const ts = timefmt.isoTime7Buf(&ts_buf, l.ts_ms);
            // The log is only appended to, and `count` read the same part of it; a line that
            // would go past `len` all the same ends the upload, not the runner (`broker.Body`).
            written += ts.len + 1 + it.textLen() + 1;
            if (written > b.len) return error.LogChangedWhileUploaded;
            try w.writeAll(ts);
            try w.writeByte(' ');
            try it.writeText(w);
            try w.writeByte('\n');
        }
    }
};

const Kept = sink.Kept;

pub const Result = struct {
    ok: bool,
    /// Human-readable outcome; error bodies are short and carry no credentials.
    detail: []const u8,
    /// A failure that another try may get past (`transientError`, `transientStatus`).
    transient: bool = false,
};

/// What every call answers for a job that names no results service.
const no_endpoint: Result = .{ .ok = false, .detail = "job has no results endpoint" };

/// The most of an error body a failure's detail quotes.
const max_detail_body = 300;

pub const Which = union(enum) { step: []const u8, job };
const Meta = struct { uploaded_at: []const u8, line_count: usize };

fn twirpUrl(arena: Allocator, endpoint: []const u8, method: []const u8) Allocator.Error![]const u8 {
    const base = std.mem.trimEnd(u8, endpoint, "/");
    return std.fmt.allocPrint(arena, "{s}/twirp/{s}/{s}", .{ base, service, method });
}

fn ids(arena: Allocator, job: job_mod.Job, which: Which, meta: ?Meta) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("{\"workflow_run_backend_id\":");
    try std.json.Stringify.value(job.plan_id, .{}, w);
    try w.writeAll(",\"workflow_job_run_backend_id\":");
    try std.json.Stringify.value(job.job_id, .{}, w);
    switch (which) {
        .step => |id| {
            try w.writeAll(",\"step_backend_id\":");
            try std.json.Stringify.value(id, .{}, w);
        },
        .job => {},
    }
    if (meta) |m| {
        try w.writeAll(",\"uploaded_at\":");
        try std.json.Stringify.value(m.uploaded_at, .{}, w);
        try w.print(",\"line_count\":{d}", .{m.line_count});
    }
    try w.writeByte('}');
    return aw.written();
}

/// How an upload is tried again, as `job.completeJob` is: after each delay in turn, while the
/// failure is transient. No try starts after `budget` since the first one began, so a job's end
/// waits at most the budget and one more request's deadline for a log (`http.request_deadline`,
/// `blobDeadline`). 15 s of delays wait out a resolver that is back within seconds, which is what
/// the failures seen were (NameServerFailure on all three uploads of one job).
pub const Retry = struct {
    delays_ms: []const i64 = &.{ 1000, 2000, 4000, 8000 },
    budget: std.Io.Duration = .fromSeconds(30),
};

pub fn upload(arena: Allocator, io: std.Io, job: job_mod.Job, which: Which, blob: Blob) Result {
    return uploadRetrying(arena, io, job, which, blob, .{});
}

pub fn uploadRetrying(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    which: Which,
    blob: Blob,
    retry: Retry,
) Result {
    if (job.results_endpoint.len == 0) return no_endpoint;
    // A signed URL and the PUT to it are one try: a URL that expired between two tries is asked
    // for again, and the PUT writes the whole blob over whatever a failed one left, so a log is
    // never doubled. Registering it is a try of its own, so a blob that is up is not sent again
    // for a failed registration.
    const put = retrying(io, retry, putLog, .{ arena, io, job, which, blob });
    if (!put.ok) return put;
    const meta = retrying(io, retry, registerLog, .{ arena, io, job, which, blob.line_count });
    if (!meta.ok) return meta;
    return .{
        .ok = true,
        .detail = std.fmt.allocPrint(arena, "{d} lines", .{blob.line_count}) catch "ok",
    };
}

/// `try_fn(args)` once; an error it returns is a failed Result, transient or not by the error.
fn tryOnce(comptime try_fn: anytype, args: anytype) Result {
    return @call(.auto, try_fn, args) catch |e| .{
        .ok = false,
        .detail = @errorName(e),
        .transient = transientError(e),
    };
}

/// `try_fn(args)` until it succeeds, fails for good or `retry` runs out; the last outcome.
fn retrying(io: std.Io, retry: Retry, comptime try_fn: anytype, args: anytype) Result {
    const started = std.Io.Clock.awake.now(io).toNanoseconds();
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const r = tryOnce(try_fn, args);
        if (r.ok or !r.transient or attempt == retry.delays_ms.len) return r;
        const delay_ns = retry.delays_ms[attempt] * std.time.ns_per_ms;
        const elapsed = std.Io.Clock.awake.now(io).toNanoseconds() - started;
        if (elapsed + delay_ns >= retry.budget.nanoseconds) return r;
        io.sleep(.fromNanoseconds(delay_ns), .awake) catch return r;
    }
}

/// Whether a request that failed with `err` may pass when made again: the name server, the
/// connection or the time it took, not the request (a log that changed while it went up).
fn transientError(err: anyerror) bool {
    return switch (err) {
        error.NameServerFailure,
        error.TemporaryNameServerFailure,
        error.UnknownHostName,
        error.ConnectionRefused,
        error.ConnectionTimedOut,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.Timeout,
        error.ReadFailed,
        error.WriteFailed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.BrokenPipe,
        error.HttpConnectionClosing,
        // The network library's (`net_client.Error`): the same kinds.
        error.DnsFailed,
        error.ConnectionFailed,
        error.StaleConnection,
        error.NetworkIo,
        => true,
        else => false,
    };
}

/// 5xx and 429 pass with time; any other status is the request's own fault.
fn transientStatus(status: std.http.Status) bool {
    return status.class() == .server_error or status == .too_many_requests;
}

fn putLog(arena: Allocator, io: std.Io, job: job_mod.Job, which: Which, blob: Blob) !Result {
    const get_method = switch (which) {
        .step => "GetStepLogsSignedBlobURL",
        .job => "GetJobLogsSignedBlobURL",
    };
    const signed = try broker.call(
        arena,
        io,
        .POST,
        try twirpUrl(arena, job.results_endpoint, get_method),
        job.job_token,
        try ids(arena, job, which, null),
    );
    if (signed.status.class() != .success) return failed(arena, get_method, signed);
    const logs_url = (try jsonString(arena, signed.body, "logs_url")) orelse return .{
        .ok = false,
        .detail = try std.fmt.allocPrint(arena, "{s}: no logs_url in response", .{get_method}),
    };

    const put = try putBlob(arena, io, logs_url, blob);
    if (put.status.class() != .success) return failed(arena, "blob upload", put);
    return .{ .ok = true, .detail = "" };
}

fn registerLog(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    which: Which,
    line_count: usize,
) !Result {
    const meta_method = switch (which) {
        .step => "CreateStepLogsMetadata",
        .job => "CreateJobLogsMetadata",
    };
    const uploaded_at = try timefmt.isoTime(arena, std.Io.Clock.real.now(io).toMilliseconds());
    const meta = try broker.call(arena, io, .POST, try twirpUrl(
        arena,
        job.results_endpoint,
        meta_method,
    ), job.job_token, try ids(arena, job, which, .{
        .uploaded_at = uploaded_at,
        .line_count = line_count,
    }));
    if (meta.status.class() != .success) return failed(arena, meta_method, meta);
    return .{ .ok = true, .detail = "" };
}

/// Uploads what a step wrote to $GITHUB_STEP_SUMMARY, as actions/runner does: a signed URL from
/// `GetStepSummarySignedBlobURL` (`summary_url`), the markdown PUT to it, then
/// `CreateStepSummaryMetadata` with its size. GitHub shows it on the run's summary page.
pub fn uploadSummary(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    step_id: []const u8,
    markdown: []const u8,
) Result {
    // Tried again whole: the PUT overwrites the summary, and the metadata names its size.
    return retrying(io, .{}, uploadSummaryInner, .{ arena, io, job, step_id, markdown });
}

fn uploadSummaryInner(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    step_id: []const u8,
    markdown: []const u8,
) !Result {
    if (job.results_endpoint.len == 0) return no_endpoint;
    const which: Which = .{ .step = step_id };
    const signed = try broker.call(
        arena,
        io,
        .POST,
        try twirpUrl(arena, job.results_endpoint, "GetStepSummarySignedBlobURL"),
        job.job_token,
        try ids(arena, job, which, null),
    );
    if (signed.status.class() != .success) return failed(
        arena,
        "GetStepSummarySignedBlobURL",
        signed,
    );
    const url = (try jsonString(arena, signed.body, "summary_url")) orelse return .{
        .ok = false,
        .detail = "GetStepSummarySignedBlobURL: no summary_url in response",
    };
    const put = try putBlob(arena, io, url, .{ .text = markdown, .line_count = 0 });
    if (put.status.class() != .success) return failed(arena, "summary upload", put);
    const uploaded_at = try timefmt.isoTime(arena, std.Io.Clock.real.now(io).toMilliseconds());
    // The ids, then the size and time (the object's closing brace is replaced).
    const head = try ids(arena, job, which, null);
    const body = try std.fmt.allocPrint(
        arena,
        "{s},\"upload_size\":{d},\"uploaded_at\":\"{s}\"}}",
        .{ head[0 .. head.len - 1], markdown.len, uploaded_at },
    );
    const meta = try broker.call(
        arena,
        io,
        .POST,
        try twirpUrl(arena, job.results_endpoint, "CreateStepSummaryMetadata"),
        job.job_token,
        body,
    );
    if (meta.status.class() != .success) return failed(arena, "CreateStepSummaryMetadata", meta);
    return .{ .ok = true, .detail = try std.fmt.allocPrint(arena, "{d} bytes", .{markdown.len}) };
}

/// Tells GitHub the job's steps and where each stands, so its UI lists them while the job runs
/// (actions/runner's `WorkflowStepsUpdate`). `steps` is a JSON array of `{external_id, number,
/// name, status, conclusion, started_at, completed_at}`; a later `change_order` replaces earlier
/// ones.
pub fn updateSteps(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    steps: []const u8,
    change_order: u64,
) Result {
    return tryOnce(updateStepsInner, .{ arena, io, job, steps, change_order });
}

fn updateStepsInner(
    arena: Allocator,
    io: std.Io,
    job: job_mod.Job,
    steps: []const u8,
    change_order: u64,
) !Result {
    if (job.results_endpoint.len == 0) return no_endpoint;
    const base = std.mem.trimEnd(u8, job.results_endpoint, "/");
    const url = try std.fmt.allocPrint(
        arena,
        "{s}/twirp/github.actions.results.api.v1.WorkflowStepUpdateService/WorkflowStepsUpdate",
        .{base},
    );
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.print(
        "{{\"steps\":{s},\"change_order\":{d},\"workflow_job_run_backend_id\":",
        .{ steps, change_order },
    );
    try std.json.Stringify.value(job.job_id, .{}, w);
    try w.writeAll(",\"workflow_run_backend_id\":");
    try std.json.Stringify.value(job.plan_id, .{}, w);
    try w.writeByte('}');
    const r = try broker.call(arena, io, .POST, url, job.job_token, aw.written());
    if (r.status.class() != .success) return failed(arena, "WorkflowStepsUpdate", r);
    return .{ .ok = true, .detail = "" };
}

/// PUTs a blob to a signed blob URL: no bearer token (the URL is the authorization), but Azure
/// needs the blob type. Through the network library (`net_client`): a log too big to hold is
/// written as it is sent, in a queue of a fixed size. A kept connection that turned out to be
/// closed (`error.StaleConnection`, seen on log uploads to blob storage), or one that went away
/// without a word (no answer by the deadline, a read or write that failed: a log upload read such a
/// connection for 17 minutes, #100), is tried once more on a connection made for it, as
/// `broker.request` did.
fn putBlob(arena: Allocator, io: std.Io, url: []const u8, blob: Blob) !broker.Response {
    const text: ?[]const u8 = if (blob.stream == null) blob.text else null;
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        const r = net_client.fetch(arena, io, .{
            .method = .PUT,
            .url = url,
            .headers = &.{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "x-ms-blob-type", .value = "BlockBlob" },
            },
            .payload = text,
            .upload = blob.stream,
            .deadline = blobDeadline(blob.len()),
            .fresh = attempt > 0,
            .retry = attempt,
        }) catch |e| switch (e) {
            error.StaleConnection, error.Timeout, error.NetworkIo => if (attempt == 0) continue else return e,
            else => return e,
        };
        return .{ .status = r.status, .body = r.body };
    }
}

/// How long a blob upload of `bytes` may take: a request's deadline, and as long again for each
/// `blob_rate` bytes, at most `blob_deadline_max`. A step's log is at most 1 MiB
/// (`StepLogs.max_bytes`, 38 s), a job's up to 64 MiB (`sink.CollectSink.max_bytes`), and a
/// Raspberry Pi on a slow uplink sends far less than a server: a fixed 30 s would cut off a big
/// log that was still going up.
pub fn blobDeadline(bytes: usize) std.Io.Duration {
    const base = http.request_deadline.nanoseconds;
    const ns = base + @as(i96, @intCast(bytes / blob_rate)) * std.time.ns_per_s;
    return .{ .nanoseconds = @min(ns, blob_deadline_max.nanoseconds) };
}

/// The slowest upload rate, in bytes a second, that a blob upload's deadline allows for: 128 KiB/s,
/// about 1 Mbit/s.
const blob_rate = 128 * 1024;
/// 64 MiB at `blob_rate` would be over 8 minutes; the job's end waits at most this long for one.
pub const blob_deadline_max: std.Io.Duration = .fromSeconds(5 * 60);

fn failed(arena: Allocator, what: []const u8, r: broker.Response) !Result {
    return .{
        .ok = false,
        .transient = transientStatus(r.status),
        .detail = try std.fmt.allocPrint(arena, "{s}: HTTP {d}: {s}", .{
            what,
            @backingInt(r.status),
            r.body[0..@min(r.body.len, max_detail_body)],
        }),
    };
}

/// The string at `key` in the JSON object `body`, or null when it is not one. Running out of memory
/// is an error, not a missing key: read as one, a response was reported as having no `logs_url`.
fn jsonString(arena: Allocator, body: []const u8, key: []const u8) Allocator.Error!?[]const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (v != .object) return null;
    const s = v.object.get(key) orelse return null;
    return if (s == .string) s.string else null;
}

test "formatBlob prefixes timestamps and filters by step" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const lines = [_]sink.CollectedLine{
        .{ .step = 0, .seq = 1, .ts_ms = 1000, .text = "job acquired" },
        .{ .step = 1, .seq = 1, .ts_ms = 2000, .text = "hello" },
        .{ .step = 2, .seq = 1, .ts_ms = 3500, .text = "two" },
        .{ .step = 1, .seq = 2, .ts_ms = 4000, .text = "done" },
    };
    const s1 = try formatBlob(a.allocator(), &lines, 1);
    try std.testing.expectEqual(@as(usize, 2), s1.line_count);
    try std.testing.expectEqualStrings("1970-01-01T00:00:02.0000000Z hello\n1970-01-01T00:00:04.0000000Z done\n", s1.text);
    const all = try formatBlob(a.allocator(), &lines, null);
    try std.testing.expectEqual(@as(usize, 4), all.line_count);
}

test "a kept log's blobs are read as they go up, as formatBlob makes them, through one buffer" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "spool", .{ .read = true });
    defer file.close(io);
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var dbuf: [256]u8 = undefined;
    var disc: std.Io.Writer.Discarding = .init(&dbuf);
    var inner: sink.LogSink = .{ .stdout = .{ .writer = &disc.writer } };
    var spool: sink.Spool = .{ .file = file, .io = io };
    var log: sink.LogSink = .{ .collect = .{
        .arena = arena,
        .io = io,
        .inner = &inner,
        .spool = &spool,
    } };

    // Lines of three steps, interleaved; the last ones in memory after the spool stopped taking
    // writes. Some lines are long, one has a newline in it, one is empty.
    const long: [3000]u8 = @splat('y');
    for (0..2000) |i| {
        const step: u32 = @intCast(i % 3);
        const text: []const u8 = switch (i) {
            5 => "two\nlines",
            6 => "",
            else => if (i % 7 == 0) &long else "line",
        };
        if (i == 1500) spool.broken = true;
        try log.append(1, step, .stdout, text);
    }
    const lines = log.collect.collected(arena);
    try std.testing.expectEqual(@as(usize, 2000), lines.len);

    const kept = log.collect.kept();
    var buf: [64 * 1024]u8 = undefined;
    var sizes: [3]KeptBlob.Size = undefined;
    const all = try KeptBlob.count(&kept, io, &buf, &sizes);
    for ([_]?u32{ 0, 1, 2, null }) |step| {
        const want = try formatBlob(arena, lines, step);
        const size = if (step) |s| sizes[s] else all;
        try std.testing.expectEqual(want.line_count, size.lines);
        try std.testing.expectEqual(want.text.len, size.bytes);
        var blob_buf: [64 * 1024]u8 = undefined;
        const kb: KeptBlob = .{
            .kept = &kept,
            .io = io,
            .step = step,
            .buf = &blob_buf,
            .len = size.bytes,
        };
        try std.testing.expectEqualStrings(want.text, try kb.blob(size.lines).textAlloc(arena));
    }

    // 16 MB of log goes up through the 64 KiB buffer, and is never held.
    const big_file = try tmp.dir.createFile(io, "big", .{ .read = true });
    defer big_file.close(io);
    var big_spool: sink.Spool = .{ .file = big_file, .io = io };
    var big_log: sink.LogSink = .{ .collect = .{
        .arena = arena,
        .io = io,
        .inner = &inner,
        .spool = &big_spool,
    } };
    const line: [4096]u8 = @splat('z');
    for (0..4096) |_| try big_log.append(1, 1, .stdout, &line);
    const big = big_log.collect.kept();
    var big_sizes: [2]KeptBlob.Size = undefined;
    const big_all = try KeptBlob.count(&big, io, &buf, &big_sizes);
    try std.testing.expectEqual(@as(usize, 4096), big_sizes[1].lines);
    const kb: KeptBlob = .{ .kept = &big, .io = io, .step = 1, .buf = &buf, .len = big_all.bytes };
    var sent: std.Io.Writer.Discarding = .init(&dbuf);
    const stream = kb.blob(big_sizes[1].lines).stream.?;
    try stream.writeFn(stream.ptr, &sent.writer);
    try std.testing.expectEqual(@as(u64, big_all.bytes), sent.fullCount());

    // And into a request, over a real connection.
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var url_buf: [64]u8 = undefined;
    const url = server.url(&url_buf, "127.0.0.1", "/same");
    const put = try broker.request(arena, io, .PUT, url, null, .{ .body = stream });
    try std.testing.expectEqual(std.http.Status.found, put.status);
}

test "a blob upload's deadline grows with its size, up to a cap" {
    try std.testing.expectEqual(http.request_deadline, blobDeadline(0));
    try std.testing.expectEqual(http.request_deadline, blobDeadline(blob_rate - 1));
    // A step's whole log, at most.
    try std.testing.expectEqual(std.Io.Duration.fromSeconds(38), blobDeadline(1 << 20));
    try std.testing.expectEqual(blob_deadline_max, blobDeadline(64 << 20));
}

test "request bodies" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const job: job_mod.Job = .{ .plan_id = "P", .job_id = "J", .job_token = "t", .check_run_id = 1, .secrets = &.{}, .steps = &.{} };
    try std.testing.expectEqualStrings(
        "{\"workflow_run_backend_id\":\"P\",\"workflow_job_run_backend_id\":\"J\",\"step_backend_id\":\"S\",\"uploaded_at\":\"T\",\"line_count\":3}",
        try ids(a.allocator(), job, .{ .step = "S" }, .{ .uploaded_at = "T", .line_count = 3 }),
    );
    try std.testing.expectEqualStrings("https://r.test/twirp/" ++ service ++ "/X", try twirpUrl(a.allocator(), "https://r.test/", "X"));
}

test "allocation failures: a response's string" {
    const af = @import("../alloc_failures.zig");
    const S = struct {
        fn run(a: Allocator, body: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            const url = (try jsonString(arena.allocator(), body, "logs_url")) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings("https://blob.test/x", url);
        }
    };
    try af.checkOne(S.run, .{
        \\{"logs_url":"https://blob.test/x","expires":["a","b"],"n":{"k":1}}
    });
}

test "jsonString: no string at the key is null, not an error" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try std.testing.expect(try jsonString(a.allocator(), "{\"logs_url\":1}", "logs_url") == null);
    try std.testing.expect(try jsonString(a.allocator(), "{}", "logs_url") == null);
    try std.testing.expect(try jsonString(a.allocator(), "[1]", "logs_url") == null);
    try std.testing.expect(try jsonString(a.allocator(), "not json", "logs_url") == null);
}

/// A log of 3 lines (6 bytes) to the results service at `server`.
fn testUpload(server: *const @import("testserver.zig").Server, which: Which, retry: Retry) Result {
    var url_buf: [64]u8 = undefined;
    const job: job_mod.Job = .{
        .plan_id = "P",
        .job_id = "J",
        .job_token = "t",
        .check_run_id = 1,
        .secrets = &.{},
        .steps = &.{},
        .results_endpoint = server.url(&url_buf, "127.0.0.1", "/results"),
    };
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const r = uploadRetrying(a.allocator(), std.testing.io, job, which, .{
        .text = "a\nb\nc\n",
        .line_count = 3,
    }, retry);
    // The detail lives in the arena; the outcome is all a test looks at.
    return .{ .ok = r.ok, .detail = "", .transient = r.transient };
}

const quick: Retry = .{ .delays_ms = &.{ 1, 1, 1, 1 } };

test "a blob upload that failed on a blip is made again, with a new signed URL, and goes up once" {
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    server.results_fail = 1;
    server.results_fail_on = "-blob";
    var r = testUpload(&server, .job, quick);
    try std.testing.expect(r.ok);
    try std.testing.expectEqual(@as(u32, 2), server.results.urls);
    try std.testing.expectEqual(@as(u32, 1), server.results.puts);
    try std.testing.expectEqual(@as(usize, 6), server.results.put_bytes);
    try std.testing.expectEqual(@as(u32, 1), server.results.metas);

    // Rate limited asking for the URL.
    server.results_fail = 1;
    server.results_fail_on = "GetStepLogs";
    server.results_fail_status = "429 Too Many Requests";
    r = testUpload(&server, .{ .step = "S" }, quick);
    try std.testing.expect(r.ok);
    try std.testing.expectEqual(@as(u32, 2), server.results.puts);
}

test "a failed registration is made again without sending the blob again" {
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    server.results_fail = 2;
    server.results_fail_on = "CreateJobLogsMetadata";
    const r = testUpload(&server, .job, quick);
    try std.testing.expect(r.ok);
    try std.testing.expectEqual(@as(u32, 1), server.results.urls);
    try std.testing.expectEqual(@as(u32, 1), server.results.puts);
    try std.testing.expectEqual(@as(u32, 1), server.results.metas);
}

test "a failure of the request itself is not tried again" {
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    server.results_fail = 10;
    server.results_fail_on = "SignedBlobURL";
    server.results_fail_status = "403 Forbidden";
    const r = testUpload(&server, .job, quick);
    try std.testing.expect(!r.ok and !r.transient);
    // One request answered, 9 left unused.
    try std.testing.expectEqual(@as(u32, 9), server.results_fail);
}

test "tries stop at the budget, however many delays are left" {
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    server.results_fail = 100;
    server.results_fail_on = "SignedBlobURL";
    const slow: Retry = .{
        .delays_ms = &.{ 100, 100, 100, 100 },
        .budget = .fromMilliseconds(150),
    };
    const started = std.Io.Clock.awake.now(std.testing.io).toNanoseconds();
    const r = testUpload(&server, .job, slow);
    const took = std.Io.Clock.awake.now(std.testing.io).toNanoseconds() - started;
    try std.testing.expect(!r.ok and r.transient);
    // The second try, 100 ms in, is the last: a third would start at 200 ms, past the 150.
    try std.testing.expect(100 - server.results_fail <= 2);
    try std.testing.expect(took < 400 * std.time.ns_per_ms);
}

test "what is worth trying again" {
    try std.testing.expect(transientError(error.NameServerFailure));
    try std.testing.expect(transientError(error.Timeout));
    try std.testing.expect(!transientError(error.OutOfMemory));
    try std.testing.expect(!transientError(error.Canceled));
    try std.testing.expect(!transientError(error.LogChangedWhileUploaded));
    try std.testing.expect(transientStatus(.too_many_requests));
    try std.testing.expect(transientStatus(.bad_gateway));
    try std.testing.expect(!transientStatus(.forbidden));
    try std.testing.expect(!transientStatus(.not_found));
}
