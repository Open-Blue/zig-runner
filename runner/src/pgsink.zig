//! LogSink that writes job logs to the `job_logs` hypertable in batches (SPEC §4, §5.1).
//!
//! Lines are redacted, stamped with a per-job `seq` (1, 2, 3, ... with no gaps) and a timestamp
//! when appended, and buffered. A batch is written with one `COPY` when it reaches `flush_lines`,
//! when `flush_ms` has passed since the last write (checked on append and by a background flusher,
//! so a quiet job's last line is not stuck), and on `flush()`/`close()` (step and job end).
//!
//! The database must never fail a job, nor hold one up. If a write fails, the lines stay buffered and
//! the next flush reconnects and retries (not more often than every 2 s); if the buffer outgrows
//! `max_buffered`, the oldest lines are dropped and counted, which is the only way a `seq` gap can
//! appear. Every line is also passed to `inner` (the console) first.
//!
//! Once `startFlusher` has run, only the flusher talks to the database, and never with `mu` held:
//! a line is only buffered, and `flush` waits a bounded time. Before, whoever appended the line that
//! made a batch due wrote it while holding `mu`, which every runner's lines go through, so a
//! database that stopped answering stopped every runner: paused for 60 s, it added 52 s to every job
//! that started meanwhile. Without a flusher (tests, one-off commands) lines are written inline.
const std = @import("std");
const pg = @import("pg.zig");
const db = @import("db.zig");
const sink = @import("sink.zig");
const redact = @import("redact.zig");
const timefmt = @import("timefmt.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const Row = struct {
    ts_ms: i64,
    job_id: u64,
    step: u32,
    /// Per job, gapless: the order of the whole job's log.
    seq: u64,
    /// Per step, as the line was numbered when it was logged (`sink.CollectedLine.seq`), so a row
    /// can be matched to a line in the log GitHub shows. Null for the runner's own messages, which
    /// belong to no step's output.
    step_seq: ?u64,
    stream: sink.Stream,
    text: []u8,
};

pub const PgSink = struct {
    gpa: Allocator,
    io: Io,
    cfg: pg.Config,
    /// A scratch schema for tests; null in production.
    schema: ?[]const u8 = null,
    inner: *sink.LogSink,
    secrets: []const []const u8 = &.{},
    index: ?*const redact.Set = null,
    flush_lines: usize = 200,
    flush_ms: u32 = 500,
    max_buffered: usize = 100_000,

    mu: Io.Mutex = .init,
    client: ?*pg.Client = null,
    rows: std.ArrayList(Row) = .empty,
    next_seq: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    last_flush_ms: i64 = 0,
    written: u64 = 0,
    dropped: u64 = 0,
    /// The most recent failure, for reporting once the job is done, and the back-off after one.
    outage: db.Outage = .{},

    stop: std.atomic.Value(bool) = .init(false),
    flusher: ?Io.Future(void) = null,
    /// `flush` asks for a write (`flush_asked`) and waits until the flusher has made one since
    /// (`flush_done`), or `flush_wait_ms` have passed.
    flush_asked: std.atomic.Value(u64) = .init(0),
    flush_done: std.atomic.Value(u64) = .init(0),
    flush_wait_ms: u32 = 1000,
    /// When the flusher's current write began, 0 while it is not writing. `flush` does not wait on
    /// a write that has taken longer than `stuck_ms`: the database is not answering, and waiting
    /// out `flush_wait_ms` at the end of every step added 6 s to each job while it was paused.
    writing_since: std.atomic.Value(i64) = .init(0),
    stuck_ms: i64 = 250,
    flusher_started: bool = false,
    flusher_stopped: std.atomic.Value(bool) = .init(false),
    /// What `close` gives the flusher to write what is left before cutting it short.
    close_wait_ms: u32 = 5000,

    pub fn append(
        s: *PgSink,
        job_id: u64,
        step_number: u32,
        stream: sink.Stream,
        line: []const u8,
    ) sink.Error!void {
        return s.appendStep(job_id, step_number, null, stream, line);
    }

    /// As `append`, with the line's number in its own step (`sink.CollectedLine.seq`). Only the
    /// job's sink knows it; the runner's own messages come through `append`.
    pub fn appendStep(
        s: *PgSink,
        job_id: u64,
        step_number: u32,
        step_seq: ?u64,
        stream: sink.Stream,
        line: []const u8,
    ) sink.Error!void {
        try s.inner.append(job_id, step_number, stream, line);
        // Job id 0 marks messages that belong to no job (registering, waiting for work): console
        // only.
        if (job_id == 0) return;

        var aw: Io.Writer.Allocating = .init(s.gpa);
        defer aw.deinit();
        try redact.writeWith(&aw.writer, line, s.secrets, s.index);
        const owned = try s.gpa.dupe(u8, aw.written());
        errdefer s.gpa.free(owned);

        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const gop = try s.next_seq.getOrPut(s.gpa, job_id);
        if (!gop.found_existing) gop.value_ptr.* = 1;
        const seq = gop.value_ptr.*;
        gop.value_ptr.* += 1;
        try s.rows.append(s.gpa, .{
            .ts_ms = now(s.io),
            .job_id = job_id,
            .step = step_number,
            .seq = seq,
            .step_seq = step_seq,
            .stream = stream,
            .text = owned,
        });
        if (s.flusher == null and
            (s.rows.items.len >= s.flush_lines or now(s.io) - s.last_flush_ms >= s.flush_ms))
            s.flushLocked();
        s.enforceCap();
    }

    pub fn flush(s: *PgSink) sink.Error!void {
        try s.inner.flush();
        if (s.flusher != null) {
            const want = s.flush_asked.fetchAdd(1, .acq_rel) + 1;
            var waited: u32 = 0;
            while (s.flush_done.load(.acquire) < want and waited < s.flush_wait_ms and
                !s.stuck()) : (waited += 10)
                s.io.sleep(.fromMilliseconds(10), .awake) catch return;
            return;
        }
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        s.flushLocked();
    }

    pub fn close(s: *PgSink) void {
        s.stop.store(true, .release);
        if (s.flusher) |*f| {
            // The flusher writes what is left as it stops. A database that does not answer gets
            // `close_wait_ms`; then the write is cancelled, and what it held is dropped below.
            db.waitFor(s.io, &s.flusher_stopped, s.close_wait_ms);
            f.cancel(s.io);
        }
        s.flusher = null;
        s.mu.lockUncancelable(s.io);
        // With a flusher, it wrote what it could; without one, this is the last write.
        if (!s.flusher_started) s.flushLocked();
        if (s.client) |c| c.close();
        s.client = null;
        s.mu.unlock(s.io);
        for (s.rows.items) |r| s.gpa.free(r.text);
        s.rows.deinit(s.gpa);
        s.next_seq.deinit(s.gpa);
    }

    /// Starts the task that writes buffered lines: on time for a quiet job, at once when a batch is
    /// full or `flush` asks, and the rest when the sink closes.
    pub fn startFlusher(s: *PgSink) !void {
        s.flusher_started = true;
        s.flusher = try s.io.concurrent(flusherMain, .{s});
    }

    fn flusherMain(s: *PgSink) void {
        defer s.flusher_stopped.store(true, .release);
        while (true) {
            // In short steps, so a full batch or a `flush` is written within 20 ms.
            const asked = s.flush_asked.load(.acquire);
            const stopping = s.stop.load(.acquire);
            if (stopping or asked > s.flush_done.load(.acquire) or s.due()) {
                s.writePending();
                s.flush_done.store(asked, .release);
                if (stopping) return;
            }
            s.io.sleep(.fromMilliseconds(20), .awake) catch return;
        }
    }

    /// Whether the flusher's current write has gone on too long to be worth waiting for.
    fn stuck(s: *PgSink) bool {
        const since = s.writing_since.load(.acquire);
        return since != 0 and now(s.io) - since > s.stuck_ms;
    }

    /// Whether the buffered lines should be written now: a full batch, or the oldest waiting too long.
    fn due(s: *PgSink) bool {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        if (s.rows.items.len == 0) return false;
        return s.rows.items.len >= s.flush_lines or now(s.io) - s.last_flush_ms >= s.flush_ms;
    }

    /// The flusher's write: the buffered lines are taken under `mu` and written without it, so lines
    /// keep arriving while the database is slow. A failed batch goes back in front of what came
    /// meanwhile, so the order (and `seq`) is kept.
    fn writePending(s: *PgSink) void {
        var batch: std.ArrayList(Row) = .empty;
        {
            s.mu.lockUncancelable(s.io);
            defer s.mu.unlock(s.io);
            if (s.rows.items.len == 0 or s.outage.backingOff(s.io)) return;
            batch = s.rows;
            s.rows = .empty;
        }
        const t = now(s.io);
        s.writing_since.store(t, .release);
        defer s.writing_since.store(0, .release);
        const n = s.writeRows(batch.items) catch |e| {
            s.mu.lockUncancelable(s.io);
            defer s.mu.unlock(s.io);
            s.writeFailed(e);
            // Put back, in front: the batch, then what arrived while it was being written.
            batch.appendSlice(s.gpa, s.rows.items) catch {
                // No memory to put it back: the failed batch is lost, and counted as dropped.
                s.dropped += batch.items.len;
                for (batch.items) |r| s.gpa.free(r.text);
                batch.deinit(s.gpa);
                return;
            };
            s.rows.deinit(s.gpa);
            s.rows = batch;
            s.enforceCap();
            return;
        };
        for (batch.items) |r| s.gpa.free(r.text);
        batch.deinit(s.gpa);
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        s.written += n;
        s.last_flush_ms = t;
    }

    pub fn errorText(s: *const PgSink) []const u8 {
        return s.outage.lastError();
    }

    fn now(io: Io) i64 {
        return Io.Clock.real.now(io).toMilliseconds();
    }

    /// After a write failed: says why, lets the connection go (the next write dials again) and
    /// backs off, from now: a write that took its whole time (`pg.Config.query_timeout`) would
    /// otherwise be followed at once by the next (#100). Called with `mu` held, by the only writer
    /// there is.
    fn writeFailed(s: *PgSink, e: anyerror) void {
        const detail = if (s.client) |c| c.last_error else "";
        s.outage.remember("log write failed", if (detail.len > 0) detail else @errorName(e));
        if (s.client) |c| c.close();
        s.client = null;
        s.outage.backOff(s.io);
    }

    /// Writes the buffered rows; on failure keeps them and backs off. Called with `mu` held, and
    /// only without a flusher.
    fn flushLocked(s: *PgSink) void {
        if (s.rows.items.len == 0) return;
        const t = now(s.io);
        if (s.outage.backingOff(s.io)) return;
        const n = s.writeRows(s.rows.items) catch |e| {
            s.writeFailed(e);
            return;
        };
        s.written += n;
        for (s.rows.items) |r| s.gpa.free(r.text);
        s.rows.clearRetainingCapacity();
        s.last_flush_ms = t;
    }

    /// One COPY of `rows`, connecting first if there is no connection. Only one caller at a time:
    /// the flusher, or `flushLocked` under `mu` when there is none.
    fn writeRows(s: *PgSink, rows: []const Row) !u64 {
        if (s.client == null) {
            const c = try pg.Client.connect(s.gpa, s.io, s.cfg);
            s.client = c;
            if (s.schema) |sc| try db.setSchema(s.gpa, c, sc);
        }
        var arena_state: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena_state.deinit();
        var data: Io.Writer.Allocating = .init(arena_state.allocator());
        const w = &data.writer;
        for (rows) |r| {
            try w.writeAll(try timefmt.isoTime(arena_state.allocator(), r.ts_ms));
            try w.print("\t{d}\t{d}\t{d}\t{s}\t", .{ r.job_id, r.step, r.seq, @tagName(r.stream) });
            try pg.copyField(w, r.text);
            // `\N` is COPY's null: a line that belongs to no step has no number in one.
            if (r.step_seq) |ss| try w.print("\t{d}", .{ss}) else try w.writeAll("\t\\N");
            try w.writeByte('\n');
        }
        const n = try s.client.?.copyIn(
            "COPY job_logs (ts, job_id, step_number, seq, stream, line, step_seq) FROM STDIN",
            data.written(),
        );
        if (n != rows.len) return error.ShortCopy;
        return n;
    }

    /// If the database stays down, drop the oldest lines rather than grow without bound.
    fn enforceCap(s: *PgSink) void {
        if (s.rows.items.len <= s.max_buffered) return;
        const drop = s.rows.items.len - s.max_buffered;
        for (s.rows.items[0..drop]) |r| s.gpa.free(r.text);
        std.mem.copyForwards(Row, s.rows.items[0..s.max_buffered], s.rows.items[drop..]);
        s.rows.shrinkRetainingCapacity(s.max_buffered);
        s.dropped += drop;
    }
};

// --- tests ---

fn countLogs(sc: *@import("dbtest.zig").Scratch) !u64 {
    return std.fmt.parseInt(u64, try sc.scalar("select count(*) from job_logs"), 10);
}

fn testSink(sc: *@import("dbtest.zig").Scratch, inner: *sink.LogSink) PgSink {
    return .{
        .gpa = std.testing.allocator,
        .io = std.testing.io,
        .cfg = sc.cfg,
        .schema = sc.schema,
        .inner = inner,
    };
}

test "integration: batches are written with gapless seq, redaction and the right columns" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    // job_logs has no foreign key, so no run or job rows are needed (SPEC §4).
    var console_out: Io.Writer.Allocating = .init(arena);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &console_out.writer } };
    var pgs = testSink(&sc, &console);
    pgs.flush_lines = 100;
    pgs.flush_ms = 60_000; // only size and explicit flushes
    pgs.secrets = &.{"s3cr3t"};
    defer pgs.close();

    // 450 lines across several batches, with hostile content.
    for (0..450) |i| {
        const text = if (i % 90 == 0) "tab\there \\ back\\slash \"quote\" it's s3cr3t \x1b[31mred\x1b[0m" else "plain line";
        try pgs.append(99, if (i < 200) 0 else 1, if (i % 2 == 0) .stdout else .stderr, text);
    }
    try std.testing.expect(pgs.written >= 400); // size-triggered batches already went out
    try pgs.flush();

    try std.testing.expectEqual(@as(u64, 450), try countLogs(&sc));
    try std.testing.expectEqualStrings("1/450/450", try sc.scalar("select min(seq) || '/' || max(seq) || '/' || count(distinct seq) from job_logs where job_id = 99")); // gapless
    try std.testing.expectEqualStrings("0", try sc.scalar("select count(*) from job_logs where line like '%s3cr3t%'")); // redacted
    try std.testing.expectEqualStrings("tab\there \\ back\\slash \"quote\" it's *** \x1b[31mred\x1b[0m", try sc.scalar("select line from job_logs where seq = 1"));
    try std.testing.expectEqualStrings("200", try sc.scalar("select count(*) from job_logs where step_number = 0"));
    try std.testing.expectEqualStrings("225", try sc.scalar("select count(*) from job_logs where stream = 'stderr'"));
    // seq order is also arrival order.
    try std.testing.expectEqualStrings("true", try sc.scalar("select (bool_and(ts >= prev_ts))::text from (select ts, lag(ts) over (order by seq) as prev_ts from job_logs) t where prev_ts is not null"));
    // Everything was shown on the console too.
    try std.testing.expectEqual(@as(usize, 450), std.mem.count(u8, console_out.written(), "[job 99 step"));
}

test "integration: a quiet job's last lines are written by the background flusher" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var pgs = testSink(&sc, &console);
    pgs.flush_lines = 10_000;
    pgs.flush_ms = 100;
    try pgs.startFlusher();
    defer pgs.close();

    pgs.last_flush_ms = Io.Clock.real.now(std.testing.io).toMilliseconds();
    try pgs.append(5, 1, .stdout, "only line, then silence");
    try std.testing.expectEqual(@as(u64, 0), try countLogs(&sc)); // not yet: below the thresholds
    // The flusher wakes every 100 ms, but a loaded machine can hold it off much longer: wait for its
    // write, up to 10 s, rather than a fixed while.
    var waited_ms: u32 = 0;
    while (try countLogs(&sc) == 0 and waited_ms < 10_000) : (waited_ms += 50)
        try std.testing.io.sleep(.fromMilliseconds(50), .awake);
    try std.testing.expectEqual(@as(u64, 1), try countLogs(&sc)); // written without another append or an explicit flush
}

test "integration: a database outage never fails the caller; lines are kept and written after recovery" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var pgs = testSink(&sc, &console);
    pgs.cfg.port = 1; // nothing listens here
    defer pgs.close();

    try pgs.append(8, 0, .stdout, "line during the outage");
    try pgs.flush(); // fails inside, is swallowed
    try std.testing.expectEqual(@as(usize, 1), pgs.rows.items.len);
    try std.testing.expect(pgs.errorText().len > 0);
    try std.testing.expectEqual(@as(u64, 0), try countLogs(&sc));

    pgs.cfg = sc.cfg; // the database is back
    pgs.outage.retry_after_ms = 0;
    try pgs.append(8, 0, .stdout, "line after recovery");
    try pgs.flush();
    try std.testing.expectEqual(@as(u64, 2), try countLogs(&sc));
    try std.testing.expectEqualStrings("1,2", try sc.scalar("select string_agg(seq::text, ',' order by seq) from job_logs where job_id = 8"));
}

test "the buffer is capped: the oldest lines are dropped and counted when the database stays down" {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var pgs: PgSink = .{ .gpa = std.testing.allocator, .io = std.testing.io, .cfg = .{ .host = "127.0.0.1", .port = 1, .user = "u", .database = "d", .sslmode = .disable }, .inner = &console };
    pgs.max_buffered = 5;
    pgs.flush_lines = 1_000_000;
    pgs.flush_ms = 1_000_000;
    pgs.last_flush_ms = Io.Clock.real.now(std.testing.io).toMilliseconds();
    defer pgs.close();
    for (0..8) |_| try pgs.append(1, 0, .stdout, "x");
    try std.testing.expectEqual(@as(usize, 5), pgs.rows.items.len);
    try std.testing.expectEqual(@as(u64, 3), pgs.dropped);
    // seq keeps counting, so the gap is visible in the data.
    try std.testing.expectEqual(@as(u64, 4), pgs.rows.items[0].seq);
}

test "messages that belong to no job (id 0) stay on the console" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var pgs: PgSink = .{ .gpa = std.testing.allocator, .io = std.testing.io, .cfg = .{ .host = "127.0.0.1", .port = 1, .user = "u", .database = "d", .sslmode = .disable }, .inner = &console };
    defer pgs.close();
    try pgs.append(0, 0, .stderr, "registered runner");
    try std.testing.expectEqual(@as(usize, 0), pgs.rows.items.len);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "registered runner") != null);
}

test "integration: a line's number in its step reaches the database, and a runner's message has none" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    var console_out: Io.Writer.Allocating = .init(arena);
    var console: sink.LogSink = .{ .stdout = .{ .writer = &console_out.writer } };
    var db_sink: sink.LogSink = .{ .postgres = testSink(&sc, &console) };
    defer db_sink.postgres.close();

    // As a job logs: through the collector, which numbers a line in its step and passes the number
    // down. Two steps, interleaved, so the numbering cannot be a count of the job's lines.
    var collect: sink.LogSink = .{ .collect = .{ .arena = arena, .io = std.testing.io, .inner = &db_sink } };
    try collect.append(7, 1, .stdout, "step one, first");
    try collect.append(7, 2, .stdout, "step two, first");
    try collect.append(7, 1, .stdout, "step one, second");
    // As the runner logs its own messages: no step of its own, so no number in one.
    try db_sink.append(7, 0, .stderr, "job succeeded");
    try db_sink.flush();

    try std.testing.expectEqual(@as(u64, 4), try countLogs(&sc));
    // In the job's order the step numbers read 1, 1, 2: step two's first line falls between step
    // one's two, which is the whole point of numbering a line in its step rather than in the job.
    try std.testing.expectEqualStrings("1/1/2", try sc.scalar(
        "select string_agg(step_seq::text, '/' order by seq) from job_logs where job_id = 7 and step_number in (1, 2)",
    ));
    try std.testing.expectEqualStrings("1/2/3", try sc.scalar(
        "select string_agg(seq::text, '/' order by seq) from job_logs where job_id = 7 and step_number in (1, 2)",
    ));
    // The one with no step has no number: null, not zero, so a reader cannot mistake it for a line.
    try std.testing.expectEqualStrings("1", try sc.scalar("select count(*) from job_logs where job_id = 7 and step_seq is null"));
    try std.testing.expectEqualStrings("job succeeded", try sc.scalar("select line from job_logs where job_id = 7 and step_seq is null"));
}

test "a database that stops answering holds up no line, flush or close" {
    const io = std.testing.io;
    // Connections complete in the listener's backlog and are never answered: a database that has
    // stopped answering, as a paused one does.
    const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var console_out: Io.Writer.Allocating = .init(arena_state.allocator());
    var console: sink.LogSink = .{ .stdout = .{ .writer = &console_out.writer } };
    var pgs: PgSink = .{
        .gpa = std.testing.allocator,
        .io = io,
        .cfg = .{
            .host = "127.0.0.1",
            .port = listener.socket.address.getPort(),
            .user = "u",
            .database = "d",
            .sslmode = .disable,
        },
        .inner = &console,
        .flush_lines = 10,
        .flush_ms = 50,
        .close_wait_ms = 300,
    };
    try pgs.startFlusher();

    // Batches fall due all along, and the flusher is stuck on the first one: the lines still go
    // straight in, and the flush gives up after its bounded wait.
    const started = PgSink.now(io);
    for (0..200) |_| try pgs.append(1, 1, .stdout, "line");
    try pgs.flush();
    try std.testing.expect(PgSink.now(io) - started < 3000);
    // Once the write is plainly stuck, a step's end does not wait on it at all.
    try io.sleep(.fromMilliseconds(300), .awake);
    const flushing = PgSink.now(io);
    for (0..5) |_| try pgs.flush();
    try std.testing.expect(PgSink.now(io) - flushing < 200);

    const closing = PgSink.now(io);
    pgs.close();
    try std.testing.expect(PgSink.now(io) - closing < 3000);
    try std.testing.expectEqual(@as(u64, 0), pgs.written);
}
