//! Run state in Postgres/TimescaleDB (SPEC §4, §5.2): `runs`, `jobs` and `steps` upserts.
//!
//! The runner is the only writer. It updates state at transitions only (job start, step start, step
//! end, job end); every statement is an idempotent upsert on the primary key, so a retry or a crash
//! halfway is harmless. `runs.created_at` is the first time a run was seen and is never
//! overwritten.
const std = @import("std");
const pg = @import("pg.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const RunRow = struct {
    id: u64,
    repo: []const u8,
    workflow: []const u8,
    event: ?[]const u8 = null,
    branch: ?[]const u8 = null,
    sha: ?[]const u8 = null,
    /// queued | in_progress | completed
    status: []const u8,
    /// success | failure | cancelled
    conclusion: ?[]const u8 = null,
    /// ISO-8601 UTC.
    completed_at: ?[]const u8 = null,
};

pub const JobRow = struct {
    id: u64,
    run_id: u64,
    name: []const u8,
    runner_name: ?[]const u8 = null,
    status: []const u8,
    conclusion: ?[]const u8 = null,
    started_at: ?[]const u8 = null,
    completed_at: ?[]const u8 = null,
};

pub const StepRow = struct {
    job_id: u64,
    /// Step 0 is "Set up job"; the workflow's steps are 1..n.
    number: u32,
    name: []const u8,
    status: []const u8,
    conclusion: ?[]const u8 = null,
    started_at: ?[]const u8 = null,
    completed_at: ?[]const u8 = null,
};

fn text(w: *Io.Writer, v: ?[]const u8) Io.Writer.Error!void {
    if (v) |s| try pg.quote(w, s) else try w.writeAll("NULL");
}

pub fn writeUpsertRun(w: *Io.Writer, r: RunRow) Io.Writer.Error!void {
    try w.print(
        "INSERT INTO runs (id, repo, workflow, event, branch, sha, status, conclusion, " ++
            "completed_at) VALUES ({d}, ",
        .{r.id},
    );
    try pg.quote(w, r.repo);
    try w.writeAll(", ");
    try pg.quote(w, r.workflow);
    try w.writeAll(", ");
    try text(w, r.event);
    try w.writeAll(", ");
    try text(w, r.branch);
    try w.writeAll(", ");
    try text(w, r.sha);
    try w.writeAll(", ");
    try pg.quote(w, r.status);
    try w.writeAll(", ");
    try text(w, r.conclusion);
    try w.writeAll(", ");
    try text(w, r.completed_at);
    // created_at is deliberately not updated: it records when the run was first seen.
    try w.writeAll(") ON CONFLICT (id) DO UPDATE SET repo = EXCLUDED.repo, " ++
        "workflow = EXCLUDED.workflow, event = EXCLUDED.event, branch = EXCLUDED.branch, " ++
        "sha = EXCLUDED.sha, status = EXCLUDED.status, " ++
        "conclusion = EXCLUDED.conclusion, completed_at = EXCLUDED.completed_at");
}

pub fn writeUpsertJob(w: *Io.Writer, j: JobRow) Io.Writer.Error!void {
    try w.print(
        "INSERT INTO jobs (id, run_id, name, runner_name, status, conclusion, started_at, " ++
            "completed_at) VALUES ({d}, {d}, ",
        .{ j.id, j.run_id },
    );
    try pg.quote(w, j.name);
    try w.writeAll(", ");
    try text(w, j.runner_name);
    try w.writeAll(", ");
    try pg.quote(w, j.status);
    try w.writeAll(", ");
    try text(w, j.conclusion);
    try w.writeAll(", ");
    try text(w, j.started_at);
    try w.writeAll(", ");
    try text(w, j.completed_at);
    try w.writeAll(") ON CONFLICT (id) DO UPDATE SET run_id = EXCLUDED.run_id, " ++
        "name = EXCLUDED.name, runner_name = EXCLUDED.runner_name, " ++
        "status = EXCLUDED.status, conclusion = EXCLUDED.conclusion, " ++
        "started_at = COALESCE(EXCLUDED.started_at, jobs.started_at), " ++
        "completed_at = EXCLUDED.completed_at");
}

pub fn writeUpsertStep(w: *Io.Writer, s: StepRow) Io.Writer.Error!void {
    try w.print(
        "INSERT INTO steps (job_id, number, name, status, conclusion, started_at, completed_at) " ++
            "VALUES ({d}, {d}, ",
        .{ s.job_id, s.number },
    );
    try pg.quote(w, s.name);
    try w.writeAll(", ");
    try pg.quote(w, s.status);
    try w.writeAll(", ");
    try text(w, s.conclusion);
    try w.writeAll(", ");
    try text(w, s.started_at);
    try w.writeAll(", ");
    try text(w, s.completed_at);
    try w.writeAll(") ON CONFLICT (job_id, number) DO UPDATE SET name = EXCLUDED.name, " ++
        "status = EXCLUDED.status, " ++
        "conclusion = EXCLUDED.conclusion, " ++
        "started_at = COALESCE(EXCLUDED.started_at, steps.started_at), " ++
        "completed_at = EXCLUDED.completed_at");
}

/// `SET search_path TO "<schema>", public` with the identifier quoted (public keeps TimescaleDB's
/// functions visible).
pub fn writeSetSchema(w: *Io.Writer, schema: []const u8) Io.Writer.Error!void {
    try w.writeAll("SET search_path TO \"");
    for (schema) |c| {
        if (c == '"') try w.writeAll("\"\"") else try w.writeByte(c);
    }
    try w.writeAll("\", public");
}

/// Sets `schema` as the connection's search path (`writeSetSchema`).
pub fn setSchema(gpa: Allocator, c: *pg.Client, schema: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var aw: Io.Writer.Allocating = .init(arena_state.allocator());
    try writeSetSchema(&aw.writer, schema);
    try c.exec(aw.written());
}

pub const Store = struct {
    gpa: Allocator,
    io: Io,
    cfg: pg.Config,
    /// A scratch schema, set on every connection this makes. For the tests; production uses the
    /// default search path.
    schema: ?[]const u8 = null,
    client: ?*pg.Client = null,
    /// One connection, shared by the process's runners: one query at a time.
    mu: Io.Mutex = .init,
    /// Not dialled again before this, so a database that is down costs one attempt every two
    /// seconds instead of one per row. `PgSink` backs off the same way, for the same reason.
    retry_after_ms: i64 = 0,
    /// The most recent failure, for `Reporter` to report when the job ends. Under `error_mu`, not
    /// `mu`: the writer holds `mu` through a connect or a statement, and the job's end waited
    /// behind one that the database never answered, before completejob (#100).
    last_error: [256]u8 = undefined,
    last_error_len: usize = 0,
    error_mu: Io.Mutex = .init,
    /// Writes that failed, for the life of the process. `Reporter` reports those made while its
    /// job ran: with a writer, a row's failure comes after the call that queued it has returned.
    failed: std.atomic.Value(u64) = .init(0),

    /// Set by `startWriter`: rows are queued, and a task of their own writes them in order, so a
    /// database that is slow or has stopped answering never holds up a job. They were written by
    /// the job's own steps as they started and finished, under `mu`, which every runner shares: one
    /// write that hung held up every runner's next step. Without a writer (tests, `--db-check`),
    /// rows are written as they come.
    writer: ?Io.Future(void) = null,
    queue_mu: Io.Mutex = .init,
    queue: std.ArrayList([]u8) = .empty,
    /// Past this many waiting rows (a database down for long), the oldest are dropped and counted.
    max_queued: usize = 10_000,
    dropped: u64 = 0,
    stop: std.atomic.Value(bool) = .init(false),
    writer_stopped: std.atomic.Value(bool) = .init(false),
    /// Set by `close` once it stops waiting, before it cancels the writer: what is still queued
    /// is dropped. The cancel alone ends only the statement it lands in (`error.Canceled`, once),
    /// and the writer went on dialling and writing the rest of a long queue while `close` waited
    /// for it, a statement timeout per row.
    abandon: std.atomic.Value(bool) = .init(false),
    /// What `close` gives the writer to write what is left before cutting it short.
    close_wait_ms: u32 = 5000,

    const retry_ms = 2000;

    /// Describes the connection without making it. The first write dials, and a write that finds
    /// the connection gone dials again, so a database that is down or restarted costs run-state
    /// rows and nothing else: it never fails a job (SPEC §5.2) and never stops the runner starting.
    pub fn init(gpa: Allocator, io: Io, cfg: pg.Config, schema: ?[]const u8) Store {
        return .{ .gpa = gpa, .io = io, .cfg = cfg, .schema = schema };
    }

    /// Connects now and reports it if it cannot: for `--db-check`, the tests, and the one probe at
    /// startup, all of which want the error itself rather than a retry.
    pub fn open(gpa: Allocator, io: Io, cfg: pg.Config, schema: ?[]const u8) !Store {
        var s: Store = .init(gpa, io, cfg, schema);
        try s.dial();
        return s;
    }

    pub fn close(s: *Store) void {
        s.stop.store(true, .release);
        if (s.writer) |*f| {
            var waited: u32 = 0;
            while (!s.writer_stopped.load(.acquire) and waited < s.close_wait_ms) : (waited += 50)
                s.io.sleep(.fromMilliseconds(50), .awake) catch break;
            s.abandon.store(true, .release);
            f.cancel(s.io);
            s.writer = null;
        }
        for (s.queue.items) |q| s.gpa.free(q);
        s.queue.deinit(s.gpa);
        if (s.client) |c| c.close();
        s.client = null;
    }

    /// Starts the task that writes queued rows (see `writer`).
    pub fn startWriter(s: *Store) !void {
        s.writer = try s.io.concurrent(writerMain, .{s});
    }

    fn writerMain(s: *Store) void {
        defer s.writer_stopped.store(true, .release);
        while (!s.abandon.load(.acquire)) {
            const sql = s.next() orelse {
                if (s.stop.load(.acquire)) return;
                s.io.sleep(.fromMilliseconds(20), .awake) catch return;
                continue;
            };
            defer s.gpa.free(sql);
            s.mu.lockUncancelable(s.io);
            defer s.mu.unlock(s.io);
            s.execLocked(sql) catch |e| switch (e) {
                error.Canceled => return, // `close` gave up waiting (`abandon`)
                else => {}, // counted in `failed` and remembered, for `Reporter`
            };
        }
    }

    /// The oldest queued row, if any.
    fn next(s: *Store) ?[]u8 {
        s.queue_mu.lockUncancelable(s.io);
        defer s.queue_mu.unlock(s.io);
        if (s.queue.items.len == 0) return null;
        return s.queue.orderedRemove(0);
    }

    fn enqueue(s: *Store, sql: []const u8) pg.Error!void {
        const owned = s.gpa.dupe(u8, sql) catch return error.OutOfMemory;
        s.queue_mu.lockUncancelable(s.io);
        defer s.queue_mu.unlock(s.io);
        s.queue.append(s.gpa, owned) catch {
            s.gpa.free(owned);
            return error.OutOfMemory;
        };
        if (s.queue.items.len > s.max_queued) {
            s.gpa.free(s.queue.orderedRemove(0));
            s.dropped += 1;
            _ = s.failed.fetchAdd(1, .monotonic);
        }
    }

    /// What went wrong most recently, empty if nothing has. Copied, under `error_mu`: the writer
    /// may be recording a newer failure.
    pub fn lastError(s: *Store, arena: Allocator) []const u8 {
        s.error_mu.lockUncancelable(s.io);
        defer s.error_mu.unlock(s.io);
        return arena.dupe(u8, s.last_error[0..s.last_error_len]) catch "";
    }

    fn remember(s: *Store, what: []const u8, detail: []const u8) void {
        s.error_mu.lockUncancelable(s.io);
        defer s.error_mu.unlock(s.io);
        const t = std.fmt.bufPrint(&s.last_error, "{s}: {s}", .{ what, detail }) catch
            s.last_error[0..0];
        s.last_error_len = t.len;
    }

    fn dial(s: *Store) !void {
        const c = try pg.Client.connect(s.gpa, s.io, s.cfg);
        errdefer c.close();
        if (s.schema) |sc| try setSchema(s.gpa, c, sc);
        s.client = c;
    }

    /// The connection, dialled if there is none. Called with `mu` held.
    fn ensure(s: *Store) pg.Error!*pg.Client {
        if (s.client) |c| return c;
        const t = Io.Clock.real.now(s.io).toMilliseconds();
        if (t < s.retry_after_ms) return error.ConnectionClosed;
        s.dial() catch |e| {
            // From when the attempt ended: one that took its whole time (a database that accepts
            // and never answers) was followed at once by the next, and `mu` was hardly ever free.
            s.retry_after_ms = Io.Clock.real.now(s.io).toMilliseconds() + retry_ms;
            s.remember("connect failed", @errorName(e));
            return error.ConnectionClosed;
        };
        return s.client.?;
    }

    pub fn upsertRun(s: *Store, r: RunRow) pg.Error!void {
        return s.run(RunRow, writeUpsertRun, r);
    }

    pub fn upsertJob(s: *Store, j: JobRow) pg.Error!void {
        return s.run(JobRow, writeUpsertJob, j);
    }

    pub fn upsertStep(s: *Store, st: StepRow) pg.Error!void {
        return s.run(StepRow, writeUpsertStep, st);
    }

    fn run(
        s: *Store,
        comptime T: type,
        comptime build: fn (*Io.Writer, T) Io.Writer.Error!void,
        row: T,
    ) pg.Error!void {
        var arena_state: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena_state.deinit();
        var aw: Io.Writer.Allocating = .init(arena_state.allocator());
        build(&aw.writer, row) catch return error.OutOfMemory;
        if (s.writer != null) return s.enqueue(aw.written());
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        return s.execLocked(aw.written());
    }

    /// One statement, on the connection (dialled if need be). Called with `mu` held.
    fn execLocked(s: *Store, sql: []const u8) pg.Error!void {
        const c = s.ensure() catch |e| {
            _ = s.failed.fetchAdd(1, .monotonic);
            return e;
        };
        c.exec(sql) catch |e| {
            _ = s.failed.fetchAdd(1, .monotonic);
            s.remember(
                "write failed",
                if (c.lastErrorText().len > 0) c.lastErrorText() else @errorName(e),
            );
            // A connection the server has dropped is let go, so the next row dials again instead
            // of failing for the life of the process. A `ServerError` is the statement's problem,
            // not the connection's, so that one is kept. One given up mid-statement (`Timeout`,
            // `Canceled`) cannot be used again.
            switch (e) {
                error.ConnectionClosed,
                error.BadMessage,
                error.UnexpectedMessage,
                error.Timeout,
                error.Canceled,
                => {
                    c.close();
                    s.client = null;
                },
                else => {},
            }
            return e;
        };
    }
};

// --- tests ---

test "a store whose database is down describes itself, writes nothing, and never stops the runner" {
    const down: pg.Config = .{ .host = "127.0.0.1", .port = 1, .user = "u", .database = "d", .sslmode = .disable };

    // `open` is for the callers that want the error: `--db-check`, and the one probe at startup.
    try std.testing.expectError(error.ConnectionRefused, Store.open(std.testing.allocator, std.testing.io, down, null));

    // `init` is what the runner falls back to, and it cannot fail: the whole point is that a
    // database nobody can reach is not a reason to refuse to run jobs.
    var store: Store = .init(std.testing.allocator, std.testing.io, down, null);
    defer store.close();

    // A write reports the failure and keeps the process going. The store counts these, and
    // `Reporter` reports them when the job ends; nothing here propagates to the job's result.
    try std.testing.expectError(error.ConnectionClosed, store.upsertRun(.{ .id = 1, .repo = "o/r", .workflow = "ci", .status = "in_progress" }));
    const last = store.lastError(std.testing.allocator);
    defer std.testing.allocator.free(last);
    try std.testing.expect(std.mem.indexOf(u8, last, "connect failed") != null);

    // The second write inside the backoff window does not dial again — a job of forty steps must
    // not cost forty connection attempts to a database that is down.
    const first_deadline = store.retry_after_ms;
    try std.testing.expectError(error.ConnectionClosed, store.upsertStep(.{ .job_id = 1, .number = 1, .name = "s", .status = "in_progress" }));
    try std.testing.expectEqual(first_deadline, store.retry_after_ms);
}

test "upsert statements quote values, keep created_at, and use NULL for absent fields" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeUpsertRun(&w, .{ .id = 42, .repo = "o/r", .workflow = "it's", .branch = "main", .status = "in_progress" });
    const sql = w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, sql, "INSERT INTO runs (id, repo, workflow, event, branch, sha, status, conclusion, completed_at) VALUES (42, 'o/r', 'it''s', NULL, 'main', NULL, 'in_progress', NULL, NULL)"));
    try std.testing.expect(std.mem.indexOf(u8, sql, "ON CONFLICT (id) DO UPDATE") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "created_at") == null);

    var w2: Io.Writer = .fixed(&buf);
    try writeUpsertJob(&w2, .{ .id = 7, .run_id = 42, .name = "build", .status = "completed", .conclusion = "success", .started_at = "2026-10-11T17:00:00.000Z" });
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "VALUES (7, 42, 'build', NULL, 'completed', 'success', '2026-10-11T17:00:00.000Z', NULL)") != null);
    // A later upsert without a start time must not erase the recorded one.
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "COALESCE(EXCLUDED.started_at, jobs.started_at)") != null);

    var w3: Io.Writer = .fixed(&buf);
    try writeUpsertStep(&w3, .{ .job_id = 7, .number = 0, .name = "Set up job", .status = "completed", .conclusion = "success" });
    try std.testing.expect(std.mem.indexOf(u8, w3.buffered(), "VALUES (7, 0, 'Set up job', 'completed', 'success', NULL, NULL)") != null);
    try std.testing.expect(std.mem.indexOf(u8, w3.buffered(), "ON CONFLICT (job_id, number)") != null);

    var w4: Io.Writer = .fixed(&buf);
    try writeSetSchema(&w4, "zig \"it\"");
    try std.testing.expectEqualStrings("SET search_path TO \"zig \"\"it\"\"\", public", w4.buffered());
}

test "integration: state upserts are idempotent, keep created_at and started_at, and respect foreign keys" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    var store = try Store.open(std.testing.allocator, std.testing.io, sc.cfg, sc.schema);
    defer store.close();

    // A job cannot exist before its run (foreign key).
    try std.testing.expectError(error.ServerError, store.upsertJob(.{ .id = 7, .run_id = 42, .name = "build", .status = "in_progress" }));

    const run: RunRow = .{ .id = 42, .repo = "o/r", .workflow = "ci", .event = "push", .branch = "main", .sha = "abc", .status = "in_progress" };
    try store.upsertRun(run);
    const created = try sc.scalar("select created_at::text from runs where id = 42");
    try store.upsertRun(run); // idempotent
    try store.upsertRun(.{ .id = 42, .repo = "o/r", .workflow = "ci", .event = "push", .branch = "main", .sha = "abc", .status = "completed", .conclusion = "success", .completed_at = "2026-10-11T18:00:00.000Z" });
    try std.testing.expectEqualStrings("1", try sc.scalar("select count(*) from runs"));
    try std.testing.expectEqualStrings("completed/success", try sc.scalar("select status || '/' || conclusion from runs where id = 42"));
    try std.testing.expectEqualStrings(created, try sc.scalar("select created_at::text from runs where id = 42"));

    try store.upsertJob(.{ .id = 7, .run_id = 42, .name = "it's a job", .runner_name = "zig-1", .status = "in_progress", .started_at = "2026-10-11T17:00:00.000Z" });
    try store.upsertJob(.{ .id = 7, .run_id = 42, .name = "it's a job", .runner_name = "zig-1", .status = "completed", .conclusion = "success", .completed_at = "2026-10-11T17:00:05.000Z" });
    try std.testing.expectEqualStrings("completed", try sc.scalar("select status from jobs where id = 7"));
    try std.testing.expectEqualStrings("2026-10-11 17:00:00+00", try sc.scalar("select started_at::text from jobs where id = 7")); // kept
    try std.testing.expectEqualStrings("it's a job", try sc.scalar("select name from jobs where id = 7"));

    try store.upsertStep(.{ .job_id = 7, .number = 0, .name = "Set up job", .status = "completed", .conclusion = "success" });
    try store.upsertStep(.{ .job_id = 7, .number = 1, .name = "Build", .status = "in_progress", .started_at = "2026-10-11T17:00:01.000Z" });
    try store.upsertStep(.{ .job_id = 7, .number = 1, .name = "Build", .status = "completed", .conclusion = "failure", .completed_at = "2026-10-11T17:00:04.000Z" });
    try std.testing.expectEqualStrings("2", try sc.scalar("select count(*) from steps"));
    try std.testing.expectEqualStrings("completed/failure", try sc.scalar("select status || '/' || conclusion from steps where number = 1"));
    try std.testing.expectEqualStrings("2026-10-11 17:00:01+00", try sc.scalar("select started_at::text from steps where number = 1")); // kept
}

test "a database that accepts and never answers holds up neither the job's end nor the next row" {
    const io = std.testing.io;
    // Connections complete in the listener's backlog and are never answered.
    const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);

    // With its writer, a row is queued at once though the database does not answer. At the same
    // time as the rest, which waits out a connect: each has its own store and listener.
    const Queued = struct {
        fn run(a: Io.net.IpAddress) !void {
            var listener = try a.listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const cfg: pg.Config = .{
                .host = "127.0.0.1",
                .port = listener.socket.address.getPort(),
                .user = "u",
                .database = "d",
                .sslmode = .disable,
            };
            var store: Store = .init(std.testing.allocator, io, cfg, null);
            store.close_wait_ms = 300;
            try store.startWriter();
            defer store.close();

            // The writer is stuck dialling; each step's start and end would have waited on it.
            const started = Io.Clock.awake.now(io).toMilliseconds();
            for (0..20) |i| try store.upsertStep(.{
                .job_id = 1,
                .number = @intCast(i),
                .name = "step",
                .status = "in_progress",
            });
            try std.testing.expect(Io.Clock.awake.now(io).toMilliseconds() - started < 500);
        }
    };
    var queued = try io.concurrent(Queued.run, .{addr});
    defer queued.cancel(io) catch {};

    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    // Long enough that the question below is asked well within it, even on a busy machine.
    const connect_ms = 2_000;
    const cfg: pg.Config = .{
        .host = "127.0.0.1",
        .port = listener.socket.address.getPort(),
        .user = "u",
        .database = "d",
        .sslmode = .disable,
        .connect_timeout = .fromMilliseconds(connect_ms),
    };
    var store: Store = .init(std.testing.allocator, io, cfg, null);
    store.close_wait_ms = 300;
    try store.startWriter();
    defer store.close();

    const started = Io.Clock.real.now(io).toMilliseconds();
    try store.upsertStep(.{ .job_id = 1, .number = 1, .name = "step", .status = "in_progress" });
    io.sleep(.fromMilliseconds(50), .awake) catch {};
    // The writer is dialling, holding `mu`. The job's end asks what failed (`finishReporter`),
    // before completejob: it is answered while the connect still goes on, not once it is given
    // up (which the writer counts in `failed` before it lets `mu` go). Not a time limit: on a
    // busy CI machine 100 ms was not always enough to see the answer.
    const Ask = struct {
        fn run(st: *Store, done: *std.atomic.Value(bool)) void {
            std.testing.allocator.free(st.lastError(std.testing.allocator));
            done.store(true, .release);
        }
    };
    var done: std.atomic.Value(bool) = .init(false);
    var asking = try io.concurrent(Ask.run, .{ &store, &done });
    while (!done.load(.acquire) and store.failed.load(.acquire) == 0)
        io.sleep(.fromMilliseconds(10), .awake) catch {};
    // In this order: answered, and the connect not yet given up after that.
    const asked = done.load(.acquire);
    const answered = asked and store.failed.load(.acquire) == 0;

    // The connect is given up at its deadline, where it used to wait for good.
    var waited: u32 = 0;
    while (store.failed.load(.acquire) == 0 and waited < 10_000) : (waited += 10)
        io.sleep(.fromMilliseconds(10), .awake) catch {};
    asking.await(io);
    try std.testing.expect(answered);
    try std.testing.expectEqual(@as(u64, 1), store.failed.load(.acquire));
    const last = store.lastError(std.testing.allocator);
    defer std.testing.allocator.free(last);
    try std.testing.expectEqualStrings("connect failed: Timeout", last);
    // The next dial waits `retry_ms` from when this one ended, not from when it began.
    store.mu.lockUncancelable(io);
    const retry_after = store.retry_after_ms;
    store.mu.unlock(io);
    try std.testing.expect(retry_after >= started + connect_ms + Store.retry_ms);
    try queued.await(io);
}
