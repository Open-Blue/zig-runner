const std = @import("std");
const Config = @import("config.zig").Config;
const loop = @import("loop.zig");
const inspect = @import("inspect.zig");
const dagger = @import("dagger.zig");
const set_up = @import("dagger/set_up.zig");
const sandbox = @import("native/sandbox.zig");
const net = @import("native/net.zig");
const nft = @import("native/nft.zig");

const forward = @import("native/forward.zig");
const trust = @import("trust.zig");
const job_mod = @import("job.zig");
const db = @import("db.zig");
const pg = @import("pg.zig");
const redact = @import("redact.zig");
const sink = @import("sink.zig");
const http = @import("github/http.zig");
const zig_release = @import("zig_release.zig");
const broker = @import("github/broker.zig");
const jitconfig = @import("github/jitconfig.zig");
const app = @import("github/app.zig");
const engine = @import("engine.zig");
const build_version = @import("version.zig");

comptime {
    _ = @import("sink.zig");
    _ = @import("native/Backend.zig");
    _ = @import("native/Store.zig");
    _ = @import("native/sandbox.zig");
    _ = @import("native/net.zig");
    _ = @import("native/seccomp.zig");
    _ = @import("native/nft.zig");
    _ = @import("native/oci/layer.zig");
    _ = @import("native/oci/registry.zig");
    _ = @import("native/oci/Store.zig");
    _ = @import("native/oci/image.zig");
    _ = @import("native/oci/testregistry.zig");
    _ = @import("native/key_vectors.zig");
    _ = @import("native/services.zig");
    _ = @import("native/health.zig");
    _ = @import("native/images.zig");
    _ = @import("native/forward.zig");
    _ = @import("redact.zig");
    _ = @import("yaml.zig");
    _ = @import("action.zig");
    _ = @import("config.zig");
    _ = @import("admission.zig");
    _ = @import("github/jitconfig.zig");
    _ = @import("github/rsa_sign.zig");
    _ = @import("github/auth.zig");
    _ = @import("github/app.zig");
    _ = @import("inspect.zig");
    _ = @import("github/broker.zig");
    _ = @import("github/runservice.zig");
    _ = @import("github/results.zig");
    _ = @import("github/feed.zig");
    _ = @import("live.zig");
    _ = @import("job.zig");
    _ = @import("trust.zig");
    _ = @import("dagger.zig");
    _ = @import("engine.zig");
    _ = @import("hpack.zig");
    _ = @import("loop.zig");
    _ = @import("timefmt.zig");
    _ = @import("expr.zig");
    _ = @import("glob.zig");
    _ = @import("context.zig");
    _ = @import("commands.zig");
    _ = @import("regex.zig");
    _ = @import("minisign.zig");
    _ = @import("zig_release.zig");
    _ = @import("matcher.zig");
    _ = @import("fuzz.zig");
    _ = @import("pg.zig");
    _ = @import("db.zig");
    _ = @import("pgsink.zig");
    _ = @import("dbtest.zig");
}

const Exit = loop.Exit;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;

    var err_buf: [1024]u8 = undefined;
    var err_w: std.Io.File.Writer = .initStreaming(.stderr(), io, &err_buf);
    const err = &err_w.interface;
    defer err.flush() catch {};

    const args = try init.minimal.args.toSlice(arena);
    // A native step's sandbox (`native/sandbox.zig`): before anything else, so nothing has
    // started a thread when it makes its namespaces.
    if (args.len == 2 and std.mem.eql(u8, args[1], sandbox.command)) return sandbox.main(arena);
    if (args.len == 2 and std.mem.eql(u8, args[1], forward.command)) return forward.main(arena);
    if (args.len == 5 and std.mem.eql(u8, args[1], net.command))
        return net.upMain(arena, args[2], args[3], args[4]);
    if (args.len >= 3 and std.mem.eql(u8, args[1], nft.command)) return nft.main(args[2..]);
    if (try printVersionIfAsked(io, args)) return @backingInt(Exit.done);
    if (try printProvisionIfAsked(io, args)) return @backingInt(Exit.done);

    var cfg = Config.load(init.environ_map, args) catch |e| {
        try err.print("config error: {s}\n", .{Config.explain(e) orelse @errorName(e)});
        return @backingInt(Exit.config);
    };
    // Where logs and run state go: DATABASE_URL / PG* when set, else stdout only.
    const pg_cfg = cfg.pgConfig(arena, init.environ_map) catch |e| {
        try err.print("config error: invalid database settings ({s})\n", .{@errorName(e)});
        return @backingInt(Exit.config);
    };
    const secrets = try allSecrets(arena, &cfg, pg_cfg);

    var out_buf: [4096]u8 = undefined;
    var stdout: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    var console: sink.LogSink = .{
        .stdout = .{ .writer = &stdout.interface, .secrets = secrets, .io = io },
    };
    defer console.close();

    var db_sink: sink.LogSink = undefined;
    var log: *sink.LogSink = &console;
    var store: ?db.Store = null;
    const live = !cfg.dry_run and !cfg.inspect and cfg.exec_job == null and !cfg.db_check;
    if (pg_cfg) |dbcfg| if (live) {
        try openDatabase(init, dbcfg, &cfg, &console, secrets, err, &db_sink, &store);
        log = &db_sink;
    };
    defer if (store != null) {
        log.close();
        store.?.close();
    };

    const name = try runnerName(arena, io, cfg.name_prefix);

    if (cfg.db_check) return dbCheck(init, pg_cfg, secrets, &stdout.interface, err);
    if (cfg.exec_job) |path| return execJobFile(init, &cfg, path, log, err);
    if (cfg.dry_run) return dryRun(arena, log, name, cfg.labels);
    var app_auth: app.Auth = undefined;
    if (cfg.gh_app) |settings| {
        app_auth = startApp(arena, io, settings, cfg.scope, log, err) catch |e| return switch (e) {
            error.AppConfig => @backingInt(Exit.config),
            error.AppRejected => @backingInt(Exit.github),
            else => e,
        };
        cfg.app_auth = &app_auth;
    }
    if (cfg.inspect) return inspect.run(arena, io, &cfg, name, &stdout.interface);

    // One HTTP client for every runner (see `github/http.zig`).
    var client: std.http.Client = .{
        .allocator = init.gpa,
        .io = io,
        .write_buffer_size = http.write_buffer_size,
    };
    defer client.deinit();
    http.shared.store(&client, .release);
    // The seeds' tarballs are checked here, once, outside any job (`zig_release.zig`); the tool
    // caches' Zig versions join them as `repo` jobs find them.
    var zig_seeds: zig_release.Registry = .{ .io = io, .gpa = init.gpa, .client = &client };
    if (cfg.zig_seed) |*s| {
        cfg.zig_seeds = s[0..1];
    } else if (cfg.package_caches) {
        const r = try zig_release.resolve(arena, init.gpa, &client, cfg.zig_seed_versions);
        cfg.zig_seeds = r.seeds;
        cfg.zig_seeds_unverified = r.unverified;
        try zig_seeds.add(r);
        cfg.zig_seed_registry = &zig_seeds;
    }
    const stale = try settleRegistrations(arena, io, &cfg, log);
    installStopSignals();
    // Removed while the runners start, not before: that wait was 60 s every restart that found any.
    var sweep: StaleSweep = .{ .gpa = init.gpa, .io = io, .cfg = &cfg, .log = log };
    sweep.start(stale);
    defer sweep.stop();
    return runPool(init, &cfg, log, err, secrets, name, if (store) |*st| st else null);
}

/// The GitHub App's installation tokens, with the first one minted now: a key GitHub does not
/// take, or an App not installed on GH_SCOPE, is said once at startup, not as a registration
/// failure later. Neither the key nor the token is ever written out.
fn startApp(
    arena: std.mem.Allocator,
    io: std.Io,
    settings: @import("config.zig").GhApp,
    scope: @import("config.zig").Scope,
    log: *sink.LogSink,
    err: *std.Io.Writer,
) !app.Auth {
    var a = app.Auth.init(arena, io, settings, scope) catch |e| {
        switch (settings.key) {
            .file => |path| try err.print(
                "config error: GH_APP_PRIVATE_KEY_FILE {s}: {s}\n",
                .{ path, @errorName(e) },
            ),
            .pem => try err.print("config error: GH_APP_PRIVATE_KEY: {s}\n", .{@errorName(e)}),
        }
        return error.AppConfig;
    };
    var status: std.http.Status = .ok;
    var message: []const u8 = "";
    _ = a.token(arena, io, &status, &message) catch |e| {
        try err.print("github error: GitHub App {s}: {s} (HTTP {d})", .{
            settings.id,
            @errorName(e),
            @backingInt(status),
        });
        if (message.len > 0) try err.print(": {s}", .{message});
        try err.writeAll("\n  The App must be installed on GH_SCOPE with \"Administration: read " ++
            "and write\" (a repository) or \"Self-hosted runners: read and write\" (an " ++
            "organization).\n");
        return error.AppRejected;
    };
    try log.say(try std.fmt.allocPrint(
        arena,
        "GitHub App {s}: installation {d}, token refreshed 5 minutes before it expires",
        .{ settings.id, a.installation_id.? },
    ));
    return a;
}

/// The runners, until a stop signal: `cfg.runners` of them in one process (see `loop.pool`).
fn runPool(
    init: std.process.Init,
    cfg: *const Config,
    log: *sink.LogSink,
    err: *std.Io.Writer,
    secrets: []const []const u8,
    name: []const u8,
    store: ?*db.Store,
) !u8 {
    return @backingInt(try loop.pool(.{
        .arena = init.arena.allocator(),
        .gpa = init.gpa,
        .io = init.io,
        .environ = init.environ_map,
        .cfg = cfg,
        .log = log,
        .err = err,
        .secrets = secrets,
        .name = name,
        .store = store,
    }, cfg.runners));
}

/// `--version`, answered before the configuration is read, so that asking which binary this is
/// never needs a token: the question is usually asked of a machine whose behaviour is a surprise,
/// where every other answer is in doubt. True when it was asked and answered.
fn printVersionIfAsked(io: std.Io, args: []const [:0]const u8) !bool {
    for (args[1..]) |arg| if (std.mem.eql(u8, arg, "--version")) {
        var out_buf: [256]u8 = undefined;
        var w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
        try w.interface.print(
            "zig-runner {s} (runner protocol {s}, Dagger {s})\n",
            .{ build_version.string, broker.version, engine.client_version },
        );
        try w.interface.flush();
        return true;
    };
    return false;
}

/// `--provision-script`: the shell script the default image is provisioned with when steps run as
/// the runner user (`set_up.provision_runner_script`), for making the native backend's rootfs
/// from `ubuntu:24.04` (docs/native-backend.md, "The rootfs"; .github/scripts/e2e.sh). Answered,
/// as `--version`, before the configuration is read.
fn printProvisionIfAsked(io: std.Io, args: []const [:0]const u8) !bool {
    for (args[1..]) |arg| if (std.mem.eql(u8, arg, "--provision-script")) {
        var out_buf: [256]u8 = undefined;
        var w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
        try w.interface.print("{s}\n", .{set_up.provision_runner_script});
        try w.interface.flush();
        return true;
    };
    return false;
}

/// Everything that must never appear in output: the configuration's secrets, and the database
/// password when there is one.
fn allSecrets(
    arena: std.mem.Allocator,
    cfg: *const Config,
    pg_cfg: ?pg.Config,
) ![]const []const u8 {
    var secret_buf: [2][]const u8 = undefined;
    var list: std.ArrayList([]const u8) = .empty;
    try list.appendSlice(arena, cfg.secrets(&secret_buf));
    if (pg_cfg) |p| if (p.password.len > 0) try list.append(arena, p.password);
    return list.items;
}

/// The database, for logs and run state. Dialled once here so a wrong password or a stopped
/// database is in the journal at startup rather than at the first job — but never fatal. The
/// database holds logs and run state, both of which the runner is documented to treat as a logging
/// concern and never as a job failure (SPEC §5.1); refusing to start made an optional subsystem
/// able to take CI down, and with systemd's restart policy it crash-looped with jobs queued behind
/// it. The store and the log sink both dial again as work arrives, so this recovers on its own.
/// `db_sink` and `store` are the caller's, because the caller's `log` points at the sink.
fn openDatabase(
    init: std.process.Init,
    dbcfg: pg.Config,
    cfg: *const Config,
    console: *sink.LogSink,
    secrets: []const []const u8,
    err: *std.Io.Writer,
    db_sink: *sink.LogSink,
    store: *?db.Store,
) !void {
    const io = init.io;
    store.* = db.Store.open(init.gpa, io, dbcfg, null) catch |e| lazy: {
        try err.writeAll("database unavailable, logging to the console and retrying: ");
        try redact.write(err, @errorName(e), secrets);
        try err.writeByte('\n');
        // Flushed here, not left to the `defer`: this is the first message the runner writes
        // that is followed by the process *continuing*, and without the flush it sat in the
        // buffer for the life of the pool. A warning nobody can read is the silent failure the
        // probe exists to prevent (checked on the Pi: the line was missing from the journal).
        try err.flush();
        break :lazy .init(init.gpa, io, dbcfg, null);
    };
    db_sink.* = .{ .postgres = .{
        .gpa = init.gpa,
        .io = io,
        .cfg = dbcfg,
        .inner = console,
        .secrets = secrets,
        .flush_lines = cfg.log_flush_lines,
        .flush_ms = cfg.log_flush_ms,
    } };
    try db_sink.postgres.startFlusher();
    // Rows are written in the background from here on: neither a slow database nor one that has
    // stopped answering holds up a job (`Store.writer`).
    try store.*.?.startWriter();
}

/// The registration name: the configured prefix and a random suffix, new for every process.
fn runnerName(arena: std.mem.Allocator, io: std.Io, prefix: []const u8) ![]const u8 {
    var suffix: [4]u8 = undefined;
    io.random(&suffix);
    return std.fmt.allocPrint(arena, "{s}-{x}", .{ prefix, suffix });
}

/// Before registering: the repository's current name if it moved (GitHub's redirects for the old
/// name cannot carry a registration). Returns the registrations a stopped runner could not remove
/// (see `jitconfig.staleRegistrations`), for `StaleSweep` to remove while the runners start.
fn settleRegistrations(
    arena: std.mem.Allocator,
    io: std.Io,
    cfg: *Config,
    log: *sink.LogSink,
) ![]const u64 {
    if (jitconfig.movedRepo(arena, io, cfg)) |now| {
        const was = cfg.scope.repo;
        try log.say(try std.fmt.allocPrint(
            arena,
            "GH_SCOPE {s}/{s} moved to {s}/{s}: registering there (set GH_SCOPE to it)",
            .{ was.owner, was.name, now.repo.owner, now.repo.name },
        ));
        cfg.scope = now;
    }
    const candidates = jitconfig.staleRegistrations(arena, io, cfg) catch &.{};
    if (candidates.len > 0) try log.say(try std.fmt.allocPrint(
        arena,
        "{d} offline registration(s) named {s}-* look left behind; removing those still offline " ++
            "in {d} s",
        .{ candidates.len, cfg.name_prefix, jitconfig.stale_confirm_seconds },
    ));
    return candidates;
}

/// Removes the registrations `settleRegistrations` found, those still offline once
/// `stale_confirm_seconds` have passed, while the runners start. It only removes ids from that
/// list, and the runners' own registrations are made after it, so it never touches theirs.
const StaleSweep = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: *const Config,
    log: *sink.LogSink,
    /// Its own: the process's arena is not for use from another task.
    arena: std.heap.ArenaAllocator = undefined,
    candidates: []const u64 = &.{},
    task: ?std.Io.Future(void) = null,

    fn start(s: *StaleSweep, candidates: []const u64) void {
        if (candidates.len == 0) return;
        s.arena = .init(s.gpa);
        s.candidates = s.arena.allocator().dupe(u64, candidates) catch return s.arena.deinit();
        s.task = s.io.concurrent(run, .{s}) catch {
            s.arena.deinit();
            return;
        };
    }

    /// A stop before the wait is over leaves them for the next start.
    fn stop(s: *StaleSweep) void {
        if (s.task) |*t| {
            t.cancel(s.io);
            s.arena.deinit();
        }
    }

    fn run(s: *StaleSweep) void {
        s.io.sleep(.fromSeconds(jitconfig.stale_confirm_seconds), .awake) catch return;
        const arena = s.arena.allocator();
        const removed = jitconfig.removeStillStale(arena, s.io, s.cfg, s.candidates);
        const line = std.fmt.allocPrint(
            arena,
            "removed {d} stale registration(s) named {s}-*, which a stopped runner left behind",
            .{ removed, s.cfg.name_prefix },
        ) catch return;
        s.log.say(line) catch {};
    }
};

/// `--dry-run`: the configuration was valid; say what would have been registered, and stop.
fn dryRun(arena: std.mem.Allocator, log: *sink.LogSink, name: []const u8, labels: []const u8) !u8 {
    const line = try std.fmt.allocPrint(
        arena,
        "dry run: would register runner '{s}' with labels '{s}'",
        .{ name, labels },
    );
    try log.say(line);
    return @backingInt(Exit.done);
}

/// SIGTERM / SIGINT stop the runners gracefully (see `loop.stop_signals`); a second one exits.
fn installStopSignals() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onStopSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
}

/// The first signal asks the runners to stop; a second exits at once, with the shell's code for a
/// process ended by SIGINT (128 + 2).
fn onStopSignal(_: std.posix.SIG) callconv(.c) void {
    if (loop.stop_signals.fetchAdd(1, .acq_rel) >= 1) std.process.exit(130);
}

/// `--exec-job`, a dev helper: runs a saved acquirejob response through the Dagger executor.
fn execJobFile(
    init: std.process.Init,
    cfg: *const Config,
    path: []const u8,
    log: *sink.LogSink,
    err: *std.Io.Writer,
) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const json = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        .limited(16 * 1024 * 1024),
    ) catch |e| {
        try err.print("cannot read {s}: {s}\n", .{ path, @errorName(e) });
        return @backingInt(Exit.config);
    };
    const job = job_mod.parse(arena, json) catch |e| {
        try err.print("cannot parse job: {s}\n", .{@errorName(e)});
        return @backingInt(Exit.config);
    };
    log.setSecrets(job.secrets);
    const res = try dagger.run(arena, io, init.environ_map, .{
        .dagger_cmd = cfg.dagger_cmd,
        .image = cfg.image,
        .js_runtime = cfg.js_runtime,
        .engine = cfg.engineEndpoint(),
        .gpa = init.gpa,
        .nesting = cfg.dagger_nesting,
        .package_caches = cfg.package_caches,
        .tool_trees = cfg.tool_trees,
        .uv_env_in_cache = cfg.uv_env_in_cache,
        .zig_local_cache = cfg.zig_local_cache,
        .zig_local_cache_max_mb = cfg.zig_local_cache_max_mb,
        .zig_seeds = if (cfg.zig_seed) |*s| s[0..1] else &.{},
        .step_cache = cfg.step_cache,
        .step_user = cfg.step_user,
        .output_keys = cfg.output_keys,
        .enforce_volatile = cfg.enforce_volatile,
        .output_keys_days = cfg.output_keys_days,
        .sink_job_id = job.check_run_id,
        // A saved job is held to the same rule as one from GitHub: native steps only where the
        // runner's trusted refs vouch for it.
        .native = try dagger.Backend.configFor(
            arena,
            io,
            init.environ_map,
            cfg,
            trust.vouches(cfg.trusted_refs, cfg.trusted_events, job.github),
        ),
    }, job, log);
    for (res.steps, job.steps, 1..) |r, st, n| {
        try err.print(
            "step {d} [{s}] {s}: {s} (exit {d})\n",
            .{ n, st.name, @tagName(st.action), @tagName(r.outcome), r.exit_code },
        );
    }
    // The annotations too: they are what `::error`, `::warning` and the problem matchers produce,
    // they go to GitHub with completejob, and without them printed here there is no way to see from
    // a local replay whether a matcher matched anything.
    for (res.annotations) |a| {
        try err.print("annotation {s}", .{a.an.level});
        if (a.an.file) |f| try err.print(" {s}", .{f});
        if (a.an.line) |l| try err.print(":{s}", .{l});
        if (a.an.col) |c| try err.print(":{s}", .{c});
        if (a.an.title) |t| try err.print(" [{s}]", .{t});
        try err.print(" {s}\n", .{a.an.message});
    }
    if (res.engine_error) |m| try err.print("dagger error:\n{s}\n", .{m});
    try err.print("job {s}\n", .{if (res.succeeded) "succeeded" else "failed"});
    return @backingInt(if (res.succeeded) Exit.done else Exit.github);
}

/// `--db-check`: connect with the configured settings and report what is there. Prints no
/// credentials and no host name (CI logs of public repositories are public).
fn dbCheck(
    init: std.process.Init,
    pg_cfg: ?pg.Config,
    secrets: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    defer out.flush() catch {};

    const cfg = pg_cfg orelse {
        try err.writeAll("no database configured: set DATABASE_URL or PGHOST/PGUSER/PGDATABASE " ++
            "(and PGPASSWORD, PGSSLMODE)\n");
        return @backingInt(Exit.config);
    };
    const c = pg.Client.connect(init.gpa, io, cfg) catch |e| {
        try err.writeAll("database unavailable: ");
        try redact.write(err, @errorName(e), secrets);
        try err.writeByte('\n');
        return @backingInt(Exit.db);
    };
    defer c.close();

    try out.print(
        "connected (TLS {s}, sslmode={s})\n",
        .{ if (c.tls != null) "on" else "off", @tagName(cfg.sslmode) },
    );
    const version = (try c.query(arena, "select version()"))[0][0] orelse "?";
    const server = version[0 .. std.mem.indexOf(u8, version, " on ") orelse version.len];
    try out.print("server: {s}\n", .{server});
    const ts = try c.query(
        arena,
        "select extversion from pg_extension where extname = 'timescaledb'",
    );
    try out.print("timescaledb: {s}\n", .{if (ts.len > 0) ts[0][0].? else "not installed"});

    const tables = try c.query(
        arena,
        "select string_agg(tablename, ' ' order by tablename) from pg_tables " ++
            "where schemaname = current_schema() and " ++
            "tablename in ('runs','jobs','steps','job_logs')",
    );
    const listed: ?[]const u8 = if (tables.len > 0) tables[0][0] else null;
    try out.print(
        "tables in the default schema: {s}\n",
        .{listed orelse "none (apply db/migrations/001_init.sql)"},
    );
    if (ts.len > 0) {
        const ht = try c.query(
            arena,
            "select count(*) from timescaledb_information.hypertables " ++
                "where hypertable_schema = current_schema() and hypertable_name = 'job_logs'",
        );
        try out.print(
            "job_logs is a hypertable: {s}\n",
            .{if (std.mem.eql(u8, ht[0][0].?, "1")) "yes" else "no"},
        );
    }
    const leftovers = try c.query(
        arena,
        "select count(*) from information_schema.schemata where schema_name like 'zig\\_it\\_%'",
    );
    try out.print("leftover test schemas (zig_it_*): {s}\n", .{leftovers[0][0].?});
    return @backingInt(Exit.done);
}
