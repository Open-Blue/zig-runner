//! The job's side of its Docker API (#448, stage 1b): what `docker_api.zig`'s server asks of the
//! job, answered with the job's own native builder (`docker_action.buildApi`) and its tag index
//! (`docker_build.Index`).
//!
//! - **A build** unpacks the client's tar into `<job>/api-build-<n>` (`docker_build.unpack`, bounded
//!   and with no link leading out), plans and builds the Dockerfile with `--build-arg`s, `--target`,
//!   `--label`s and `--no-cache`, its `RUN`s in the job's cgroup, and streams Docker's own kind of
//!   lines (`Step 2/5 : RUN ...`, ` ---> Using cache`, the RUN's output, `Successfully built`,
//!   `Successfully tagged`, `{"aux":{"ID":...}}`, or an `errorDetail`). One build at a time: they
//!   share the job's build directories. Its image (layers in the shared store, keyed with the
//!   trust scope; the config) is added to the job's index, which nothing else sees.
//! - **Images**: `GET /images/{name}/json`, `POST /images/{name}/tag` and `DELETE /images/{name}`
//!   over that index.
//! - **A cancel** (the step ended, the client left, the job stops) kills the build's `RUN` and
//!   refuses the ones after it, until the gate opens again.
//!
//! Nothing here is stored for replay: a step that used the API is not published (`Backend.runStep`).
//! What the step cache would need to replay a build is the index's state in its key and its
//! delta in its record; that is left for a later stage.

const std = @import("std");
const Backend = @import("Backend.zig");
const docker_api = @import("docker_api.zig");
const docker_build = @import("docker_build.zig");
const docker_action = @import("docker_action.zig");
const dockerfile = @import("dockerfile.zig");
const images = @import("images.zig");
const sandbox = @import("sandbox.zig");
const Store = @import("Store.zig");
const job_mod = @import("../job.zig");

const Allocator = std.mem.Allocator;

pub const State = struct {
    b: *Backend,
    gpa: Allocator,
    index: docker_build.Index,
    /// One build at a time.
    build_mu: std.Io.Mutex = .init,
    /// Guards `active` and `cancelled_all`.
    mu: std.Io.Mutex = .init,
    active: ?*Active = null,
    /// The gate closed: no build runs until it opens (`resetFn`).
    cancelled_all: bool = false,

    /// The build in flight: what stops it.
    const Active = struct {
        st: *State,
        id: u32,
        running: sandbox.Running = .{},
        cancelled: bool = false,
    };

    pub fn create(b: *Backend) !*State {
        const st = try b.gpa.create(State);
        st.* = .{ .b = b, .gpa = b.gpa, .index = .init(b.gpa) };
        return st;
    }

    pub fn destroy(st: *State) void {
        st.index.deinit();
        st.gpa.destroy(st);
    }

    pub fn handler(st: *State) docker_api.Handler {
        return .{
            .ptr = st,
            .buildFn = buildFn,
            .imageFn = imageFn,
            .cancelFn = cancelFn,
            .resetFn = resetFn,
        };
    }

    fn cancelFn(ptr: *anyopaque, id: ?u32) void {
        const st: *State = @ptrCast(@alignCast(ptr));
        const io = st.b.io;
        st.mu.lockUncancelable(io);
        defer st.mu.unlock(io);
        if (id == null) st.cancelled_all = true;
        if (st.active) |a| if (id == null or id.? == a.id) {
            a.cancelled = true;
            _ = a.running.kill(io);
        };
    }

    fn resetFn(ptr: *anyopaque) void {
        const st: *State = @ptrCast(@alignCast(ptr));
        const io = st.b.io;
        st.mu.lockUncancelable(io);
        defer st.mu.unlock(io);
        st.cancelled_all = false;
    }

    /// The image the job built and tagged `ref` (`FROM x` of a later build), as a build's base: its
    /// config with its layers over the rootfs it was built on, and its ID; null when there is none.
    pub fn baseOf(st: *State, arena: Allocator, ref: []const u8) !?struct { config: images.Image, id: []const u8 } {
        const io = st.b.io;
        const norm = (try docker_build.parseRef(arena, ref)) orelse return null;
        st.index.lock(io);
        defer st.index.unlock(io);
        const rec = st.index.find(norm, "") orelse return null;
        if (rec.lowers.len == 0) return null;
        var config = rec.config;
        config.rootfs = rec.lowers[rec.lowers.len - 1];
        config.layers = rec.lowers[0 .. rec.lowers.len - 1];
        return .{ .config = config, .id = rec.id };
    }

    /// Makes `a` the build in flight, unless the gate is closed.
    fn begin(st: *State, a: *Active) bool {
        const io = st.b.io;
        st.mu.lockUncancelable(io);
        defer st.mu.unlock(io);
        if (st.cancelled_all) return false;
        st.active = a;
        return true;
    }

    fn end(st: *State) void {
        const io = st.b.io;
        st.mu.lockUncancelable(io);
        defer st.mu.unlock(io);
        st.active = null;
    }

    fn isCancelled(a: *Active) bool {
        const st = a.st;
        const io = st.b.io;
        st.mu.lockUncancelable(io);
        defer st.mu.unlock(io);
        return a.cancelled or st.cancelled_all;
    }
};

// --- builds ---

fn cancelledOf(ptr: *anyopaque) bool {
    const a: *State.Active = @ptrCast(@alignCast(ptr));
    return State.isCancelled(a);
}

/// What a build says as it goes, in Docker's classic builder's words.
const Telling = struct {
    st: *State,
    arena: Allocator,
    sink: *docker_api.Sink,
    quiet: bool,
    /// The Dockerfile's instructions by line, and `FROM`s by stage.
    ins: []const dockerfile.Instruction = &.{},
    froms: std.ArrayList(dockerfile.Instruction) = .empty,
    total: u32 = 0,
    n: u32 = 0,
    output: Output = undefined,

    const Output = struct {
        t: *Telling,
        fn out(o: *Output) sandbox.Output {
            return .{ .ptr = o, .chunkFn = chunk };
        }
        fn chunk(ptr: *anyopaque, bytes: []const u8) void {
            const o: *Output = @ptrCast(@alignCast(ptr));
            if (o.t.quiet) return;
            const line = docker_build.streamLine(o.t.arena, bytes) catch return;
            o.t.sink.write(line);
        }
    };

    fn say(t: *Telling, comptime fmt: []const u8, args: anytype) void {
        if (t.quiet) return;
        const text = std.fmt.allocPrint(t.arena, fmt, args) catch return;
        const line = docker_build.streamLine(t.arena, text) catch return;
        t.sink.write(line);
    }

    fn planned(ptr: *anyopaque, plan: dockerfile.Plan, ins: []const dockerfile.Instruction) void {
        const t: *Telling = @ptrCast(@alignCast(ptr));
        t.ins = ins;
        for (ins) |x| if (x.kind == .from) t.froms.append(t.arena, x) catch return;
        for (plan.stages) |st| {
            if (st.needed) t.total += 1 + @as(u32, @intCast(st.steps.len));
        }
    }

    fn header(t: *Telling, x: dockerfile.Instruction) void {
        t.n += 1;
        var word: [16]u8 = undefined;
        const kind = std.ascii.upperString(&word, @tagName(x.kind));
        t.say("Step {d}/{d} : {s} {s}\n", .{ t.n, t.total, kind, x.text });
    }

    fn stage(ptr: *anyopaque, i: u32) void {
        const t: *Telling = @ptrCast(@alignCast(ptr));
        if (i < t.froms.items.len) t.header(t.froms.items[i]);
    }

    fn step(ptr: *anyopaque, s: dockerfile.Step, how: dockerfile.Progress.How) void {
        const t: *Telling = @ptrCast(@alignCast(ptr));
        const short = s.key[0..12];
        if (how == .built) {
            t.say(" ---> {s}\n", .{short});
            return;
        }
        for (t.ins) |x| if (x.line == s.line and x.kind != .from) {
            t.header(x);
            break;
        };
        switch (how) {
            .cached => t.say(" ---> Using cache\n ---> {s}\n", .{short}),
            .config, .present => t.say(" ---> {s}\n", .{short}),
            .building => t.say(" ---> Running in {s}\n", .{short}),
            .built => unreachable,
        }
    }
};

fn buildFn(ptr: *anyopaque, call: *docker_api.BuildCall) void {
    const st: *State = @ptrCast(@alignCast(ptr));
    const io = st.b.io;
    st.build_mu.lockUncancelable(io);
    defer st.build_mu.unlock(io);
    const a = call.arena;
    run(st, call) catch |e| {
        std.log.warn("native: a build through the job's Docker API failed inside the runner: {t}", .{e});
        const text = std.fmt.allocPrint(a, "the build failed inside zig-runner: {t}", .{e}) catch "the build failed inside zig-runner";
        call.sink.write(docker_build.errorLine(a, text) catch return);
    };
}

fn fail(call: *docker_api.BuildCall, message: []const u8) void {
    call.sink.write(docker_build.errorLine(call.arena, message) catch return);
}

fn run(st: *State, call: *docker_api.BuildCall) !void {
    const b = st.b;
    const a = call.arena;
    const q = call.query;
    var active: State.Active = .{ .st = st, .id = call.id };
    if (!st.begin(&active)) return fail(call, "the build was cancelled: the step that asked for it has ended");
    defer st.end();

    // The tags first: a build is not made for a name it cannot give.
    var tags: std.ArrayList([]const u8) = .empty;
    for (q.tags) |t| {
        const ref = (try docker_build.parseRef(a, t)) orelse
            return fail(call, try std.fmt.allocPrint(a, "invalid reference format: {s}", .{try shown(a, t)}));
        try tags.append(a, ref);
    }

    const dir = try std.fmt.allocPrint(a, "{s}/api-build-{d}", .{ b.dir, call.id });
    try std.Io.Dir.cwd().createDirPath(b.io, dir);
    defer Store.removeTree(a, b.io, dir);
    var why: []const u8 = "";
    const unpacked = docker_build.unpack(a, b.io, dir, call.tar_path, call.limits, &why) catch |e| switch (e) {
        error.BadContext => return fail(call, why),
        else => return e,
    };

    var tell: Telling = .{ .st = st, .arena = a, .sink = call.sink, .quiet = q.quiet };
    tell.output = .{ .t = &tell };
    // The CLI says "Sending build context" itself.
    _ = unpacked;

    var args: std.ArrayList(dockerfile.Var) = .empty;
    for (q.build_args) |p| try args.append(a, .{ .name = p.name, .value = p.value });
    var labels: std.ArrayList(dockerfile.Var) = .empty;
    for (q.labels) |p| try labels.append(a, .{ .name = p.name, .value = p.value });
    var salt: []const u8 = "";
    if (q.nocache) {
        var raw: [16]u8 = undefined;
        b.io.random(&raw);
        salt = try std.fmt.allocPrint(a, "{s}", .{std.fmt.bytesToHex(raw, .lower)});
    }

    const built = try docker_action.buildApi(b, .{
        .dir = dir,
        .dockerfile = q.dockerfile,
        .options = .{ .build_args = args.items, .target = q.target, .salt = salt, .labels = labels.items },
        .api = .{
            .ptr = &active,
            .running = &active.running,
            .out = tell.output.out(),
            .cancelledFn = cancelledOf,
        },
        .observer = .{
            .ptr = &tell,
            .plannedFn = Telling.planned,
            .progress = .{ .ptr = &tell, .stageFn = Telling.stage, .stepFn = Telling.step },
        },
    });
    if (State.isCancelled(&active) or call.sink.gone()) return fail(call, "the build was cancelled");
    const image = switch (built) {
        .failed => |m| return fail(call, m),
        .image => |im| im,
    };

    const keys = try docker_build.layerKeys(a, image.lowers);
    const config = try docker_build.configJson(a, image.config, keys);
    const id = try docker_build.imageId(a, config, image.final_key);
    const created = try docker_build.rfc3339(a, std.Io.Clock.real.now(b.io).toSeconds());
    st.index.lock(b.io);
    defer st.index.unlock(b.io);
    const rec = st.index.add(.{
        .id = try st.index.arena.allocator().dupe(u8, id),
        // The index outlives this request: its own copies.
        .lowers = try dupeAll(st.index.arena.allocator(), image.lowers),
        .config = try dupeImage(st.index.arena.allocator(), image.config),
        .final_key = try st.index.arena.allocator().dupe(u8, image.final_key),
        .created = try st.index.arena.allocator().dupe(u8, created),
    }, tags.items) catch |e| return fail(call, switch (e) {
        error.TooManyImages => "too many images in this job's Docker API (100)",
        error.TooManyTags => "too many tags in this job's Docker API (256)",
        else => return e,
    });
    call.sink.write(try docker_build.auxLine(a, rec.id));
    if (q.quiet) {
        // As Docker's daemon does for `-q`: the ID is all the client prints.
        call.sink.write(try docker_build.streamLine(a, try std.fmt.allocPrint(a, "{s}\n", .{rec.id})));
        return;
    }
    tell.say("Successfully built {s}\n", .{rec.id["sha256:".len..][0..12]});
    for (tags.items) |t| tell.say("Successfully tagged {s}\n", .{t});
}

/// A client's text as one short printable line.
fn shown(a: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text[0..@min(text.len, 100)]) |c| try out.append(a, if (c < 0x20 or c == 0x7f) '?' else c);
    return out.items;
}

fn dupeAll(a: Allocator, list: []const []const u8) ![]const []const u8 {
    const out = try a.alloc([]const u8, list.len);
    for (list, out) |s, *o| o.* = try a.dupe(u8, s);
    return out;
}

fn dupeImage(a: Allocator, im: images.Image) !images.Image {
    var out = im;
    out.rootfs = try a.dupe(u8, im.rootfs);
    out.entrypoint = try dupeAll(a, im.entrypoint);
    out.cmd = try dupeAll(a, im.cmd);
    out.env = try dupeAll(a, im.env);
    out.workdir = try a.dupe(u8, im.workdir);
    out.user = try a.dupe(u8, im.user);
    const labels = try a.alloc(images.Label, im.labels.len);
    for (im.labels, labels) |l, *o| o.* = .{ .name = try a.dupe(u8, l.name), .value = try a.dupe(u8, l.value) };
    out.labels = labels;
    out.digest = null;
    out.manifest = null;
    out.layers = &.{};
    return out;
}

// --- images ---

fn imageFn(ptr: *anyopaque, a: Allocator, op: docker_api.ImageOp) docker_api.ImageAnswer {
    const st: *State = @ptrCast(@alignCast(ptr));
    return images_(st, a, op) catch .{ .status = 500, .body = "{\"message\":\"out of memory\"}\n" };
}

fn reply(a: Allocator, status: u16, comptime fmt: []const u8, args: anytype) !docker_api.ImageAnswer {
    const text = try std.fmt.allocPrint(a, fmt, args);
    return .{ .status = status, .body = try std.fmt.allocPrint(a, "{f}\n", .{std.json.fmt(.{ .message = text }, .{})}) };
}

fn images_(st: *State, a: Allocator, op: docker_api.ImageOp) !docker_api.ImageAnswer {
    const io = st.b.io;
    st.index.lock(io);
    defer st.index.unlock(io);
    switch (op) {
        .inspect => |name| {
            const ref = try docker_build.parseRef(a, name);
            const rec = st.index.find(ref, name) orelse return reply(a, 404, "No such image: {s}", .{try shown(a, name)});
            return .{ .status = 200, .body = try docker_build.inspectJson(a, rec.*) };
        },
        .tag => |t| {
            const rec = st.index.find(try docker_build.parseRef(a, t.name), t.name) orelse
                return reply(a, 404, "No such image: {s}", .{try shown(a, t.name)});
            if (t.repo.len == 0) return reply(a, 400, "invalid reference format: the repository is empty", .{});
            const text = if (t.tag.len > 0) try std.fmt.allocPrint(a, "{s}:{s}", .{ t.repo, t.tag }) else t.repo;
            const ref = (try docker_build.parseRef(a, text)) orelse
                return reply(a, 400, "invalid reference format: {s}", .{try shown(a, text)});
            st.index.addTag(rec, ref) catch |e| return switch (e) {
                error.TooManyTags => reply(a, 400, "too many tags in this job's Docker API (256)", .{}),
                else => e,
            };
            return .{ .status = 201, .body = "" };
        },
        .remove => |r| {
            const removed = try st.index.remove(a, try docker_build.parseRef(a, r.name), r.name, r.force);
            switch (removed) {
                .missing => return reply(a, 404, "No such image: {s}", .{try shown(a, r.name)}),
                .conflict => |id| return reply(a, 409, "conflict: unable to delete {s} (must be forced) - image is referenced in multiple repositories", .{id["sha256:".len..][0..12]}),
                .done => |d| {
                    var out: std.Io.Writer.Allocating = .init(a);
                    try out.writer.writeAll("[");
                    var first = true;
                    if (d.untagged) |u| {
                        try out.writer.print("{f}", .{std.json.fmt(.{ .Untagged = u }, .{})});
                        first = false;
                    }
                    if (d.deleted) |id| {
                        if (!first) try out.writer.writeAll(",");
                        try out.writer.print("{f}", .{std.json.fmt(.{ .Deleted = id }, .{})});
                    }
                    try out.writer.writeAll("]\n");
                    return .{ .status = 200, .body = out.written() };
                },
            }
        },
    }
}

// --- ahead of the job: what needs more than the API serves ---

/// The `docker` subcommands the job's API answers (`build`, `tag`, `rmi`, `inspect` of an image,
/// `version`, `info`): a script that uses only these can run natively with the API.
fn servedSubcommand(sub: []const u8, next: []const u8) bool {
    const plain = [_][]const u8{ "build", "tag", "rmi", "inspect", "version", "info", "help" };
    for (plain) |p| if (std.mem.eql(u8, sub, p)) return true;
    if (std.mem.eql(u8, sub, "image"))
        for ([_][]const u8{ "build", "inspect", "tag", "rm", "remove" }) |p| if (std.mem.eql(u8, next, p)) return true;
    if (std.mem.eql(u8, sub, "builder") and std.mem.eql(u8, next, "build")) return true;
    return false;
}

/// `docker` options that take a value (the next word), which a subcommand follows.
fn takesValue(opt: []const u8) bool {
    for ([_][]const u8{ "--context", "-c", "--host", "-H", "--config", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey" }) |o|
        if (std.mem.eql(u8, opt, o)) return true;
    return false;
}

/// Words that put the next word in command position.
fn introducesCommand(word: []const u8) bool {
    for ([_][]const u8{ "sudo", "then", "do", "else", "elif", "if", "while", "until", "time", "exec", "command", "nohup", "!" }) |w|
        if (std.mem.eql(u8, word, w)) return true;
    return false;
}

/// The first `docker` command in `script` that the job's API does not serve (`docker run`,
/// `docker compose`, `docker push`, `docker buildx`, `docker-compose` ...), as it is written, or
/// null. A heuristic that reads the script as text, not as a shell does: `docker` is a command when
/// it starts a line or follows `;`, `&`, `|`, `(`, `{`, a backtick, `$(`, `then`, `do`, `else`,
/// `sudo`, `exec` or a variable assignment; its options are skipped to its subcommand. It errs
/// toward the engine: a quoted command or an `echo docker push` is found, and a command that a
/// script, a Makefile or `xargs` runs for it is not.
pub fn needsDaemon(script: []const u8) ?[]const u8 {
    var i: usize = 0;
    var at_command = true;
    var words: [2][]const u8 = undefined;
    while (i < script.len) {
        const c = script[i];
        if (c == '\n' or c == ';' or c == '&' or c == '|' or c == '(' or c == '{' or c == '`') {
            at_command = true;
            i += 1;
            continue;
        }
        if (c == ' ' or c == '\t' or c == '\r' or c == ')' or c == '}' or c == '"' or c == '\'' or c == '\\') {
            i += 1;
            continue;
        }
        if (c == '$' and i + 1 < script.len and script[i + 1] == '(') {
            at_command = true;
            i += 2;
            continue;
        }
        const w = wordAt(script, i);
        if (w.len == 0) {
            i += 1;
            continue;
        }
        i += w.len;
        if (!at_command) continue;
        if (std.mem.indexOfScalar(u8, w, '=') != null and std.mem.indexOfScalar(u8, w, '/') == null) continue;
        if (introducesCommand(w)) continue;
        at_command = false;
        const base = if (std.mem.lastIndexOfScalar(u8, w, '/')) |s| w[s + 1 ..] else w;
        if (std.mem.eql(u8, base, "docker-compose") or std.mem.eql(u8, base, "docker-buildx")) return base;
        if (!std.mem.eql(u8, base, "docker")) continue;
        // The next words: options (and their values), then the subcommand and the word after it.
        var n: usize = 0;
        var j = i;
        var skip_value = false;
        while (j < script.len and n < 2) {
            const d = script[j];
            if (d == ' ' or d == '\t' or d == '"' or d == '\'') {
                j += 1;
                continue;
            }
            if (d == '\\' and j + 1 < script.len and script[j + 1] == '\n') {
                j += 2;
                continue;
            }
            if (d == '\n' or d == ';' or d == '&' or d == '|' or d == ')' or d == '`' or d == '<' or d == '>') break;
            if (d == '\\') {
                j += 1;
                continue;
            }
            const x = wordAt(script, j);
            if (x.len == 0) {
                j += 1;
                continue;
            }
            j += x.len;
            if (skip_value) {
                skip_value = false;
                continue;
            }
            if (n == 0 and x[0] == '-') {
                // `--version` and `-v` are answered as `docker version` is.
                if (std.mem.eql(u8, x, "--version") or std.mem.eql(u8, x, "-v") or std.mem.eql(u8, x, "--help")) return null;
                if (takesValue(x)) skip_value = true;
                continue;
            }
            words[n] = x;
            n += 1;
        }
        if (n == 0) continue;
        if (!servedSubcommand(words[0], if (n > 1) words[1] else "")) return words[0];
    }
    return null;
}

fn wordAt(s: []const u8, from: usize) []const u8 {
    var e = from;
    while (e < s.len) : (e += 1) switch (s[e]) {
        ' ', '\t', '\r', '\n', ';', '&', '|', '(', ')', '{', '}', '`', '"', '\'', '<', '>', '\\' => break,
        else => {},
    };
    return s[from..e];
}

/// Whether `uses: owner/name` is an action that talks to a Docker daemon beyond what the job's API
/// serves: all of the `docker/` organisation's (setup-buildx, build-push, login, bake, compose ...)
/// but the one that only computes tags.
pub fn actionNeedsDaemon(owner: []const u8, name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(owner, "docker") and !std.ascii.eqlIgnoreCase(name, "metadata-action");
}

/// Whether a step of the job needs a Docker daemon the API is not (`needsDaemon`,
/// `actionNeedsDaemon`). For `Backend.unsupported`, with the API on and an engine to fall back to.
pub fn jobNeedsDaemon(steps: []const job_mod.Step) bool {
    for (steps) |step| switch (step.action) {
        .script => |s| {
            const text = switch (s.script) {
                .lit => |t| t,
                .expr => |t| t,
            };
            if (needsDaemon(text) != null) return true;
        },
        .uses => |u| if (!u.local and actionNeedsDaemon(u.owner, u.name)) return true,
        .checkout, .docker, .unsupported => {},
    };
    return false;
}

test "docker api job: scripts that build, tag, inspect and remove images are served; the rest is not" {
    const served = [_][]const u8{
        "docker build -t x .",
        "set -e\ndocker build --build-arg A=1 -f sub/Dockerfile -t x:1 -t x:2 .\ndocker image inspect x:1",
        "docker --context default build .",
        "docker -H unix:///var/run/docker.sock tag x y && docker rmi y",
        "docker image build .",
        "docker builder build .",
        "docker version; docker info",
        "docker --version",
        "if docker inspect x >/dev/null 2>&1; then echo yes; fi",
        "DOCKER_BUILDKIT=0 docker build .",
        "cd docker && make",
        "ls docker/ build/docker",
        "echo $(docker build -q .)",
        "x=$(docker image inspect --format '{{.Id}}' x)",
        "sudo docker build .",
        "/usr/bin/docker build .",
        "make docker",
        "echo docker-ish",
        "docker",
        "",
    };
    for (served) |s| if (needsDaemon(s)) |why| {
        std.debug.print("ERROR served script found to need {s}: {s}\n", .{ why, s });
        return error.TestUnexpectedResult;
    };
    const Case = struct { script: []const u8, sub: []const u8 };
    const not_served = [_]Case{
        .{ .script = "docker run --rm alpine true", .sub = "run" },
        .{ .script = "docker build .\ndocker push x", .sub = "push" },
        .{ .script = "docker compose up -d", .sub = "compose" },
        .{ .script = "docker-compose up", .sub = "docker-compose" },
        .{ .script = "docker buildx build .", .sub = "buildx" },
        .{ .script = "docker login -u x --password-stdin", .sub = "login" },
        .{ .script = "docker pull alpine && docker build .", .sub = "pull" },
        .{ .script = "docker images", .sub = "images" },
        .{ .script = "docker image ls", .sub = "image" },
        .{ .script = "docker save x | gzip > x.tgz", .sub = "save" },
        .{ .script = "echo hi && docker exec c true", .sub = "exec" },
        .{ .script = "if true; then docker ps; fi", .sub = "ps" },
        .{ .script = "DOCKER_BUILDKIT=1 docker -H x ps", .sub = "ps" },
        .{ .script = "docker \\\n  run x", .sub = "run" },
        .{ .script = "x=$(docker run --rm a)", .sub = "run" },
        .{ .script = "(docker network create n)", .sub = "network" },
        .{ .script = "sudo docker system prune -f", .sub = "system" },
    };
    for (not_served) |c| {
        const got = needsDaemon(c.script) orelse {
            std.debug.print("ERROR not found: {s}\n", .{c.script});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(c.sub, got);
    }
}

test "docker api job: the docker organisation's actions need a daemon, but not the one that only computes tags" {
    try std.testing.expect(actionNeedsDaemon("docker", "build-push-action"));
    try std.testing.expect(actionNeedsDaemon("docker", "setup-buildx-action"));
    try std.testing.expect(actionNeedsDaemon("Docker", "login-action"));
    try std.testing.expect(!actionNeedsDaemon("docker", "metadata-action"));
    try std.testing.expect(!actionNeedsDaemon("actions", "checkout"));
    try std.testing.expect(!actionNeedsDaemon("dockerfile", "x"));
}
