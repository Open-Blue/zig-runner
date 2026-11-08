//! One step in a sandbox of its own (docs/native-backend.md, P1): a fresh overlay on the job's
//! layers, user, mount, PID, UTS and IPC namespaces (and the job's network namespace on a root
//! runner), a minimal /dev, /proc with its sensitive files masked, pivot_root, Docker's default
//! capabilities, no_new_privs, a seccomp filter, and `sh -c <script>`.
//!
//! The runner is multi-threaded, and a thread may not unshare a user namespace, so each step runs
//! in a helper process: the runner's own binary started as `zig-runner native-step` (`command`).
//! `run` is the runner's side, `main` the helper's. The helper's stdin carries the step's `Spec`
//! as one line of JSON and then stays open as its lifeline: when it closes, because the runner
//! stops the step (`Running.kill`) or the runner itself is gone, the helper kills the step's PID 1,
//! and with it every process in the step's PID namespace. Before that the runner can warn the step
//! through it (`Running.warn`), a byte each, and the helper signals the step's processes
//! (`Warning`). The helper's stdout is the step's stdout and stderr, streamed into the job's log
//! as it is read; its stderr carries only its own failures, so anything there means the sandbox,
//! not the step, failed.
//!
//! What it replaces in Dagger: BuildKit's runc executor. runc did implicitly several things a
//! step relies on, each now explicit here: HOME from the image's /etc/passwd when the env has
//! none, the host's /etc/resolv.conf and /etc/hosts, a /dev of a few nodes, /proc for the step's
//! PID namespace with runc's masked and read-only paths, the working directory made when it is
//! missing, umask 022, Docker's default capability set and seccomp profile (its allow list,
//! `seccomp.zig`), and killing every process of the step when its first one ends.
//!
//! Every path inside the overlay is resolved inside it (`openIn`): the layers are the steps' to
//! write, and a symlink a step left must not send the helper to the host's files.

const std = @import("std");
const linux = std.os.linux;
const seccomp = @import("seccomp.zig");
const health = @import("health.zig");
const phases = @import("phases.zig");
const host_paths = @import("host_paths.zig");

const Allocator = std.mem.Allocator;

/// The helper's subcommand (`main.zig` dispatches it before anything else runs).
pub const command = "native-step";

/// The mount point, in the job's directory, of the tmpfs that holds a step's secret files
/// (`Spec.File.keep`): mounted in the step's own mount namespace, so it is nowhere on the host's
/// disk or in its mounts, and gone with the step.
pub const secrets_dir = "S";

/// What the helper is told to run. Paths of layers are relative to `root` (the job's directory),
/// which keeps overlay's mount options short however many layers there are.
pub const Spec = struct {
    /// The job's directory: holds the layers, the work directory and the mount points.
    root: []const u8,
    /// Lower layers, top first; the last is the image's rootfs (absolute).
    lowers: []const []const u8,
    /// This step's layer, the overlay work directory and where the overlay is mounted.
    upper: []const u8,
    work: []const u8,
    merged: []const u8,
    /// The step's working directory inside.
    workdir: []const u8,
    /// Who the step runs as inside.
    uid: u32 = 0,
    gid: u32 = 0,
    /// A non-root step's supplementary groups, as the job sees them.
    groups: []const u32 = &.{},
    argv: []const []const u8,
    /// What is executed: a path inside the root, or "" for `argv[0]` looked up in the env's PATH
    /// there, as Docker starts an image's entrypoint (a service's, `services.zig`).
    exec: []const u8 = "/bin/sh",
    /// `NAME=value`, the whole environment.
    env: []const []const u8,
    /// Files written into the overlay before the step and removed after it, as Dagger mounts a
    /// secret file for one exec (a script holding a secret, `Resolved.run.script_mounted`).
    files: []const File = &.{},
    /// Host paths mounted into the step (`Backend.Config.binds`, and the job's resolv.conf).
    binds: []const Bind = &.{},
    /// How the helper gets its user namespace (`Userns`).
    userns: Userns,
    /// `mapped`: the first host id of the job's range; ids 0 to `id_count` - 1 inside are
    /// `id_base` onwards outside.
    id_base: u32 = 0,
    id_count: u32 = 0,
    /// The job's network namespace (a bind-mounted namespace file), when it has one.
    netns: ?[]const u8 = null,
    /// A layer below every other, the image's included (and below a container's image), with
    /// empty files where the job's resolver and hosts file are bound (`/etc/resolv.conf`,
    /// `/etc/hosts`): an image without them (Alpine's, most of Docker Hub's but Debian's and
    /// Ubuntu's) still gets them, as Docker and BuildKit make them, and no step's layer ever
    /// holds the mount point. An image's own file is above it, and its directories' owners and
    /// modes win. Relative to `root`, as the job's layers are; seen as the image's own ids.
    mount_points: ?[]const u8 = null,
    /// The job's cgroup (`cgroup.zig`), which the helper joins before anything else, so every
    /// process of the step is born in it and held to its limits.
    cgroup: ?[]const u8 = null,
    /// How many of `lowers`, counted from the last (the rootfs), are the image's: owned on disk
    /// by ids 0 to 65535 and, on a root runner, seen through the job's ids (`idmapLowers`). The
    /// Zig cache seeds' layers sit just above the rootfs (`volumes.zig`).
    image_layers: u32 = 1,
    /// `mapped`: for each of the job's own layers (the first `lowers.len - image_layers`), whether
    /// its files have the canonical ids, 0 to 65535 on disk (a stored layer: `Store.unshift`), and
    /// are seen through the job's ids as the image's are; the others have the slot's host ids.
    /// Missing entries are false.
    canonical: []const bool = &.{},
    /// `mapped`: the first on-disk id of the cache volumes' range (`Bind.volume`), which the job
    /// sees as its 0 onwards.
    volume_id_base: u32 = 0,
    /// A service (`services.zig`): it runs until it is stopped, and the helper says when it is
    /// ready (`health.supervise`).
    service: ?health.Ready = null,
    /// A Docker action's container: the step runs in its image instead of the job's overlay,
    /// with directories of the job's overlay bound in (`Container`). `argv` is then the action's
    /// command, its first word found through the env's PATH as `docker run` finds it; otherwise
    /// `argv` runs under `/bin/sh`.
    container: ?Container = null,

    pub const Bind = struct {
        host: []const u8,
        at: []const u8,
        read_only: bool = true,
        /// Only over a file or directory the image has: making one would put it in the layer.
        optional: bool = false,
        /// A cache volume (`volumes.zig`): nosuid and nodev, and on a root runner its files'
        /// on-disk ids are the volumes' range (`Spec.volume_id_base`), seen as the job's own
        /// through an idmapped mount, so a volume filled in one slot is the next slot's too.
        volume: bool = false,
        /// A cache volume's root, `<store>/volumes`: `host` is below it. Reached as the operator
        /// set it up, links and all; from there on no link is followed (`openVolume`).
        volume_root: []const u8 = "",
        /// Its mount point is made when the overlay has none, owned by the job's root, as Dagger
        /// makes a cache mount's missing parents.
        make: bool = false,
        /// nosuid and nodev (a JavaScript runtime's files from the store, `Backend.applyMounts`):
        /// a setuid file or a device node there is never one for the step.
        nosuid: bool = false,
        /// A job container's host-path volume (`host_paths.zig`): `host` is canonical and was
        /// checked against the operator's list, and is opened with no symlink followed, so one
        /// swapped in since fails the step. Not recursive, nosuid and nodev, read-only when
        /// `read_only`, and on a root runner idmapped as a cache volume is where its filesystem
        /// can be (`bindHostIn`).
        host_path: bool = false,
        /// A host path whose filesystem the kernel cannot idmap is bound with the host's ids
        /// (`RUNNER_NATIVE_HOST_PATHS_UNMAPPED`); otherwise the step fails.
        unmapped_ok: bool = false,
    };

    /// The job's overlay (`lowers`, `upper`) is still mounted, and this step's layer is where
    /// what the action writes into the shared directories lands, as GitHub's `docker run` writes
    /// into the host's workspace through its bind. `files` go into the job's overlay too.
    pub const Container = struct {
        /// The image's layers, absolute, top first: its filesystem, or a built image's layers
        /// over its base's (`dockerfile.build`). Each is the image's own ids, idmapped on a root
        /// runner as the job's rootfs is.
        lowers: []const []const u8,
        /// The container's own layer (thrown away when the step ends, as `docker run --rm`
        /// does, or a build's new layer), its work directory and its mount point, relative to
        /// `root` or absolute.
        upper: []const u8,
        work: []const u8,
        merged: []const u8,
        /// Directories of the job's overlay bound into the container: made in the job's overlay
        /// when missing, resolved inside each overlay.
        shares: []const Share = &.{},

        pub const Share = struct { from: []const u8, at: []const u8 };
    };

    pub const File = struct {
        path: []const u8,
        contents: []const u8,
        mode: u32 = 0o444,
        /// Left in the layer, as `withNewFile` leaves a file (the event payload). Otherwise the
        /// file holds a secret (a script with one in it) and never reaches the store's disk: it
        /// is written to a tmpfs of the step's own (`secrets_dir`) and bound at `path` over an
        /// empty file, which goes once the step ends.
        keep: bool = false,
    };
};

/// How the helper gets a user namespace. `mapped`: the runner is root, and the job's range of
/// host ids (`Spec.id_base`) is mapped whole, so its root and every other user are nobody on the
/// host. `self`: rootless, it makes one itself, mapping the runner's user to root, and only root.
/// `inherited`: rootless, started inside one already (under `unshare -r -m`, where an LSM lets
/// only allow-listed programs make user namespaces, as Ubuntu's AppArmor does).
pub const Userns = enum { mapped, self, inherited };

/// What a step ended with: its exit code (128 + n for signal n, as a shell reports it), and the
/// helper's own failure, when the sandbox could not be made. `killed`: it was stopped
/// (`Running.warn`, `Running.kill`), so its end is not the step's own. Never code 0 then: a script
/// can go on past a program a warning killed and exit 0 with its work half done, and a caller that
/// keeps what an exec made on its code (a Dockerfile's `RUN`, a seed) must not keep that.
pub const Ended = struct {
    code: i32,
    failure: []const u8,
    killed: bool = false,
    /// The helper's phases (`phases.Helper`, a line on its stderr, not part of `failure`), and
    /// when it was started and waited for, on the same clock.
    helper: phases.Helper = .{},
    spawned: u64 = 0,
    ended: u64 = 0,
};

/// Starts the helper and streams the step's output to `out` (`Output.chunk`) as it arrives;
/// returns once the step and every process it started have ended. `Running` lets another task
/// stop it (`Running.kill`).
pub fn run(
    arena: Allocator,
    io: std.Io,
    argv_prefix: []const []const u8,
    spec: Spec,
    running: *Running,
    out: Output,
) !Ended {
    const argv = try std.mem.concat(arena, []const u8, &.{ argv_prefix, &.{command} });
    // Nothing of the runner's environment (its tokens among it): the step's is in the spec.
    var empty: std.process.Environ.Map = .init(arena);
    const spawned = phases.now();
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &empty,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    // The spec holds the step's secrets: through a pipe, never on disk or on a command line. One
    // line (JSON's strings escape their newlines); the pipe then stays open as the lifeline.
    var json: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(spec, .{}, &json.writer);
    try json.writer.writeByte('\n');
    {
        // A task's cancel waits for `finish`'s read: taken here, it would end nothing.
        const protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(protection);
        child.stdin.?.writeStreamingAll(io, json.written()) catch {};
    }
    running.begin(io, child.stdin.?);
    child.stdin = null;
    defer running.end(io);
    var ended = try finish(arena, io, &child, running, out);
    ended.spawned = spawned;
    return ended;
}

/// The helper's output to its end, then how it ended.
fn finish(
    arena: Allocator,
    io: std.Io,
    child: *std.process.Child,
    running: *Running,
    out: Output,
) !Ended {
    var buf: [64 * 1024]u8 = undefined;
    var canceled = false;
    while (true) {
        const n = child.stdout.?.readStreaming(io, &.{&buf}) catch |e| {
            if (e != error.Canceled) break;
            // The task's own cancel, not the job's (`dagger.Cancel`): it stops the step, whose
            // output and end are still to come. It is delivered once, so `run`'s caller sees it
            // only if it is delivered again, which waits until the helper is gone.
            canceled = true;
            _ = running.kill(io);
            continue;
        };
        if (n == 0) break;
        // The sink's writes may wait, and do not report a cancel: the next read gets it.
        const sink_protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(sink_protection);
        out.chunk(buf[0..n]);
    }
    const protection = io.swapCancelProtection(.blocked);
    defer {
        _ = io.swapCancelProtection(protection);
        if (canceled) io.recancel();
    }
    var failure: std.ArrayList(u8) = .empty;
    while (failure.items.len < max_failure_bytes) {
        const n = child.stderr.?.readStreaming(io, &.{&buf}) catch break;
        if (n == 0) break;
        try failure.appendSlice(arena, buf[0..n]);
    }
    const term = try child.wait(io);
    const waited = phases.now();
    const said = phases.Helper.take(failure.items);
    const code: i32 = switch (term) {
        .exited => |c| c,
        .signal => |s| 128 + @as(i32, @intCast(@backingInt(s))),
        else => 128,
    };
    const killed = running.wasKilled(io);
    return .{
        .code = if (killed and code == 0) stopped_code else code,
        .failure = std.mem.trimEnd(u8, said.rest, "\n"),
        .killed = killed,
        .helper = said.helper,
        .ended = waited,
    };
}

const max_failure_bytes = 16 * 1024;

/// The code of a step stopped that exited 0 (`Ended`): what the kill gives, 128 + SIGKILL.
const stopped_code = 137;

/// Where `run` hands the step's output, in pieces as read (not lines).
pub const Output = struct {
    ptr: *anyopaque,
    chunkFn: *const fn (ptr: *anyopaque, bytes: []const u8) void,

    fn chunk(o: Output, bytes: []const u8) void {
        o.chunkFn(o.ptr, bytes);
    }
};

/// The helper running now, if any, for `warn` and `kill` from another task (a timeout or a cancel,
/// through `dagger.Watch`): its lifeline, the write end of its stdin.
pub const Running = struct {
    mu: std.Io.Mutex = .init,
    lifeline: ?std.Io.File = null,
    killed: bool = false,
    /// `stop` was called: a helper not started yet is stopped as soon as it is (a service).
    stopped: bool = false,

    fn begin(r: *Running, io: std.Io, lifeline: std.Io.File) void {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        if (r.stopped) {
            lifeline.close(io);
            r.killed = true;
            return;
        }
        r.lifeline = lifeline;
        r.killed = false;
    }

    fn wasKilled(r: *Running, io: std.Io) bool {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        return r.killed;
    }

    fn end(r: *Running, io: std.Io) void {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        if (r.lifeline) |f| f.close(io);
        r.lifeline = null;
    }

    /// Sends `sig` to the step's processes, through its lifeline (`Warning`). The step goes on,
    /// but its end is taken for a stop, as after `kill`: what it does now is not its own. False
    /// when none was running.
    pub fn warn(r: *Running, io: std.Io, sig: linux.SIG) bool {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        const f = r.lifeline orelse return false;
        r.killed = true;
        // Fails when the helper has gone, and the step with it.
        const stage = [1]u8{@intCast(@backingInt(sig))};
        f.writeStreamingAll(io, &stage) catch return false;
        return true;
    }

    /// Stops the running step: its lifeline closes, and the helper kills the step's PID 1, and
    /// with it every process in its PID namespace. False when none was running.
    pub fn kill(r: *Running, io: std.Io) bool {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        const f = r.lifeline orelse return false;
        f.close(io);
        r.lifeline = null;
        r.killed = true;
        return true;
    }

    /// Stops a service for good: as `kill`, and a helper still starting is stopped once it has
    /// its lifeline (`begin`). Steps use `kill`, which leaves the next step alone.
    pub fn stop(r: *Running, io: std.Io) void {
        r.mu.lockUncancelable(io);
        defer r.mu.unlock(io);
        r.stopped = true;
        const f = r.lifeline orelse return;
        f.close(io);
        r.lifeline = null;
        r.killed = true;
    }
};

// --- paths inside the overlay ---

/// `struct mount_attr`, for `mount_setattr(2)`.
const MountAttr = extern struct {
    set: u64,
    clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};

/// `openat2(2)`'s `resolve`: every symlink and `..` is taken inside `dirfd`, as if it were `/`
/// (`IN_ROOT`), and `/proc`'s magic links are refused.
const resolve_in_root = 0x10;
const resolve_no_magiclinks = 0x02;
/// And no symlink at all: the runner reading a file a step left (`readIn`).
pub const resolve_no_symlinks = 0x04;
/// And no mount crossed: a path below another mount (a bind made before it) is refused, EXDEV.
const resolve_no_xdev = 0x01;

const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };

/// Tries of an `openat2` the kernel gave up on. A `..` on the way fails with EAGAIN when any rename
/// or mount on the machine races it, as it cannot tell the race from an escape, and it says to
/// try again: another job publishing a layer is enough.
const open_tries = 64;

/// Opens `path` under `root`, resolved inside it (see the file's comment). A file descriptor, or
/// the errno.
pub fn openIn(
    root: linux.fd_t,
    path: [*:0]const u8,
    flags: linux.O,
    mode: u32,
    resolve: u64,
) union(enum) { fd: linux.fd_t, err: linux.E } {
    var o = flags;
    o.CLOEXEC = true;
    var how: OpenHow = .{
        .flags = @as(u32, @bitCast(o)),
        .mode = mode,
        .resolve = resolve | resolve_in_root | resolve_no_magiclinks,
    };
    for (0..open_tries) |_| {
        const rc = linux.syscall4(
            .openat2,
            @as(usize, @bitCast(@as(isize, root))),
            @intFromPtr(path),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        );
        const e = linux.errno(rc);
        if (e == .AGAIN) continue;
        return if (e == .SUCCESS) .{ .fd = @intCast(rc) } else .{ .err = e };
    }
    return .{ .err = .AGAIN };
}

/// What `readIn` finds.
pub const LayerFile = union(enum) { text: []const u8, missing, whiteout };

/// The contents of `path` in a layer, read by the runner: resolved inside the layer and through no
/// symlink. `missing` when it is not a regular file there; `whiteout` when the layer deletes it (an
/// overlay whiteout, a character device), so lower layers must not be looked in.
pub fn readIn(
    arena: Allocator,
    layer: []const u8,
    path: []const u8,
    limit: usize,
) !LayerFile {
    return readResolved(arena, layer, path, limit, resolve_no_symlinks);
}

/// `readIn` for a tree no job wrote, an image's own, whose links are the image's: they are
/// followed, staying inside it.
pub fn readFollowingIn(
    arena: Allocator,
    layer: []const u8,
    path: []const u8,
    limit: usize,
) !LayerFile {
    return readResolved(arena, layer, path, limit, 0);
}

fn readResolved(
    arena: Allocator,
    layer: []const u8,
    path: []const u8,
    limit: usize,
    resolve: u64,
) !LayerFile {
    const dir = linux.open(try arena.dupeSentinel(u8, layer, 0), .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(dir) != .SUCCESS) return .missing;
    defer _ = linux.close(@intCast(dir));
    const rel = try arena.dupeSentinel(u8, std.mem.trimStart(u8, path, "/"), 0);
    const fd = switch (openIn(@intCast(dir), rel, .{
        .ACCMODE = .RDONLY,
        .NONBLOCK = true,
        .NOCTTY = true,
    }, 0, resolve)) {
        .fd => |f| f,
        .err => return .missing,
    };
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
        return .missing;
    const kind = st.mode & linux.S.IFMT;
    if (kind == linux.S.IFCHR) return .whiteout;
    if (kind != linux.S.IFREG) return .missing;
    var out: std.ArrayList(u8) = .empty;
    var buf: [64 * 1024]u8 = undefined;
    while (out.items.len <= limit) {
        const n = linux.read(fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return .missing;
        if (n == 0) break;
        try out.appendSlice(arena, buf[0..n]);
    }
    if (out.items.len > limit) return .missing;
    return .{ .text = out.items };
}

/// Removes `path` from a layer, resolved inside it: the runner taking out a file the helper
/// should have (a script holding a secret, when the helper was stopped before it could).
pub fn unlinkIn(arena: Allocator, layer: []const u8, path: []const u8) void {
    const dir = linux.open(arena.dupeSentinel(u8, layer, 0) catch return, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(dir) != .SUCCESS) return;
    defer _ = linux.close(@intCast(dir));
    unlinkAt(arena, @intCast(dir), path);
}

fn unlinkAt(arena: Allocator, root: linux.fd_t, path: []const u8) void {
    const rel = std.mem.trimStart(u8, path, "/");
    const slash = std.mem.lastIndexOfScalar(u8, rel, '/');
    const parent = dirIn(arena, root, if (slash) |s| rel[0..s] else "") orelse return;
    defer _ = linux.close(parent);
    const base = if (slash) |s| rel[s + 1 ..] else rel;
    _ = linux.unlinkat(parent, arena.dupeSentinel(u8, base, 0) catch return, 0);
}

/// A directory under `root`, resolved inside it, for the `*at` calls; null when it is not there.
fn dirIn(arena: Allocator, root: linux.fd_t, path: []const u8) ?linux.fd_t {
    return dirResolved(arena, root, path, 0);
}

fn dirResolved(arena: Allocator, root: linux.fd_t, path: []const u8, resolve: u64) ?linux.fd_t {
    const rel = std.mem.trim(u8, path, "/");
    const p = arena.dupeSentinel(u8, if (rel.len == 0) "." else rel, 0) catch return null;
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .PATH = true };
    return switch (openIn(root, p, flags, 0, resolve)) {
        .fd => |f| f,
        .err => null,
    };
}

// --- the helper ---

/// The helper's entry: reads the spec from stdin, runs the step, and exits with its code. Uses
/// only raw system calls once it has the spec, so nothing starts a thread before `unshare`.
pub fn main(arena: Allocator) u8 {
    var early: std.ArrayList(u8) = .empty;
    const spec = readJsonLine(Spec, arena, &early) catch |e|
        fatal("cannot read the step's spec", @intFromError(e));
    var marks: phases.Helper = .{ .start = phases.now() };
    const code = runStep(arena, spec, &marks, early.items);
    // Its phases, for the runner (`phases.Helper.take`): once the step has ended, so never
    // mixed with a failure, which ends the helper before this (`fatal`).
    marks.end = phases.now();
    var buf: [256]u8 = undefined;
    const line = marks.line(&buf);
    _ = linux.write(2, line.ptr, line.len);
    return code;
}

/// A helper's spec: one line of JSON on stdin (`main`; `forward.zig`'s too). Read as it comes,
/// not a byte at a time (a step's spec, its env and files, is tens of KB: as many reads, the
/// larger part of a helper's start). What came after the line on the same read goes to `rest`:
/// the runner may warn a step that is still starting (`Running.warn`).
pub fn readJsonLine(comptime T: type, arena: Allocator, rest: *std.ArrayList(u8)) !T {
    var data: std.ArrayList(u8) = .empty;
    var buf: [64 * 1024]u8 = undefined;
    const line = while (true) {
        const rc = linux.read(0, &buf, buf.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0) break data.items;
        const got = buf[0..rc];
        if (std.mem.indexOfScalar(u8, got, '\n')) |end| {
            try data.appendSlice(arena, got[0..end]);
            try rest.appendSlice(arena, got[end + 1 ..]);
            break data.items;
        }
        try data.appendSlice(arena, got);
    };
    return std.json.parseFromSliceLeaky(T, arena, line, .{ .allocate = .alloc_always });
}

fn runStep(arena: Allocator, spec: Spec, marks: *phases.Helper, early: []const u8) u8 {
    // First, so every process the step makes, and this helper, is held to the job's limits.
    if (spec.cgroup) |dir| joinCgroup(arena, dir);
    // Before anything is forked, so the step's processes and its children inherit it.
    setOomScoreAdj(spec.env);
    // Files a step creates get the modes they get under runc.
    _ = linux.syscall1(.umask, 0o022);
    check("chdir to the job directory", linux.chdir(z(arena, spec.root)));
    // A service's state goes to a file of the job's (`health.Ready.status`), opened while the
    // helper is still the host's user that may.
    const status: linux.fd_t = if (spec.service) |s| health.openStatus(arena, s.status) else -1;

    // 1. The user namespace, and the overlay mounted in a mount namespace the helper owns. The
    // mount points' layer, when there is one, lowest of all, as the image's own.
    const mp: []const []const u8 = if (spec.mount_points) |m| &.{m} else &.{};
    var lowers: []const []const u8 =
        std.mem.concat(arena, []const u8, &.{ spec.lowers, mp }) catch oom();
    const image_layers = spec.image_layers + @intFromBool(spec.mount_points != null);
    const c_lowers: []const []const u8 = if (spec.container) |c|
        std.mem.concat(arena, []const u8, &.{ c.lowers, mp }) catch oom()
    else
        &.{};
    switch (spec.userns) {
        .mapped => {
            // As the host's root: into the job's network, then a namespace of the job's ids, the
            // rootfs seen through it (an idmapped mount, so its root's files are the job's
            // root's), the overlay mounted, and only then into the namespace.
            if (spec.netns) |p| joinNetns(arena, p);
            const userns = mappedUserns(0, spec.id_base, spec.id_count);
            // The cache volumes' on-disk ids, seen as the job's.
            var volumes = false;
            for (spec.binds) |bd| volumes = volumes or bd.volume or bd.host_path;
            const volume_ns: ?linux.fd_t = if (volumes)
                mappedUserns(spec.volume_id_base, spec.id_base, spec.id_count)
            else
                null;
            check("unshare(mount)", linux.unshare(linux.CLONE.NEWNS));
            makePrivate();
            marks.namespaces = phases.now();
            lowers = idmapLowers(arena, lowers, image_layers, spec.canonical, userns);
            marks.idmap = phases.now();
            mountOverlay(arena, spec, lowers, false);
            if (spec.container) |c| {
                const mapped = arena.alloc([]const u8, c_lowers.len) catch oom();
                for (c_lowers, mapped, 0..) |l, *m, i| {
                    const at = std.fmt.allocPrintSentinel(arena, "I{d}", .{i}, 0) catch oom();
                    m.* = idmapped(arena, l, userns, at);
                }
                mountContainer(arena, c, mapped, false);
            }
            marks.overlay = phases.now();
            // The binds, as the host's root: in the job's namespace the helper is nobody on the
            // host and may not search the directories on the way to a host path. They go on
            // with the overlay into the step's namespace (its bind onto itself is recursive).
            bindAll(arena, spec, volume_ns);
            if (volume_ns) |fd| _ = linux.close(fd);
            check("enter the job's user namespace", linux.setns(userns, linux.CLONE.NEWUSER));
            _ = linux.close(userns);
            // Joining a user namespace changes no ids: the helper is still the host's root,
            // which the job's namespace does not map, so what it made would belong to no one
            // there (EOVERFLOW). It becomes the namespace's root, as runc does after joining.
            check("setgroups", linux.setgroups(0, no_groups));
            check("setgid", linux.setgid(0));
            check("setuid", linux.setuid(0));
            marks.binds = phases.now();
        },
        .self, .inherited => {
            if (spec.userns == .self) enterUserns();
            makePrivate();
            marks.namespaces = phases.now();
            marks.idmap = marks.namespaces;
            mountOverlay(arena, spec, lowers, true);
            if (spec.container) |c| mountContainer(arena, c, c_lowers, true);
            marks.overlay = phases.now();
        },
    }

    // 2. The step's own namespaces, owned by the user namespace; its first process is PID 1.
    check("unshare(mount, pid, uts, ipc)", linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWPID |
        linux.CLONE.NEWUTS | linux.CLONE.NEWIPC));
    makePrivate();
    const merged = z(arena, topOf(spec));
    // The overlay bound onto itself, a mount of this namespace's own: on a root runner it was
    // mounted in the host's root's namespace, so here it is locked, and `pivot_root` refuses a
    // locked mount as the new root (runc binds its rootfs so for the same reason).
    check("bind the overlay onto itself", linux.mount(
        merged,
        merged,
        null,
        linux.MS.BIND | linux.MS.REC,
        0,
    ));
    const dir_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const root_rc = linux.open(merged, dir_flags, 0);
    check("open the overlay", root_rc);
    const root: linux.fd_t = @intCast(root_rc);
    // As the namespace's root, so what is made here is the job's root's.
    if (spec.userns != .mapped) {
        bindAll(arena, spec, null);
        marks.binds = phases.now();
    }
    var secrets = false;
    for (spec.files) |f| secrets = secrets or !f.keep;
    if (secrets) check("mount the tmpfs for secret files", linux.mount(
        "tmpfs",
        secrets_dir,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr("mode=0700,size=16m"),
    ));
    // A container's files go into the job's overlay, under the directories it shares.
    const files_root = if (spec.container) |c| shareJobDirs(arena, spec, c, root) else root;
    for (spec.files, 0..) |f, i| {
        if (f.keep) writeFileIn(arena, files_root, f) else bindSecretIn(arena, files_root, f, i);
    }
    if (files_root != root) _ = linux.close(files_root);

    // 3. PID 1, told by `alive` whether the helper is still there once it has re-armed its
    // parent-death signal; then until the step ends or the lifeline closes.
    const argv = zList(arena, spec.argv);
    const env = withHome(arena, root, spec);
    const envp = zList(arena, env);
    const workdir = z(arena, spec.workdir);
    var alive: [2]linux.fd_t = undefined;
    check("make a pipe", linux.pipe2(&alive, .{ .CLOEXEC = true }));
    marks.root = phases.now();
    const pid = linux.fork();
    check("fork", pid);
    if (pid == 0) {
        _ = linux.close(alive[1]);
        // no_new_privs for every step but the runner user's on a root runner: its sudo can
        // reach only the job's own root, bounded still by the capabilities and seccomp below.
        const nnp = spec.userns != .mapped or spec.uid == 0;
        const program: Program = if (spec.exec.len > 0)
            .{ .path = spec.exec }
        else
            .{ .search = .{ .name = spec.argv[0], .env = env } };
        const in_image = spec.container != null;
        stepInit(arena, root, workdir, spec.uid, spec.gid, spec.groups, nnp, alive[0], in_image, program, argv, envp);
    }
    _ = linux.close(alive[0]);
    const st = if (spec.service) |s|
        health.supervise(arena, spec, s, @intCast(pid), root, status, env)
    else
        superviseStep(@intCast(pid), spec.container != null, early);
    for (spec.files) |f| if (!f.keep) {
        // Its bind first: a mount point cannot be removed in the namespace it is mounted in.
        if (targetIn(arena, root, f.path, false)) |fd| {
            _ = linux.umount2(procFd(arena, fd), linux.MNT.DETACH);
            _ = linux.close(fd);
        }
        unlinkAt(arena, root, f.path);
    };
    if (linux.W.IFEXITED(st)) return linux.W.EXITSTATUS(st);
    if (linux.W.IFSIGNALED(st)) return @truncate(128 + @backingInt(linux.W.TERMSIG(st)));
    return 128;
}

/// Where the step's `/` is mounted: the container's overlay for a Docker action, else the job's.
fn topOf(spec: Spec) []const u8 {
    return if (spec.container) |c| c.merged else spec.merged;
}

/// `spec.binds`, at their places in the step's root, read-only where asked. On a root runner a
/// cache volume is seen through `volume_ns` (`Bind.volume`), and a mount point made here is the
/// job's root's. Every mount point is made before the first bind, and through no mount: on a root
/// runner the helper is still the host's root here, and a mount point made through a bind (a
/// target below another volume, or reached through an image's symlink into one) would be a
/// directory it made, and gave the job, on the host. A cache volume's or a host path's target is
/// then found through no mount either: one that lies inside another bind (`/x/y` with `/x` a
/// host path, or `/y/z` with the image's `/y` a link to `/x`) fails the step.
fn bindAll(arena: Allocator, spec: Spec, volume_ns: ?linux.fd_t) void {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const rc = linux.open(z(arena, topOf(spec)), flags, 0);
    check("open the overlay", rc);
    const root: linux.fd_t = @intCast(rc);
    defer _ = linux.close(root);
    const owner: ?u32 = if (spec.userns == .mapped) spec.id_base else null;
    // A Docker action's image gets a bind only where it has the path: the job's binds are made
    // for the job's image, and nothing is made in the image for them.
    if (spec.container == null) for (spec.binds) |bd| {
        if (bd.make) makeDirsIn(arena, root, bd.at, owner);
    };
    for (spec.binds) |bd| {
        // Nor the job's cache volumes (P4): Dagger gives a Docker action's container none either.
        if (spec.container != null and (bd.volume or bd.host_path)) continue;
        if (bd.volume) {
            bindVolumeIn(arena, root, bd.volume_root, bd.host, bd.at, volume_ns);
            continue;
        }
        if (bd.host_path) {
            bindHostIn(arena, root, bd, volume_ns);
            continue;
        }
        const required = !bd.optional and spec.container == null;
        if (!bindIn(arena, root, bd.host, bd.at, required)) continue;
        var add: u32 = 0;
        if (bd.read_only) add |= linux.MS.RDONLY;
        if (bd.nosuid) add |= linux.MS.NOSUID | linux.MS.NODEV;
        if (add != 0) remountWith(arena, root, bd.at, add);
    }
}

/// The directory `host` itself, held. A volume inside another (`<key>/runner`) is a name a job in
/// the outer one can replace; that is the one place a job reaches today (`volumes.open`), and a
/// link there must fail the step. No link is followed below `volume_root` at all, so that holds
/// if a key ever nests deeper. `volume_root` and above are the operator's.
fn openVolume(arena: Allocator, volume_root: []const u8, host: []const u8) union(enum) {
    fd: linux.fd_t,
    err: linux.E,
} {
    std.debug.assert(volume_root.len > 0 and host.len > volume_root.len + 1);
    std.debug.assert(std.mem.startsWith(u8, host, volume_root) and host[volume_root.len] == '/');
    const rc = linux.open(z(arena, volume_root), .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return .{ .err = linux.errno(rc) };
    const root = std.math.cast(linux.fd_t, rc) orelse return .{ .err = .BADF };
    defer _ = linux.close(root);
    return switch (openIn(root, z(arena, host[volume_root.len + 1 ..]), .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true }, 0, resolve_no_symlinks)) {
        .fd => |fd| .{ .fd = fd },
        .err => |e| .{ .err = e },
    };
}

/// A cache volume at `at`, writable, nosuid and nodev, and idmapped through `userns` when given:
/// a detached clone of the host's directory, its attributes set in one `mount_setattr`, then
/// moved into place. Fails the step when it cannot.
fn bindVolumeIn(
    arena: Allocator,
    root: linux.fd_t,
    volume_root: []const u8,
    host: []const u8,
    at: []const u8,
    userns: ?linux.fd_t,
) void {
    const volume = switch (openVolume(arena, volume_root, host)) {
        .fd => |fd| fd,
        .err => |e| fatal(about(arena, "open the cache volume for", at), @backingInt(e)),
    };
    defer _ = linux.close(volume);
    const open_tree_clone = 1;
    const tree = linux.syscall3(
        .open_tree,
        std.math.cast(usize, volume) orelse unreachable,
        @intFromPtr(""),
        open_tree_clone | linux.AT.EMPTY_PATH | linux.SOCK.CLOEXEC,
    );
    check(about(arena, "clone the cache volume for", at), tree);
    defer _ = linux.close(@intCast(tree));
    const nosuid = 0x2;
    const nodev = 0x4;
    const idmap = 0x00100000;
    var attr: MountAttr = .{ .set = nosuid | nodev };
    if (userns) |ns| {
        attr.set |= idmap;
        attr.userns_fd = @intCast(ns);
    }
    check(about(arena, "set up the cache volume for", at), linux.syscall5(
        .mount_setattr,
        tree,
        @intFromPtr(""),
        linux.AT.EMPTY_PATH,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    ));
    const target = ownTarget(arena, root, at);
    defer _ = linux.close(target);
    const move_mount_f_empty_path = 0x4;
    const move_mount_t_empty_path = 0x40;
    check(about(arena, "mount the cache volume at", at), linux.syscall5(
        .move_mount,
        @as(usize, @intCast(tree)),
        @intFromPtr(""),
        @as(usize, @intCast(target)),
        @intFromPtr(""),
        move_mount_f_empty_path | move_mount_t_empty_path,
    ));
}

/// A host directory at `bd.at` (`Bind.host_path`): `bd.host`, canonical and allowed by the
/// operator (`host_paths.zig`), opened from `/` with no symlink followed at all (`openHostPath`),
/// so a link put in its path since the runner checked it fails the step instead of reaching
/// outside the allowed directory, and on a mount that is `nosuid` and `nodev` on the host (else a
/// setuid file the job left there would be one for the host's users). Cloned alone (no mount below
/// it comes along), nosuid and nodev, read-only when `read_only`, set in one `mount_setattr` and
/// moved into place in the step's mount namespace only, at a target found through no other mount
/// (`ownTarget`). On a root runner it is idmapped through `userns` as a cache volume is: files
/// owned on disk by the volumes' range are the job's own ids, any other id (the host's users, root
/// included) is nobody to the job, so a job can never make a file a host user owns. A filesystem
/// that cannot be idmapped (the kernel refuses with EINVAL, as for NFS) fails the step, unless the
/// operator allowed it (`unmapped_ok`): then it is mounted with the host's ids as they are, what
/// the job writes is owned by its slot's ids, and host ids are nobody all the same.
fn bindHostIn(arena: Allocator, root: linux.fd_t, bd: Spec.Bind, userns: ?linux.fd_t) void {
    const at = bd.at;
    const dir = switch (openHostPath(arena, bd.host)) {
        .fd => |fd| fd,
        .err => |e| fatal(about(arena, "open the host path (no symlink followed) for", at), @backingInt(e)),
    };
    defer _ = linux.close(dir);
    if (!host_paths.safeMountFd(dir)) refused(arena, "the host path for {s} is on a mount without " ++
        "nosuid and nodev on the host; the operator must mount it so ({s})", .{ at, host_paths.setting });
    const open_tree_clone = 1;
    const tree = linux.syscall3(
        .open_tree,
        std.math.cast(usize, dir) orelse unreachable,
        @intFromPtr(""),
        open_tree_clone | linux.AT.EMPTY_PATH | linux.SOCK.CLOEXEC,
    );
    check(about(arena, "clone the host path for", at), tree);
    const tree_fd = std.math.cast(linux.fd_t, tree) orelse fatal(about(arena, "clone the host path for", at), @as(u32, 9));
    defer _ = linux.close(tree_fd);
    const rdonly = 0x1;
    const nosuid = 0x2;
    const nodev = 0x4;
    const idmap = 0x00100000;
    var attr: MountAttr = .{ .set = nosuid | nodev };
    if (bd.read_only) attr.set |= rdonly;
    var set_rc: usize = 0;
    if (userns) |ns| {
        var mapped = attr;
        mapped.set |= idmap;
        mapped.userns_fd = std.math.cast(u64, ns) orelse 0;
        set_rc = linux.syscall5(.mount_setattr, tree, @intFromPtr(""), linux.AT.EMPTY_PATH, @intFromPtr(&mapped), @sizeOf(MountAttr));
        if (linux.errno(set_rc) == .INVAL and !bd.unmapped_ok) refused(arena, "the host path for " ++
            "{s} is on a filesystem the kernel cannot idmap, so the job's ids would be its " ++
            "slot's on the host; {s}=true allows that", .{ at, host_paths.unmapped_setting });
    }
    if (userns == null or linux.errno(set_rc) == .INVAL)
        set_rc = linux.syscall5(.mount_setattr, tree, @intFromPtr(""), linux.AT.EMPTY_PATH, @intFromPtr(&attr), @sizeOf(MountAttr));
    check(about(arena, "set up the host path for", at), set_rc);
    const target = ownTarget(arena, root, at);
    defer _ = linux.close(target);
    const move_mount_f_empty_path = 0x4;
    const move_mount_t_empty_path = 0x40;
    check(about(arena, "mount the host path at", at), linux.syscall5(
        .move_mount,
        tree,
        @intFromPtr(""),
        std.math.cast(usize, target) orelse unreachable,
        @intFromPtr(""),
        move_mount_f_empty_path | move_mount_t_empty_path,
    ));
}

/// The host directory `host` (canonical), opened from `/` with no symlink followed: a link put
/// anywhere in its path since it was checked fails the open (ELOOP).
pub fn openHostPath(arena: Allocator, host: []const u8) union(enum) { fd: linux.fd_t, err: linux.E } {
    std.debug.assert(host.len > 1 and host[0] == '/');
    const slash_rc = linux.open("/", .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(slash_rc) != .SUCCESS) return .{ .err = linux.errno(slash_rc) };
    const slash = std.math.cast(linux.fd_t, slash_rc) orelse return .{ .err = .BADF };
    defer _ = linux.close(slash);
    return switch (openIn(slash, z(arena, host[1..]), .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true }, 0, resolve_no_symlinks)) {
        .fd => |fd| .{ .fd = fd },
        .err => |e| .{ .err = e },
    };
}

/// The mount point `at` of a cache volume or a host path, found through no other mount: one that
/// lies inside another bind, as written or through a symlink of the image's, fails the step
/// (a volume inside another is refused when the job starts, `container_options.volumes`; this
/// catches what a link makes of a path).
fn ownTarget(arena: Allocator, root: linux.fd_t, at: []const u8) linux.fd_t {
    const rel = z(arena, std.mem.trimStart(u8, at, "/"));
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true };
    return switch (openIn(root, rel, flags, 0, resolve_no_xdev)) {
        .fd => |f| f,
        .err => |e| if (e == .XDEV) refused(arena, "the volume at {s} lies inside another " ++
            "mount of the job (a volume, a host path or the runner's, perhaps through a symlink " ++
            "of the image's); a volume may not be inside another", .{at}) else fatal(about(arena, "find", at), @backingInt(e)),
    };
}

/// Ends the helper with `fmt`, a refusal the step's log shows as it is (not an errno).
fn refused(arena: Allocator, comptime fmt: []const u8, args: anytype) noreturn {
    const msg = std.fmt.allocPrint(arena, "native step: " ++ fmt ++ "\n", args) catch "native step: refused\n";
    _ = linux.write(2, msg.ptr, msg.len);
    linux.exit_group(125);
}

/// The directory `path` in the overlay, its missing parts made (mode 0755) inside it, each one
/// made owned by host id `owner` when given (the job's root on a root runner, which the helper,
/// still the host's root here, is not).
/// No mount is crossed on the way (`bindAll` makes them all before the first bind, so none is
/// there to cross), and none could take the helper to a host directory.
fn makeDirsIn(arena: Allocator, root: linux.fd_t, path: []const u8, owner: ?u32) void {
    const rel = std.mem.trim(u8, path, "/");
    var i: usize = 0;
    while (i <= rel.len) {
        const end = std.mem.indexOfScalarPos(u8, rel, i, '/') orelse rel.len;
        const parent = dirResolved(arena, root, rel[0..i], resolve_no_xdev) orelse return;
        defer _ = linux.close(parent);
        const name = z(arena, rel[i..end]);
        if (linux.errno(linux.mkdirat(parent, name, 0o755)) == .SUCCESS) if (owner) |o| {
            _ = linux.fchownat(parent, name, o, o, linux.AT.SYMLINK_NOFOLLOW);
        };
        i = end + 1;
    }
}

/// What GitHub's runner gives a job's processes (`ProcessInvoker.cs`, `WriteProcessOomScoreAdj`),
/// and the env name that sets another (-1000 to 1000, else this): a machine-wide OOM then
/// prefers the job's processes to the runner's.
const default_oom_score_adj: i32 = 500;
pub const oom_score_adj_env = "PIPELINE_JOB_OOMSCOREADJ";

/// The `oom_score_adj` for a step with `env`, never below `current`: lowering one needs
/// CAP_SYS_RESOURCE, which a root runner's helper has and a workflow must not borrow to make its
/// processes the last the kernel kills.
fn pickOomScoreAdj(env: []const []const u8, current: i32) i32 {
    var want = default_oom_score_adj;
    for (env) |e| if (std.mem.startsWith(u8, e, oom_score_adj_env ++ "=")) {
        const text = std.mem.trim(u8, e[oom_score_adj_env.len + 1 ..], " ");
        const v = std.fmt.parseInt(i32, text, 10) catch default_oom_score_adj;
        want = if (v >= -1000 and v <= 1000) v else default_oom_score_adj;
    };
    return @max(want, current);
}

/// Sets this process's `oom_score_adj`, which its children inherit across fork and exec, in or
/// out of a namespace. Raising a value needs no privilege, and neither seccomp (installed later,
/// in the step's init) nor no_new_privs touches a write to /proc. Best effort: it never fails a
/// step.
fn setOomScoreAdj(env: []const []const u8) void {
    const path = "/proc/self/oom_score_adj";
    var buf: [16]u8 = undefined;
    const rc = linux.open(path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.pread(fd, &buf, buf.len, 0);
    if (linux.errno(n) != .SUCCESS) return;
    const current = std.fmt.parseInt(i32, std.mem.trim(u8, buf[0..n], " \n"), 10) catch return;
    const text = std.fmt.bufPrint(&buf, "{d}", .{pickOomScoreAdj(env, current)}) catch return;
    _ = linux.pwrite(fd, text.ptr, text.len, 0);
}

/// Moves the helper into the job's cgroup: `0` written to its `cgroup.procs`.
pub fn joinCgroup(arena: Allocator, dir: []const u8) void {
    const path = z(arena, std.fmt.allocPrint(arena, "{s}/cgroup.procs", .{dir}) catch oom());
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    check("open the job's cgroup", fd);
    defer _ = linux.close(@intCast(fd));
    check("join the job's cgroup", linux.write(@intCast(fd), "0", 1));
}

fn makePrivate() void {
    check("make / private", linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0));
}

/// Overlay's options: `lowerdir=` every lower layer, top first, then this step's upper and the
/// work directory; `userxattr` in a user namespace, where unprivileged overlay keeps its own
/// metadata in `user.` xattrs (Linux 5.11). Zero-terminated, for `mount`.
fn overlayOptions(
    arena: Allocator,
    spec: Spec,
    lowers: []const []const u8,
    userxattr: bool,
) [:0]const u8 {
    var opts: std.ArrayList(u8) = .empty;
    opts.appendSlice(arena, "lowerdir=") catch oom();
    for (lowers, 0..) |l, i| {
        if (i > 0) opts.append(arena, ':') catch oom();
        opts.appendSlice(arena, l) catch oom();
    }
    opts.print(arena, ",upperdir={s},workdir={s}", .{ spec.upper, spec.work }) catch oom();
    opts.appendSlice(arena, overlayFeatures(userxattr)) catch oom();
    return opts.toOwnedSliceSentinel(arena, 0) catch oom();
}

/// No redirects and no metacopy, whatever the host's kernel defaults to: `Merged` follows neither,
/// and a layer with either fails a `hashFiles()`. `userxattr` already turns both off (a redirect
/// is `nofollow`) and refuses `redirect_dir=off` beside it, so asking there fails the mount.
fn overlayFeatures(userxattr: bool) []const u8 {
    return if (userxattr) ",userxattr" else ",redirect_dir=off,metacopy=off";
}

fn mountOverlay(arena: Allocator, spec: Spec, lowers: []const []const u8, userxattr: bool) void {
    mountVolatile(arena, "mount the overlay", spec.merged, spec.work, overlayOptions(arena, spec, lowers, userxattr));
}

/// An overlay at `merged` with `opts`, `volatile` (Linux 5.10): never synced to its upper's
/// filesystem, which otherwise its unmount does, whole (`sync_filesystem` of the upper's
/// superblock), at every step's end: a step then waited for every other write to that disk, a
/// tool cache being filled by another job, 5.7 s a step on a laptop's NVMe under one writer. What
/// must outlive a crash is synced on its own, before the rename that names it: a layer
/// (`Store.publish`), a rootfs or image (`oci.Store.ensure`), a seed (`volumes.adoptSeed`). An upper is never mounted again after a crash (a dead runner's job directory is swept), and
/// `volatile`'s mark in the work directory, which would refuse the next step's mount on it, is
/// removed first. A kernel without it gets the overlay as before.
fn mountVolatile(arena: Allocator, what: []const u8, merged: []const u8, work: []const u8, opts: []const u8) void {
    const mark = std.fmt.allocPrintSentinel(arena, "{s}/work/incompat/volatile", .{work}, 0) catch oom();
    // The mark: a directory holding one file, `dirty`.
    _ = linux.unlink(z(arena, std.fmt.allocPrint(arena, "{s}/dirty", .{mark}) catch oom()));
    _ = linux.rmdir(mark);
    _ = linux.rmdir(z(arena, std.fs.path.dirname(mark).?));
    const with = std.fmt.allocPrintSentinel(arena, "{s},volatile", .{opts}, 0) catch oom();
    const rc = linux.mount("overlay", z(arena, merged), "overlay", 0, @intFromPtr(with.ptr));
    if (linux.errno(rc) == .INVAL) {
        check(what, linux.mount("overlay", z(arena, merged), "overlay", 0, @intFromPtr(z(arena, opts))));
        return;
    }
    check(what, rc);
}

/// Joins the job's network namespace (its file, bind-mounted by `netUp`).
fn joinNetns(arena: Allocator, path: []const u8) void {
    const fd = linux.open(z(arena, path), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    check("open the job's network namespace", fd);
    defer _ = linux.close(@intCast(fd));
    check("enter the job's network namespace", linux.setns(@intCast(fd), linux.CLONE.NEWNET));
}

/// A user namespace with host ids `base` to `base + count - 1` as `inside` onwards (0 for the
/// job's own): made by a child, since only a process outside it may map more than its own id,
/// and kept by its file descriptor once the child is gone.
fn mappedUserns(inside: u32, base: u32, count: u32) linux.fd_t {
    var ready: [2]linux.fd_t = undefined;
    var hold: [2]linux.fd_t = undefined;
    check("make a pipe", linux.pipe2(&ready, .{ .CLOEXEC = true }));
    check("make a pipe", linux.pipe2(&hold, .{ .CLOEXEC = true }));
    const pid = linux.fork();
    check("fork", pid);
    if (pid == 0) {
        _ = linux.close(hold[1]);
        if (linux.errno(linux.unshare(linux.CLONE.NEWUSER)) != .SUCCESS) linux.exit_group(1);
        _ = linux.write(ready[1], "u", 1);
        var c: [1]u8 = undefined;
        _ = linux.read(hold[0], &c, 1);
        linux.exit_group(0);
    }
    _ = linux.close(ready[1]);
    _ = linux.close(hold[0]);
    var c: [1]u8 = undefined;
    if (linux.read(ready[0], &c, 1) != 1) fatal("make the job's user namespace", @as(u32, 0));
    var buf: [128]u8 = undefined;
    for ([_][]const u8{ "uid_map", "gid_map" }) |m| {
        const path = std.fmt.bufPrintSentinel(&buf, "/proc/{d}/{s}", .{ pid, m }, 0) catch
            unreachable;
        var line: [64]u8 = undefined;
        writeProc(path, std.fmt.bufPrint(&line, "{d} {d} {d}", .{
            inside,
            base,
            count,
        }) catch unreachable);
    }
    const path = std.fmt.bufPrintSentinel(&buf, "/proc/{d}/ns/user", .{pid}, 0) catch unreachable;
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    check("open the job's user namespace", fd);
    _ = linux.close(hold[1]);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    return @intCast(fd);
}

/// The lower layers with the canonical ids replaced by mounts of them idmapped through `userns`:
/// the image's (the last `image_layers`: the rootfs, and the Zig cache seeds above it) at `R`,
/// `R1`, ..., and the job's own that are stored (`canonical`) at `S0`, `S1`, ... by position. The
/// host's root's files are the job's root's, its uid 1001's the job's 1001's, whichever slot's
/// range the job has, without a copy of a layer per range. Linux 5.19 lets overlay take an
/// idmapped layer. The step's upper is not idmapped: what it writes has the slot's host ids.
fn idmapLowers(
    arena: Allocator,
    lowers: []const []const u8,
    image_layers: u32,
    canonical: []const bool,
    userns: linux.fd_t,
) []const []const u8 {
    const out = arena.dupe([]const u8, lowers) catch oom();
    const n = @min(@max(image_layers, 1), lowers.len);
    for (0..n) |k| {
        const at = if (k == 0) "R" else std.fmt.allocPrint(arena, "R{d}", .{k}) catch oom();
        idmapLayer(arena, lowers[lowers.len - 1 - k], at, userns);
        out[out.len - 1 - k] = at;
    }
    for (0..lowers.len - n) |k| {
        if (k >= canonical.len or !canonical[k]) continue;
        const at = std.fmt.allocPrint(arena, "S{d}", .{k}) catch oom();
        idmapLayer(arena, lowers[k], at, userns);
        out[k] = at;
    }
    return out;
}

/// One layer `layer` with the canonical ids mounted at `at` (in the job's directory) idmapped
/// through `userns`, read-only, nosuid and nodev. Overlay only reads a lower, and a step never
/// sees this mount (its root is the overlay, the host's detached), so the flags take nothing from
/// it: a set-id file in a layer works in the overlay as in the image, as the job's own ids
/// (exec checks the overlay's mount, not the lower's). They keep the mount itself, should it ever
/// be reached, from being written or lending its set-id files or devices.
fn idmapLayer(arena: Allocator, layer: []const u8, at: []const u8, userns: linux.fd_t) void {
    const open_tree_clone = 1;
    const at_recursive = 0x8000;
    const tree = linux.syscall3(
        .open_tree,
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(z(arena, layer)),
        open_tree_clone | at_recursive | linux.SOCK.CLOEXEC,
    );
    check("open a lower layer's mount", tree);
    const rdonly = 0x1;
    const nosuid = 0x2;
    const nodev = 0x4;
    const idmap = 0x00100000;
    var attr: MountAttr = .{ .set = idmap | rdonly | nosuid | nodev, .userns_fd = @intCast(userns) };
    check("idmap a lower layer", linux.syscall5(
        .mount_setattr,
        tree,
        @intFromPtr(""),
        linux.AT.EMPTY_PATH | at_recursive,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    ));
    const at_z = z(arena, at);
    _ = linux.mkdir(at_z, 0o755);
    const move_mount_f_empty_path = 4;
    check("mount an idmapped lower layer", linux.syscall5(
        .move_mount,
        tree,
        @intFromPtr(""),
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(at_z),
        move_mount_f_empty_path,
    ));
    _ = linux.close(@intCast(tree));
}

/// `rootfs` mounted idmapped through `userns` at `at` in the job's directory, for an overlay's
/// lower layer (a Docker action's image, P7); `at`, as overlay takes it.
fn idmapped(arena: Allocator, rootfs: []const u8, userns: linux.fd_t, at: []const u8) []const u8 {
    idmapLayer(arena, rootfs, at, userns);
    return at;
}

/// A Docker action's overlay: the image's layers (`lowers`, idmapped on a root runner) under the
/// container's own layer.
fn mountContainer(arena: Allocator, c: Spec.Container, lowers: []const []const u8, userxattr: bool) void {
    const opts = std.fmt.allocPrint(arena, "lowerdir={s},upperdir={s},workdir={s}{s}", .{
        std.mem.join(arena, ":", lowers) catch oom(),
        c.upper,
        c.work,
        overlayFeatures(userxattr),
    }) catch oom();
    mountVolatile(arena, "mount the container's overlay", c.merged, c.work, opts);
}

/// Binds each of the container's shares from the job's overlay into the container (`root`), as
/// the step's root: each made where missing (in the job's overlay, so in this step's layer, as
/// GitHub's runner makes them on the host; in the container's own layer for the mount point),
/// and bound with whatever is mounted under it. The job's overlay, opened, for `files`.
fn shareJobDirs(arena: Allocator, spec: Spec, c: Spec.Container, root: linux.fd_t) linux.fd_t {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const rc = linux.open(z(arena, spec.merged), flags, 0);
    check("open the job's overlay", rc);
    const job: linux.fd_t = @intCast(rc);
    for (c.shares) |sh| {
        const from = makeDirsOpen(arena, job, sh.from);
        defer _ = linux.close(from);
        const at = makeDirsOpen(arena, root, sh.at);
        defer _ = linux.close(at);
        check(about(arena, "share", sh.at), linux.mount(
            procFd(arena, from),
            procFd(arena, at),
            null,
            linux.MS.BIND | linux.MS.REC,
            0,
        ));
    }
    return job;
}

/// `path` under `root` made as `mkdir -p` makes it (root's, 0755), resolved inside it, and opened
/// for a mount; a failure fails the step.
fn makeDirsOpen(arena: Allocator, root: linux.fd_t, path: []const u8) linux.fd_t {
    const rel = std.mem.trim(u8, path, "/");
    var i: usize = 0;
    while (i <= rel.len) {
        const end = std.mem.indexOfScalarPos(u8, rel, i, '/') orelse rel.len;
        const parent = dirIn(arena, root, rel[0..i]) orelse
            fatal(about(arena, "make", path), @as(u32, 2));
        _ = linux.mkdirat(parent, z(arena, rel[i..end]), 0o755);
        _ = linux.close(parent);
        i = end + 1;
    }
    return dirIn(arena, root, rel) orelse fatal(about(arena, "make", path), @as(u32, 2));
}

/// Waits for the step's PID 1, killing it when the lifeline (stdin) closes or says anything but a
/// warning (`Warning.take`): the runner stopped the step, or is gone. Killing PID 1 kills every
/// process of the step's PID namespace: the kernel stops the namespace's forks first, so nothing
/// outruns it, and a process that left its group or its parent goes too. `own_program`: PID 1 is
/// the step's own, not the `sh -c` around it (`Warning.pid1`). The wait status.
fn superviseStep(pid: linux.pid_t, own_program: bool, early: []const u8) u32 {
    const pidfd_rc = linux.pidfd_open(pid, 0);
    const pidfd: ?linux.fd_t = if (linux.errno(pidfd_rc) == .SUCCESS) @intCast(pidfd_rc) else null;
    var warning: Warning = .{ .pid1 = if (own_program) pid else null };
    var stopped = false;
    for (early) |byte| stopped = stopped or !warning.take(byte);
    while (!stopped) {
        warning.tend();
        var fds = [_]linux.pollfd{
            .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = pidfd orelse -1, .events = linux.POLL.IN, .revents = 0 },
        };
        // Without a pidfd (Linux before 5.3), the step's end is polled for.
        const wait_ms: i32 = if (warning.busy()) 20 else if (pidfd == null) 100 else -1;
        const rc = linux.poll(&fds, fds.len, wait_ms);
        if (linux.errno(rc) == .INTR) continue;
        check("wait for the step or its stop", rc);
        if (fds[0].revents != 0) {
            var byte: [1]u8 = undefined;
            const n = linux.read(0, &byte, 1);
            if (linux.errno(n) == .INTR) continue;
            stopped = n != 1 or !warning.take(byte[0]);
            continue;
        }
        if (fds[1].revents != 0) break;
        if (pidfd == null) {
            var status: i32 = 0;
            const done = linux.waitpid(pid, &status, linux.W.NOHANG);
            if (linux.errno(done) == .SUCCESS and done == @as(usize, @intCast(pid)))
                return @bitCast(status);
        }
    }
    if (stopped) _ = linux.kill(pid, .KILL);
    warning.drop();
    var status: i32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        if (linux.errno(rc) == .INTR) continue;
        check("wait for the step", rc);
        break;
    }
    return @bitCast(status);
}

/// One stage of a stop in the helper (`Running.warn`): a signal to every process of the step, so a
/// step's foreground child, a background job and a process in a session of its own all hear it,
/// where GitHub's runner signals only the step's entry process (`ProcessInvoker.cs`, `SendSignal`).
///
/// From outside its PID namespace no call reaches all of a namespace, and a signal to PID 1 is
/// dropped unless PID 1 has a handler for it. `kill(-1)` from inside does reach all but PID 1, as
/// one act the kernel holds forks off from, so a process in a fork cannot slip past it. So a
/// process is forked for that one call (the helper's forks land in the step's namespace, as
/// `unshare` left them): it can be nothing the step's own could become, since it lasts one system
/// call, is not dumpable, and has capabilities the step's bounding set has not, which is what
/// keeps a step's root from tracing it. A step that stops it only loses its warning.
///
/// Its fork can fail, with a fork bomb at `pids.max`: it is tried again while the stage lasts, and
/// the ladder's last stage needs no fork.
const Warning = struct {
    /// PID 1, for a Docker action's container, whose first process is the action's own: it is
    /// signalled as `docker stop` would. A `run:` step's PID 1 is the `sh -c` around the step's
    /// shell (`scripts.stepScriptFc`), which is left alone: it reports the step's end, and where
    /// `sh` is bash it would act on a signal and end the namespace under a step still cleaning up.
    pid1: ?linux.pid_t,
    /// A signal no process could be forked for yet.
    pending: ?linux.SIG = null,
    /// The process sending it. Its zombie must be reaped: PID 1 cannot finish exiting while one
    /// of its namespace is left (`zap_pid_ns_processes`), and the step would never end.
    sender: ?linux.pid_t = null,

    /// A byte from the lifeline: false when it is no warning, which stops the step.
    fn take(w: *Warning, byte: u8) bool {
        const sig: linux.SIG = switch (byte) {
            @backingInt(linux.SIG.INT) => .INT,
            @backingInt(linux.SIG.TERM) => .TERM,
            else => return false,
        };
        if (w.pid1) |p| _ = linux.kill(p, sig);
        w.drop();
        w.pending = sig;
        w.tend();
        return true;
    }

    fn busy(w: *const Warning) bool {
        return w.pending != null or w.sender != null;
    }

    /// Forks for the signal waiting for it, and reaps a sender that is done.
    fn tend(w: *Warning) void {
        if (w.sender) |p| {
            var status: i32 = 0;
            const rc = linux.waitpid(p, &status, linux.W.NOHANG);
            if (rc == 0 and linux.errno(rc) == .SUCCESS) return;
            w.sender = null;
        }
        const sig = w.pending orelse return;
        const pid = linux.fork();
        if (linux.errno(pid) != .SUCCESS) return;
        if (pid == 0) {
            _ = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
            _ = linux.kill(-1, sig);
            linux.exit_group(0);
        }
        w.pending = null;
        w.sender = @intCast(pid);
    }

    /// Whatever is still being sent, given up on: the next stage, or the end of the step.
    fn drop(w: *Warning) void {
        w.pending = null;
        const p = w.sender orelse return;
        w.sender = null;
        _ = linux.kill(p, .KILL);
        var status: i32 = 0;
        while (linux.errno(linux.waitpid(p, &status, 0)) == .INTR) {}
    }
};

/// PID 1 of the step: its /dev, /proc and /sys, the overlay as its root (`pivot_root`, the host's
/// root detached), its working directory, capabilities, user, no_new_privs and seccomp filter,
/// then the shell. Never returns.
fn stepInit(
    arena: Allocator,
    root: linux.fd_t,
    workdir: [*:0]const u8,
    uid: u32,
    gid: u32,
    groups: []const u32,
    no_new_privs: bool,
    alive: linux.fd_t,
    in_image: bool,
    program: Program,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) noreturn {
    armParentDeath(alive);
    makeDev(arena, root);
    mountIn(arena, root, "/proc", "proc", "proc", linux.MS.NOSUID | linux.MS.NODEV |
        linux.MS.NOEXEC, null);
    // The host's /sys, read-only with every mount under it, as BuildKit mounts sysfs read-only.
    // A new sysfs needs a network namespace the job's user namespace owns, which steps do not
    // have.
    bindTreeReadOnly(arena, root, "/sys");
    maskPaths(arena, root);

    // The overlay becomes `/`, and the host's root is unmounted from under it: unlike a chroot,
    // nothing left in the namespace leads back to it.
    check("enter the overlay", linux.fchdir(root));
    check("pivot_root", linux.syscall2(.pivot_root, @intFromPtr("."), @intFromPtr(".")));
    check("detach the host's root", linux.umount2(".", linux.MNT.DETACH));
    check("chdir /", linux.chdir("/"));
    // BuildKit makes a missing working directory; one that cannot be made fails the step.
    _ = linux.mkdir(workdir, 0o755);
    check("chdir to the working directory", linux.chdir(workdir));

    dropCapabilities();
    // The filter goes in while PID 1 is still the namespace's root: without no_new_privs (the
    // runner user on a root runner), installing one takes CAP_SYS_ADMIN, which the bounding set
    // no longer holds but the effective set does until `setuid` or exec. It binds every process
    // the step makes, sudo's root included.
    installSeccomp();
    if (uid != 0 or gid != 0) {
        check("setgroups", if (groups.len == 0) linux.setgroups(0, no_groups) else linux.setgroups(groups.len, groups.ptr));
        check("setgid", linux.setgid(gid));
        check("setuid", linux.setuid(uid));
        // The kernel clears the parent-death signal on a change of credentials.
        armParentDeath(alive);
    }
    _ = linux.close(alive);
    // No setuid program gains anything. Every step but the runner user's on a root runner, whose
    // sudo reaches only the job's own root (`runStep`).
    if (no_new_privs)
        check("no_new_privs", linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    // The step gets no stdin, as on GitHub.
    const devnull = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    check("open /dev/null", devnull);
    _ = linux.dup2(@intCast(devnull), 0);
    // From here the helper's failures would be the step's output; the step's stderr is its
    // stdout, as the script's `exec 2>&1` would make it anyway.
    _ = linux.dup2(1, 2);
    if (in_image) execCommand(argv, envp);
    const path = switch (program) {
        .path => |p| z(arena, p),
        .search => |s| lookPath(arena, s.name, s.env),
    };
    const rc = linux.execve(path, argv, envp);
    fatal(about(arena, "exec", std.mem.span(path)), @backingInt(linux.errno(rc)));
}

/// What a sandbox's first process executes: a path, or a name looked up in PATH once inside.
const Program = union(enum) {
    path: []const u8,
    search: struct { name: []const u8, env: []const []const u8 },
};

/// `name` as `execvp` finds it, inside the current root: itself when it holds a slash, else the
/// first executable of that name in `env`'s PATH (the image's, Docker's default when none). Itself
/// when none is found, so the exec fails with ENOENT and says so.
pub fn lookPath(arena: Allocator, name: []const u8, env: []const []const u8) [*:0]const u8 {
    if (std.mem.indexOfScalar(u8, name, '/') != null or name.len == 0) return z(arena, name);
    var path: []const u8 = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for (env) |e| if (std.mem.startsWith(u8, e, "PATH=")) {
        path = e["PATH=".len..];
    };
    var dirs = std.mem.splitScalar(u8, path, ':');
    while (dirs.next()) |d| {
        const dir = if (d.len == 0) "." else d;
        const full = std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name }) catch oom();
        const p = z(arena, full);
        if (linux.errno(linux.access(p, linux.X_OK)) == .SUCCESS) return p;
    }
    return z(arena, name);
}

/// Runs a Docker action's command as `docker run` does: its first word as a path when it has a
/// slash, else found in the env's PATH (runc's default PATH when it has none). What cannot be run
/// is the step's failure, on its output, with the shell's codes: 126 when a file was found but
/// could not be run, 127 when none was.
fn execCommand(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) noreturn {
    const name = std.mem.span(argv[0].?);
    var denied = false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        const e = linux.errno(linux.execve(argv[0].?, argv, envp));
        denied = e != .NOENT and e != .NOTDIR;
    } else if (name.len > 0) {
        var path: []const u8 = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        var i: usize = 0;
        while (envp[i]) |e| : (i += 1) {
            const kv = std.mem.span(e);
            if (std.mem.startsWith(u8, kv, "PATH=")) path = kv["PATH=".len..];
        }
        var dirs = std.mem.splitScalar(u8, path, ':');
        var buf: [4096]u8 = undefined;
        while (dirs.next()) |dir| {
            const full = std.fmt.bufPrintSentinel(&buf, "{s}/{s}", .{
                if (dir.len == 0) "." else dir,
                name,
            }, 0) catch continue;
            const e = linux.errno(linux.execve(full.ptr, argv, envp));
            if (e != .NOENT and e != .NOTDIR) denied = true;
        }
    }
    var msg: [512]u8 = undefined;
    const text = std.fmt.bufPrint(&msg, "exec: \"{s}\": {s}\n", .{
        name,
        if (denied) "permission denied" else "executable file not found in $PATH",
    }) catch "exec failed\n";
    _ = linux.write(1, text.ptr, text.len);
    linux.exit_group(if (denied) 126 else 127);
}

/// No supplementary groups at all: `setgroups(0, NULL)`.
pub const no_groups: [*]const linux.gid_t = @ptrFromInt(@alignOf(linux.gid_t));

/// Dies with the helper, and exits at once if the helper is already gone (its end of `alive` then
/// reads as hung up): the helper is how the runner stops a step.
fn armParentDeath(alive: linux.fd_t) void {
    _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0);
    var fds = [_]linux.pollfd{.{ .fd = alive, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&fds, 1, 0) == 1 and fds[0].revents & linux.POLL.HUP != 0) linux.exit_group(137);
}

/// runc's masked paths, hidden (files under /dev/null, directories under an empty read-only
/// tmpfs), and its read-only ones, made read-only from the step's own /proc (never the helper's,
/// which is the host's, with its submounts) with every mount under them. A path the kernel does
/// not have is skipped; one it has that cannot be hidden or made read-only fails the step, since
/// the step would otherwise run with it open.
fn maskPaths(arena: Allocator, root: linux.fd_t) void {
    const files = [_][]const u8{
        "/proc/interrupts", "/proc/kcore",       "/proc/keys",        "/proc/latency_stats",
        "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
    };
    for (files) |f| {
        const fd = existingIn(arena, root, f, false) orelse continue;
        defer _ = linux.close(fd);
        const rc = linux.mount("/dev/null", procFd(arena, fd), null, linux.MS.BIND, 0);
        check(about(arena, "mask", f), rc);
    }
    const dirs = [_][]const u8{
        "/proc/acpi",    "/proc/asound",                  "/proc/scsi",
        "/sys/firmware", "/sys/devices/virtual/powercap",
    };
    for (dirs) |d| {
        const fd = existingIn(arena, root, d, true) orelse continue;
        defer _ = linux.close(fd);
        const rc = linux.mount("tmpfs", procFd(arena, fd), "tmpfs", linux.MS.RDONLY, 0);
        check(about(arena, "mask", d), rc);
    }
    const read_only = [_][]const u8{
        "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
    };
    for (read_only) |p| {
        const fd = existingIn(arena, root, p, false) orelse continue;
        defer _ = linux.close(fd);
        const tree = cloneTreeReadOnly(arena, fd, "", p);
        defer _ = linux.close(tree);
        moveTree(arena, tree, fd, p);
    }
}

/// `at` inside the overlay, resolved inside it, for a mount on it; null when it does not exist,
/// and any other failure fails the step.
fn existingIn(arena: Allocator, root: linux.fd_t, at: []const u8, dir: bool) ?linux.fd_t {
    const rel = z(arena, std.mem.trimStart(u8, at, "/"));
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = dir };
    return switch (openIn(root, rel, flags, 0, 0)) {
        .fd => |f| f,
        .err => |e| if (e == .NOENT) null else fatal(about(arena, "find", at), @backingInt(e)),
    };
}

/// Docker's default capabilities: the bounding set cut to them, so a root step has these and no
/// more (no CAP_SYS_ADMIN, no CAP_NET_ADMIN), and the ambient set cleared.
pub fn dropCapabilities() void {
    const keep = [_]u6{ 0, 1, 3, 4, 5, 6, 7, 8, 10, 13, 18, 27, 29, 31 };
    var cap: u6 = 0;
    while (true) : (cap += 1) {
        if (std.mem.indexOfScalar(u6, &keep, cap) == null) {
            const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
            // Past the kernel's last capability.
            if (linux.errno(rc) == .INVAL) break;
            check("drop a capability", rc);
        }
        if (cap == 63) break;
    }
    check("clear ambient capabilities", linux.prctl(
        @backingInt(linux.PR.CAP_AMBIENT),
        linux.PR.CAP_AMBIENT_CLEAR_ALL,
        0,
        0,
        0,
    ));
}

/// Docker's default capability set, as a step's root sees it in /proc/self/status (`CapEff`).
pub const docker_caps: u64 = 0xa80425fb;

/// Docker's default seccomp profile, its allow list (`seccomp.zig`).
pub fn installSeccomp() void {
    check("install the seccomp filter", seccomp.install());
}

/// A /dev of the nodes a step needs, bound from the host's, as runc builds one: not the host's
/// whole /dev, which would hand a step its disks.
fn makeDev(arena: Allocator, root: linux.fd_t) void {
    const ms = linux.MS;
    mountIn(arena, root, "/dev", "tmpfs", "tmpfs", ms.NOSUID | ms.NOEXEC, "mode=755,size=65536k");
    for ([_][]const u8{ "null", "zero", "full", "random", "urandom", "tty" }) |name| {
        const at = std.fmt.allocPrint(arena, "/dev/{s}", .{name}) catch oom();
        const node: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true };
        switch (openIn(root, z(arena, at[1..]), node, 0o666, 0)) {
            .fd => |f| _ = linux.close(f),
            .err => |e| fatal(about(arena, "make", at), @backingInt(e)),
        }
        _ = bindIn(arena, root, at, at, true);
    }
    const dev = dirIn(arena, root, "/dev") orelse fatal("open /dev", @as(u32, 0));
    defer _ = linux.close(dev);
    for ([_][*:0]const u8{ "pts", "shm", "mqueue" }) |d| _ = linux.mkdirat(dev, d, 0o755);
    mountIn(arena, root, "/dev/pts", "devpts", "devpts", ms.NOSUID | ms.NOEXEC, "newinstance," ++
        "ptmxmode=0666,mode=0620");
    const shm_flags = ms.NOSUID | ms.NODEV | ms.NOEXEC;
    mountIn(arena, root, "/dev/shm", "shm", "tmpfs", shm_flags, "mode=1777,size=65536k");
    const links = [_][2][*:0]const u8{
        .{ "pts/ptmx", "ptmx" },
        .{ "/proc/self/fd", "fd" },
        .{ "/proc/self/fd/0", "stdin" },
        .{ "/proc/self/fd/1", "stdout" },
        .{ "/proc/self/fd/2", "stderr" },
    };
    for (links) |l| _ = linux.symlinkat(l[0], dev, l[1]);
}

/// Mounts `source` at `at` inside the overlay, `at` resolved inside it, and fails the step when
/// it cannot.
fn mountIn(
    arena: Allocator,
    root: linux.fd_t,
    at: []const u8,
    source: [*:0]const u8,
    fstype: [*:0]const u8,
    flags: u32,
    data: ?[*:0]const u8,
) void {
    const fd = targetIn(arena, root, at, true) orelse fatal(about(arena, "find", at), @as(u32, 2));
    defer _ = linux.close(fd);
    const d: usize = if (data) |p| @intFromPtr(p) else 0;
    check("mount", linux.mount(source, procFd(arena, fd), fstype, flags, d));
}

/// Binds the host's `host` at `at` inside the overlay, `at` resolved inside it. Whether it was
/// made; one that is `required` fails the step when it cannot be.
fn bindIn(
    arena: Allocator,
    root: linux.fd_t,
    host: []const u8,
    at: []const u8,
    required: bool,
) bool {
    const rel = z(arena, std.mem.trimStart(u8, at, "/"));
    const fd = switch (openIn(root, rel, .{ .ACCMODE = .RDONLY, .PATH = true }, 0, 0)) {
        .fd => |f| f,
        .err => |e| if (required) fatal(about(arena, "find", at), @backingInt(e)) else return false,
    };
    defer _ = linux.close(fd);
    const rc = linux.mount(z(arena, host), procFd(arena, fd), null, linux.MS.BIND, 0);
    if (required) check("bind a host path", rc);
    return linux.errno(rc) == .SUCCESS;
}

/// Binds the host's `path`, with every mount under it, at the same place inside, all of them
/// read-only, nosuid, nodev and noexec, in one `mount_setattr` over the cloned tree. A bind of
/// `path` alone is refused in a user namespace, since it would uncover what the mounts under it
/// hide, and a remount covers one mount at a time.
fn bindTreeReadOnly(arena: Allocator, root: linux.fd_t, path: []const u8) void {
    const tree = cloneTreeReadOnly(arena, linux.AT.FDCWD, path, path);
    defer _ = linux.close(tree);
    const target = targetIn(arena, root, path, true) orelse
        fatal(about(arena, "find", path), @as(u32, 2));
    defer _ = linux.close(target);
    moveTree(arena, tree, target, path);
}

/// A detached clone of the mount at `path` from `dirfd` ("" for `dirfd` itself), with every mount
/// under it, made read-only, nosuid, nodev and noexec; `what` names it when that fails the step.
fn cloneTreeReadOnly(
    arena: Allocator,
    dirfd: linux.fd_t,
    path: []const u8,
    what: []const u8,
) linux.fd_t {
    const open_tree_clone = 1;
    const at_recursive = 0x8000;
    const empty: u32 = if (path.len == 0) linux.AT.EMPTY_PATH else 0;
    const tree = linux.syscall3(
        .open_tree,
        @as(usize, @bitCast(@as(isize, dirfd))),
        @intFromPtr(z(arena, path)),
        open_tree_clone | at_recursive | linux.SOCK.CLOEXEC | empty,
    );
    check(about(arena, "clone the mount of", what), tree);
    var attr: MountAttr = .{ .set = 0x1 | 0x2 | 0x4 | 0x8 };
    check(about(arena, "make read-only", what), linux.syscall5(
        .mount_setattr,
        tree,
        @intFromPtr(""),
        linux.AT.EMPTY_PATH | at_recursive,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    ));
    return @intCast(tree);
}

/// Mounts the detached `tree` on `target` (a file descriptor), and fails the step when it cannot.
fn moveTree(arena: Allocator, tree: linux.fd_t, target: linux.fd_t, what: []const u8) void {
    const move_mount_f_empty_path = 0x4;
    const move_mount_t_empty_path = 0x40;
    check(about(arena, "mount read-only", what), linux.syscall5(
        .move_mount,
        @as(usize, @intCast(tree)),
        @intFromPtr(""),
        @as(usize, @intCast(target)),
        @intFromPtr(""),
        move_mount_f_empty_path | move_mount_t_empty_path,
    ));
}

/// Remounts the bind at `at` with `add` (`MS.RDONLY`, `MS.NOSUID`, `MS.NODEV`), and fails the
/// step when it cannot. The mount's own flags go with it: in a user namespace, those a more
/// privileged one set (nosuid, nodev, noexec, the atime ones) are locked, and a remount that drops
/// any of them is refused, as runc found.
fn remountWith(arena: Allocator, root: linux.fd_t, at: []const u8, add: u32) void {
    const fd = targetIn(arena, root, at, false) orelse
        fatal(about(arena, "find", at), @as(u32, 2));
    defer _ = linux.close(fd);
    var st: [120]u8 align(8) = undefined;
    check("statfs a mount", linux.syscall2(.fstatfs, @as(usize, @intCast(fd)), @intFromPtr(&st)));
    // `struct statfs`'s `f_flags`, at the same place on x86_64 and aarch64.
    const st_flags = std.mem.readInt(u64, st[80..88], .little);
    var keep: u32 = 0;
    const same = [_]u32{
        linux.MS.NOSUID, linux.MS.NODEV, linux.MS.NOEXEC, linux.MS.NOATIME, linux.MS.NODIRATIME,
    };
    for (same) |f| {
        if (st_flags & f != 0) keep |= f;
    }
    const st_relatime = 4096;
    if (st_flags & st_relatime != 0) keep |= linux.MS.RELATIME;
    check("remount a bind", linux.mount(
        null,
        procFd(arena, fd),
        null,
        linux.MS.REMOUNT | linux.MS.BIND | add | keep,
        0,
    ));
}

fn targetIn(arena: Allocator, root: linux.fd_t, at: []const u8, dir: bool) ?linux.fd_t {
    const rel = z(arena, std.mem.trimStart(u8, at, "/"));
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = dir };
    return switch (openIn(root, rel, flags, 0, 0)) {
        .fd => |f| f,
        .err => null,
    };
}

/// `/proc/self/fd/<fd>`: what mount(2) takes for a target opened by `openIn`. It follows the link
/// to the directory or file itself, wherever a symlink a step left would have pointed.
fn procFd(arena: Allocator, fd: linux.fd_t) [*:0]const u8 {
    return z(arena, std.fmt.allocPrint(arena, "/proc/self/fd/{d}", .{fd}) catch oom());
}

/// Writes `f` into the overlay, `f.path` resolved inside it, its missing parents made as
/// `withNewFile` makes them (root's, 0755).
fn writeFileIn(arena: Allocator, root: linux.fd_t, f: Spec.File) void {
    const fd = createIn(arena, root, f.path, f.mode, true);
    defer _ = linux.close(fd);
    writeAll(fd, f.contents);
}

/// A secret file (`Spec.File.keep` false): written to the step's tmpfs (`secrets_dir`), and bound
/// at `f.path` over an empty file made in the overlay, so the overlay's upper layer, on the
/// store's disk, never holds its contents.
fn bindSecretIn(arena: Allocator, root: linux.fd_t, f: Spec.File, i: usize) void {
    const held = z(arena, std.fmt.allocPrint(arena, secrets_dir ++ "/{d}", .{i}) catch oom());
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true };
    const fd = linux.open(held, flags, f.mode);
    check("write a secret file for the step", fd);
    writeAll(@intCast(fd), f.contents);
    _ = linux.close(@intCast(fd));
    const at = createIn(arena, root, f.path, f.mode, false);
    defer _ = linux.close(at);
    const rc = linux.mount(held, procFd(arena, at), null, linux.MS.BIND, 0);
    check("bind a secret file for the step", rc);
}

/// Opens `path` in the overlay for writing, made if missing (emptied when `truncate`), its
/// missing parents made root's with mode 0755; never through a symlink at its end.
fn createIn(
    arena: Allocator,
    root: linux.fd_t,
    path: []const u8,
    mode: u32,
    truncate: bool,
) linux.fd_t {
    const rel = std.mem.trimStart(u8, path, "/");
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, rel, i, '/')) |slash| : (i = slash + 1) {
        const parent = dirIn(arena, root, rel[0..i]) orelse continue;
        defer _ = linux.close(parent);
        _ = linux.mkdirat(parent, z(arena, rel[i..slash]), 0o755);
    }
    return switch (openIn(root, z(arena, rel), .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = truncate,
        .NOFOLLOW = true,
    }, mode, 0)) {
        .fd => |fd| fd,
        .err => |e| fatal("write a file for the step", @backingInt(e)),
    };
}

fn writeAll(fd: linux.fd_t, contents: []const u8) void {
    var done: usize = 0;
    while (done < contents.len) {
        const rc = linux.write(fd, contents[done..].ptr, contents.len - done);
        check("write a file for the step", rc);
        done += rc;
    }
}

fn enterUserns() void {
    const uid = linux.getuid();
    const gid = linux.getgid();
    check("unshare(user, mount)", linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS));
    var buf: [64]u8 = undefined;
    writeProc("/proc/self/setgroups", "deny");
    writeProc("/proc/self/uid_map", std.fmt.bufPrint(&buf, "0 {d} 1", .{uid}) catch unreachable);
    writeProc("/proc/self/gid_map", std.fmt.bufPrint(&buf, "0 {d} 1", .{gid}) catch unreachable);
}

fn writeProc(path: [*:0]const u8, text: []const u8) void {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    check("open a user namespace map", fd);
    defer _ = linux.close(@intCast(fd));
    check("write a user namespace map", linux.write(@intCast(fd), text.ptr, text.len));
}

/// The env, with HOME from the image's /etc/passwd when it has none: runc sets it so, and every
/// step under Dagger saw it.
pub fn withHome(arena: Allocator, root: linux.fd_t, spec: Spec) []const []const u8 {
    for (spec.env) |e| if (std.mem.startsWith(u8, e, "HOME=")) return spec.env;
    const home = passwdHome(arena, root, spec.uid) orelse "/";
    const extra = std.fmt.allocPrint(arena, "HOME={s}", .{home}) catch oom();
    return std.mem.concat(arena, []const u8, &.{ spec.env, &.{extra} }) catch oom();
}

/// The home directory of `uid` in /etc/passwd as the step sees it.
fn passwdHome(arena: Allocator, root: linux.fd_t, uid: u32) ?[]const u8 {
    const fd = switch (openIn(root, "etc/passwd", .{ .ACCMODE = .RDONLY }, 0, 0)) {
        .fd => |f| f,
        .err => return null,
    };
    defer _ = linux.close(fd);
    const buf = arena.alloc(u8, 256 * 1024) catch return null;
    const n = linux.read(fd, buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return homeOf(buf[0..n], uid);
}

/// `uid`'s home directory in the text of an /etc/passwd.
pub fn homeOf(passwd: []const u8, uid: u32) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        var f: [7][]const u8 = undefined;
        var i: usize = 0;
        while (fields.next()) |v| : (i += 1) {
            if (i == f.len) break;
            f[i] = v;
        }
        if (i < 6) continue;
        const id = std.fmt.parseInt(u32, f[2], 10) catch continue;
        if (id == uid) return f[5];
    }
    return null;
}

pub fn z(arena: Allocator, s: []const u8) [*:0]const u8 {
    return (arena.dupeSentinel(u8, s, 0) catch oom()).ptr;
}

pub fn zList(arena: Allocator, items: []const []const u8) [*:null]const ?[*:0]const u8 {
    const out = arena.allocSentinel(?[*:0]const u8, items.len, null) catch oom();
    for (items, out) |s, *o| o.* = z(arena, s);
    return out.ptr;
}

/// A failed system call ends the helper with the reason on its stderr, which the runner reports
/// as the sandbox's failure, not the step's.
pub fn check(what: []const u8, rc: usize) void {
    const e = linux.errno(rc);
    if (e != .SUCCESS) fatal(what, @backingInt(e));
}

/// "<what> <path>", for `fatal`.
pub fn about(arena: Allocator, what: []const u8, path: []const u8) []const u8 {
    return std.fmt.allocPrint(arena, "{s} {s}", .{ what, path }) catch what;
}

pub fn fatal(what: []const u8, code: anytype) noreturn {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "native step: {s} failed (errno {d})\n", .{
        what,
        code,
    }) catch "native step: failed\n";
    _ = linux.write(2, msg.ptr, msg.len);
    linux.exit_group(125);
}

pub fn oom() noreturn {
    fatal("allocate", @as(u32, 12));
}

test "an overlay asks for no redirects or metacopy, where the kernel lets it" {
    try std.testing.expectEqualStrings(",redirect_dir=off,metacopy=off", overlayFeatures(false));
    // The kernel fails a mount with `userxattr` and `redirect_dir=off` (Linux 7.0).
    try std.testing.expectEqualStrings(",userxattr", overlayFeatures(true));
}

test "a link anywhere below a cache volume's root is refused, and above it is the operator's" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "store/volumes/key/runner/deeper");
    try tmp.dir.createDirPath(io, "store/volumes/other-repo/runner");
    try tmp.dir.createDirPath(io, "elsewhere/runner");
    // The operator's store behind a link, as `/var/lib` on another disk is.
    try tmp.dir.symLink(io, "store", "linked-store", .{});
    // What a job in the outer volume can plant at the last name, and one on the way to it, which
    // no job reaches today.
    // Out of the root, and more to the point inside it, at another repository's volume, which
    // staying in the root alone would allow.
    try tmp.dir.symLink(io, "../../../elsewhere", "store/volumes/key/last", .{});
    try tmp.dir.symLink(io, "other-repo", "store/volumes/middle", .{});
    try tmp.dir.symLink(io, "../other-repo/runner", "store/volumes/key/neighbour", .{});
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &buf);
    const base = buf[0..n];
    const root = try std.fmt.allocPrint(arena, "{s}/store/volumes", .{base});
    const linked = try std.fmt.allocPrint(arena, "{s}/linked-store/volumes", .{base});
    for ([_][]const u8{ root, linked }) |r| {
        const ok = openVolume(arena, r, try std.fmt.allocPrint(arena, "{s}/key/runner", .{r}));
        try std.testing.expect(ok == .fd);
        _ = linux.close(ok.fd);
        const deep = openVolume(arena, r, try std.fmt.allocPrint(arena, "{s}/key/runner/deeper", .{r}));
        try std.testing.expect(deep == .fd);
        _ = linux.close(deep.fd);
    }
    const last = openVolume(arena, root, try std.fmt.allocPrint(arena, "{s}/key/last", .{root}));
    try std.testing.expect(last == .err);
    const middle = openVolume(arena, root, try std.fmt.allocPrint(arena, "{s}/middle/runner", .{root}));
    try std.testing.expect(middle == .err);
    const neighbour = openVolume(arena, root, try std.fmt.allocPrint(arena, "{s}/key/neighbour", .{root}));
    try std.testing.expect(neighbour == .err);
}

test "homeOf reads the home directory of a uid from /etc/passwd" {
    const passwd = "root:x:0:0:root:/root:/bin/bash\n" ++
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" ++
        "runner:x:1001:1001::/home/runner:/bin/bash\n";
    try std.testing.expectEqualStrings("/root", homeOf(passwd, 0).?);
    try std.testing.expectEqualStrings("/home/runner", homeOf(passwd, 1001).?);
    try std.testing.expect(homeOf(passwd, 7) == null);
    try std.testing.expect(homeOf("garbage", 0) == null);
}

/// Renames a file back and forth in `dir` until `stop`, to race what follows a `..`.
fn renameUntil(dir: linux.fd_t, stop: *std.atomic.Value(bool)) void {
    while (!stop.load(.monotonic)) {
        _ = linux.renameat(dir, "a", dir, "b");
        _ = linux.renameat(dir, "b", dir, "a");
    }
}

test "openIn: a rename elsewhere on the machine does not fail a `..` on the way" {
    // Valgrind runs one thread at a time, and threads this busy never hand it over: the job's 45
    // minutes pass with the test on its first open. It is a race, which memcheck would not see.
    if (std.valgrind.runningOnValgrind() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "root");
    try tmp.dir.createDirPath(io, "busy");
    try tmp.dir.writeFile(io, .{ .sub_path = "busy/a", .data = "" });
    try tmp.dir.symLink(io, "/../../..", "root/up", .{});
    const root = try tmp.dir.openDir(io, "root", .{});
    defer root.close(io);
    const busy = try tmp.dir.openDir(io, "busy", .{});
    defer busy.close(io);

    var stop: std.atomic.Value(bool) = .init(false);
    var threads: [2]std.Thread = undefined;
    for (&threads) |*t| t.* = try .spawn(.{}, renameUntil, .{ busy.handle, &stop });
    defer for (threads) |t| t.join();
    defer stop.store(true, .monotonic);

    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .PATH = true };
    for (0..20_000) |_| switch (openIn(root.handle, "up", flags, 0, 0)) {
        .fd => |fd| _ = linux.close(fd),
        .err => |e| return std.debug.panic("openIn through a `..`: {t}", .{e}),
    };
}

test "readIn reads inside a layer: no symlink is followed, and a whiteout is told apart" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "layer/github");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside", .data = "host secret" });
    try tmp.dir.writeFile(io, .{ .sub_path = "layer/github/ok", .data = "fine" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const outside = try std.fmt.allocPrint(arena, "{s}/outside", .{root});
    // A step's symlinks to the host's files, by absolute path and by `..`.
    try tmp.dir.symLink(io, outside, "layer/github/abs", .{});
    try tmp.dir.symLink(io, "../../outside", "layer/github/rel", .{});
    try tmp.dir.symLink(io, "/", "layer/github/dir", .{});
    const layer = try std.fmt.allocPrint(arena, "{s}/layer", .{root});
    try std.testing.expectEqualStrings("fine", (try readIn(arena, layer, "/github/ok", 1024)).text);
    for ([_][]const u8{ "/github/abs", "/github/rel", "/github/dir/outside", "/../outside" }) |p|
        try std.testing.expect(try readIn(arena, layer, p, 1024) == .missing);
    try std.testing.expect(try readIn(arena, layer, "/github/ok", 2) == .missing);
}

test "a step's oom_score_adj is GitHub's 500, or the env's within -1000 to 1000, never lowered" {
    const name = "PIPELINE_JOB_OOMSCOREADJ=";
    try std.testing.expectEqual(@as(i32, 500), pickOomScoreAdj(&.{"A=b"}, 0));
    try std.testing.expectEqual(@as(i32, 300), pickOomScoreAdj(&.{name ++ "300"}, 0));
    try std.testing.expectEqual(@as(i32, 1000), pickOomScoreAdj(&.{name ++ "1000"}, 0));
    // Out of range or not a number: 500, as upstream.
    for ([_][]const u8{ name ++ "1001", name ++ "-1001", name ++ "lots", name }) |bad|
        try std.testing.expectEqual(@as(i32, 500), pickOomScoreAdj(&.{bad}, 0));
    // Not below the runner's own: a negative or low value from a workflow is only a request.
    try std.testing.expectEqual(@as(i32, 0), pickOomScoreAdj(&.{name ++ "-1000"}, 0));
    try std.testing.expectEqual(@as(i32, 200), pickOomScoreAdj(&.{name ++ "100"}, 200));
    try std.testing.expectEqual(@as(i32, 500), pickOomScoreAdj(&.{}, -500));
}

test "a host path swapped for a symlink after its check fails to open, wherever on its way" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    for ([_][]const u8{ "allowed/mid/sub", "outside/sub" }) |d| try tmp.dir.createDirPath(io, d);
    const base = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const sub = try std.fmt.allocPrint(arena, "{s}/allowed/mid/sub", .{base});
    // Checked: the canonical path `host_paths.resolve` gave the runner opens.
    const ok = openHostPath(arena, sub);
    try std.testing.expect(ok == .fd);
    _ = linux.close(ok.fd);
    // Then the last name swapped for a link out of the allowed directory: the open fails.
    try tmp.dir.rename("allowed/mid/sub", tmp.dir, "allowed/mid/was-sub", io);
    try tmp.dir.symLink(io, "../../outside/sub", "allowed/mid/sub", .{});
    const last = openHostPath(arena, sub);
    try std.testing.expect(last == .err and last.err == .LOOP);
    // And a name on the way.
    try tmp.dir.deleteFile(io, "allowed/mid/sub");
    try tmp.dir.rename("allowed/mid/was-sub", tmp.dir, "allowed/mid/sub", io);
    try tmp.dir.rename("allowed/mid", tmp.dir, "allowed/was-mid", io);
    try tmp.dir.symLink(io, "../outside", "allowed/mid", .{});
    const middle = openHostPath(arena, sub);
    try std.testing.expect(middle == .err and middle.err == .LOOP);
}
