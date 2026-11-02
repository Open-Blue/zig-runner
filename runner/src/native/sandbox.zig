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
//! and with it every process in the step's PID namespace. The helper's stdout is the step's stdout
//! and stderr, streamed into the job's log as it is read; its stderr carries only its own failures,
//! so anything there means the sandbox, not the step, failed.
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
        /// Its mount point is made when the overlay has none, owned by the job's root, as Dagger
        /// makes a cache mount's missing parents.
        make: bool = false,
    };

    /// The job's overlay (`lowers`, `upper`) is still mounted, and this step's layer is where
    /// what the action writes into the shared directories lands, as GitHub's `docker run` writes
    /// into the host's workspace through its bind. `files` go into the job's overlay too.
    pub const Container = struct {
        /// The image's filesystem, absolute: the container's only lower layer.
        rootfs: []const u8,
        /// The container's own layer (thrown away when the step ends, as `docker run --rm`
        /// does), its work directory and its mount point, relative to `root`.
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
/// helper's own failure, when the sandbox could not be made. `killed`: it was stopped by
/// `Running.kill`, so its end is not the step's own.
pub const Ended = struct { code: i32, failure: []const u8, killed: bool = false };

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
    child.stdin.?.writeStreamingAll(io, json.written()) catch {};
    running.begin(io, child.stdin.?);
    child.stdin = null;
    defer running.end(io);
    return finish(arena, io, &child, running, out);
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
    while (true) {
        const n = child.stdout.?.readStreaming(io, &.{&buf}) catch break;
        if (n == 0) break;
        out.chunk(buf[0..n]);
    }
    var failure: std.ArrayList(u8) = .empty;
    while (failure.items.len < max_failure_bytes) {
        const n = child.stderr.?.readStreaming(io, &.{&buf}) catch break;
        if (n == 0) break;
        try failure.appendSlice(arena, buf[0..n]);
    }
    const term = try child.wait(io);
    const code: i32 = switch (term) {
        .exited => |c| c,
        .signal => |s| 128 + @as(i32, @intCast(@backingInt(s))),
        else => 128,
    };
    return .{
        .code = code,
        .failure = std.mem.trimEnd(u8, failure.items, "\n"),
        .killed = running.wasKilled(io),
    };
}

const max_failure_bytes = 16 * 1024;

/// Where `run` hands the step's output, in pieces as read (not lines).
pub const Output = struct {
    ptr: *anyopaque,
    chunkFn: *const fn (ptr: *anyopaque, bytes: []const u8) void,

    fn chunk(o: Output, bytes: []const u8) void {
        o.chunkFn(o.ptr, bytes);
    }
};

/// The helper running now, if any, for `kill` from another task (a timeout or a cancel, through
/// `dagger.Watch`): its lifeline, the write end of its stdin.
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
const resolve_no_symlinks = 0x04;

const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };

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
    const rc = linux.syscall4(
        .openat2,
        @as(usize, @bitCast(@as(isize, root))),
        @intFromPtr(path),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    const e = linux.errno(rc);
    return if (e == .SUCCESS) .{ .fd = @intCast(rc) } else .{ .err = e };
}

/// The contents of `path` in a layer, read by the runner: resolved inside the layer and through no
/// symlink. `missing` when it is not a regular file there; `whiteout` when the layer deletes it (an
/// overlay whiteout, a character device), so lower layers must not be looked in.
pub fn readIn(
    arena: Allocator,
    layer: []const u8,
    path: []const u8,
    limit: usize,
) !union(enum) { text: []const u8, missing, whiteout } {
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
    }, 0, resolve_no_symlinks)) {
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
    const rel = std.mem.trim(u8, path, "/");
    const p = arena.dupeSentinel(u8, if (rel.len == 0) "." else rel, 0) catch return null;
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .PATH = true };
    return switch (openIn(root, p, flags, 0, 0)) {
        .fd => |f| f,
        .err => null,
    };
}

// --- the helper ---

/// The helper's entry: reads the spec from stdin, runs the step, and exits with its code. Uses
/// only raw system calls once it has the spec, so nothing starts a thread before `unshare`.
pub fn main(arena: Allocator) u8 {
    const spec = readSpec(arena) catch |e| fatal("cannot read the step's spec", @intFromError(e));
    return runStep(arena, spec);
}

/// The spec's one line from stdin, read a byte at a time so nothing after it is taken: what
/// follows on the pipe is the lifeline's end.
fn readSpec(arena: Allocator) !Spec {
    return readJsonLine(Spec, arena);
}

/// A helper's spec: one line of JSON on stdin (`readSpec`; `forward.zig`'s too).
pub fn readJsonLine(comptime T: type, arena: Allocator) !T {
    var data: std.ArrayList(u8) = .empty;
    while (true) {
        var c: [1]u8 = undefined;
        const rc = linux.read(0, &c, 1);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0 or c[0] == '\n') break;
        try data.append(arena, c[0]);
    }
    return std.json.parseFromSliceLeaky(T, arena, data.items, .{ .allocate = .alloc_always });
}

fn runStep(arena: Allocator, spec: Spec) u8 {
    // First, so every process the step makes, and this helper, is held to the job's limits.
    if (spec.cgroup) |dir| joinCgroup(arena, dir);
    // Files a step creates get the modes they get under runc.
    _ = linux.syscall1(.umask, 0o022);
    check("chdir to the job directory", linux.chdir(z(arena, spec.root)));
    // A service's state goes to a file of the job's (`health.Ready.status`), opened while the
    // helper is still the host's user that may.
    const status: linux.fd_t = if (spec.service) |s| health.openStatus(arena, s.status) else -1;

    // 1. The user namespace, and the overlay mounted in a mount namespace the helper owns.
    var lowers = spec.lowers;
    switch (spec.userns) {
        .mapped => {
            // As the host's root: into the job's network, then a namespace of the job's ids, the
            // rootfs seen through it (an idmapped mount, so its root's files are the job's
            // root's), the overlay mounted, and only then into the namespace.
            if (spec.netns) |p| joinNetns(arena, p);
            const userns = mappedUserns(0, spec.id_base, spec.id_count);
            // The cache volumes' on-disk ids, seen as the job's.
            var volumes = false;
            for (spec.binds) |bd| volumes = volumes or bd.volume;
            const volume_ns: ?linux.fd_t = if (volumes)
                mappedUserns(spec.volume_id_base, spec.id_base, spec.id_count)
            else
                null;
            check("unshare(mount)", linux.unshare(linux.CLONE.NEWNS));
            makePrivate();
            lowers = idmapLowers(arena, spec.lowers, spec.image_layers, spec.canonical, userns);
            mountOverlay(arena, spec, lowers, false);
            if (spec.container) |c|
                mountContainer(arena, c, idmapped(arena, c.rootfs, userns, "I"), false);
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
        },
        .self, .inherited => {
            if (spec.userns == .self) enterUserns();
            makePrivate();
            mountOverlay(arena, spec, lowers, true);
            if (spec.container) |c| mountContainer(arena, c, c.rootfs, true);
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
    if (spec.userns != .mapped) bindAll(arena, spec, null);
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
        stepInit(arena, root, workdir, spec.uid, spec.gid, nnp, alive[0], in_image, program, argv, envp);
    }
    _ = linux.close(alive[0]);
    const st = if (spec.service) |s|
        health.supervise(arena, spec, s, @intCast(pid), root, status, env)
    else
        superviseStep(@intCast(pid));
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
/// job's root's.
fn bindAll(arena: Allocator, spec: Spec, volume_ns: ?linux.fd_t) void {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const rc = linux.open(z(arena, topOf(spec)), flags, 0);
    check("open the overlay", rc);
    const root: linux.fd_t = @intCast(rc);
    defer _ = linux.close(root);
    const owner: ?u32 = if (spec.userns == .mapped) spec.id_base else null;
    for (spec.binds) |bd| {
        if (bd.make) makeDirsIn(arena, root, bd.at, owner);
        if (bd.volume) {
            bindVolumeIn(arena, root, bd.host, bd.at, volume_ns);
            continue;
        }
        if (!bindIn(arena, root, bd.host, bd.at, !bd.optional)) continue;
        if (bd.read_only) remountReadOnly(arena, root, bd.at);
    }
}

/// A cache volume at `at`, writable, nosuid and nodev, and idmapped through `userns` when given:
/// a detached clone of the host's directory, its attributes set in one `mount_setattr`, then
/// moved into place. Fails the step when it cannot.
fn bindVolumeIn(
    arena: Allocator,
    root: linux.fd_t,
    host: []const u8,
    at: []const u8,
    userns: ?linux.fd_t,
) void {
    const open_tree_clone = 1;
    const tree = linux.syscall3(
        .open_tree,
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(z(arena, host)),
        open_tree_clone | linux.SOCK.CLOEXEC,
    );
    check(about(arena, "open the cache volume for", at), tree);
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
    const target = targetIn(arena, root, at, true) orelse
        fatal(about(arena, "find", at), @as(u32, 2));
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

/// The directory `path` in the overlay, its missing parts made (mode 0755) inside it, each one
/// made owned by host id `owner` when given (the job's root on a root runner, which the helper,
/// still the host's root here, is not).
fn makeDirsIn(arena: Allocator, root: linux.fd_t, path: []const u8, owner: ?u32) void {
    const rel = std.mem.trim(u8, path, "/");
    var i: usize = 0;
    while (i <= rel.len) {
        const end = std.mem.indexOfScalarPos(u8, rel, i, '/') orelse rel.len;
        const parent = dirIn(arena, root, rel[0..i]) orelse return;
        defer _ = linux.close(parent);
        const name = z(arena, rel[i..end]);
        if (linux.errno(linux.mkdirat(parent, name, 0o755)) == .SUCCESS) if (owner) |o| {
            _ = linux.fchownat(parent, name, o, o, linux.AT.SYMLINK_NOFOLLOW);
        };
        i = end + 1;
    }
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
    if (userxattr) opts.appendSlice(arena, ",userxattr") catch oom();
    return opts.toOwnedSliceSentinel(arena, 0) catch oom();
}

fn mountOverlay(arena: Allocator, spec: Spec, lowers: []const []const u8, userxattr: bool) void {
    check("mount the overlay", linux.mount(
        "overlay",
        z(arena, spec.merged),
        "overlay",
        0,
        @intFromPtr(overlayOptions(arena, spec, lowers, userxattr).ptr),
    ));
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

/// A Docker action's overlay: the image's filesystem (`lower`, idmapped on a root runner) under
/// the container's own layer.
fn mountContainer(arena: Allocator, c: Spec.Container, lower: []const u8, userxattr: bool) void {
    const opts = std.fmt.allocPrint(arena, "lowerdir={s},upperdir={s},workdir={s}{s}", .{
        lower,
        c.upper,
        c.work,
        if (userxattr) ",userxattr" else "",
    }) catch oom();
    check("mount the container's overlay", linux.mount(
        "overlay",
        z(arena, c.merged),
        "overlay",
        0,
        @intFromPtr(z(arena, opts)),
    ));
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

/// Waits for the step's PID 1, killing it when the lifeline (stdin) closes or says anything: the
/// runner stopped the step, or is gone. Killing PID 1 kills every process of the step's PID
/// namespace. The wait status.
fn superviseStep(pid: linux.pid_t) u32 {
    const pidfd_rc = linux.pidfd_open(pid, 0);
    const pidfd: ?linux.fd_t = if (linux.errno(pidfd_rc) == .SUCCESS) @intCast(pidfd_rc) else null;
    while (true) {
        var fds = [_]linux.pollfd{
            .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = pidfd orelse -1, .events = linux.POLL.IN, .revents = 0 },
        };
        // Without a pidfd (Linux before 5.3), the step's end is polled for.
        const rc = linux.poll(&fds, fds.len, if (pidfd == null) 100 else -1);
        if (linux.errno(rc) == .INTR) continue;
        check("wait for the step or its stop", rc);
        if (fds[0].revents != 0) {
            _ = linux.kill(pid, .KILL);
            break;
        }
        if (fds[1].revents != 0) break;
        if (pidfd == null) {
            var status: i32 = 0;
            const done = linux.waitpid(pid, &status, linux.W.NOHANG);
            if (linux.errno(done) == .SUCCESS and done == @as(usize, @intCast(pid)))
                return @bitCast(status);
        }
    }
    var status: i32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        if (linux.errno(rc) == .INTR) continue;
        check("wait for the step", rc);
        break;
    }
    return @bitCast(status);
}

/// PID 1 of the step: its /dev, /proc and /sys, the overlay as its root (`pivot_root`, the host's
/// root detached), its working directory, capabilities, user, no_new_privs and seccomp filter,
/// then the shell. Never returns.
fn stepInit(
    arena: Allocator,
    root: linux.fd_t,
    workdir: [*:0]const u8,
    uid: u32,
    gid: u32,
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
        check("setgroups", linux.setgroups(0, no_groups));
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

/// Makes the mount at `at` read-only, and fails the step when it cannot. The mount's own flags
/// go with it: in a user namespace, those a more privileged one set (nosuid, nodev, noexec, the
/// atime ones) are locked, and a remount that drops any of them is refused, as runc found.
fn remountReadOnly(arena: Allocator, root: linux.fd_t, at: []const u8) void {
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
    check("remount read-only", linux.mount(
        null,
        procFd(arena, fd),
        null,
        linux.MS.REMOUNT | linux.MS.BIND | linux.MS.RDONLY | keep,
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

test "homeOf reads the home directory of a uid from /etc/passwd" {
    const passwd = "root:x:0:0:root:/root:/bin/bash\n" ++
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" ++
        "runner:x:1001:1001::/home/runner:/bin/bash\n";
    try std.testing.expectEqualStrings("/root", homeOf(passwd, 0).?);
    try std.testing.expectEqualStrings("/home/runner", homeOf(passwd, 1001).?);
    try std.testing.expect(homeOf(passwd, 7) == null);
    try std.testing.expect(homeOf("garbage", 0) == null);
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
