//! `hashFiles()` on the native backend: glob.zig's search and GitHub's hash over the job's files as
//! the next step would see them, read from the layers themselves.
//!
//! The job's view is overlay's merge of its layers (the steps' uppers, the Zig cache seeds, the
//! rootfs), which is only a mount inside a step's sandbox. The runner does not mount it: that needs
//! privilege a rootless runner has not got, and a mount of the runner's own for each call would be
//! slower than the walk. `Merged` is the merge done by lookup instead, as `Store.flatten` does it
//! for a whole tree: the topmost layer with an entry decides what it is, a whiteout deletes it, a
//! non-directory hides what is below it, and a directory marked opaque stops the directories
//! below it from adding their entries. Overlay's redirects and metacopy, which the runner never
//! asks for but a host's kernel may default to, are refused (the call fails) rather than read
//! wrongly. Mounts (the cache volumes, an action's runtime) are in no layer, so they are not seen,
//! as Dagger's `rootfs` does not see them either.
//!
//! The layers are the job's to write, so every look at one goes through `sandbox.openIn` with no
//! symlink followed: a link in a layer is read, never taken. The links of the merged view (the
//! job's `docs -> ../docs`, which GitHub's `fs.statSync` follows when it hashes a link that
//! `hashFiles()` found) are resolved here, on the merged paths, with `/` the job's root, so an
//! absolute link names the job's file and not the host's, and `..` is taken on the path already
//! resolved. Nothing the job plants reaches a file outside the layers.
//!
//! The job also controls how much there is to do, so a call is bounded (`Limits`): the files and
//! directories its walk visits, the path components it takes, the memory it holds (its own arena,
//! freed when it returns), the time it takes (GitHub's 120 seconds), and it stops when the job is
//! cancelled, also in the middle of a file. A file is read in full, however large and however
//! sparse: the hash is GitHub's, which has no shortcut for holes, so only the time limit or a
//! cancel ends a read of a file that takes hours.
//!
//! The runner reads as itself, but a file is hashed only if the step's user could read it, as
//! Dagger's did (`dagger/hash_files.zig`). The two halves of that call ran as different users, and
//! this keeps them apart. The search was the engine's own (`exists` and `entries` on `rootfs`), so
//! it sees what the step's user could not, here as there; what it finds may name such a file, and
//! a name was all Dagger's search gave too. The read was `sha256sum` as the step's user, and
//! `realpath` when links are followed as well: those two are `Merged.checked`. Which of the
//! kernel's checks that takes is in `Merged.stepMay`, for a file, and in `Merged.walkPath`, for
//! the directories on the way, where a search permission missing ends the walk before the name is
//! looked up: what is behind such a directory, or is not, then reads the same.

const std = @import("std");
const linux = std.os.linux;
const expr = @import("../expr.zig");
const glob = @import("../glob.zig");
const sandbox = @import("sandbox.zig");
const images = @import("images.zig");
const Store = @import("Store.zig");
const dagger = @import("../dagger.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Error = glob.Fs.Error;

/// GitHub's own limit for one `hashFiles()` (`_hashFileTimeoutSeconds` in actions/runner's
/// `HashFilesFunction.cs`, which throws "couldn't finish within 120 seconds").
pub const default_timeout_s: u32 = 120;

/// What the runner configures (`RUNNER_NATIVE_HASHFILES_MEMORY_MB`, `RUNNER_NATIVE_HASHFILES_TIMEOUT_S`).
pub const Settings = struct {
    /// What one call may hold once it has its turn (see `Budget`); null for the smaller of 1 GiB
    /// and an eighth of the machine's memory (`MemTotal`, which in a container is the host's: the
    /// runner has no reading of its own cgroup's limit), 0 for no limit.
    memory_mb: ?u32 = null,
    /// How long one call may take; 0 for no limit.
    timeout_s: u32 = default_timeout_s,

    pub fn limits(s: Settings, io: std.Io) Limits {
        const memory: usize = if (s.memory_mb) |mb|
            (if (mb == 0) std.math.maxInt(usize) else @as(usize, mb) << 20)
        else
            @min(1 << 30, (memTotal(io) orelse (8 << 30)) / 8);
        return .{
            .memory = memory,
            .allowance = @min(64 << 20, memory / 4),
            .timeout_ms = if (s.timeout_s == 0) std.math.maxInt(u64) else @as(u64, s.timeout_s) * 1000,
        };
    }
};

/// `MemTotal` in /proc/meminfo, in bytes.
fn memTotal(io: std.Io) ?usize {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/meminfo", &buf) catch return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var words = std.mem.tokenizeScalar(u8, line["MemTotal:".len..], ' ');
        const kb = std.fmt.parseInt(usize, words.next() orelse return null, 10) catch return null;
        return kb * 1024;
    }
    return null;
}

/// The memory the calls of this process share. The memory is the runner's, not the job's cgroup's,
/// and there is one process for all the jobs of a machine, so the limit is for all of them: but a
/// call cannot wait for memory it needs while holding memory others need, or two of them wait for
/// each other for good. So the memory is not shared out by the byte. Each call has a small
/// allowance of its own (`Limits.allowance`) that no one else's use touches, and a call that goes
/// past it takes the turn, one at a time in the order they asked, and then has the whole of
/// `Limits.memory` to itself until it returns. A call waiting for its turn holds only its
/// allowance, and the one whose turn it is waits for nothing, so there is nothing to wait in a
/// circle on: a big call is delayed by the big calls before it, one turn each, and is failed only
/// when it is too big alone.
///
/// The tool trees' checks (`tool_trees.zig`) share the number, not the queue: `held` is every
/// byte that calls and checks hold now. A check never waits and is refused (its tree left out, the
/// job goes on) when `held` would pass its limit; a call is never refused for what checks hold, so
/// a check cannot fail a `hashFiles()`, and a check holds memory only for as long as it takes.
pub const Budget = struct {
    spin: std.atomic.Value(bool) = .init(false),
    /// Bytes held now by the calls (under their allowance and in their turn) and by the checks.
    held: std.atomic.Value(u64) = .init(0),
    /// The ticket the next call to ask gets, and the one whose turn it is.
    next: u64 = 0,
    serving: u64 = 0,
    /// Tickets of calls that gave up waiting, to be passed over when their turn comes.
    skipped: [max_skipped]u64 = undefined,
    n_skipped: usize = 0,

    const max_skipped = 256;

    fn lock(b: *Budget) void {
        while (b.spin.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(b: *Budget) void {
        b.spin.store(false, .release);
    }

    /// A place in the queue. It is the caller's to give back with `done`, whether it got its turn
    /// or not.
    pub fn ticket(b: *Budget) u64 {
        b.lock();
        defer b.unlock();
        defer b.next += 1;
        return b.next;
    }

    /// The ticket being served: it moves as the queue does.
    pub fn position(b: *Budget) u64 {
        b.lock();
        defer b.unlock();
        return b.serving;
    }

    pub fn isTurn(b: *Budget, t: u64) bool {
        b.lock();
        defer b.unlock();
        return b.serving == t;
    }

    /// Ends the turn of ticket `t`, or its wait: the next in the queue is served. False when the
    /// ticket cannot be passed over yet (its call is far back in a queue of hundreds), and the
    /// caller must wait for its turn first.
    pub fn done(b: *Budget, t: u64) bool {
        b.lock();
        defer b.unlock();
        if (b.serving == t) {
            b.serving += 1;
            b.passOver();
            return true;
        }
        if (b.n_skipped == max_skipped) return false;
        b.skipped[b.n_skipped] = t;
        b.n_skipped += 1;
        return true;
    }

    fn passOver(b: *Budget) void {
        var again = true;
        while (again) {
            again = false;
            for (b.skipped[0..b.n_skipped], 0..) |t, i| if (t == b.serving) {
                b.skipped[i] = b.skipped[b.n_skipped - 1];
                b.n_skipped -= 1;
                b.serving += 1;
                again = true;
                break;
            };
        }
    }
};

/// The budget of this process's calls.
pub var process_budget: Budget = .{};

/// What one call may use. A job's own files decide how much work they are.
pub const Limits = struct {
    /// Files and directories the walk visits (`glob.max_nodes`).
    nodes: usize = glob.max_nodes,
    /// Path components taken, one for each name of each path looked up and each entry listed: a
    /// real tree of a million files at depth ten is about twenty million.
    steps: u64 = 200_000_000,
    /// What a call may hold once it has the turn, and what it has before that (see `Budget`): a
    /// call is held to `allowance + memory` at most, and the calls of a process to `memory` and
    /// one allowance for each that is running.
    memory: usize = 1 << 30,
    allowance: usize = 64 << 20,
    budget: *Budget = &process_budget,
    /// How long a call may work, as GitHub's does (`default_timeout_s`). The time it waits for its
    /// turn is not part of it, as it is not the call's own: it is limited on its own to as long
    /// again, which is the longest a call may hold the turn it is waiting for.
    timeout_ms: u64 = default_timeout_s * 1000,
    /// The job's cancel. A call it interrupts stops at once; one that began after it (an
    /// `if: always()` step, the job's outputs) runs on, as GitHub's does in the grace period, until
    /// its `hard_deadline_ms`. Waiting for a turn is interrupted the same way.
    cancel: ?*const dagger.Cancel = null,
};

/// The layers of the job's overlay, as it would mount them for the next step.
pub const Stack = struct {
    /// Their directories, topmost first: the job's layers newest first, the Zig cache seeds', then
    /// the rootfs (`Backend.execIn`'s `lowers`, in the same order).
    layers: []const []const u8,
    /// Overlay's opaque-directory attribute: `trusted.overlay.opaque`, or `user.overlay.opaque`
    /// under `userxattr` (`Backend.opaqueXattr`).
    opaque_xattr: [:0]const u8,
    /// Whose permissions decide what is read; null for a step that may read everything. No
    /// default: every caller says.
    step: ?Step,
    limits: Limits = .{},
};

/// The step's user, for whom a call reads, as the job's namespace sees it. Null in `Stack.step`
/// for root, which needs no check on either kind of runner: root in a step has `CAP_DAC_OVERRIDE`
/// (`sandbox.docker_caps`), as Dagger's had, and a rootless runner's steps are all root.
pub const Step = struct {
    uid: u32,
    gid: u32,
    /// As the engine was given it: the image's `USER`, or `dagger.runner_user`. Its form decides
    /// the supplementary groups (`Merged.supplementary`), which `uid` and `gid` cannot say.
    user: []const u8,
    /// How each layer's ids look from the job, by position in `Stack.layers`: a layer holds
    /// the canonical ids, the slot's or the runner's own (`Backend.hashStep`).
    ids: []const Store.Ids,
};

/// An allocator that counts what it hands out, and refuses what a call may not have: past its
/// allowance it takes the turn (waiting for it, where the job's cancel and the time it may wait
/// are seen), and past `limit` in its turn it is refused. So a call that grows too far stops where
/// it is, whatever it was doing.
const Counted = struct {
    child: Allocator,
    io: std.Io,
    budget: *Budget,
    limit: usize,
    allowance: usize,
    cancel: ?*const dagger.Cancel,
    cancelled_before: bool,
    wait_limit_ms: u64,
    /// Bytes under the allowance, and bytes in the turn.
    free_used: usize = 0,
    pool_used: usize = 0,
    ticket: ?u64 = null,
    turn: bool = false,
    /// The task was cancelled during a wait (`nap`), which ended it.
    io_cancelled: bool = false,
    /// How long the call waited in all, so that its own clock leaves it out.
    waited_ms: i64 = 0,
    refused: Refusal = .none,

    const Refusal = enum { none, too_big, cancelled, waited_too_long };

    fn allocator(c: *Counted) Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn of(ctx: *anyopaque) *Counted {
        return @ptrCast(@alignCast(ctx));
    }

    fn take(c: *Counted, n: usize) bool {
        if (c.free_used + n <= c.allowance and !c.turn) {
            c.free_used += n;
            _ = c.budget.held.fetchAdd(n, .acq_rel);
            return true;
        }
        // Refused already: the arena tries again after a resize, and a second wait would be for
        // nothing.
        if (!c.turn and c.refused != .none) return false;
        if (!c.turn and !c.acquire()) return false;
        if (n > c.limit or c.pool_used > c.limit - n) {
            c.refused = .too_big;
            return false;
        }
        c.pool_used += n;
        _ = c.budget.held.fetchAdd(n, .acq_rel);
        return true;
    }

    fn give(c: *Counted, n: usize) void {
        const from_pool = @min(n, c.pool_used);
        const from_free = @min(n - from_pool, c.free_used);
        c.pool_used -= from_pool;
        c.free_used -= from_free;
        _ = c.budget.held.fetchSub(from_pool + from_free, .acq_rel);
    }

    /// Waits for the turn, in the queue's order.
    fn acquire(c: *Counted) bool {
        const t = c.budget.ticket();
        c.ticket = t;
        const began = nowMs(c.io, .awake);
        // The limit is on a queue that has stopped, not on the wait: each call ahead may hold the
        // turn for its own timeout, so a wait is as long as the calls ahead make it, and a job
        // that keeps taking turns only delays a neighbour.
        var moved = began;
        var seen = c.budget.position();
        while (!c.budget.isTurn(t)) {
            const position = c.budget.position();
            if (position != seen) {
                seen = position;
                moved = nowMs(c.io, .awake);
            }
            if (c.cancel) |cancel| {
                if (!c.cancelled_before and cancel.requested.load(.acquire)) return c.abandon(.cancelled);
                if (c.cancelled_before) {
                    const hard = cancel.hard_deadline_ms.load(.acquire);
                    if (hard > 0 and nowMs(c.io, .real) > hard) return c.abandon(.cancelled);
                }
            }
            if (c.wait_limit_ms != std.math.maxInt(u64) and nowMs(c.io, .awake) - moved > c.wait_limit_ms)
                return c.abandon(.waited_too_long);
            c.nap();
            if (c.io_cancelled) return c.abandon(.cancelled);
        }
        c.waited_ms += nowMs(c.io, .awake) - began;
        c.turn = true;
        return true;
    }

    /// Gives up the wait, which still has its place in the queue.
    fn abandon(c: *Counted, why: Refusal) bool {
        c.refused = why;
        const t = c.ticket.?;
        c.ticket = null;
        if (!c.budget.done(t)) {
            // Too many have given up for it to be remembered: it stays until its turn, then ends.
            while (!c.budget.isTurn(t)) c.nap();
            _ = c.budget.done(t);
        }
        // std.Io delivers a cancel once: re-armed for what runs after the call. Not sooner, or
        // each nap above would return at once and the wait would spin.
        if (c.io_cancelled) c.io.recancel();
        return false;
    }

    /// One look's wait. An allocator's callback can return no error, so a cancel is kept for later.
    fn nap(c: *Counted) void {
        c.io.sleep(.fromMilliseconds(2), .awake) catch {
            c.io_cancelled = true;
        };
    }

    /// The call is over (its arena freed): the next in the queue has the turn.
    fn release(c: *Counted) void {
        if (c.ticket) |t| _ = c.budget.done(t);
        c.ticket = null;
        c.turn = false;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c = of(ctx);
        if (!c.take(len)) return null;
        return c.child.rawAlloc(len, alignment, ra) orelse {
            c.give(len);
            return null;
        };
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const c = of(ctx);
        if (new_len > memory.len and !c.take(new_len - memory.len)) return false;
        if (!c.child.rawResize(memory, alignment, new_len, ra)) {
            if (new_len > memory.len) c.give(new_len - memory.len);
            return false;
        }
        if (new_len < memory.len) c.give(memory.len - new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const c = of(ctx);
        if (new_len > memory.len and !c.take(new_len - memory.len)) return null;
        const p = c.child.rawRemap(memory, alignment, new_len, ra) orelse {
            if (new_len > memory.len) c.give(new_len - memory.len);
            return null;
        };
        if (new_len < memory.len) c.give(memory.len - new_len);
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const c = of(ctx);
        c.child.rawFree(memory, alignment, ra);
        c.give(memory.len);
    }
};

/// `hashFiles(args)` over `stack`: the SHA-256 of the SHA-256 digests of the files the patterns
/// find under `ws`, in GitHub's order; "" when none. As GitHub's script does, a name that is a
/// directory once links are followed is skipped, and a link is hashed as the file it leads to.
/// The call works in an arena of its own, freed on return, whose every byte is counted (see
/// `Budget`): only the result is copied to `out`.
pub fn hashFiles(
    gpa: Allocator,
    out: Allocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    const l = stack.limits;
    var counted: Counted = .{
        .child = gpa,
        .io = io,
        .budget = l.budget,
        .limit = l.memory,
        .allowance = l.allowance,
        .cancel = l.cancel,
        .cancelled_before = if (l.cancel) |c| c.requested.load(.acquire) else false,
        .wait_limit_ms = l.timeout_ms *| 2,
    };
    // The turn goes on once the arena is freed (deferred first, so it runs last).
    defer counted.release();
    var scratch: std.heap.ArenaAllocator = .init(counted.allocator());
    defer scratch.deinit();
    const result = runWaited(&scratch, io, stack, ws, home, args, &counted.waited_ms) catch |e| {
        if (e != error.OutOfMemory) return e;
        return .{ .failed = switch (counted.refused) {
            .none => return e,
            .too_big => try std.fmt.allocPrint(
                out,
                "hashFiles() would take more than {d} MiB of memory (RUNNER_NATIVE_HASHFILES_MEMORY_MB, " ++
                    "for one call at a time): the job's tree is too large or too tangled to search",
                .{l.memory >> 20},
            ),
            .cancelled => try out.dupe(u8, "hashFiles() stopped: the job was cancelled"),
            .waited_too_long => try std.fmt.allocPrint(
                out,
                "hashFiles() waited {d} seconds with no other hashFiles() call finishing with " ++
                    "the memory they share (RUNNER_NATIVE_HASHFILES_MEMORY_MB)",
                .{(l.timeout_ms *| 2 + 999) / 1000},
            ),
        } };
    };
    return switch (result) {
        .ok => |h| .{ .ok = try out.dupe(u8, h) },
        .failed => |why| .{ .failed = try out.dupe(u8, why) },
    };
}

var no_wait: i64 = 0;

/// `hashFiles` in `scratch`, which the caller frees.
fn run(
    scratch: *std.heap.ArenaAllocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    return runWaited(scratch, io, stack, ws, home, args, &no_wait);
}

/// As `run`, its clock leaving out `waited` milliseconds (the time spent waiting for the turn).
fn runWaited(
    scratch: *std.heap.ArenaAllocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
    waited: *const i64,
) Allocator.Error!expr.HashFiles.Result {
    var m: Merged = .{
        .arena = scratch.allocator(),
        .io = io,
        .roots = &.{},
        .layers = stack.layers,
        .step = stack.step,
        .opaque_xattr = stack.opaque_xattr,
        .limits = stack.limits,
        .began_ms = nowMs(io, .awake),
        .waited = waited,
    };
    // A call that began after the cancel is not cut short by it: see `Limits.cancel`.
    if (m.limits.cancel) |c| m.cancelled_before = c.requested.load(.acquire);
    m.openLayers(stack.layers) catch |e| return failed(&m, e);
    defer m.close();
    if (stack.step) |s| {
        std.debug.assert(s.ids.len == stack.layers.len);
        m.groups = m.supplementary(s.user) catch |e| return failed(&m, e);
    }
    return hashAll(&m, ws, home, args) catch |e| failed(&m, e);
}

fn nowMs(io: std.Io, clock: std.Io.Clock) i64 {
    return clock.now(io).toMilliseconds();
}

fn failed(m: *const Merged, e: Error) Allocator.Error!expr.HashFiles.Result {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.FsFailed => .{ .failed = m.why },
    };
}

fn hashAll(m: *Merged, ws: []const u8, home: []const u8, args: []const []const u8) Error!expr.HashFiles.Result {
    const arena = m.arena;
    const files = switch (try glob.find(arena, m.fs(), args, ws, home, m.limits.nodes, &m.why)) {
        .failed => |msg| return .{ .failed = msg },
        .files => |f| f,
    };
    // The search is over: from here on it is `sha256sum`, as the step's user.
    m.check(true);
    var all = Sha256.init(.{});
    var hashed: usize = 0;
    var path: std.ArrayList(u8) = .empty;
    for (files) |name| {
        path.clearRetainingCapacity();
        try path.print(arena, "{s}/{s}", .{ ws, name });
        // Not `[ -d ]`'s skip when the walk is refused: `stat` fails under a directory the user
        // cannot enter, so Dagger's script took even a directory for a file, and `sha256sum`
        // failed on it.
        const at = (try m.resolve(path.items, true)) orelse return .{ .failed = if (m.denied)
            try std.fmt.allocPrint(arena, "sha256sum: {s}: Permission denied", .{name})
        else
            try std.fmt.allocPrint(arena, "{s}: No such file or directory", .{name}) };
        switch (at.node.kind) {
            .dir => continue,
            .file => {},
            else => return .{ .failed = try std.fmt.allocPrint(arena, "{s}: Not a regular file", .{name}) },
        }
        const sum = try m.digest(at.path, name, at.node.layer);
        all.update(&sum);
        hashed += 1;
    }
    if (hashed == 0) return .{ .ok = "" };
    return .{ .ok = try arena.dupe(u8, &std.fmt.bytesToHex(all.finalResult(), .lower)) };
}

/// What a path of the merged view is.
const Node = struct {
    kind: enum { missing, whiteout, dir, file, symlink, other },
    /// The topmost layer that has it.
    layer: u32 = 0,
    /// Where a link leads.
    target: []const u8 = "",
    /// A directory marked opaque in its layer.
    opaque_dir: bool = false,
};

/// Links followed in one path before it counts as a loop (Linux's `MAXSYMLINKS`).
const max_links = 40;

/// What the kernel takes as a path (`PATH_MAX`, with its terminating zero).
const path_max = 4096;

/// What a path resolves to: the real path and what it is.
const Resolved = struct { path: []const u8, node: Node };

/// Where a followed link leads, how many links that took, and whether it was walked as the step's
/// user: where a link leads is the same for all, but one walked only by the search does not say
/// the step's user may take it.
const Lead = struct { to: Resolved, cost: u32, checked: bool };

/// The merged view of a stack of layers. Paths are absolute, `/` the job's root, with no symlink,
/// `.` or `..` in a path that names a real entry (`resolve` makes them so); the root is "".
const Merged = struct {
    arena: Allocator,
    io: std.Io,
    limits: Limits,
    /// When the call began (the monotonic clock, ms), and whether the job had been cancelled then.
    began_ms: i64,
    /// Milliseconds the call spent waiting for its turn: its own clock leaves them out.
    waited: *const i64,
    cancelled_before: bool = false,
    /// The layers' directories, opened, topmost first.
    roots: []linux.fd_t,
    /// Their paths, in the same order.
    layers: []const []const u8,
    /// Who reads (`Stack.step`), and the supplementary groups of that user.
    step: ?Step,
    groups: []const u32 = &.{},
    /// Whether walks are the step's user's, in the kernel's order (`walkPath`), or the search's.
    checked: bool = false,
    /// A checked walk stopped at a directory the step's user may not search, which ends the call.
    denied: bool = false,
    /// Whether the step's user may search each real directory walked.
    searchable: std.StringHashMapUnmanaged(bool) = .empty,
    opaque_xattr: [:0]const u8,
    /// The attributes overlay's other features leave (same prefix as `opaque_xattr`).
    redirect_xattr: [:0]const u8 = "",
    metacopy_xattr: [:0]const u8 = "",
    /// What each real path is, and in which layers it is a directory that adds its entries (the
    /// topmost first; null when it is not a directory).
    nodes: std.StringHashMapUnmanaged(Node) = .empty,
    dirs: std.StringHashMapUnmanaged(?[]const u32) = .empty,
    /// Where each link that was followed leads (what its target resolves to), by the link's path.
    leads: std.StringHashMapUnmanaged(Lead) = .empty,
    /// The path a top-level `resolve` builds, kept between calls.
    path: std.ArrayList(u8) = .empty,
    /// The directory the last `resolve` was in as it was asked, where that really is, and the
    /// links it took to get there.
    dir_in: std.ArrayList(u8) = .empty,
    dir_real: std.ArrayList(u8) = .empty,
    dir_links: u32 = 0,
    steps: u64 = 0,
    /// What went wrong, for `Error.FsFailed`.
    why: []const u8 = "",

    fn openLayers(m: *Merged, layers: []const []const u8) Error!void {
        const prefix = m.opaque_xattr[0 .. m.opaque_xattr.len - "opaque".len];
        m.redirect_xattr = try std.fmt.allocPrintSentinel(m.arena, "{s}redirect", .{prefix}, 0);
        m.metacopy_xattr = try std.fmt.allocPrintSentinel(m.arena, "{s}metacopy", .{prefix}, 0);
        const roots = try m.arena.alloc(linux.fd_t, layers.len);
        for (layers, 0..) |path, i| {
            const fd = linux.open(try m.arena.dupeSentinel(u8, path, 0), .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
            }, 0);
            if (linux.errno(fd) != .SUCCESS) {
                for (roots[0..i]) |r| _ = linux.close(r);
                return m.fail("cannot read the job's layer {s}: {t}", .{ path, linux.errno(fd) });
            }
            roots[i] = std.math.cast(linux.fd_t, fd).?;
        }
        m.roots = roots;
    }

    fn close(m: *Merged) void {
        for (m.roots) |r| _ = linux.close(r);
    }

    fn fail(m: *Merged, comptime fmt: []const u8, args: anytype) Error {
        m.why = try std.fmt.allocPrint(m.arena, fmt, args);
        return error.FsFailed;
    }

    /// One unit of work: counted, and the job's cancel seen, and every 1024th the clocks read, so
    /// a call the job made too big, or took too long, or that the job gave up on, ends here.
    /// (The memory is counted by the allocator, which refuses what is over the limit.)
    fn tick(m: *Merged) Error!void {
        m.steps += 1;
        if (m.steps > m.limits.steps) return m.fail("hashFiles() took more than {d} steps through the " ++
            "job's files: its tree is too deep or too tangled to search", .{m.limits.steps});
        if (m.limits.cancel) |c| if (!m.cancelled_before and c.requested.load(.acquire))
            return m.fail("hashFiles() stopped: the job was cancelled", .{});
        if (m.steps % 1024 == 0) try m.clocks();
    }

    /// Whether the call's time, or the grace period after a cancel, is over. Each block of a file
    /// reads them too: 1024 blocks are 64 MiB, whose hash takes seconds on a slow machine.
    fn clocks(m: *Merged) Error!void {
        if (m.limits.timeout_ms != std.math.maxInt(u64) and
            nowMs(m.io, .awake) - m.began_ms - m.waited.* > m.limits.timeout_ms)
            return m.fail("couldn't finish within {d} seconds", .{(m.limits.timeout_ms + 999) / 1000});
        // Begun after the cancel, it runs to the end of the grace period GitHub gives.
        if (m.limits.cancel) |c| if (m.cancelled_before) {
            const hard = c.hard_deadline_ms.load(.acquire);
            if (hard > 0 and nowMs(m.io, .real) > hard)
                return m.fail("hashFiles() stopped: the job's grace period after its cancel is over", .{});
        };
    }

    fn fs(m: *Merged) glob.Fs {
        return .{ .ptr = m, .vtable = &.{ .stat = statAll, .list = listAll, .realpath = realpathAll, .poll = pollAll } };
    }

    fn pollAll(ptr: *anyopaque) Error!void {
        return erased(ptr).tick();
    }

    /// Turns the step's user's walks on or off, for a step that is checked at all. The directory
    /// `resolve` keeps was reached by the other kind of walk, so it is forgotten.
    fn check(m: *Merged, on: bool) void {
        if (m.step == null) return;
        m.checked = on;
        m.dir_in.clearRetainingCapacity();
    }

    // --- the step's user ---

    /// The supplementary groups the engine gave the step's user at each exec (BuildKit's
    /// `oci.GetUser`, moby's `user.GetExecUser`), though not a native step's own processes, which
    /// `setgroups(0)` leaves with none (`sandbox.zig`): hashFiles() answers as Dagger did. Those
    /// of a user named by a name or uid that is in /etc/passwd, by the first line that matches,
    /// and none with an explicit group (`app:staff`, `1000:1000`) or for a uid not there. Read
    /// through the job's root like any file, so no link in them leaves the tree, and from the view
    /// the next step has, as the engine read the container's. Not there, or not a file, they give
    /// no group.
    fn supplementary(m: *Merged, user: []const u8) Error![]const u32 {
        if (std.mem.indexOfScalar(u8, user, ':') != null) return &.{};
        const passwd = (try m.userFile("/etc/passwd")) orelse return &.{};
        const line = if (std.fmt.parseInt(u32, user, 10)) |uid|
            images.entryOf(passwd, null, uid)
        else |_|
            images.entryOf(passwd, user, null);
        const name = (line orelse return &.{})[0];
        if (name.len == 0) return &.{};
        const group = (try m.userFile("/etc/group")) orelse return &.{};
        var groups: std.ArrayList(u32) = .empty;
        var lines = std.mem.splitScalar(u8, group, '\n');
        while (lines.next()) |raw| {
            const text = std.mem.trim(u8, raw, " \t\r");
            if (text.len == 0 or text[0] == '#') continue;
            var fields = std.mem.splitScalar(u8, text, ':');
            _ = fields.next();
            _ = fields.next();
            const gid = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
            var members = std.mem.splitScalar(u8, fields.next() orelse continue, ',');
            while (members.next()) |member| if (std.mem.eql(u8, member, name)) {
                try groups.append(m.arena, gid);
                break;
            };
        }
        return groups.items;
    }

    /// `path`'s contents in the job's view, up to the engine's limit: resolved as `resolve` does,
    /// then read from the one layer with no link taken.
    fn userFile(m: *Merged, path: []const u8) Error!?[]const u8 {
        const at = (try m.resolve(path, true)) orelse return null;
        if (at.node.kind != .file) return null;
        const max_bytes = 10 << 20;
        return switch (try sandbox.readIn(m.arena, m.layers[at.node.layer], at.path, max_bytes)) {
            .text => |t| t,
            .missing, .whiteout => null,
        };
    }

    /// Whether the step's user may search the real directory `dir`. The step's `/` is the top of
    /// its own upper, which `Backend.execIn` leaves 0755.
    fn canSearch(m: *Merged, s: Step, dir: []const u8) Error!bool {
        if (dir.len == 0) return true;
        if (m.searchable.get(dir)) |yes| return yes;
        const layer = (try m.entry(dir)).layer;
        var buf: [path_max]u8 = undefined;
        const rel = try m.relativeZ(&buf, dir);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .PATH = true,
            .NOFOLLOW = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| return m.fail("cannot look at {s} in the job's layers: {t}", .{ dir, e }),
        };
        defer _ = linux.close(fd);
        const yes = try m.stepMay(s, fd, layer, dir, may_search);
        try m.searchable.put(m.arena, try m.arena.dupe(u8, dir), yes);
        return yes;
    }

    /// Whether the step's user has `want` on the entry `fd` (`O_PATH`) is in `layer`, by the
    /// kernel's `acl_permission_check`: the owner has the owner's bits, whatever the others have;
    /// an ACL, which is consulted only with group bits set, decides for everyone else; without
    /// one the group's bits go to its members and the others' to the rest. `CAP_DAC_OVERRIDE`, the
    /// only other way past them, is root's (`Step`): a process that changes to another uid has
    /// none.
    fn stepMay(
        m: *Merged,
        s: Step,
        fd: linux.fd_t,
        layer: u32,
        path: []const u8,
        want: u16,
    ) Error!bool {
        var st: linux.Statx = undefined;
        const mask: linux.STATX = .{ .MODE = true, .UID = true, .GID = true };
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, mask, &st)) != .SUCCESS)
            return m.fail("cannot look at {s} in the job's layers", .{path});
        const ids = s.ids[layer];
        if (jobId(ids, st.uid) == s.uid) return st.mode >> 6 & want == want;
        const who: Who = .{ .uid = s.uid, .gid = s.gid, .groups = m.groups, .ids = ids };
        if (st.mode & 0o070 != 0) if (try m.acl(fd, path)) |value|
            return aclGives(value, who, st.gid, want);
        return (if (who.inGroup(jobId(ids, st.gid))) st.mode >> 3 else st.mode) & want == want;
    }

    /// The entry's POSIX ACL as the kernel keeps it, in the call's arena; null when it has none,
    /// or its file system keeps none. `fd` is an `O_PATH` descriptor: through its link in /proc,
    /// as `attributes` does.
    fn acl(m: *Merged, fd: linux.fd_t, path: []const u8) Error!?[]const u8 {
        var proc: [32]u8 = undefined;
        const p = std.mem.printSentinel(&proc, "/proc/self/fd/{d}", .{fd}, 0) catch
            return m.fail("cannot read {s}'s ACL in the job's layers", .{path});
        var value: [64 * 1024]u8 = undefined;
        const got = linux.getxattr(p, "system.posix_acl_access", &value, value.len);
        return switch (linux.errno(got)) {
            .SUCCESS => try m.arena.dupe(u8, value[0..got]),
            .NODATA, .OPNOTSUPP => null,
            else => |e| m.fail("cannot read {s}'s ACL in the job's layers: {t}", .{ path, e }),
        };
    }

    // --- one layer ---

    /// `path` for a layer's `openat2`, in `buf`: relative, "." for the root.
    fn relativeZ(m: *Merged, buf: *[path_max]u8, path: []const u8) Error![:0]const u8 {
        return std.mem.printSentinel(buf, "{s}", .{relative(path)}, 0) catch
            return m.fail("a path in the job's files is longer than {d} bytes", .{path_max - 1});
    }

    /// `path` as a layer has it, with nothing followed: what it is, and where a link leads. A
    /// whiteout is overlay's character device 0:0.
    fn lstat(m: *Merged, layer: u32, path: []const u8) Error!Node {
        var buf: [path_max]u8 = undefined;
        const rel = try m.relativeZ(&buf, path);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .PATH = true,
            .NOFOLLOW = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| {
                if (e == .NOENT or e == .NOTDIR) return .{ .kind = .missing };
                return m.fail("cannot look at {s} in the job's layers: {t}", .{ path, e });
            },
        };
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
            return m.fail("cannot look at {s} in the job's layers", .{path});
        const kind = st.mode & linux.S.IFMT;
        if (kind == linux.S.IFDIR) return .{ .kind = .dir, .opaque_dir = try m.attributes(fd, path, true) };
        if (kind == linux.S.IFREG) {
            _ = try m.attributes(fd, path, false);
            return .{ .kind = .file };
        }
        if (kind == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0)
            return .{ .kind = .whiteout };
        if (kind != linux.S.IFLNK) return .{ .kind = .other };
        var link: [path_max]u8 = undefined;
        const n = linux.readlinkat(fd, "", &link, link.len);
        if (linux.errno(n) != .SUCCESS or n == link.len)
            return m.fail("cannot read the link {s} in the job's layers", .{path});
        return .{ .kind = .symlink, .target = try m.arena.dupe(u8, link[0..n]) };
    }

    /// What overlay's attributes say of an entry of a layer (`fd` is an `O_PATH` one): whether the
    /// directory is opaque. The call fails when it has a redirect or metacopy, which this merge
    /// does not do: what overlay shows is then not what the entry holds, and the hash would be
    /// wrong without a word (`Store.flatten` refuses them as well).
    fn attributes(m: *Merged, fd: linux.fd_t, path: []const u8, is_dir: bool) Error!bool {
        // Through the descriptor's link in /proc, which these (following) calls take to the file.
        var proc: [32]u8 = undefined;
        const p = std.mem.printSentinel(&proc, "/proc/self/fd/{d}", .{fd}, 0) catch
            return m.fail("cannot look at {s}'s attributes in the job's layers", .{path});
        var small: [1024]u8 = undefined;
        var list: []u8 = &small;
        var n = linux.listxattr(p, list.ptr, list.len);
        // A list that does not fit is asked its size.
        if (linux.errno(n) == .RANGE) {
            const size = linux.listxattr(p, list.ptr, 0);
            if (linux.errno(size) == .SUCCESS) {
                list = try m.arena.alloc(u8, size + 4096);
                n = linux.listxattr(p, list.ptr, list.len);
            } else n = size;
        }
        switch (linux.errno(n)) {
            .SUCCESS => {},
            // A file system without attributes cannot have marked anything.
            .NODATA, .OPNOTSUPP => return false,
            // The kernel lists no more than 64 KiB (`XATTR_LIST_MAX`), and a tmpfs holds up to 128
            // KiB of attributes: the three that matter are asked for by name.
            .@"2BIG" => return m.attributesByName(p, path, is_dir),
            else => |e| return m.fail("cannot read {s}'s attributes in the job's layers: {t}", .{ path, e }),
        }
        var opaque_dir = false;
        var names = std.mem.splitScalar(u8, list[0..n], 0);
        while (names.next()) |name| {
            if (std.mem.eql(u8, name, m.redirect_xattr) or std.mem.eql(u8, name, m.metacopy_xattr))
                return m.redirected(path);
            if (is_dir and std.mem.eql(u8, name, m.opaque_xattr)) opaque_dir = true;
        }
        return opaque_dir and try m.opaqueValue(p, path);
    }

    /// `attributes` for an entry whose list of them is too long to be listed.
    fn attributesByName(m: *Merged, p: [:0]const u8, path: []const u8, is_dir: bool) Error!bool {
        var none: [1]u8 = undefined;
        for ([_][:0]const u8{ m.redirect_xattr, m.metacopy_xattr }) |name| {
            const got = linux.getxattr(p, name, &none, 0);
            switch (linux.errno(got)) {
                .SUCCESS => return m.redirected(path),
                .NODATA, .OPNOTSUPP => {},
                else => |e| return m.fail("cannot read {s}'s attributes in the job's layers: {t}", .{ path, e }),
            }
        }
        return is_dir and try m.opaqueValue(p, path);
    }

    fn redirected(m: *Merged, path: []const u8) Error {
        return m.fail("{s} is renamed or copied up by overlay's redirect or metacopy in the " ++
            "job's layers, which hashFiles() cannot read", .{path});
    }

    /// Whether the opaque mark is the "y" overlay writes.
    fn opaqueValue(m: *Merged, p: [:0]const u8, path: []const u8) Error!bool {
        var value: [1]u8 = undefined;
        const got = linux.getxattr(p, m.opaque_xattr, &value, value.len);
        return switch (linux.errno(got)) {
            .SUCCESS => got == 1 and value[0] == 'y',
            // Gone since it was listed, or longer than one byte (so not "y").
            .NODATA, .RANGE, .OPNOTSUPP => false,
            // Not being able to read it (a directory the runner may not read, rootless) must not
            // read as "not opaque": the entries below it would show through.
            else => |e| m.fail("cannot read {s}'s attributes in the job's layers: {t}", .{ path, e }),
        };
    }

    // --- the merge ---

    /// The layers that add to the directory `dir`, topmost first: those where it is a directory,
    /// down to the first where it is hidden (a whiteout, or a file or link there) or opaque.
    /// Null when it is not a directory.
    fn contribs(m: *Merged, dir: []const u8) Error!?[]const u32 {
        if (m.dirs.get(dir)) |c| return c;
        var found: std.ArrayList(u32) = .empty;
        if (dir.len == 0) {
            var i: u32 = 0;
            while (i < m.roots.len) : (i += 1) try found.append(m.arena, i);
        } else if (try m.contribs(parentOf(dir))) |above| {
            for (above) |layer| {
                const node = try m.lstat(layer, dir);
                switch (node.kind) {
                    .missing => continue,
                    .dir => {
                        try found.append(m.arena, layer);
                        if (node.opaque_dir) break;
                    },
                    else => break,
                }
            }
        }
        const result: ?[]const u32 = if (found.items.len == 0) null else found.items;
        try m.dirs.put(m.arena, try m.arena.dupe(u8, dir), result);
        return result;
    }

    /// What the real path is: the topmost layer's entry for it, unless that is a whiteout.
    fn entry(m: *Merged, path: []const u8) Error!Node {
        if (path.len == 0) return .{ .kind = .dir };
        if (m.nodes.get(path)) |n| return n;
        var node: Node = .{ .kind = .missing };
        if (try m.contribs(parentOf(path))) |above| for (above) |layer| {
            const l = try m.lstat(layer, path);
            if (l.kind == .missing) continue;
            if (l.kind != .whiteout) {
                node = l;
                node.layer = layer;
            }
            break;
        };
        // A file is looked at once for the search and once for its hash, and a tree of a million
        // of them would hold each name twice over for that: only what has to be found again, for
        // the paths below it (directories, links) and what is not there, is kept.
        if (node.kind != .file and node.kind != .other)
            try m.nodes.put(m.arena, try m.arena.dupe(u8, path), node);
        return node;
    }

    /// `path` with every link taken (the last one only when `follow_last`), as the job's own
    /// root sees it: null when something on the way is missing, is not a directory, or is a
    /// loop. The path it returns is real, and good until the next call.
    fn resolve(m: *Merged, path: []const u8, follow_last: bool) Error!?Resolved {
        m.path.clearRetainingCapacity();
        var links: u32 = 0;
        // The files of a directory are asked about one after another: the directory is resolved
        // once, not for each of them (a path 1,900 names deep is 1,900 lookups).
        if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
            const name = path[slash + 1 ..];
            if (slash > 0 and name.len > 0 and !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                const dir = path[0..slash];
                if (!std.mem.eql(u8, dir, m.dir_in.items)) {
                    const at = (try m.walkPath(&m.path, dir, true, &links)) orelse return null;
                    if (at.node.kind != .dir) return null;
                    m.dir_in.clearRetainingCapacity();
                    try m.dir_in.appendSlice(m.arena, dir);
                    m.dir_real.clearRetainingCapacity();
                    if (!std.mem.eql(u8, at.path, "/")) try m.dir_real.appendSlice(m.arena, at.path);
                    m.dir_links = links;
                }
                links = m.dir_links;
                m.path.clearRetainingCapacity();
                try m.path.appendSlice(m.arena, m.dir_real.items);
                return m.walkPath(&m.path, name, follow_last, &links);
            }
        }
        return m.walkPath(&m.path, path, follow_last, &links);
    }

    /// `path` taken from the real directory `buf` holds ("" the root), which it leaves holding
    /// where the path leads. Names are added to `buf` and cut off it again, and looked up where
    /// they are, so a long path costs no copy of itself for each of its names. `links` counts the
    /// links taken in all of one resolution, nested ones too, as the kernel counts them (40, then
    /// ELOOP).
    fn walkPath(m: *Merged, buf: *std.ArrayList(u8), path: []const u8, follow_last: bool, links: *u32) Error!?Resolved {
        const arena = m.arena;
        var rest = path;
        while (true) {
            rest = std.mem.trimStart(u8, rest, "/");
            if (rest.len == 0) break;
            const slash = std.mem.indexOfScalar(u8, rest, '/');
            const name = rest[0 .. slash orelse rest.len];
            rest = if (slash) |s| rest[s + 1 ..] else "";
            try m.tick();
            // As the kernel's walk: every name, `.` and `..` too, needs search permission on the
            // directory it is in, and that comes first. Asking only once a name is found would
            // say which names are there behind a directory the user cannot enter, which neither
            // `sha256sum` nor `realpath` could say.
            if (m.checked and !try m.canSearch(m.step.?, buf.items)) {
                m.denied = true;
                return null;
            }
            if (std.mem.eql(u8, name, ".")) continue;
            if (std.mem.eql(u8, name, "..")) {
                buf.shrinkRetainingCapacity(parentOf(buf.items).len);
                continue;
            }
            const parent_len = buf.items.len;
            try buf.append(arena, '/');
            try buf.appendSlice(arena, name);
            const node = try m.entry(buf.items);
            switch (node.kind) {
                .missing, .whiteout => return null,
                .dir => {},
                .file, .other => if (rest.len > 0) return null,
                .symlink => {
                    if (rest.len == 0 and !follow_last) break;
                    links.* += 1;
                    if (links.* > max_links) return null;
                    const to = (try m.follow(buf.items, parent_len, node.target, links)) orelse return null;
                    // Something is still to be taken from where the link leads, so it must be a
                    // directory (`lf/../real`, with `lf` a link to a file, is ENOTDIR).
                    if (rest.len > 0 and to.node.kind != .dir) return null;
                    buf.clearRetainingCapacity();
                    if (!std.mem.eql(u8, to.path, "/")) try buf.appendSlice(arena, to.path);
                },
            }
        }
        return .{ .path = if (buf.items.len == 0) "/" else buf.items, .node = try m.entry(buf.items) };
    }

    /// Where the link at `link` (in the directory its first `parent_len` bytes are) leads, once
    /// all its links are taken, and `links` is counted for them. Kept, with the links it took, so
    /// that a thousand links to one chain take it once and still count it each time.
    fn follow(m: *Merged, link: []const u8, parent_len: usize, target: []const u8, links: *u32) Error!?Resolved {
        if (m.leads.get(link)) |lead| if (lead.checked or !m.checked) {
            links.* += lead.cost;
            return if (links.* > max_links) null else lead.to;
        };
        var local: std.ArrayList(u8) = .empty;
        if (target.len == 0 or target[0] != '/') try local.appendSlice(m.arena, link[0..parent_len]);
        const before = links.*;
        const to = (try m.walkPath(&local, target, true, links)) orelse return null;
        try m.leads.put(m.arena, try m.arena.dupe(u8, link), .{
            .to = to,
            .cost = links.* - before,
            .checked = m.checked,
        });
        return to;
    }

    /// The SHA-256 of a regular file, read from the layer that has it: no link on the way is
    /// taken. What is found is looked at (`O_PATH`, no read) before it is opened, and opened
    /// through the descriptor that was looked at, so a file that has become a pipe, which would
    /// block, is refused and not opened, and so is one the step's user may not read: that is
    /// decided on this very inode, before anything of it is read, and `name` (as the job named it)
    /// is what `sha256sum` said. Read in blocks, between which the job's cancel is seen.
    fn digest(m: *Merged, path: []const u8, name: []const u8, layer: u32) Error![32]u8 {
        var buf: [path_max]u8 = undefined;
        const rel = try m.relativeZ(&buf, path);
        const looked = switch (sandbox.openIn(m.roots[layer], rel, .{ .PATH = true }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
        };
        defer _ = linux.close(looked);
        if (!try m.isRegular(looked, path)) return m.fail("{s}: Not a regular file", .{path});
        if (m.step) |s| if (!try m.stepMay(s, looked, layer, path, may_read))
            return m.fail("sha256sum: {s}: Permission denied", .{name});
        var proc: [32]u8 = undefined;
        const p = std.mem.printSentinel(&proc, "/proc/self/fd/{d}", .{looked}, 0) catch
            return m.fail("{s}: cannot be read", .{path});
        const opened = linux.open(p, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .NOCTTY = true, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS)
            return m.fail("{s}: cannot be read: {t}", .{ path, linux.errno(opened) });
        const fd = std.math.cast(linux.fd_t, opened).?;
        defer _ = linux.close(fd);
        if (!try m.isRegular(fd, path)) return m.fail("{s}: Not a regular file", .{path});
        var h = Sha256.init(.{});
        var block: [64 * 1024]u8 = undefined;
        while (true) {
            try m.tick();
            try m.clocks();
            const n = linux.read(fd, &block, block.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
            }
            if (n == 0) break;
            h.update(block[0..n]);
        }
        return h.finalResult();
    }

    fn isRegular(m: *Merged, fd: linux.fd_t, path: []const u8) Error!bool {
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
            return m.fail("{s}: cannot be read", .{path});
        return st.mode & linux.S.IFMT == linux.S.IFREG;
    }

    // --- glob.Fs ---

    fn erased(ptr: *anyopaque) *Merged {
        return @ptrCast(@alignCast(ptr));
    }

    fn statAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow_links: bool) Error![]const glob.Kind {
        const m = erased(ptr);
        const out = try arena.alloc(glob.Kind, paths.len);
        for (paths, out) |p, *k| {
            const at = (try m.resolve(p, follow_links)) orelse {
                k.* = .missing;
                continue;
            };
            k.* = switch (at.node.kind) {
                .dir => .directory,
                .file => .file,
                .symlink => .symlink,
                .missing, .whiteout => .missing,
                .other => .other,
            };
        }
        return out;
    }

    /// The names in each directory: the union of its layers' entries, less those a whiteout hides.
    fn listAll(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Error![]const []const []const u8 {
        const m = erased(ptr);
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *list| list.* = try m.listDir(arena, d);
        return out;
    }

    fn listDir(m: *Merged, arena: Allocator, dir: []const u8) Error![]const []const u8 {
        const at = (try m.resolve(dir, true)) orelse return &.{};
        if (at.node.kind != .dir) return &.{};
        // The directory's path is in `m.path`, which a look at a whiteout's name would not touch,
        // but copy it: it is the key of the layers' lookups below.
        const real = try arena.dupe(u8, if (std.mem.eql(u8, at.path, "/")) "" else at.path);
        const layers = (try m.contribs(real)) orelse return &.{};
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var out: std.ArrayList([]const u8) = .empty;
        for (layers) |layer| {
            var buf: [path_max]u8 = undefined;
            const rel = try m.relativeZ(&buf, real);
            const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
            }, 0, sandbox.resolve_no_symlinks)) {
                .fd => |f| f,
                .err => |e| return m.fail("cannot read {s} in the job's layers: {t}", .{ real, e }),
            };
            defer _ = linux.close(fd);
            const d: std.Io.Dir = .{ .handle = fd };
            var it = d.iterateAssumeFirstIteration();
            while (it.next(m.io) catch |e|
                return m.fail("cannot list {s} in the job's layers: {t}", .{ real, e })) |e|
            {
                try m.tick();
                if (seen.contains(e.name)) continue;
                const name = try arena.dupe(u8, e.name);
                try seen.put(arena, name, {});
                if (e.kind == .character_device or e.kind == .unknown) {
                    var joined: [path_max]u8 = undefined;
                    const child = std.fmt.bufPrint(&joined, "{s}/{s}", .{ real, name }) catch
                        return m.fail("a path in the job's files is longer than {d} bytes", .{path_max - 1});
                    if ((try m.lstat(layer, child)).kind == .whiteout) continue;
                }
                try out.append(arena, name);
            }
        }
        return out.items;
    }

    /// Each path with every link taken. A path that is not there cannot be listed or followed:
    /// the walk asks only about directories it has just seen.
    /// `realpath` ran as the step's user on Dagger, so these are that user's walks, which fail the
    /// call on a directory reached through one it cannot enter.
    fn realpathAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8) Error![]const []const u8 {
        const m = erased(ptr);
        m.check(true);
        defer m.check(false);
        const out = try arena.alloc([]const u8, paths.len);
        for (paths, out) |p, *r| {
            const at = (try m.resolve(p, true)) orelse {
                if (m.denied) return m.fail("realpath: {s}: Permission denied", .{p});
                return m.fail("{s}: No such file or directory", .{p});
            };
            r.* = try arena.dupe(u8, at.path);
        }
        return out;
    }
};

/// The permission bits `Merged.stepMay` asks for.
const may_read: u16 = 0o4;
const may_search: u16 = 0o1;

/// The step's user, as one layer's ids compare with it.
const Who = struct {
    uid: u32,
    gid: u32,
    groups: []const u32,
    ids: Store.Ids,

    /// Whether a group id, as the job sees it, is the user's primary or supplementary group.
    fn inGroup(w: Who, gid: ?u32) bool {
        const id = gid orelse return false;
        return id == w.gid or std.mem.indexOfScalar(u32, w.groups, id) != null;
    }
};

/// `id`, as a layer holds it, as the job sees it; null for one the job's ids do not reach. Not
/// `Ids.inside`, whose overflow id is 65534: that is a real user, `nobody`, which such a file's
/// owner is not, as an unmapped id matches no one in the kernel.
fn jobId(ids: Store.Ids, id: u32) ?u32 {
    if (id < ids.base or id - ids.base >= ids.count) return null;
    return id - ids.base;
}

/// Whether an ACL gives `want` to someone who is not the file's owner, as `posix_acl_permission`
/// decides: a named user's entry settles it, the group entries of the user's groups give it if
/// any of them does and refuse it otherwise, and only someone in none of those has the others'
/// entry; all but the last are cut by the mask. `value` is the kernel's format (`Store.unshiftAcl`,
/// whose ids a layer holds as it holds its owners). `file_gid` is the group entry's id, which the
/// entry does not hold. One not in the only format there is gives nothing.
fn aclGives(value: []const u8, w: Who, file_gid: u32, want: u16) bool {
    const header = 4;
    const size = 8;
    const version = 2;
    const tag_user = 0x02;
    const tag_group_obj = 0x04;
    const tag_group = 0x08;
    const tag_mask = 0x10;
    const tag_other = 0x20;
    if (value.len < header or (value.len - header) % size != 0) return false;
    if (std.mem.readInt(u32, value[0..4], .little) != version) return false;
    const entries = value[header..];
    var mask: u16 = 0o7;
    var i: usize = 0;
    while (i < entries.len) : (i += size) {
        if (std.mem.readInt(u16, entries[i..][0..2], .little) == tag_mask)
            mask = std.mem.readInt(u16, entries[i + 2 ..][0..2], .little);
    }
    var in_a_group = false;
    var other: u16 = 0;
    i = 0;
    while (i < entries.len) : (i += size) {
        const perm = std.mem.readInt(u16, entries[i + 2 ..][0..2], .little);
        const id = jobId(w.ids, std.mem.readInt(u32, entries[i + 4 ..][0..4], .little));
        const gives = perm & mask & want == want;
        switch (std.mem.readInt(u16, entries[i..][0..2], .little)) {
            tag_user => if (id == w.uid) return gives,
            tag_group_obj => if (w.inGroup(jobId(w.ids, file_gid))) {
                if (gives) return true;
                in_a_group = true;
            },
            tag_group => if (w.inGroup(id)) {
                if (gives) return true;
                in_a_group = true;
            },
            tag_other => other = perm,
            else => {},
        }
    }
    return !in_a_group and other & want == want;
}

/// The path without its leading `/`, for a layer's `openat2`: "." for the root.
fn relative(path: []const u8) []const u8 {
    const t = std.mem.trimStart(u8, path, "/");
    return if (t.len == 0) "." else t;
}

/// The directory a real path is in; the root's is "".
fn parentOf(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

// --- tests ---

const Fixture = struct {
    arena: Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,

    fn init(arena: Allocator) !Fixture {
        var f: Fixture = .{ .arena = arena, .tmp = std.testing.tmpDir(.{}), .root = "" };
        f.root = try f.tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
        return f;
    }

    fn cleanup(f: *Fixture) void {
        f.tmp.cleanup();
    }

    fn put(f: Fixture, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
    }

    fn link(f: Fixture, path: []const u8, target: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.symLink(std.testing.io, target, path, .{});
    }

    fn abs(f: Fixture, path: []const u8) ![:0]const u8 {
        return std.fmt.allocPrintSentinel(f.arena, "{s}/{s}", .{ f.root, path }, 0);
    }

    /// `hashFiles(args)` with `/ws` as the workspace over the layers, topmost first.
    fn hash(f: Fixture, layers: []const []const u8, args: []const []const u8) !expr.HashFiles.Result {
        const paths = try f.arena.alloc([]const u8, layers.len);
        for (layers, paths) |l, *p| p.* = try std.fmt.allocPrint(f.arena, "{s}/{s}", .{ f.root, l });
        const stack_: Stack = .{ .layers = paths, .opaque_xattr = "user.overlay.opaque", .step = null };
        return f.hashWith(stack_, args);
    }

    fn hashWith(f: Fixture, st: Stack, args: []const []const u8) !expr.HashFiles.Result {
        return hashFiles(std.testing.allocator, f.arena, std.testing.io, st, "/ws", "/home/runner", args);
    }

    fn stackOf(f: Fixture, layers: []const []const u8, limits: Limits) !Stack {
        const paths = try f.arena.alloc([]const u8, layers.len);
        for (layers, paths) |l, *p| p.* = try std.fmt.allocPrint(f.arena, "{s}/{s}", .{ f.root, l });
        return .{ .layers = paths, .opaque_xattr = "user.overlay.opaque", .step = null, .limits = limits };
    }
};

/// GitHub's hash of files with these contents, in this order.
fn hashOf(contents: []const []const u8) [64]u8 {
    var all = Sha256.init(.{});
    for (contents) |c| {
        var d: [32]u8 = undefined;
        Sha256.hash(c, &d, .{});
        all.update(&d);
    }
    return std.fmt.bytesToHex(all.finalResult(), .lower);
}

fn expectHash(want: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| try std.testing.expectEqualStrings(want, h),
        .failed => |why| {
            std.debug.print("hashFiles failed: {s}\n", .{why});
            return error.TestUnexpectedResult;
        },
    }
}

fn expectFailed(part: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| {
            std.debug.print("hashFiles gave {s}, wanted a failure with {s}\n", .{ h, part });
            return error.TestUnexpectedResult;
        },
        .failed => |why| if (std.mem.indexOf(u8, why, part) == null) {
            std.debug.print("hashFiles failed with {s}, wanted {s}\n", .{ why, part });
            return error.TestUnexpectedResult;
        },
    }
}

test "native hashFiles: layers merge as overlay's do, the topmost entry wins, a whiteout deletes, an opaque directory hides" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // The rootfs, then two layers of steps.
    try f.put("l0/ws/a.txt", "a0");
    try f.put("l0/ws/gone.txt", "gone");
    try f.put("l0/ws/keep.txt", "keep");
    try f.put("l0/ws/dir/old.txt", "old");
    try f.put("l0/ws/dir/sub/deep.txt", "deep");
    try f.put("l1/ws/a.txt", "a1");
    try f.put("l1/ws/dir/new.txt", "new");
    try f.put("l2/ws/later.txt", "later");
    // l1's `dir` is opaque (a step removed it and made it again): l0's entries are hidden. l2
    // deletes `gone.txt`. Where this machine cannot make either, the case is left out.
    const opaque_dir = linux.errno(linux.setxattr(try f.abs("l1/ws/dir"), "user.overlay.opaque", "y", 1, 0)) == .SUCCESS;
    const whiteout = linux.errno(linux.mknod(try f.abs("l2/ws/gone.txt"), linux.S.IFCHR | 0o000, 0)) == .SUCCESS;
    const layers = [_][]const u8{ "l2", "l1", "l0" };

    // In GitHub's order: a.txt, dir/..., gone.txt, keep.txt, later.txt.
    var want: std.ArrayList([]const u8) = .empty;
    try want.append(f.arena, "a1");
    try want.append(f.arena, "new");
    if (!opaque_dir) try want.appendSlice(f.arena, &.{ "old", "deep" });
    if (!whiteout) try want.append(f.arena, "gone");
    try want.appendSlice(f.arena, &.{ "keep", "later" });
    try expectHash(&hashOf(want.items), try f.hash(&layers, &.{"**"}));
    // One layer sees only itself: the others are not what it is merged with.
    try expectHash(&hashOf(&.{ "a0", "old", "deep", "gone", "keep" }), try f.hash(&.{"l0"}, &.{"**"}));
    // Nothing found is "".
    try expectHash("", try f.hash(&layers, &.{"**/nothing.txt"}));
    // A pattern with `..` is refused, as GitHub refuses it.
    try expectFailed("Relative pathing", try f.hash(&layers, &.{"dir/../a.txt"}));
}

test "native hashFiles: a link is hashed as what it leads to inside the job's tree" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/secret", "S");
    try f.put("l0/ws/real.txt", "R");
    try f.put("l0/ws/sub/inner.txt", "I");
    try f.link("l0/ws/link.txt", "real.txt");
    try f.link("l0/ws/abs.txt", "/etc/secret");
    try f.link("l0/ws/up.txt", "sub/../real.txt");
    try f.link("l0/ws/dl", "sub");
    try f.link("l0/ws/sub/back", "../real.txt");
    try f.link("l0/ws/sub/to-ws", "..");
    // The links are in a layer under the one that has the files: the merged view takes them.
    try f.put("l1/ws/top.txt", "T");
    const layers = [_][]const u8{ "l1", "l0" };

    // Links are not followed: each is a name found, hashed as its target (a directory skipped, as
    // GitHub skips what `statSync` calls one): abs.txt, dl, link.txt, real.txt, sub/back,
    // sub/inner.txt, sub/to-ws, top.txt, up.txt.
    try expectHash(&hashOf(&.{ "S", "R", "R", "R", "I", "T", "R" }), try f.hash(&layers, &.{"**"}));
    // Followed: `dl` is walked (its files are named by the path through it), `sub/to-ws` is the
    // workspace again and is not.
    try expectHash(
        &hashOf(&.{ "S", "R", "I", "R", "R", "R", "I", "T", "R" }),
        try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }),
    );
}

test "native hashFiles: nothing a link names outside the layers is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // A file of the host's, at a path the job's tree does not have.
    try f.put("host/secret.txt", "HOST");
    try f.put("l0/ws/ok.txt", "ok");
    const abs_target = try f.abs("host/secret.txt");
    // Through `..`, as many as it takes to reach the host's root if the job's were it.
    const dots = "../../../../../../../../../../../../../../../../../../../../../../../../../../../../";
    const rel_target = try std.fmt.allocPrint(f.arena, "{s}{s}", .{ dots, std.mem.trimStart(u8, abs_target, "/") });
    try f.link("l0/ws/abs-link", abs_target);
    try f.link("l0/ws/rel-link", rel_target);
    try f.link("l0/ws/dir-link", try f.abs("host"));
    const layers = [_][]const u8{"l0"};
    // Not followed, the links are names, and their targets are not there: hashFiles fails on
    // them, as it fails on a broken link on GitHub, and the host's file is not hashed.
    try expectFailed("abs-link", try f.hash(&layers, &.{"abs-link"}));
    try expectFailed("rel-link", try f.hash(&layers, &.{"rel-link"}));
    // Followed, they lead to nothing, so there is nothing to find or to walk.
    try expectHash(&hashOf(&.{"ok"}), try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }));
    try expectHash("", try f.hash(&layers, &.{ "--follow-symbolic-links", "dir-link/**" }));
    // A loop of links is no file either.
    try f.link("l0/ws/loop-a", "loop-b");
    try f.link("l0/ws/loop-b", "loop-a");
    try expectFailed("loop-a", try f.hash(&layers, &.{"loop-a"}));
}

test "native hashFiles: a directory in a layer hides a link below it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/x", "from-etc");
    try f.link("l0/ws/d", "/etc");
    try f.put("l1/ws/d/x", "upper");
    try expectHash(&hashOf(&.{"upper"}), try f.hash(&.{ "l1", "l0" }, &.{"d/**"}));
    // Below the link only, `d` is the link: not followed, hashed as what it leads to (a directory,
    // so skipped); followed, /etc's files.
    try expectHash("", try f.hash(&.{"l0"}, &.{"d"}));
    try expectHash(&hashOf(&.{"from-etc"}), try f.hash(&.{"l0"}, &.{ "--follow-symbolic-links", "d/**" }));
}

test "native hashFiles: a pipe is refused, not waited for" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok.txt", "ok");
    if (linux.errno(linux.mknod(try f.abs("l0/ws/pipe"), linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("pipe", try f.hash(&.{"l0"}, &.{"pipe"}));
}

fn many(arena: Allocator, s: []const u8, n: usize) ![]const []const u8 {
    const out = try arena.alloc([]const u8, n);
    @memset(out, s);
    return out;
}

/// What a call over these small trees may hold: well under what copying paths took.
const MEMORY_BOUND = 64 << 20;

test "native hashFiles: links that name one directory by many paths end in an error, not in memory" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // d0 .. d9, each with two links to the next: 2^9 paths lead to d9, and none is a cycle.
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        for ([_][]const u8{ "a", "b" }) |name| try f.link(
            try std.fmt.allocPrint(f.arena, "l0/ws/d{d}/{s}", .{ i, name }),
            try std.fmt.allocPrint(f.arena, "../d{d}", .{i + 1}),
        );
    }
    try f.put("l0/ws/d9/x", "x");
    const follow = [_][]const u8{ "--follow-symbolic-links", "d0/**" };
    try expectFailed("more than 300 files and directories", try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 300 }), &follow));
    // With room for them it is the same tree: 512 files, each named by its own path.
    const all = try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 5000 }), &follow);
    try expectHash(&hashOf(try many(f.arena, "x", 512)), all);
    // Not following, the links are names and there is almost nothing to visit.
    try expectHash("", try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 300 }), &.{"d0/**"}));
}

test "native hashFiles: a deep path is not copied for each of its names" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // 300 directories deep (a path of 600 bytes), 1500 files at the bottom.
    var dir: std.ArrayList(u8) = .empty;
    try dir.appendSlice(f.arena, "l0/ws");
    for (0..300) |_| try dir.appendSlice(f.arena, "/n");
    try f.tmp.dir.createDirPath(std.testing.io, dir.items);
    for (0..1500) |n| try f.put(try std.fmt.allocPrint(f.arena, "{s}/f{d}", .{ dir.items, n }), "x");
    var scratch: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer scratch.deinit();
    const got = try run(&scratch, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"**"});
    try expectHash(&hashOf(try many(f.arena, "x", 1500)), got);
    // A copy of the path for each name of it, for each file, twice, was over 300 MB.
    const used = scratch.queryCapacity();
    errdefer std.debug.print("the call held {d} bytes\n", .{used});
    try std.testing.expect(used < MEMORY_BOUND);
}

test "native hashFiles: many links to one long chain follow it once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/end.txt", "end");
    // 39 links in a chain, each target 3 KB of `./` before the next name.
    const pad = try f.arena.alloc(u8, 3000);
    for (0..1500) |k| @memcpy(pad[2 * k ..][0..2], "./");
    var i: usize = 39;
    while (i > 0) : (i -= 1) {
        const target = if (i == 39) "end.txt" else try std.fmt.allocPrint(f.arena, "{s}c{d}", .{ pad, i + 1 });
        try f.link(try std.fmt.allocPrint(f.arena, "l0/ws/c{d}", .{i}), target);
    }
    for (0..3000) |n| try f.link(try std.fmt.allocPrint(f.arena, "l0/ws/l{d}", .{n}), try std.fmt.allocPrint(f.arena, "{s}c1", .{pad}));
    var scratch: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer scratch.deinit();
    const got = try run(&scratch, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"l*"});
    try expectHash(&hashOf(try many(f.arena, "end", 3000)), got);
    const used = scratch.queryCapacity();
    errdefer std.debug.print("the call held {d} bytes\n", .{used});
    try std.testing.expect(used < MEMORY_BOUND);
}

test "native hashFiles: the job's cancel ends a call in the middle of a file" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok.txt", "ok");
    // A file of 16 GiB that takes no disk: reading it takes seconds, and a bigger one hours.
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws");
    const big = try f.tmp.dir.createFile(std.testing.io, "l0/ws/big", .{});
    defer big.close(std.testing.io);
    big.setLength(std.testing.io, 16 << 30) catch return error.SkipZigTest;
    var cancel: dagger.Cancel = .{};
    const Canceller = struct {
        fn run(c: *dagger.Cancel, io: std.Io) void {
            io.sleep(.fromMilliseconds(300), .awake) catch return;
            c.request(std.Io.Clock.real.now(io).toMilliseconds() + 60_000);
        }
    };
    const thread = try std.Thread.spawn(.{}, Canceller.run, .{ &cancel, std.testing.io });
    defer thread.join();
    const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const got = try f.hashWith(try f.stackOf(&.{"l0"}, .{ .cancel = &cancel }), &.{"big"});
    const took = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0;
    try expectFailed("cancelled", got);
    errdefer std.debug.print("it took {d} ms\n", .{took});
    try std.testing.expect(took < 3000);
}

test "native hashFiles: a redirect or metacopy in a layer fails the call, for a directory and for a file" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/plain/a.txt", "a");
    try f.put("l1/ws/renamed/b.txt", "b");
    try f.put("l1/ws/copied.txt", "c");
    // Overlay shows a renamed directory's lower entries by its redirect, and a file that only had
    // its metadata changed by its metacopy: without either followed the hash would be wrong.
    if (linux.errno(linux.setxattr(try f.abs("l1/ws/renamed"), "user.overlay.redirect", "/ws/plain", 9, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("redirect or metacopy", try f.hash(&.{ "l1", "l0" }, &.{"**"}));
    _ = linux.removexattr(try f.abs("l1/ws/renamed"), "user.overlay.redirect");
    try expectHash(&hashOf(&.{ "c", "a", "b" }), try f.hash(&.{ "l1", "l0" }, &.{"**"}));
    if (linux.errno(linux.setxattr(try f.abs("l1/ws/copied.txt"), "user.overlay.metacopy", "", 0, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("copied.txt is renamed or copied up", try f.hash(&.{ "l1", "l0" }, &.{"**"}));
}

/// `files` files of one byte ("x") in a directory `depth` deep under the workspace.
fn deepDir(f: *Fixture, depth: usize, files: usize) !void {
    var dir: std.ArrayList(u8) = .empty;
    try dir.appendSlice(f.arena, "l0/ws");
    for (0..depth) |_| try dir.appendSlice(f.arena, "/n");
    try f.tmp.dir.createDirPath(std.testing.io, dir.items);
    for (0..files) |n| try f.put(try std.fmt.allocPrint(f.arena, "{s}/f{d}", .{ dir.items, n }), "x");
}

test "native hashFiles: a directory of thousands of entries costs its entries, not the matching of each" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 200, 12000);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const got = try hashFiles(failing.allocator(), f.arena, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"**"});
    try expectHash(&hashOf(try many(f.arena, "x", 12000)), got);
    // The matching of each path (with 200 segments) took 8 KB each and was never given back: 96 MB.
    errdefer std.debug.print("the call took {d} bytes\n", .{failing.allocated_bytes});
    try std.testing.expect(failing.allocated_bytes < 48 << 20);
}

test "native hashFiles: a call that began after the job's cancel runs through the grace period" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 3, 1500);
    var cancel: dagger.Cancel = .{};
    const now = std.Io.Clock.real.now(std.testing.io).toMilliseconds();
    cancel.request(now + 60_000);
    const stack = try f.stackOf(&.{"l0"}, .{ .cancel = &cancel });
    // An `if: always()` step, or the job's outputs: evaluated as they are on GitHub.
    try expectHash(&hashOf(try many(f.arena, "x", 1500)), try f.hashWith(stack, &.{"**"}));
    // Past the grace period it ends.
    cancel.hard_deadline_ms.store(now - 1000, .release);
    try expectFailed("grace period", try f.hashWith(stack, &.{"**"}));
}

test "native hashFiles: a call that takes longer than its limit fails as GitHub's does" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws");
    const big = try f.tmp.dir.createFile(std.testing.io, "l0/ws/big", .{});
    defer big.close(std.testing.io);
    big.setLength(std.testing.io, 4 << 30) catch return error.SkipZigTest;
    const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const got = try f.hashWith(try f.stackOf(&.{"l0"}, .{ .timeout_ms = 500 }), &.{"big"});
    const took = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0;
    try expectFailed("couldn't finish within 1 seconds", got);
    errdefer std.debug.print("it took {d} ms\n", .{took});
    try std.testing.expect(took < 5000);
}

test "native hashFiles: the settings give GitHub's 120 seconds and a share of the machine's memory" {
    const d = (Settings{}).limits(std.testing.io);
    try std.testing.expectEqual(@as(u64, 120_000), d.timeout_ms);
    try std.testing.expect(d.memory > 0 and d.memory <= 1 << 30);
    const set = (Settings{ .memory_mb = 64, .timeout_s = 7 }).limits(std.testing.io);
    try std.testing.expectEqual(@as(usize, 64 << 20), set.memory);
    try std.testing.expectEqual(@as(u64, 7000), set.timeout_ms);
    const none = (Settings{ .memory_mb = 0, .timeout_s = 0 }).limits(std.testing.io);
    try std.testing.expectEqual(std.math.maxInt(usize), none.memory);
    try std.testing.expectEqual(std.math.maxInt(u64), none.timeout_ms);
}

test "native hashFiles: a directory whose opaque mark cannot be read fails the call; what is below does not show" {
    // As root nothing is unreadable.
    if (linux.geteuid() == 0) return error.SkipZigTest;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/d/f", "deleted below");
    try f.tmp.dir.createDirPath(std.testing.io, "l1/ws/d");
    if (linux.errno(linux.setxattr(try f.abs("l1/ws/d"), "user.overlay.opaque", "y", 1, 0)) != .SUCCESS)
        return error.SkipZigTest;
    // `rm -rf d; mkdir d; chmod 111 d`: opaque, and not readable by the runner's user.
    const unreadable = try f.abs("l1/ws/d");
    _ = linux.chmod(unreadable, 0o111);
    defer _ = linux.chmod(unreadable, 0o755);
    try expectFailed("attributes", try f.hash(&.{ "l1", "l0" }, &.{"d/f"}));
}

test "native hashFiles: a path through a link to a file is not found" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // `lf/../real` where `lf` leads to a file: the kernel says ENOTDIR, not `real`'s contents.
    try f.put("l0/ws/real", "real");
    try f.put("l0/ws/real2", "real2");
    try f.link("l0/ws/lf", "real2");
    try f.link("l0/ws/x", "lf/../real");
    try expectFailed("x: No such file", try f.hash(&.{"l0"}, &.{"x"}));
}

test "native hashFiles: 40 links in one path are the most, however they are nested" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // Three chains of 20 links, one in each directory: 61 links with the one that names the path.
    try f.put("l0/ws/end.txt", "end");
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws/d1");
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws/d2");
    for ([_][2][]const u8{
        .{ "l0/ws/a", "d1" },
        .{ "l0/ws/d1/b", "../d2" },
        .{ "l0/ws/d2/c", "../end.txt" },
    }) |chain| {
        var i: usize = 1;
        while (i <= 20) : (i += 1) {
            const target = if (i == 20) chain[1] else try std.fmt.allocPrint(f.arena, "{s}{d}", .{ std.fs.path.basename(chain[0]), i + 1 });
            try f.link(try std.fmt.allocPrint(f.arena, "{s}{d}", .{ chain[0], i }), target);
        }
    }
    try f.link("l0/ws/long", "a1/b1/c1");
    try expectFailed("long: No such file", try f.hash(&.{"l0"}, &.{"long"}));
    // 21 links are fine (the chain in `d2` is 20, and the one that names the path).
    try f.link("l0/ws/ok", "d2/c1");
    try expectHash(&hashOf(&.{"end"}), try f.hash(&.{"l0"}, &.{"ok"}));
}

test "native hashFiles: a file with more attributes than a short list holds is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    // A tmpfs keeps up to 128 KiB of them; ext4, where the tests' directories are, 4 KiB in all.
    var raw: [6]u8 = undefined;
    io.random(&raw);
    const dir = try std.fmt.allocPrint(arena, "/dev/shm/zr-hashfiles-{s}", .{&std.fmt.bytesToHex(raw, .lower)});
    std.Io.Dir.cwd().createDirPath(io, try std.fmt.allocPrint(arena, "{s}/ws", .{dir})) catch return error.SkipZigTest;
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    const file = try std.fmt.allocPrintSentinel(arena, "{s}/ws/a.txt", .{dir}, 0);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = file, .data = "a" });
    for (0..400) |i| {
        const name = try std.fmt.allocPrintSentinel(arena, "user.zr-test-attribute-with-a-long-name-{d}", .{i}, 0);
        if (linux.errno(linux.setxattr(file, name, "v", 1, 0)) != .SUCCESS) return error.SkipZigTest;
    }
    const stack: Stack = .{ .layers = &.{dir}, .opaque_xattr = "user.overlay.opaque", .step = null };
    const got = try hashFiles(std.testing.allocator, arena, io, stack, "/ws", "/home/runner", &.{"**"});
    try expectHash(&hashOf(&.{"a"}), got);
}

test "native hashFiles: a file whose attributes are too many to be listed is read by name" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    // 1,500 names of 46 bytes: past the 64 KiB the kernel lists (it says E2BIG), under the 128 KiB a tmpfs holds.
    var raw: [6]u8 = undefined;
    io.random(&raw);
    const dir = try std.fmt.allocPrint(arena, "/dev/shm/zr-hashfiles-{s}", .{&std.fmt.bytesToHex(raw, .lower)});
    std.Io.Dir.cwd().createDirPath(io, try std.fmt.allocPrint(arena, "{s}/ws", .{dir})) catch return error.SkipZigTest;
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    const file = try std.fmt.allocPrintSentinel(arena, "{s}/ws/a.txt", .{dir}, 0);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = file, .data = "a" });
    for (0..1500) |i| {
        const name = try std.fmt.allocPrintSentinel(arena, "user.zr-test-attribute-with-a-long-name-{d}", .{i}, 0);
        if (linux.errno(linux.setxattr(file, name, "v", 1, 0)) != .SUCCESS) return error.SkipZigTest;
    }
    const stack: Stack = .{ .layers = &.{dir}, .opaque_xattr = "user.overlay.opaque", .step = null };
    const got = try hashFiles(std.testing.allocator, arena, io, stack, "/ws", "/home/runner", &.{"**"});
    try expectHash(&hashOf(&.{"a"}), got);
}

/// A call in a thread of its own: what it gave back, and how long it took.
const Runner = struct {
    fx: *const Fixture,
    stack: Stack,
    args: []const []const u8,
    result: ?expr.HashFiles.Result = null,
    took_ms: i64 = 0,

    fn run(r: *Runner) void {
        const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
        const gpa = std.heap.smp_allocator;
        r.result = hashFiles(gpa, gpa, std.testing.io, r.stack, "/ws", "/home/runner", r.args) catch null;
        r.took_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0;
    }
};

fn sleepMs(ms: i64) void {
    std.testing.io.sleep(.fromMilliseconds(ms), .awake) catch {};
}

test "native hashFiles: the memory a call holds is in the budget's number, and given back" {
    var budget: Budget = .{};
    var counted: Counted = .{
        .child = std.testing.allocator,
        .io = std.testing.io,
        .budget = &budget,
        .limit = 1 << 20,
        .allowance = 1000,
        .cancel = null,
        .cancelled_before = false,
        .wait_limit_ms = 1000,
    };
    defer counted.release();
    const al = counted.allocator();
    // Under the allowance, then in the turn.
    const small = try al.alloc(u8, 600);
    try std.testing.expectEqual(@as(u64, 600), budget.held.load(.acquire));
    const big = try al.alloc(u8, 5000);
    try std.testing.expectEqual(@as(u64, 5600), budget.held.load(.acquire));
    al.free(big);
    al.free(small);
    try std.testing.expectEqual(@as(u64, 0), budget.held.load(.acquire));
}

test "native hashFiles: what the tool trees' checks hold does not refuse a call" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 8, 400);
    var budget: Budget = .{};
    // Checks hold more than the whole limit (a tree that overshoots, as many at once can).
    _ = budget.held.fetchAdd(64 << 20, .acq_rel);
    const stack = try f.stackOf(
        &.{"l0"},
        .{ .memory = 8 << 20, .allowance = 64 << 10, .budget = &budget },
    );
    const r = try f.hashWith(stack, &.{"**"});
    try std.testing.expect(r == .ok);
    try std.testing.expectEqual(@as(u64, 64 << 20), budget.held.load(.acquire));
}

test "native hashFiles: a call too big for the memory alone fails at once, without waiting" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 100, 4000);
    var budget: Budget = .{};
    const stack = try f.stackOf(&.{"l0"}, .{ .memory = 2 << 20, .allowance = 64 << 10, .budget = &budget });
    const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    // An error of its own, not the allocator's `OutOfMemory`, and the queue left as it was.
    try expectFailed("would take more than 2 MiB", try f.hashWith(stack, &.{"**"}));
    try std.testing.expect(std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0 < 2000);
    try std.testing.expectEqual(budget.next, budget.serving);
}

test "native hashFiles: a call that needs the turn waits for the call that has it, and then runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 8, 400);
    var budget: Budget = .{};
    const stack = try f.stackOf(&.{"l0"}, .{ .memory = 64 << 20, .allowance = 64 << 10, .budget = &budget });
    // Another call has the turn (a big one, in a job that is hashing a huge file).
    const held = budget.ticket();
    try std.testing.expect(budget.isTurn(held));
    var r: Runner = .{ .fx = &f, .stack = stack, .args = &.{"**"} };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&r});
    sleepMs(400);
    try std.testing.expect(r.result == null);
    _ = budget.done(held);
    thread.join();
    try expectHash(&hashOf(try many(f.arena, "x", 400)), r.result.?);
    // It waited, and the wait is not what its own clock (or its result) is.
    try std.testing.expect(r.took_ms >= 350);
    try std.testing.expectEqual(budget.next, budget.serving);
}

test "native hashFiles: a call with little to do never waits for the turn" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/a.txt", "a");
    var budget: Budget = .{};
    const held = budget.ticket();
    // The big call that has the turn does not hold a neighbour's small one up.
    try expectHash(&hashOf(&.{"a"}), try f.hashWith(try f.stackOf(&.{"l0"}, .{ .budget = &budget }), &.{"**"}));
    _ = budget.done(held);
}

test "native hashFiles: a call waiting for the turn is ended by the job's cancel, and by its own time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 8, 400);
    var budget: Budget = .{};
    const held = budget.ticket();
    // By the cancel.
    var cancel: dagger.Cancel = .{};
    var r: Runner = .{ .fx = &f, .stack = try f.stackOf(&.{"l0"}, .{ .allowance = 64 << 10, .budget = &budget, .cancel = &cancel }), .args = &.{"**"} };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&r});
    sleepMs(200);
    cancel.request(std.Io.Clock.real.now(std.testing.io).toMilliseconds() + 60_000);
    thread.join();
    try expectFailed("cancelled", r.result.?);
    try std.testing.expect(r.took_ms < 3000);
    // By its time, which is twice as long as a call may hold the turn it waits for.
    var r2: Runner = .{ .fx = &f, .stack = try f.stackOf(&.{"l0"}, .{ .allowance = 64 << 10, .budget = &budget, .timeout_ms = 300 }), .args = &.{"**"} };
    r2.run();
    try expectFailed("waited 1 seconds", r2.result.?);
    try std.testing.expect(r2.took_ms < 3000);
    // Neither left its place in the queue: the turn goes on past both.
    _ = budget.done(held);
    try std.testing.expectEqual(budget.next, budget.serving);
    try std.testing.expect(budget.isTurn(budget.next));
}

test "native hashFiles: a task's cancel ends a wait for the turn, and is there for what runs next" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 8, 400);
    var budget: Budget = .{};
    const held = budget.ticket();
    defer _ = budget.done(held);
    const Task = struct {
        fn run(r: *Runner, kept: *bool) void {
            r.run();
            std.testing.io.sleep(.fromSeconds(30), .awake) catch {
                kept.* = true;
            };
        }
    };
    var r: Runner = .{ .fx = &f, .stack = try f.stackOf(&.{"l0"}, .{ .allowance = 64 << 10, .budget = &budget }), .args = &.{"**"} };
    var kept = false;
    var task = try std.testing.io.concurrent(Task.run, .{ &r, &kept });
    sleepMs(200);
    task.cancel(std.testing.io);
    try expectFailed("cancelled", r.result.?);
    try std.testing.expect(r.took_ms < 3000);
    try std.testing.expect(kept);
}

test "native hashFiles: a queue that moves outlasts the wait's limit, so calls ahead only delay a call" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 8, 400);
    var budget: Budget = .{};
    const first = budget.ticket();
    const second = budget.ticket();
    var r: Runner = .{ .fx = &f, .stack = try f.stackOf(&.{"l0"}, .{ .allowance = 64 << 10, .budget = &budget, .timeout_ms = 500 }), .args = &.{"**"} };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&r});
    // Each call ahead holds the turn for less than the limit of a second, and more than a second
    // goes by in all.
    sleepMs(700);
    _ = budget.done(first);
    sleepMs(700);
    _ = budget.done(second);
    thread.join();
    try std.testing.expect(r.result.? == .ok);
    try std.testing.expectEqual(budget.next, budget.serving);
}

test "native hashFiles: calls that each hold memory and need more run in turn, none waits on another for good" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try deepDir(&f, 60, 6000);
    // What one call takes, and a limit of two and a half times that: each fits alone (the counted bytes run a little over), four do not.
    var alone = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try expectHash(&hashOf(try many(f.arena, "x", 6000)), try hashFiles(alone.allocator(), f.arena, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"**"}));
    var budget: Budget = .{};
    // Each is over its allowance, so each holds some and wants more; one at a time has the room.
    const stack = try f.stackOf(&.{"l0"}, .{ .memory = alone.allocated_bytes / 4 * 10, .allowance = 64 << 10, .budget = &budget });
    var runners: [4]Runner = undefined;
    var threads: [4]std.Thread = undefined;
    for (&runners, &threads) |*r, *t| {
        r.* = .{ .fx = &f, .stack = stack, .args = &.{"**"} };
        t.* = try std.Thread.spawn(.{}, Runner.run, .{r});
    }
    for (threads) |t| t.join();
    // Together they need more than the 16 MiB: on a limit shared by the byte, some were refused.
    const want = hashOf(try many(f.arena, "x", 6000));
    for (runners) |r| try expectHash(&want, r.result.?);
    try std.testing.expectEqual(budget.next, budget.serving);
}

/// The id that owns `path` here (whoever runs the tests, and the group its directory gives).
const Owner = struct { uid: u32, gid: u32 };

fn ownerOf(f: Fixture, path: []const u8) !Owner {
    var st: linux.Statx = undefined;
    const mask: linux.STATX = .{ .UID = true, .GID = true };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(
        linux.AT.FDCWD,
        try f.abs(path),
        0,
        mask,
        &st,
    )));
    return .{ .uid = st.uid, .gid = st.gid };
}

fn setMode(f: Fixture, path: []const u8, mode: u32) !void {
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chmod(try f.abs(path), mode)));
}

/// `hashFiles(args)` over `layers` for the user `step`, whose `ids` default to the layers' own.
fn hashAs(f: Fixture, layers: []const []const u8, step: Step, args: []const []const u8) !expr.HashFiles.Result {
    var st = try f.stackOf(layers, .{});
    var s = step;
    if (s.ids.len == 0) {
        const ids = try f.arena.alloc(Store.Ids, layers.len);
        @memset(ids, Store.Ids.host);
        s.ids = ids;
    }
    st.step = s;
    return f.hashWith(st, args);
}

const denied = "Permission denied";

test "native hashFiles: the file's owner has the owner's bits, whatever the others have" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/a", "a");
    const o = try ownerOf(f, "l0/ws/a");
    const owner: Step = .{ .uid = o.uid, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    try setMode(f, "l0/ws/a", 0o400);
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &.{"l0"}, owner, &.{"a"}));
    // Everyone else may read it; its owner, by the owner's bits, may not.
    try setMode(f, "l0/ws/a", 0o044);
    try expectFailed("sha256sum: a: " ++ denied, try hashAs(f, &.{"l0"}, owner, &.{"a"}));
}

test "native hashFiles: the file's group has the group's bits, whatever the others have" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/a", "a");
    const o = try ownerOf(f, "l0/ws/a");
    const member: Step = .{ .uid = o.uid +% 1, .gid = o.gid, .user = "app", .ids = &.{} };
    try setMode(f, "l0/ws/a", 0o640);
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &.{"l0"}, member, &.{"a"}));
    try setMode(f, "l0/ws/a", 0o604);
    try expectFailed("sha256sum: a: " ++ denied, try hashAs(f, &.{"l0"}, member, &.{"a"}));
}

test "native hashFiles: anyone else has the others' bits, also through a link to /etc/shadow" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/a", "a");
    try f.put("l0/etc/shadow", "root:secret");
    try f.link("l0/ws/s", "/etc/shadow");
    const o = try ownerOf(f, "l0/ws/a");
    const other: Step = .{ .uid = o.uid +% 1, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    try setMode(f, "l0/ws/a", 0o604);
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &.{"l0"}, other, &.{"a"}));
    try setMode(f, "l0/ws/a", 0o640);
    try expectFailed("sha256sum: a: " ++ denied, try hashAs(f, &.{"l0"}, other, &.{"a"}));
    // The link is the job's, the file it leads to is not its user's. Dagger's `sha256sum` failed.
    try setMode(f, "l0/etc/shadow", 0o640);
    try expectFailed("sha256sum: s: " ++ denied, try hashAs(f, &.{"l0"}, other, &.{"s"}));
    // One name it may not read fails the call, as `sha256sum`'s exit did: no hash of the rest.
    try setMode(f, "l0/ws/a", 0o604);
    try expectFailed("sha256sum: s: " ++ denied, try hashAs(f, &.{"l0"}, other, &.{"**"}));
}

test "native hashFiles: supplementary groups are the engine's, from the job's own /etc" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/a", "a");
    try setMode(f, "l0/ws/a", 0o640);
    const o = try ownerOf(f, "l0/ws/a");
    const uid = o.uid +% 1;
    const primary = o.gid +% 1;
    try f.put("l0/etc/passwd", try std.fmt.allocPrint(
        f.arena,
        "root:x:0:0::/root:/bin/sh\napp:x:{d}:{d}::/home/app:/bin/sh\n",
        .{ uid, primary },
    ));
    try f.put("l0/etc/group", try std.fmt.allocPrint(
        f.arena,
        "root:x:0:\n# app is a member\n  staff:x:{d}:other,app\nbad:x:nan:app\n",
        .{o.gid},
    ));
    const as = struct {
        fn user(name: []const u8, id: u32, gid: u32) Step {
            return .{ .uid = id, .gid = gid, .user = name, .ids = &.{} };
        }
    };
    const numeric = try std.fmt.allocPrint(f.arena, "{d}", .{uid});
    const both = try std.fmt.allocPrint(f.arena, "{d}:{d}", .{ uid, primary });
    const absent = try std.fmt.allocPrint(f.arena, "{d}", .{uid +% 1});
    const stack = [_][]const u8{"l0"};
    // A name, or a uid /etc/passwd has: the member's groups.
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &stack, as.user("app", uid, primary), &.{"a"}));
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &stack, as.user(numeric, uid, primary), &.{"a"}));
    // An explicit group leaves them out (`GetExecUser`), and `uid:gid` looks nothing up.
    try expectFailed(denied, try hashAs(f, &stack, as.user("app:app", uid, primary), &.{"a"}));
    try expectFailed(denied, try hashAs(f, &stack, as.user(both, uid, primary), &.{"a"}));
    // A uid /etc/passwd has not got has no name to be a member by.
    try expectFailed(denied, try hashAs(f, &stack, as.user(absent, uid +% 1, primary), &.{"a"}));
    // Membership is by the whole name.
    try expectFailed(denied, try hashAs(f, &stack, as.user("ap", uid, primary), &.{"a"}));

    // What the next step has decides: a layer above takes the user out of the group...
    try f.put("l1/etc/group", try std.fmt.allocPrint(f.arena, "staff:x:{d}:other\n", .{o.gid}));
    try expectFailed(denied, try hashAs(f, &.{ "l1", "l0" }, as.user("app", uid, primary), &.{"a"}));
    // ...a link stays in the job's tree...
    try f.put("l2/etc/members", try std.fmt.allocPrint(f.arena, "staff:x:{d}:app\n", .{o.gid}));
    try f.link("l2/etc/group", "members");
    try expectHash(
        &hashOf(&.{"a"}),
        try hashAs(f, &.{ "l2", "l1", "l0" }, as.user("app", uid, primary), &.{"a"}),
    );
    // ...and one out of it is not taken, so the host's file makes no one a member.
    try f.put("host/group", try std.fmt.allocPrint(f.arena, "staff:x:{d}:app\n", .{o.gid}));
    try f.link("l3/etc/group", try f.abs("host/group"));
    try expectFailed(
        denied,
        try hashAs(f, &.{ "l3", "l1", "l0" }, as.user("app", uid, primary), &.{"a"}),
    );
}

test "native hashFiles: a directory without search permission refuses what is in it, found or not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok", "ok");
    try f.put("l0/ws/d/f", "secret");
    try f.put("l0/ws/d/e/g", "deep");
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws/open");
    try f.link("l0/ws/to-f", "d/f");
    try f.link("l0/ws/to-none", "d/none");
    try f.link("l0/ws/to-e", "d/e");
    try f.link("l0/ws/through", "d/../ok");
    try f.link("l0/ws/to-open", "open");
    const o = try ownerOf(f, "l0/ws/d");
    const other: Step = .{ .uid = o.uid +% 1, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    const stack = [_][]const u8{"l0"};
    defer setMode(f, "l0/ws/d", 0o755) catch {};

    // Search, without read: only names known are reached, and the file is read.
    try setMode(f, "l0/ws/d", 0o711);
    try expectHash(&hashOf(&.{"secret"}), try hashAs(f, &stack, other, &.{"d/f"}));
    // Read, without search: `sha256sum` cannot reach it. And no permission at all.
    for ([_]u32{ 0o744, 0o700 }) |mode| {
        try setMode(f, "l0/ws/d", mode);
        // The search still finds the name (the engine's did), so the call fails on it. A deeper
        // walk the search did first must not stand for the step's: `e` alone is open.
        try expectFailed("sha256sum: d/f: " ++ denied, try hashAs(f, &stack, other, &.{"d/f"}));
        try expectFailed("sha256sum: d/e/g: " ++ denied, try hashAs(f, &stack, other, &.{"d/e/g"}));
        // A link into it, to what is there and to what is not: the same words. That the second
        // is missing is what `sha256sum` could not have seen.
        try expectFailed("sha256sum: to-f: " ++ denied, try hashAs(f, &stack, other, &.{"to-f"}));
        try expectFailed("sha256sum: to-none: " ++ denied, try hashAs(f, &stack, other, &.{"to-none"}));
        // A directory behind it is no directory to `[ -d ]`, whose `stat` fails: not skipped.
        try expectFailed("sha256sum: to-e: " ++ denied, try hashAs(f, &stack, other, &.{"to-e"}));
        // `..` is a name in `d` like any other.
        try expectFailed("sha256sum: through: " ++ denied, try hashAs(f, &stack, other, &.{"through"}));
    }
    // A directory the user can reach is skipped as ever, and `ok` is the job's.
    try expectHash("", try hashAs(f, &stack, other, &.{"to-open"}));
    try expectHash(&hashOf(&.{"ok"}), try hashAs(f, &stack, other, &.{"ok"}));
}

test "native hashFiles: links followed are walked as the step's user, as `realpath` was" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/d/f", "secret");
    try f.put("l0/ws/d/sub/g", "deep");
    try f.put("l0/plain/f", "plain");
    try f.link("l0/ws/to-f", "d/f");
    try f.link("l0/ws/to-sub", "d/sub");
    try f.link("l0/ws/to-d", "d");
    try f.link("l0/ws/to-plain", "../plain");
    const o = try ownerOf(f, "l0/ws/d");
    const other: Step = .{ .uid = o.uid +% 1, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    const stack = [_][]const u8{"l0"};
    const follow = "--follow-symbolic-links";
    try setMode(f, "l0/ws/d", 0o700);
    defer setMode(f, "l0/ws/d", 0o755) catch {};
    // The search took the link as itself first: what it learned is not the step's to use.
    try expectFailed("sha256sum: to-f: " ++ denied, try hashAs(f, &stack, other, &.{ follow, "to-f" }));
    // `realpath` reaches `d` itself, which is `ws/to-d`, and fails on what is under it.
    try expectFailed("realpath: /ws/to-d/sub: " ++ denied, try hashAs(f, &stack, other, &.{ follow, "to-d/**" }));
    // A directory behind it fails at once.
    try expectFailed("realpath: /ws/to-sub: " ++ denied, try hashAs(f, &stack, other, &.{ follow, "to-sub/**" }));
    try expectHash(&hashOf(&.{"plain"}), try hashAs(f, &stack, other, &.{ follow, "to-plain/**" }));
}

test "native hashFiles: a root step reads everything, on a root runner and on a rootless one" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/d/f", "f");
    try f.link("l0/ws/s", "d/f");
    try setMode(f, "l0/ws/d/f", 0o400);
    try setMode(f, "l0/ws/d", 0o500);
    defer setMode(f, "l0/ws/d", 0o755) catch {};
    // `Backend.hashStep` has no user for either kind (its own test): nothing is looked at.
    try expectHash(&hashOf(&.{ "f", "f" }), try f.hash(&.{"l0"}, &.{"**"}));
}

test "native hashFiles: a file's ids are read as its layer holds them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("slot/ws/a", "a");
    try f.put("slot/ws/g", "g");
    try f.put("seen/ws/b", "b");
    try setMode(f, "slot/ws/a", 0o600);
    try setMode(f, "slot/ws/g", 0o640);
    try setMode(f, "seen/ws/b", 0o600);
    const o = try ownerOf(f, "slot/ws/a");
    // The tests' own ids stand for a job's: the slot's range holds them in place.
    const base = @min(o.uid, o.gid);
    const slot: Store.Ids = .{ .base = base, .count = std.math.maxInt(u32) - base };
    // Past all of the tests' ids: to this layer they are no id of the job's.
    const far: Store.Ids = .{ .base = @max(o.uid, o.gid) + 1, .count = 65536 };
    const ids = [_]Store.Ids{ slot, far };
    const layers = [_][]const u8{ "slot", "seen" };
    const step: Step = .{ .uid = o.uid - base, .gid = o.gid - base +% 1, .user = "app", .ids = &ids };
    // The user owns `a` in the slot's ids, and the same on-disk id elsewhere is no one's.
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &layers, step, &.{"a"}));
    try expectFailed("sha256sum: b: " ++ denied, try hashAs(f, &layers, step, &.{"b"}));
    // Groups too: `g` is the user's group's, with the step's id for it.
    const member: Step = .{ .uid = o.uid - base +% 1, .gid = o.gid - base, .user = "app", .ids = &ids };
    try expectHash(&hashOf(&.{"g"}), try hashAs(f, &layers, member, &.{"g"}));
    // An id the job does not reach is `nobody` to `stat`, but not to the kernel's check.
    const nobody: Step = .{ .uid = 65534, .gid = 65534, .user = "nobody", .ids = &ids };
    try expectFailed("sha256sum: b: " ++ denied, try hashAs(f, &layers, nobody, &.{"b"}));
}

/// An ACL as the kernel keeps it: `entries` are its tag, permission and id, in the kernel's order.
fn aclValue(arena: Allocator, entries: []const [3]u32) ![]u8 {
    const out = try arena.alloc(u8, 4 + 8 * entries.len);
    std.mem.writeInt(u32, out[0..4], 2, .little);
    for (entries, 0..) |e, i| {
        const at = out[4 + 8 * i ..][0..8];
        std.mem.writeInt(u16, at[0..2], @intCast(e[0]), .little);
        std.mem.writeInt(u16, at[2..4], @intCast(e[1]), .little);
        std.mem.writeInt(u32, at[4..8], e[2], .little);
    }
    return out;
}

test "native hashFiles: an ACL decides as the kernel's does" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const user_obj = 0x01;
    const user = 0x02;
    const group_obj = 0x04;
    const group = 0x08;
    const mask = 0x10;
    const other = 0x20;
    const none = 0xffffffff;
    const who: Who = .{ .uid = 5, .gid = 6, .groups = &.{7}, .ids = .{} };
    const gives = struct {
        fn f(ar: Allocator, w: Who, entries: []const [3]u32) !bool {
            return aclGives(try aclValue(ar, entries), w, 6, may_read);
        }
    }.f;
    const head = [_]u32{ user_obj, 6, none };
    const tail = [_][3]u32{ .{ mask, 4, none }, .{ other, 0, none } };
    // A named user, or one of their groups named, is let in past the others' none.
    try std.testing.expect(try gives(arena, who, &(.{head} ++ .{[_]u32{ user, 4, 5 }} ++ tail)));
    try std.testing.expect(try gives(arena, who, &(.{head} ++ .{[_]u32{ group, 4, 7 }} ++ tail)));
    try std.testing.expect(try gives(arena, who, &(.{head} ++ .{[_]u32{ group_obj, 4, none }} ++ tail)));
    // Someone else named is not them.
    try std.testing.expect(!try gives(arena, who, &(.{head} ++ .{[_]u32{ user, 4, 9 }} ++ tail)));
    // The mask cuts what a named entry gives.
    try std.testing.expect(!try gives(arena, who, &.{ head, .{ user, 4, 5 }, .{ mask, 0, none }, .{ other, 4, none } }));
    // A named entry settles it, past what the others have.
    try std.testing.expect(!try gives(arena, who, &.{ head, .{ user, 0, 5 }, .{ mask, 7, none }, .{ other, 4, none } }));
    // So does being in a group: only someone in none has the others' entry.
    try std.testing.expect(!try gives(arena, who, &.{ head, .{ group_obj, 0, none }, .{ mask, 7, none }, .{ other, 4, none } }));
    const stranger: Who = .{ .uid = 50, .gid = 60, .groups = &.{}, .ids = .{} };
    try std.testing.expect(try gives(arena, stranger, &.{ head, .{ group_obj, 0, none }, .{ mask, 7, none }, .{ other, 4, none } }));
    // A slot's ids are the layer's, as its owners are.
    const in_slot: Who = .{ .uid = 5, .gid = 6, .groups = &.{}, .ids = .{ .base = 1000, .count = 65536 } };
    try std.testing.expect(try gives(arena, in_slot, &(.{head} ++ .{[_]u32{ user, 4, 1005 }} ++ tail)));
    try std.testing.expect(!try gives(arena, in_slot, &(.{head} ++ .{[_]u32{ user, 4, 5 }} ++ tail)));
    // What is not an ACL gives nothing.
    try std.testing.expect(!aclGives("\x01\x00\x00\x00", stranger, 6, may_read));
    try std.testing.expect(!aclGives("\x02", stranger, 6, may_read));
}

test "native hashFiles: an ACL on the file and on a directory counts, past the mode" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/d/a", "a");
    const o = try ownerOf(f, "l0/ws/d/a");
    const named = o.uid +% 1;
    const step: Step = .{ .uid = named, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    const other: Step = .{ .uid = named +% 1, .gid = o.gid +% 1, .user = "app", .ids = &.{} };
    const none = 0xffffffff;
    const acl = try aclValue(f.arena, &.{
        .{ 0x01, 7, none },
        .{ 0x02, 5, named },
        .{ 0x04, 0, none },
        .{ 0x10, 5, none },
        .{ 0x20, 0, none },
    });
    // Where the tests' file system keeps no ACLs, this one has nothing to test.
    for ([_][]const u8{ "l0/ws/d/a", "l0/ws/d" }) |p| {
        if (linux.errno(linux.setxattr(try f.abs(p), "system.posix_acl_access", acl.ptr, acl.len, 0)) != .SUCCESS)
            return error.SkipZigTest;
    }
    defer setMode(f, "l0/ws/d", 0o755) catch {};
    try expectHash(&hashOf(&.{"a"}), try hashAs(f, &.{"l0"}, step, &.{"d/a"}));
    try expectFailed("sha256sum: d/a: " ++ denied, try hashAs(f, &.{"l0"}, other, &.{"d/a"}));
    // The entry on the directory is what lets the named user through: taken away, it refuses.
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.removexattr(try f.abs("l0/ws/d"), "system.posix_acl_access")));
    try setMode(f, "l0/ws/d", 0o700);
    try expectFailed("sha256sum: d/a: " ++ denied, try hashAs(f, &.{"l0"}, step, &.{"d/a"}));
}
