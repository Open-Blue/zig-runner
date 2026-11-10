//! The tool cache's trees, checked in "Set up job" (docs/native-backend.md, "The tool cache's
//! trees"): the native counterpart of `dagger/tool_trees.sh`, which the Dagger backend runs in a
//! container. A script that pins a tree's digest (install-zig.sh pins Zig's) skips its own check
//! of the tree when the runner gives it the same one (`ZIG_RUNNER_TOOL_TREES`), and a replayed
//! step that names a directory in the tool cache is trusted only when a tree here holds it
//! (`Exec.toolDirNotHeld`, #229).
//!
//! For each directory `TOOL/VERSION/NAME` of the tool cache (the layout actions/tool-cache gives
//! what setup actions unpack, and install-zig.sh's `zig/VERSION/zig-ARCH-linux-VERSION`) the
//! digest is the one install-zig.sh pins, run inside the tree:
//!
//!   find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
//!
//! That digest sees regular files only: not a link, a pipe, a mode, an empty directory. So each
//! tree has a second, `ZIG_RUNNER_TOOL_TREES_FULL`, over every entry (type, mode, path, a regular
//! file's sha256, a link's target). Both are in every step's key, so a tree changed in either
//! way is a tree no record was made against. A tree with a link that may leave it is left out:
//! what it points at is no part of any digest. A target may go up only at its start (`../..`
//! then names), never after a name, because a name may be a link itself: `lib/d -> ..` and
//! `gcc -> lib/d/../../.evil/gcc` is a way out that a count of the `..` in one text misses.
//!
//! Re-reading a tree (19,500 files and 309 MB for Zig 0.17.0) costs about 1 s on the laptop and
//! 10-19 s on razorbill, so a check keeps a list of one line per regular file (path, size,
//! inode, mtime, ctime, sha256) and re-reads only the files whose line changed. As in the script,
//! that is sound because the lists are the runner's alone (`lists` is in no volume a step
//! mounts), and any write to a file sets its ctime to now, which a step cannot set back (that
//! takes the clock, and steps have no CAP_SYS_TIME). Two holes are closed. A file written twice
//! within one tick of the kernel's coarse clock keeps its ctime, so a file whose ctime is within
//! `Limits.racy_s` of the check's start is listed as "racy", which no stat matches (git's "racy
//! clean" entries). And a writable shared mapping, once dirty, writes again without touching
//! ctime or mtime: the check takes a read lease on each file it hashes (`F_SETLEASE`), which the
//! kernel refuses while any writer, a mapping included, holds the file, and then lists the file
//! as racy too. The signal a lease break sends is SIGURG (`F_SETSIG`), whose default is to be
//! ignored: SIGIO, the default, is what `std.Io` interrupts blocked calls with.
//! A lease only says that where it is known to: overlayfs grants one over a writable mapping,
//! whose file is the one beneath, so on a filesystem not known to refuse it every file is racy.
//!
//! Unlike the script, this runs in the runner's process, on a directory a job can write, so it is
//! confined and bounded. Every look at the volume is relative to a directory descriptor, through
//! `sandbox.openIn` with no symlink and no mount crossed, so a link a job planted is never taken;
//! only regular files are opened, with O_NONBLOCK, so a pipe cannot hold the check. Files,
//! entries, path bytes, bytes read and time are limited for the check and for each tree, memory
//! is limited for all the checks of the process at once (`Limits.memory`), the job's cancel is
//! seen at every file and every block read, and the environment it makes is bounded. What does
//! not fit in a limit is left out, as a tree it gives up on is: a step then checks the tree
//! itself, and a replayed step that names it runs again. Trees are checked oldest first, by when
//! this runner first saw each (`<tree>.born` beside its list), so what a job adds to the volume
//! is younger than the tools installed before it and cannot take the budget, or the room in the
//! environment, from them. A budget that is spent ends the reading of files, not the check: a
//! tree whose list is whole costs no reading and is still reported. A job that makes its trees
//! before an honest tool exists is older than that tool; the limits bound what that costs.

const std = @import("std");
const linux = std.os.linux;
const dagger = @import("../dagger.zig");
const sandbox = @import("sandbox.zig");
const hash_files = @import("hash_files.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The second variable (`FULL TREE` lines), beside `set_up.tool_trees_env`.
pub const full_env = "ZIG_RUNNER_TOOL_TREES_FULL";

/// What a check may spend. Zig 0.17.0 is 19,505 files and 309 MB; the defaults leave room for a
/// few such tools and stop a tree that is not one.
pub const Limits = struct {
    /// Regular files in one tree.
    tree_files: u32 = 65_536,
    /// Entries of any kind in one tree.
    tree_entries: u32 = 100_000,
    /// Bytes of paths in one tree (Zig's are 1.2 MB).
    tree_path_bytes: u32 = 8 << 20,
    /// Bytes read (hashed) in one tree.
    tree_read_bytes: u64 = 1 << 30,
    /// Time for one tree: the check's, since a tree that gives up keeps no list and the next job
    /// would start cold (Zig's is 10-19 s on razorbill).
    tree_ms: i64 = 60_000,
    /// Entries visited by the whole check, past which no more files are read.
    visited: u32 = 400_000,
    /// Bytes read (hashed) by the whole check: what is not in a list yet or changed since. Past
    /// it no more files are read.
    read_bytes: u64 = 4 << 30,
    /// Directories deep, below the tool cache.
    depth: u32 = 48,
    /// The whole check's reading of files. Razorbill's cold check of Zig is 10-19 s. The check
    /// itself ends at one and a half times this.
    time_ms: i64 = 60_000,
    /// See the file's comment.
    racy_s: i64 = 2,
    /// Bytes of memory that all the checks of the process hold at once (`Budget.checks`, part of
    /// `Budget.held` with the `hashFiles()` calls') may come to when a tree is charged: a tree
    /// that would pass it is given up on. What the calls hold does not count, so a few large
    /// `hashFiles()` cannot leave every check's trees out. Zig's tree takes about 7 MB.
    memory: u64 = 128 << 20,
    /// The process's memory number, shared with `hashFiles()`. A check only takes from it, never
    /// waits for it, and a call is never refused for what a check holds.
    budget: *hash_files.Budget = &hash_files.process_budget,
};

/// What steps are given (`env`, `full`: `DIGEST TREE` lines, `Exec.tool_trees`) and the line
/// "Set up job" says.
pub const Verdict = struct { env: []const u8, full: []const u8, note: []const u8 };

const resolve_no_xdev = 0x01;
const resolve_no_symlinks = 0x04;
/// Both the walk and the reads: no link taken, no other filesystem entered.
const confined = resolve_no_xdev | resolve_no_symlinks;
/// A list is a line per file; one larger than this is neither written nor read.
const max_list_bytes = 32 << 20;
const max_trees = 512;
/// Tools, or versions of one, in the tool cache: the names kept to walk below them.
const max_names = 1024;
/// A path below a tree, and a name: past them an open by path fails anyway.
const max_path = 4000;
const max_name = 100;
/// Each of the two variables: one string of an environment may not pass 128 KiB (`execve`).
const max_env = 64 << 10;
/// "Set up job"'s line, which lists the trees.
const max_note = 4 << 10;

/// Checks the trees under `cache` (the tool cache volume's directory on the host), keeping their
/// lists in `lists`, and says what steps are given. The trees' paths are `mount`'s (where steps
/// see the volume). `gpa` holds one tree's entries at a time.
pub fn check(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    cache: []const u8,
    lists: []const u8,
    mount: []const u8,
    limits: Limits,
    cancel: ?*const dagger.Cancel,
) Allocator.Error!Verdict {
    return (try walk(arena, gpa, io, cache, lists, mount, limits, cancel)).verdict;
}

/// What a walk found, and whether it was cut short (the job's cancel, the clock): a walk that
/// was is no answer for another job.
const Walked = struct { verdict: Verdict, stopped: bool };

fn walk(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    cache: []const u8,
    lists: []const u8,
    mount: []const u8,
    limits: Limits,
    cancel: ?*const dagger.Cancel,
) Allocator.Error!Walked {
    var c: Check = .{
        .io = io,
        .gpa = gpa,
        .limits = limits,
        .cancel = cancel,
        .deadline_ms = nowMs(io) + limits.time_ms,
        .racy_from = @as(i128, std.Io.Clock.real.now(io).toNanoseconds()) -
            @as(i128, limits.racy_s) * std.time.ns_per_s,
    };
    var env: std.ArrayList(u8) = .empty;
    var full: std.ArrayList(u8) = .empty;
    var note: std.ArrayList(u8) = .empty;
    var skipped: std.ArrayList(u8) = .empty;
    const root = openRoot(arena, cache) orelse return .{ .stopped = false, .verdict = .{
        .env = "",
        .full = "",
        .note = "Tool cache: not checked (the volume cannot be opened)",
    } };
    defer _ = linux.close(root);
    // Whatever was found before a trouble is checked: one level that cannot be read, or too many
    // names in it, costs those names and no others.
    var found: std.ArrayList([]const u8) = .empty;
    c.trees(arena, root, lists, &found) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => c.complete = false,
    };
    const order = try c.oldestFirst(arena, lists, found.items);
    for (order, 0..) |rel, at| {
        const digest = c.tree(root, lists, rel) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            // This one only; the others are still checked.
            error.Unreadable => {
                c.left_out += 1;
                try appendCapped(arena, &skipped, rel, c.tree_why, max_note);
                continue;
            },
            error.Stopped => {
                c.left_out += order.len - at;
                break;
            },
        };
        const env_line = try std.fmt.allocPrint(arena, "{x} {s}/{s}", .{ &digest.sum, mount, rel });
        const full_line = try std.fmt.allocPrint(
            arena,
            "{x} {s}/{s}",
            .{ &digest.full, mount, rel },
        );
        if (env.items.len + env_line.len + 1 > max_env or
            full.items.len + full_line.len + 1 > max_env)
        {
            c.left_out += 1;
            try appendCapped(arena, &skipped, rel, "too many trees for the environment", max_note);
            continue;
        }
        for ([_]struct { *std.ArrayList(u8), []const u8 }{
            .{ &env, env_line },
            .{ &full, full_line },
        }) |p| {
            if (p[0].items.len > 0) try p[0].append(arena, '\n');
            try p[0].appendSlice(arena, p[1]);
        }
        if (note.items.len < max_note) try note.print(arena, "{s}{s} ({d} files, {d} read)", .{
            if (note.items.len > 0) ", " else "",
            rel,
            digest.files,
            digest.read,
        });
    }
    if (c.complete) forgetGone(arena, io, lists, found.items);
    sweepLeftovers(arena, io, lists);
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, if (note.items.len == 0)
        "Tool cache: no trees to check"
    else
        try std.fmt.allocPrint(arena, "Tool cache: checked {s}", .{note.items}));
    // Counted as well as named: the names stop at `max_note`.
    if (c.left_out > 0) try text.print(arena, "; left out {d}: {s}{s}", .{
        c.left_out,
        skipped.items,
        if (skipped.items.len >= max_note) ", ..." else "",
    });
    if (c.spent) |why| try text.print(arena, "; reading stopped: {s}", .{why});
    if (c.why) |why| try text.print(arena, "; stopped: {s}", .{why});
    return .{
        .verdict = .{ .env = env.items, .full = full.items, .note = text.items },
        .stopped = c.why != null,
    };
}

/// The checks of the process that are running or waited for, by volume (`checkOnce`).
pub var process_flights: Flights = .{};

/// Single-flight for `check`. Jobs that start together walk the same tree, each stat-ing every
/// file (razorbill, a Pi 5: 220 ms for one job, 590 ms when seven start at once). A walk is
/// never reused for a job that was already waiting when it began, because a file may have been
/// written after the walk passed it. So a job arriving while a walk is running waits for it to
/// end, and the jobs that wait at that moment share the next walk, which began after every one of
/// them arrived: what it saw is no older than what that job's own walk would have seen. Nothing is
/// remembered once nobody is waiting, so a job that arrives later walks the tree itself, whatever
/// the tree's times say: a write to a file moves no directory's mtime, and only the file's own
/// ctime shows it.
pub const Flights = struct {
    mu: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// One per volume (`key`) with a caller in `checkOnce`. Few; looked at in order.
    list: std.ArrayList(*Flight) = .empty,
    /// Walks begun, all volumes (what the tests count).
    walks: u64 = 0,

    const Flight = struct {
        key: []u8,
        /// Callers using it, running or waiting; it goes with the last.
        users: u32 = 0,
        running: bool = false,
        /// Walks begun, and the number of the one `done` is of (0: none).
        begun: u64 = 0,
        done_walk: u64 = 0,
        done: ?Verdict = null,

        /// Keeps `v` as the answer of walk `n`, unless there is no memory for it.
        fn keep(f: *Flight, n: u64, v: Verdict) void {
            const a = std.heap.smp_allocator;
            const env = a.dupe(u8, v.env) catch return;
            const full = a.dupe(u8, v.full) catch return a.free(env);
            const note = a.dupe(u8, v.note) catch {
                a.free(env);
                a.free(full);
                return;
            };
            f.forget();
            f.done = .{ .env = env, .full = full, .note = note };
            f.done_walk = n;
        }

        fn forget(f: *Flight) void {
            const a = std.heap.smp_allocator;
            if (f.done) |v| {
                a.free(v.env);
                a.free(v.full);
                a.free(v.note);
            }
            f.done = null;
        }
    };

    /// Removes a flight nobody uses (the lock is held).
    fn drop(fl: *Flights, f: *Flight) void {
        const a = std.heap.smp_allocator;
        for (fl.list.items, 0..) |x, i| if (x == f) {
            _ = fl.list.swapRemove(i);
            break;
        };
        f.forget();
        a.free(f.key);
        a.destroy(f);
    }
};

/// How often a waiting job looks at its cancel.
const wait_cancel_ms = 100;

/// `check` for the jobs of one process: concurrent calls for one volume share a walk as
/// `Flights` says. Same arguments and answer as `check` with default limits. The key is
/// everything the answer depends on, so volumes of other scopes (other trust) never share one,
/// and a walk cut short (cancelled, out of time) is the leader's alone: the others walk.
pub fn checkOnce(
    fl: *Flights,
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    cache: []const u8,
    lists: []const u8,
    mount: []const u8,
    cancel: ?*const dagger.Cancel,
) Allocator.Error!Verdict {
    const key = try std.fmt.allocPrint(std.heap.smp_allocator, "{s}\x00{s}\x00{s}", .{ cache, lists, mount });
    defer std.heap.smp_allocator.free(key);
    fl.mu.lockUncancelable(io);
    var flight: *Flights.Flight = for (fl.list.items) |f| {
        if (std.mem.eql(u8, f.key, key)) break f;
    } else blk: {
        const f = std.heap.smp_allocator.create(Flights.Flight) catch {
            fl.mu.unlock(io);
            return error.OutOfMemory;
        };
        f.* = .{ .key = std.heap.smp_allocator.dupe(u8, key) catch {
            std.heap.smp_allocator.destroy(f);
            fl.mu.unlock(io);
            return error.OutOfMemory;
        } };
        fl.list.append(std.heap.smp_allocator, f) catch {
            std.heap.smp_allocator.free(f.key);
            std.heap.smp_allocator.destroy(f);
            fl.mu.unlock(io);
            return error.OutOfMemory;
        };
        break :blk f;
    };
    flight.users += 1;
    // A walk numbered above this began after this call did.
    const arrived = flight.begun;
    defer {
        flight.users -= 1;
        if (flight.users == 0) fl.drop(flight);
        fl.mu.unlock(io);
    }
    while (true) {
        if (flight.done_walk > arrived) if (flight.done) |v| return .{
            .env = try arena.dupe(u8, v.env),
            .full = try arena.dupe(u8, v.full),
            .note = try arena.dupe(u8, v.note),
        };
        const cancelled = if (cancel) |x| x.requested.load(.acquire) else false;
        if (cancelled) {
            // It walks alone and stops at once; no one waits for it.
            fl.mu.unlock(io);
            defer fl.mu.lockUncancelable(io);
            return check(arena, gpa, io, cache, lists, mount, .{}, cancel);
        }
        if (flight.running) {
            fl.cond.waitTimeout(io, &fl.mu, .{ .duration = .{
                .raw = .fromMilliseconds(wait_cancel_ms),
                .clock = .awake,
            } }) catch |e| switch (e) {
                // Either way the loop looks at the cancel and the walk again.
                error.Timeout, error.Canceled => {},
            };
            continue;
        }
        flight.running = true;
        flight.begun += 1;
        fl.walks += 1;
        const mine = flight.begun;
        fl.mu.unlock(io);
        const walked = walk(arena, gpa, io, cache, lists, mount, .{}, cancel);
        fl.mu.lockUncancelable(io);
        flight.running = false;
        defer fl.cond.broadcast(io);
        const w = try walked;
        if (!w.stopped) flight.keep(mine, w.verdict);
        return w.verdict;
    }
}

fn appendCapped(
    arena: Allocator,
    list: *std.ArrayList(u8),
    rel: []const u8,
    why: []const u8,
    cap: usize,
) Allocator.Error!void {
    if (list.items.len >= cap) return;
    try list.print(arena, "{s}{s} ({s})", .{ if (list.items.len > 0) ", " else "", rel, why });
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.awake.now(io).toMilliseconds();
}

/// A check in progress: what it has spent, and why it stopped when it did.
const Check = struct {
    io: std.Io,
    gpa: Allocator,
    limits: Limits,
    cancel: ?*const dagger.Cancel,
    deadline_ms: i64,
    /// Files with a ctime from here on are "racy" (ns since the epoch).
    racy_from: i128,
    visited: u32 = 0,
    read: u64 = 0,
    why: ?[]const u8 = null,
    /// A budget of the check is spent (why): no more files are read, and trees that need none
    /// are still checked.
    spent: ?[]const u8 = null,
    /// Trees left out, whether or not the note names them.
    left_out: usize = 0,
    /// Every tree was found (the walk to them was not cut short), so a list without one is stale.
    complete: bool = true,
    /// The tree being checked: what it has spent, its own deadline, and why it was given up on.
    in_tree: bool = false,
    tree_entries: u32 = 0,
    tree_files: u32 = 0,
    tree_path: u64 = 0,
    tree_read: u64 = 0,
    tree_deadline_ms: i64 = 0,
    tree_why: []const u8 = "",
    /// Bytes of `limits.budget.held` that this tree took.
    mine: u64 = 0,

    const Error = error{ OutOfMemory, Unreadable, Stopped };

    /// One more entry looked at: the job's cancel and the clock seen, the clock every 64th.
    fn visit(c: *Check) Error!void {
        c.visited += 1;
        c.tree_entries += 1;
        if (c.visited > c.limits.visited) c.spent = c.spent orelse "too many entries";
        if (c.in_tree and c.tree_entries > c.limits.tree_entries)
            return c.giveUp("too many entries");
        if (c.visited % 64 == 0) try c.poll();
    }

    fn poll(c: *Check) Error!void {
        if (c.cancel) |x| if (x.requested.load(.acquire)) return c.stop("the job was cancelled");
        const now = nowMs(c.io);
        if (now > c.deadline_ms) c.spent = c.spent orelse "out of time";
        if (now > c.deadline_ms + @divTrunc(c.limits.time_ms, 2)) return c.stop("out of time");
        if (c.in_tree and now > c.tree_deadline_ms) return c.giveUp("out of time for the tree");
    }

    /// The whole check ends.
    fn stop(c: *Check, why: []const u8) error{Stopped} {
        c.why = c.why orelse why;
        c.complete = false;
        return error.Stopped;
    }

    /// This tree is left out; the others go on.
    fn giveUp(c: *Check, why: []const u8) error{Unreadable} {
        c.tree_why = why;
        return error.Unreadable;
    }

    /// `n` bytes of memory about to be allocated for the tree, against what all checks hold.
    fn charge(c: *Check, n: usize) error{Unreadable}!void {
        c.mine += n;
        _ = c.limits.budget.held.fetchAdd(n, .acq_rel);
        if (c.limits.budget.checks.fetchAdd(n, .acq_rel) + n > c.limits.memory)
            return c.giveUp("too much memory in use");
    }

    /// The directories `TOOL/VERSION/NAME` of the tool cache that are real directories, none
    /// named with a dot (install-zig.sh unpacks into one before moving a tree into place).
    fn trees(
        c: *Check,
        arena: Allocator,
        root: linux.fd_t,
        lists: []const u8,
        found: *std.ArrayList([]const u8),
    ) Error!void {
        try c.level(arena, root, "", 0, lists, found);
    }

    /// The names at one level that lead to trees. Those a list says were checked once come
    /// first, whatever else the directory holds: a job that fills a level with names costs the
    /// trees that are new, and no tree that was checked before. Then the rest, in byte order,
    /// of as many as are looked at (`max_names`, from the first `max_names * 16` the directory
    /// gives); what is left out is said so.
    fn level(
        c: *Check,
        arena: Allocator,
        dir: linux.fd_t,
        prefix: []const u8,
        depth: u32,
        lists: []const u8,
        found: *std.ArrayList([]const u8),
    ) Error!void {
        var names: std.ArrayList([]const u8) = .empty;
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        try c.listedNames(arena, lists, prefix, depth, &names, &seen);
        const listed = names.items.len;
        var it = (std.Io.Dir{ .handle = dir }).iterate();
        var looked: usize = 0;
        while (it.next(c.io) catch |e| return rearmed(c.io, e, error.Unreadable)) |e| {
            try c.visit();
            if (e.kind != .directory or !treeName(e.name)) continue;
            looked += 1;
            if (looked > max_names * 16) {
                c.complete = false;
                c.why = c.why orelse "too many names in the tool cache";
                break;
            }
            if (seen.contains(e.name)) continue;
            try names.append(arena, try arena.dupe(u8, e.name));
        }
        // Byte order, so what is left out of a full level is the same in every job.
        std.mem.sort([]const u8, names.items[listed..], {}, pathLess);
        if (names.items.len > max_names) {
            names.items.len = max_names;
            c.complete = false;
            c.why = c.why orelse "too many tools or versions";
        }
        for (names.items) |name| {
            const rel = if (prefix.len == 0)
                name
            else
                try std.fmt.allocPrint(arena, "{s}/{s}", .{ prefix, name });
            const sub = openDir(dir, try arena.dupeSentinel(u8, name, 0)) orelse continue;
            defer _ = linux.close(sub);
            if (depth == 2) {
                if (found.items.len >= max_trees) {
                    c.complete = false;
                    c.why = c.why orelse "too many trees";
                    return;
                }
                try found.append(arena, rel);
                continue;
            }
            c.level(arena, sub, rel, depth + 1, lists, found) catch |e| switch (e) {
                // One directory that cannot be read costs its own trees.
                error.Unreadable => c.complete = false,
                else => return e,
            };
        }
    }

    /// The names in the lists at `prefix` (the runner's own, so as many as it ever listed: at
    /// most `max_names` are read), sorted, and in `seen`.
    fn listedNames(
        c: *Check,
        arena: Allocator,
        lists: []const u8,
        prefix: []const u8,
        depth: u32,
        names: *std.ArrayList([]const u8),
        seen: *std.StringHashMapUnmanaged(void),
    ) Allocator.Error!void {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ lists, prefix });
        var dir = std.Io.Dir.cwd().openDir(c.io, path, .{ .iterate = true }) catch |e| return rearm(c.io, e);
        defer dir.close(c.io);
        var it = dir.iterate();
        while (it.next(c.io) catch |e| noEntry(c.io, e)) |e| {
            if (names.items.len >= max_names) break;
            const name = if (depth == 2)
                (if (e.kind == .file and std.mem.endsWith(u8, e.name, ".born"))
                    e.name[0 .. e.name.len - ".born".len]
                else
                    continue)
            else if (e.kind == .directory) e.name else continue;
            if (!treeName(name)) continue;
            const owned = try arena.dupe(u8, name);
            try names.append(arena, owned);
            try seen.put(arena, owned, {});
        }
        std.mem.sort([]const u8, names.items, {}, pathLess);
    }

    /// `found` oldest first, by when this runner first saw each tree (`bornAt`), then in byte
    /// order. A tree a job makes is born after the tools an honest job installed before it, so it
    /// is checked after them, and the budget and the room in the environment it spends are the
    /// ones left. A tree seen now for the first time is born now.
    fn oldestFirst(
        c: *Check,
        arena: Allocator,
        lists: []const u8,
        found: []const []const u8,
    ) Allocator.Error![]const []const u8 {
        const Row = struct { rel: []const u8, born: i128 };
        const rows = try arena.alloc(Row, found.len);
        const now = std.Io.Clock.real.now(c.io).toNanoseconds();
        for (found, rows) |rel, *r| {
            r.* = .{ .rel = rel, .born = c.bornAt(arena, lists, rel, now) };
        }
        std.mem.sort(Row, rows, {}, struct {
            fn less(_: void, a: Row, b: Row) bool {
                if (a.born != b.born) return a.born < b.born;
                return pathLess({}, a.rel, b.rel);
            }
        }.less);
        const out = try arena.alloc([]const u8, rows.len);
        for (rows, out) |r, *o| o.* = r.rel;
        return out;
    }

    /// When the tree was first seen, from its `.born` file, which is made now if it is not there.
    fn bornAt(c: *Check, arena: Allocator, lists: []const u8, rel: []const u8, now: i128) i128 {
        const path = std.fmt.allocPrint(arena, "{s}/{s}.born", .{ lists, rel }) catch return now;
        if (std.Io.Dir.cwd().readFileAlloc(c.io, path, arena, .limited(64))) |text| {
            if (std.fmt.parseInt(i128, std.mem.trim(u8, text, "\n"), 10)) |t| return t else |_| {}
        } else |e| rearm(c.io, e);
        const text = std.fmt.allocPrint(arena, "{d}\n", .{now}) catch return now;
        keepList(arena, c.io, path, text);
        return now;
    }

    const Digest = struct {
        sum: [Sha256.digest_length]u8,
        full: [Sha256.digest_length]u8,
        files: usize,
        read: usize,
    };

    /// One tree's digests, from its list where a file's line is unchanged, and the list rewritten.
    fn tree(
        c: *Check,
        root: linux.fd_t,
        lists: []const u8,
        rel: []const u8,
    ) Error!Digest {
        var ta: std.heap.ArenaAllocator = .init(c.gpa);
        c.in_tree = true;
        c.tree_entries = 0;
        c.tree_files = 0;
        c.tree_path = 0;
        c.tree_read = 0;
        c.tree_why = "cannot be read";
        c.tree_deadline_ms = nowMs(c.io) + c.limits.tree_ms;
        defer {
            ta.deinit();
            c.in_tree = false;
            _ = c.limits.budget.held.fetchSub(c.mine, .acq_rel);
            _ = c.limits.budget.checks.fetchSub(c.mine, .acq_rel);
            c.mine = 0;
        }
        const t = ta.allocator();
        try c.visit();
        const top = openDir(root, try t.dupeSentinel(u8, rel, 0)) orelse
            return c.giveUp("cannot be opened");
        defer _ = linux.close(top);

        var entries: std.ArrayList(Entry) = .empty;
        try c.walk(t, top, "", 0, &entries);
        std.mem.sort(Entry, entries.items, {}, Entry.less);

        const list_path = try std.fmt.allocPrint(t, "{s}/{s}.stat", .{ lists, rel });
        const old_text = c.readText(t, list_path);
        const old = if (old_text) |text| c.readList(t, text, entries.items) else null;
        var sums = Sha256.init(.{});
        var all = Sha256.init(.{});
        var reread: usize = 0;
        var out: std.ArrayList(u8) = .empty;
        var buf: [2 * max_path + 128]u8 = undefined;
        var files: usize = 0;
        var i: usize = 0;
        for (entries.items) |*e| {
            try c.poll();
            var extra: []const u8 = e.target;
            var hex: [2 * Sha256.digest_length]u8 = undefined;
            if (e.kind == .file) {
                const kept = if (old) |o| o[i].keep(e.stat) else null;
                i += 1;
                files += 1;
                if (kept) |h| e.hash = h else {
                    try c.hashFile(t, top, e);
                    reread += 1;
                }
                const st = e.stat;
                // Racy: written lately, or not known to be at rest (`hashFile`).
                const racy = e.racy or st.ctime >= c.racy_from;
                try out.print(t, "{s}\t{d}\t{d}\t{d}\t", .{ e.path, st.size, st.ino, st.mtime });
                if (racy) try out.appendSlice(t, "racy") else try out.print(t, "{d}", .{st.ctime});
                try out.print(t, "\t{x}\n", .{&e.hash});
                // `sha256sum`'s line, which install-zig.sh pins the digest of.
                const line = std.fmt.bufPrint(&buf, "{x}  {s}\n", .{ &e.hash, e.path }) catch
                    return c.giveUp("a path is too long");
                sums.update(line);
                hex = std.fmt.bytesToHex(e.hash, .lower);
                extra = &hex;
            }
            const type_char: u8 = switch (e.kind) {
                .file => 'f',
                .dir => 'd',
                .link => 'l',
                .other => 'o',
            };
            const line = std.fmt.bufPrint(&buf, "{c} {o} {d} {s} {d} {s}\n", .{
                type_char, e.mode, e.path.len, e.path, extra.len, extra,
            }) catch return c.giveUp("a path is too long");
            all.update(line);
        }
        var digest: Digest = .{
            .sum = undefined,
            .full = undefined,
            .files = files,
            .read = reread,
        };
        sums.final(&digest.sum);
        all.final(&digest.full);
        // One that would not be read again is not written, and one that is the list already there
        // is not written again: the old file is the same bytes, and nothing reads its times (only
        // half-written parts are aged, in `walkLists`).
        const unchanged = if (old_text) |text| std.mem.eql(u8, text, out.items) else false;
        if (out.items.len <= max_list_bytes and !unchanged) keepList(t, c.io, list_path, out.items);
        return digest;
    }

    /// `dir`'s entries, and its directories' below it (`prefix` the path from the tree's top, `./`
    /// first). Nothing is opened but directories and, later, regular files: a symbolic link is
    /// read, not followed, and a pipe or a device is neither.
    fn walk(
        c: *Check,
        t: Allocator,
        dir: linux.fd_t,
        prefix: []const u8,
        depth: u32,
        entries: *std.ArrayList(Entry),
    ) Error!void {
        if (depth > c.limits.depth) return c.giveUp("too deep");
        const here = if (prefix.len == 0) "." else prefix;
        var subdirs: std.ArrayList([]const u8) = .empty;
        var it = (std.Io.Dir{ .handle = dir }).iterate();
        while (it.next(c.io) catch |e| return rearmed(c.io, e, error.Unreadable)) |e| {
            try c.visit();
            // A name sha256sum would escape, or one a list's line cannot hold: not listed.
            for (e.name) |ch| if (ch < 0x20 or ch == 0x7f or ch == '\\')
                return c.giveUp("a name that cannot be listed");
            if (e.name.len > 255 or here.len + 1 + e.name.len > max_path)
                return c.giveUp("a path is too long");
            var name_buf: [256]u8 = undefined;
            @memcpy(name_buf[0..e.name.len], e.name);
            name_buf[e.name.len] = 0;
            const name = name_buf[0..e.name.len :0];
            var st: linux.Statx = undefined;
            if (linux.errno(linux.statx(dir, name, linux.AT.SYMLINK_NOFOLLOW, .{
                .TYPE = true,
                .MODE = true,
                .SIZE = true,
                .INO = true,
                .MTIME = true,
                .CTIME = true,
            }, &st)) != .SUCCESS) return c.giveUp("cannot be read");
            const kind: Kind = switch (st.mode & linux.S.IFMT) {
                linux.S.IFREG => .file,
                linux.S.IFDIR => .dir,
                linux.S.IFLNK => .link,
                else => .other,
            };
            if (kind == .file) {
                c.tree_files += 1;
                if (c.tree_files > c.limits.tree_files) return c.giveUp("too many files");
            }
            c.tree_path += here.len + 1 + e.name.len;
            if (c.tree_path > c.limits.tree_path_bytes) return c.giveUp("too many bytes of paths");
            const path_len = here.len + 1 + e.name.len;
            try c.charge(@sizeOf(Entry) + 2 * path_len + 150);
            const path = try std.fmt.allocPrint(t, "{s}/{s}", .{ here, e.name });
            var target: []const u8 = "";
            if (kind == .link) {
                var tb: [max_path]u8 = undefined;
                const n = linux.readlinkat(dir, name, &tb, tb.len);
                if (linux.errno(n) != .SUCCESS or n >= tb.len) return c.giveUp("cannot be read");
                if (leavesTree(path, tb[0..n])) return c.giveUp("a link leaves the tree");
                try c.charge(n);
                target = try t.dupe(u8, tb[0..n]);
            }
            try entries.append(t, .{
                .path = path,
                .kind = kind,
                .mode = st.mode & 0o7777,
                .stat = Stat.of(st),
                .target = target,
            });
            if (kind == .dir) try subdirs.append(t, path);
        }
        for (subdirs.items) |path| {
            const sub = openDir(dir, try t.dupeSentinel(u8, std.fs.path.basename(path), 0)) orelse
                return c.giveUp("cannot be read");
            defer _ = linux.close(sub);
            try c.walk(t, sub, path, depth + 1, entries);
        }
    }

    /// `f`'s sha256, and its stat as the descriptor says it, taken before the first byte is read:
    /// a write after it has a later ctime than the line records. And whether the file is at rest
    /// (`Entry.racy`): a read lease, which the kernel refuses while anything holds the file
    /// open for writing, a shared mapping that outlived its descriptor included.
    fn hashFile(c: *Check, t: Allocator, top: linux.fd_t, f: *Entry) Error!void {
        if (c.spent) |why| return c.giveUp(why);
        const rel = try t.dupeSentinel(u8, f.path[2..], 0);
        const fd = switch (sandbox.openIn(top, rel, .{
            .ACCMODE = .RDONLY,
            .NONBLOCK = true,
            .NOCTTY = true,
        }, 0, confined)) {
            .fd => |x| x,
            .err => return c.giveUp("cannot be read"),
        };
        defer _ = linux.close(fd);
        // A lease is broken, when someone opens the file for writing, with a signal to the
        // process, SIGIO unless told otherwise, and SIGIO is `std.Io`'s to interrupt a blocked
        // call (`Threaded`): it is not ours to ignore. SIGURG is ignored by default.
        _ = linux.fcntl(fd, linux.F.SETSIG, @backingInt(linux.SIG.URG));
        const leased = linux.errno(linux.fcntl(fd, linux.F.SETLEASE, linux.F.RDLCK)) == .SUCCESS;
        defer if (leased) {
            _ = linux.fcntl(fd, linux.F.SETLEASE, linux.F.UNLCK);
        };
        f.racy = !leased or !leasesSeeMappings(fsType(fd));
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
            .TYPE = true,
            .MODE = true,
            .SIZE = true,
            .INO = true,
            .MTIME = true,
            .CTIME = true,
        }, &st)) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFREG)
            return c.giveUp("cannot be read");
        f.stat = Stat.of(st);
        var h = Sha256.init(.{});
        var block: [64 * 1024]u8 = undefined;
        while (true) {
            const n = linux.read(fd, &block, block.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return c.giveUp("cannot be read"),
            }
            if (n == 0) break;
            c.read += n;
            c.tree_read += n;
            if (c.read > c.limits.read_bytes) {
                c.spent = c.spent orelse "too many bytes to read";
                return c.giveUp("too many bytes to read");
            }
            if (c.tree_read > c.limits.tree_read_bytes) return c.giveUp("too many bytes to read");
            h.update(block[0..n]);
            try c.poll();
        }
        h.final(&f.hash);
    }

    /// The bytes of the list at `path`, null if there is none or it is too big to be one.
    fn readText(c: *Check, t: Allocator, path: []const u8) ?[]const u8 {
        const text = std.Io.Dir.cwd().readFileAlloc(c.io, path, t, .limited(max_list_bytes)) catch |e| {
            rearm(c.io, e);
            return null;
        };
        c.charge(text.len) catch return null;
        return text;
    }

    /// The list `text`, when it holds exactly the regular files' paths in order and each line
    /// parses; otherwise null and every file is read.
    fn readList(c: *Check, t: Allocator, text: []const u8, entries: []const Entry) ?[]Line {
        const lines = t.alloc(Line, entries.len) catch return null;
        c.charge(lines.len * @sizeOf(Line)) catch return null;
        var rows = std.mem.splitScalar(u8, text, '\n');
        var n: usize = 0;
        for (entries) |e| {
            if (e.kind != .file) continue;
            lines[n] = Line.parse(rows.next() orelse return null, e.path) orelse return null;
            n += 1;
        }
        // Only the empty piece after the last newline is left.
        if (!std.mem.eql(u8, rows.rest(), "")) return null;
        return lines[0..n];
    }
};

const Kind = enum { file, dir, link, other };

/// An entry of a tree: its path from the tree's top (`./a/b`), what it is, its mode and stat, and
/// a regular file's sha256 or a link's target.
const Entry = struct {
    path: []const u8,
    kind: Kind,
    mode: u16,
    stat: Stat,
    target: []const u8 = "",
    hash: [Sha256.digest_length]u8 = undefined,
    /// Not known to be at rest: listed so that the next check reads it again.
    racy: bool = false,

    fn less(_: void, a: Entry, b: Entry) bool {
        return pathLess({}, a.path, b.path);
    }
};

/// Whether the link at `path` (`./a/b`) with this `target` may lead out of the tree, taking its
/// text only: an absolute target, more leading `..` than the directories above the link, or a
/// `..` after a name. The last is refused whatever follows because a name may be a link (to `..`,
/// say), and then the `..` after it is one more than the text counts. With `..` only first, a
/// link that stays in the tree from where it is leads to a place in the tree, whatever the links
/// on its way are, since each of those was checked the same.
fn leavesTree(path: []const u8, target: []const u8) bool {
    if (target.len == 0 or target[0] == '/') return true;
    var above: usize = 0; // directories above the link inside the tree: "./a/b" has one
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |_| above += 1;
    above -= 2;
    var steps = std.mem.splitScalar(u8, target, '/');
    var leading = true;
    while (steps.next()) |s| {
        if (std.mem.eql(u8, s, "..")) {
            if (!leading) return true;
            if (above == 0) return true;
            above -= 1;
        } else if (s.len > 0 and !std.mem.eql(u8, s, ".")) leading = false;
    }
    return false;
}

const Stat = struct {
    size: u64,
    ino: u64,
    mtime: i128,
    ctime: i128,

    fn of(st: linux.Statx) Stat {
        return .{
            .size = st.size,
            .ino = st.ino,
            .mtime = ns(st.mtime),
            .ctime = ns(st.ctime),
        };
    }

    fn ns(t: linux.statx_timestamp) i128 {
        return @as(i128, t.sec) * std.time.ns_per_s + t.nsec;
    }
};

/// A list's line, as read: the stat it recorded (a ctime that is null was "racy") and the hash.
const Line = struct {
    stat: Stat,
    racy: bool,
    hash: [Sha256.digest_length]u8,

    fn parse(row: []const u8, path: []const u8) ?Line {
        var f = std.mem.splitScalar(u8, row, '\t');
        if (!std.mem.eql(u8, f.next() orelse return null, path)) return null;
        const size = std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
        const ino = std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
        const mtime = std.fmt.parseInt(i128, f.next() orelse return null, 10) catch return null;
        const ctime_text = f.next() orelse return null;
        const hash_text = f.next() orelse return null;
        if (f.next() != null) return null;
        const racy = std.mem.eql(u8, ctime_text, "racy");
        const ctime = if (racy) 0 else std.fmt.parseInt(i128, ctime_text, 10) catch return null;
        var hash: [Sha256.digest_length]u8 = undefined;
        if (hash_text.len != 2 * hash.len) return null;
        _ = std.fmt.hexToBytes(&hash, hash_text) catch return null;
        return .{
            .stat = .{ .size = size, .ino = ino, .mtime = mtime, .ctime = ctime },
            .racy = racy,
            .hash = hash,
        };
    }

    /// The hash, when the file is as the line says it was and the line was not made inside the
    /// clock's tick of a write, or of a file that was not at rest.
    fn keep(l: Line, now: Stat) ?[Sha256.digest_length]u8 {
        if (l.racy) return null;
        const s = l.stat;
        if (s.size != now.size or s.ino != now.ino or s.mtime != now.mtime or s.ctime != now.ctime)
            return null;
        return l.hash;
    }
};

fn pathLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// A name that can be a tree's (or its parents'): what a tool cache's directories are called,
/// and the characters `set_up.path_chars` lets into a path.
fn treeName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name or name[0] == '.') return false;
    for (name) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "._+-", ch) == null)
            return false;
    }
    return true;
}

fn openRoot(arena: Allocator, path: []const u8) ?linux.fd_t {
    const fd = linux.open(arena.dupeSentinel(u8, path, 0) catch return null, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    return std.math.cast(linux.fd_t, fd);
}

fn openDir(parent: linux.fd_t, name: [:0]const u8) ?linux.fd_t {
    return switch (sandbox.openIn(parent, name, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOCTTY = true,
    }, 0, confined)) {
        .fd => |fd| fd,
        .err => null,
    };
}

/// Writes a tree's list to a file of its own and moves it into place, as a job set up at the same
/// time reads the old one or the new, never a part. A list that cannot be kept costs the next
/// check a read of the tree.
fn keepList(t: Allocator, io: std.Io, path: []const u8, text: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| cwd.createDirPath(io, dir) catch |e| return rearm(io, e);
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const part = std.fmt.allocPrint(t, "{s}.{x}", .{ path, &raw }) catch return;
    cwd.writeFile(io, .{ .sub_path = part, .data = text }) catch |e| {
        rearm(io, e);
        cwd.deleteFile(io, part) catch |d| rearm(io, d);
        return;
    };
    cwd.rename(part, cwd, path, io) catch |e| {
        rearm(io, e);
        cwd.deleteFile(io, part) catch |d| rearm(io, d);
    };
}

/// The filesystem `fd` is on, 0 if that cannot be told: `struct statfs`'s `f_type`, first, a long
/// on x86_64 and aarch64.
fn fsType(fd: linux.fd_t) u64 {
    var st: [120]u8 align(8) = undefined;
    if (linux.errno(linux.syscall2(.fstatfs, std.math.cast(usize, fd) orelse return 0, @intFromPtr(&st))) != .SUCCESS)
        return 0;
    return std.mem.readInt(u64, st[0..8], .little);
}

/// Whether a read lease on this filesystem is refused while a writable mapping holds the file:
/// only those it was seen on (the test "a file a shared mapping still writes"). A file anywhere
/// else is read again at each check, which costs a read and never trust.
fn leasesSeeMappings(fs_type: u64) bool {
    const ext4 = 0xef53;
    const tmpfs = 0x01021994;
    return fs_type == ext4 or fs_type == tmpfs;
}

/// These lists are a cache: a failure here costs a read later, and is dropped. A cancel is not:
/// std.Io delivers it once, so it is re-armed for what runs next.
fn rearm(io: std.Io, e: anyerror) void {
    if (e == error.Canceled) io.recancel();
}

fn rearmed(io: std.Io, e: anyerror, as: anytype) @TypeOf(as) {
    rearm(io, e);
    return as;
}

fn noEntry(io: std.Io, e: anyerror) ?std.Io.Dir.Entry {
    rearm(io, e);
    return null;
}

/// How old a half-written list (`keepList`'s file before it is moved) must be to be a leftover of
/// a runner that died, not of one that is writing it now.
const leftover_age_ms = 5 * 60 * 1000;

/// Removes the lists of trees that are gone (`found` is every tree there is), and the
/// directories that leaves empty.
fn forgetGone(arena: Allocator, io: std.Io, lists: []const u8, found: []const []const u8) void {
    walkLists(arena, io, lists, found, false);
}

/// Removes half-written lists a dead runner left. Store eviction may remove all of `lists`: it
/// is a cache of what a check read, and a check without it reads the trees again.
fn sweepLeftovers(arena: Allocator, io: std.Io, lists: []const u8) void {
    walkLists(arena, io, lists, &.{}, true);
}

fn walkLists(
    arena: Allocator,
    io: std.Io,
    lists: []const u8,
    found: []const []const u8,
    leftovers: bool,
) void {
    const now_ms = std.Io.Clock.real.now(io).toMilliseconds();
    var tools = std.Io.Dir.cwd().openDir(io, lists, .{ .iterate = true }) catch |e| return rearm(io, e);
    defer tools.close(io);
    var t_it = tools.iterate();
    while (t_it.next(io) catch |e| noEntry(io, e)) |tool| {
        if (tool.kind != .directory) continue;
        var versions = tools.openDir(io, tool.name, .{ .iterate = true }) catch |e| {
            rearm(io, e);
            continue;
        };
        defer versions.close(io);
        var v_it = versions.iterate();
        while (v_it.next(io) catch |e| noEntry(io, e)) |version| {
            if (version.kind != .directory) continue;
            var names = versions.openDir(io, version.name, .{ .iterate = true }) catch |e| {
                rearm(io, e);
                continue;
            };
            defer names.close(io);
            var n_it = names.iterate();
            while (n_it.next(io) catch |e| noEntry(io, e)) |list| {
                if (list.kind != .file) continue;
                if (leftovers) {
                    if (std.mem.indexOf(u8, list.name, ".stat.") == null and
                        std.mem.indexOf(u8, list.name, ".born.") == null) continue;
                    const st = names.statFile(io, list.name, .{}) catch |e| {
                        rearm(io, e);
                        continue;
                    };
                    if (now_ms - st.mtime.toMilliseconds() > leftover_age_ms)
                        names.deleteFile(io, list.name) catch |e| rearm(io, e);
                    continue;
                }
                const stem = if (std.mem.endsWith(u8, list.name, ".stat"))
                    list.name[0 .. list.name.len - ".stat".len]
                else if (std.mem.endsWith(u8, list.name, ".born"))
                    list.name[0 .. list.name.len - ".born".len]
                else
                    continue;
                const rel = std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{
                    tool.name,
                    version.name,
                    stem,
                }) catch return;
                const present = for (found) |f| {
                    if (std.mem.eql(u8, f, rel)) break true;
                } else false;
                if (!present) names.deleteFile(io, list.name) catch |e| rearm(io, e);
            }
            if (!leftovers) versions.deleteDir(io, version.name) catch |e| rearm(io, e);
        }
        if (!leftovers) tools.deleteDir(io, tool.name) catch |e| rearm(io, e);
    }
}

// --- tests ---

const tree_rel = "zig/0.17.0/zig-x86_64-linux-0.17.0";

/// A tool cache with the tree of `tree_rel` in it: what a few of Zig's files look like, a name
/// that sorts differently by component than by path, and what a job could leave beside them (a
/// link out of the tree, a pipe, an empty directory, a dot-named directory a tree is unpacked in).
const Fixture = struct { cache: []const u8, lists: []const u8 };

fn fixture(arena: Allocator, tmp: *std.testing.TmpDir) !Fixture {
    const io = std.testing.io;
    const d = tmp.dir;
    for ([_][]const u8{
        tree_rel ++ "/lib/std",
        tree_rel ++ "/a-b",
        tree_rel ++ "/a",
        tree_rel ++ "/empty",
        "zig/0.17.0/.unpacking/x",
        "node/22.0.0/x64/bin",
        "shallow/1",
    }) |p| try d.createDirPath(io, try std.fmt.allocPrint(arena, "cache/{s}", .{p}));
    for ([_][2][]const u8{
        .{ tree_rel ++ "/zig", "zig binary\n" },
        .{ tree_rel ++ "/lib/std/std.zig", "pub fn main() void {}\n" },
        .{ tree_rel ++ "/a-b/x", "dash\n" },
        .{ tree_rel ++ "/a/x", "plain\n" },
        .{ tree_rel ++ "/with space", "space\n" },
        .{ "zig/0.17.0/.unpacking/x/f", "half unpacked\n" },
        .{ "node/22.0.0/x64/bin/node", "node\n" },
        .{ "shallow/1/f", "too shallow\n" },
    }) |f| try d.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "cache/{s}", .{f[0]}),
        .data = f[1],
    });
    // Links inside the tree, to a file and to a directory, and a pipe nothing writes to.
    try d.symLink(io, "zig", "cache/" ++ tree_rel ++ "/zig-link", .{});
    try d.symLink(io, "lib", "cache/" ++ tree_rel ++ "/lib-link", .{});
    try d.createDirPath(io, "lists");
    const root = try d.realPathFileAlloc(io, ".", arena);
    const cache = try std.fmt.allocPrint(arena, "{s}/cache", .{root});
    const fifo = try std.process.run(arena, io, .{
        .argv = &.{ "mkfifo", try std.fmt.allocPrint(arena, "{s}/{s}/pipe", .{ cache, tree_rel }) },
    });
    try std.testing.expect(fifo.term == .exited and fifo.term.exited == 0);
    return .{ .cache = cache, .lists = try std.fmt.allocPrint(arena, "{s}/lists", .{root}) };
}

/// The digest install-zig.sh pins, by the commands it runs.
fn shellDigest(arena: Allocator, tree: []const u8) ![]const u8 {
    const out = try std.process.run(arena, std.testing.io, .{
        .argv = &.{
            "sh", "-c",
            "cd \"$0\" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | " ++
                "sha256sum | cut -c1-64",
            tree,
        },
    });
    try std.testing.expect(out.term == .exited and out.term.exited == 0);
    return std.mem.trim(u8, out.stdout, "\n");
}

fn expectIn(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ needle, haystack });
        return error.TestUnexpectedResult;
    }
}

fn checkWith(arena: Allocator, f: anytype, limits: Limits, cancel: ?*const dagger.Cancel) !Verdict {
    const gpa = std.testing.allocator;
    return check(arena, gpa, std.testing.io, f.cache, f.lists, "/t", limits, cancel);
}

test "tool trees: the digest is the one install-zig.sh pins, for the cache's trees only" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const v = try checkWith(arena, f, .{}, null);
    const want = try std.fmt.allocPrint(arena, "{s} /t/node/22.0.0/x64\n{s} /t/{s}", .{
        try shellDigest(arena, try std.fmt.allocPrint(arena, "{s}/node/22.0.0/x64", .{f.cache})),
        try shellDigest(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel })),
        tree_rel,
    });
    try std.testing.expectEqualStrings(want, v.env);
    try std.testing.expectEqualStrings("Tool cache: checked node/22.0.0/x64 (1 files, 1 read), " ++
        tree_rel ++ " (5 files, 5 read)", v.note);
}

test "tool trees: a list spares the reading, and a change it cannot hide is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // Where a lease says nothing every file is racy, and no list spares a read.
    const dir_fd = linux.open(try std.fmt.allocPrintSentinel(arena, "{s}", .{f.cache}, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(dir_fd) == .SUCCESS);
    defer _ = linux.close(std.math.cast(linux.fd_t, dir_fd).?);
    if (!leasesSeeMappings(fsType(std.math.cast(linux.fd_t, dir_fd).?))) return error.SkipZigTest;
    const tree = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel });
    const first = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const second = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(first.env, second.env);
    try expectIn(second.note, tree_rel ++ " (5 files, 0 read)");
    // One byte changed, the size and the mtime put back: the ctime is what a job cannot.
    const forge = "cd \"$0\" && touch -r zig ref && printf 'zig binarY\\n' > zig && " ++
        "touch -r ref zig && rm ref";
    const forged = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", forge, tree } });
    try std.testing.expect(forged.term == .exited and forged.term.exited == 0);
    const third = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expect(!std.mem.eql(u8, first.env, third.env));
    try expectIn(third.note, tree_rel ++ " (5 files, 1 read)");
    try expectIn(third.env, try shellDigest(arena, tree));
}

test "tool trees: a walk that finds the list it read is not written over it, and a change is" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const dir_fd = linux.open(try std.fmt.allocPrintSentinel(arena, "{s}", .{f.cache}, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(dir_fd) == .SUCCESS);
    defer _ = linux.close(std.math.cast(linux.fd_t, dir_fd).?);
    if (!leasesSeeMappings(fsType(std.math.cast(linux.fd_t, dir_fd).?))) return error.SkipZigTest;
    const list = try std.fmt.allocPrint(arena, "{s}/{s}.stat", .{ f.lists, tree_rel });
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const first = try std.Io.Dir.cwd().statFile(io, list, .{});
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const second = try std.Io.Dir.cwd().statFile(io, list, .{});
    try std.testing.expectEqual(first.inode, second.inode);
    try std.testing.expectEqual(first.mtime.nanoseconds, second.mtime.nanoseconds);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}/new-file", .{ f.cache, tree_rel }),
        .data = "new\n",
    });
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const third = try std.Io.Dir.cwd().statFile(io, list, .{});
    try std.testing.expect(third.inode != second.inode);
}

test "tool trees: a file written within the clock's tick of the check is read next time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // Everything was just written: all of it is racy, and none of it is trusted.
    _ = try checkWith(arena, f, .{ .racy_s = 3600 }, null);
    const again = try checkWith(arena, f, .{ .racy_s = 3600 }, null);
    try expectIn(again.note, tree_rel ++ " (5 files, 5 read)");
}

test "tool trees: a list that does not fit is not believed; a gone tree loses its list" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const list = try std.fmt.allocPrint(arena, "{s}/{s}.stat", .{ f.lists, tree_rel });
    // A file added to the tree, and a list cut off in the middle of a line.
    try tmp.dir.writeFile(io, .{ .sub_path = "cache/" ++ tree_rel ++ "/new", .data = "new\n" });
    const cut = try std.Io.Dir.cwd().readFileAlloc(io, list, arena, .limited(1 << 20));
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = list, .data = cut[0 .. cut.len - 20] });
    const v = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(v.note, tree_rel ++ " (6 files, 6 read)");
    try tmp.dir.deleteTree(io, "cache/node");
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const gone = tmp.dir.access(io, "lists/node/22.0.0/x64.stat", .{});
    try std.testing.expectError(error.FileNotFound, gone);
    try tmp.dir.access(io, "lists/" ++ tree_rel ++ ".stat", .{});
}

test "tool trees: a check is bounded in files, bytes and depth, and ends with the job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // The Zig tree has five files, and the node tree, which sorts first, one.
    const files = try checkWith(arena, f, .{ .tree_files = 3 }, null);
    try expectIn(files.note, "left out 1: " ++ tree_rel ++ " (too many files)");
    try expectIn(files.env, "node/22.0.0/x64");
    try std.testing.expect(std.mem.indexOf(u8, files.env, tree_rel) == null);
    const bytes = try checkWith(arena, f, .{ .read_bytes = 5 }, null);
    try expectIn(bytes.note, "stopped: too many bytes");
    const deep = try checkWith(arena, f, .{ .depth = 0 }, null);
    try expectIn(deep.note, "(too deep)");
    var cancel: dagger.Cancel = .{};
    cancel.request(0);
    const v = try checkWith(arena, f, .{}, &cancel);
    try std.testing.expectEqualStrings("", v.env);
    try expectIn(v.note, "stopped: the job was cancelled");
}

test "tool trees: a name a list cannot hold leaves its tree out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "cache/" ++ tree_rel ++ "/back\\slash",
        .data = "x",
    });
    const v = try checkWith(arena, f, .{}, null);
    try std.testing.expect(std.mem.indexOf(u8, v.env, tree_rel) == null);
    try expectIn(v.env, "node/22.0.0/x64");
}

// Tests that use only what `check` had when the first review found each hole (K1, K2, K4, K5).

const pad_n: [96]u8 = @splat('n');
const pad_d: [238]u8 = @splat('d');
const page: [4096]u8 = @splat('x');

test "tool trees: the environment stays under what one string of it may be" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 480 empty trees, each named at the longest a name may be: one job's work, and a line each.
    for (0..480) |i| {
        const name = try std.fmt.allocPrint(arena, "cache/t/v/{d:0>4}{s}", .{ i, &pad_n });
        try tmp.dir.createDirPath(std.testing.io, name);
    }
    try tmp.dir.createDirPath(std.testing.io, "lists");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
    const f: Fixture = .{
        .cache = try std.fmt.allocPrint(arena, "{s}/cache", .{root}),
        .lists = try std.fmt.allocPrint(arena, "{s}/lists", .{root}),
    };
    const v = try checkWith(arena, f, .{}, null);
    try std.testing.expect(v.env.len > 0);
    try std.testing.expect(v.env.len <= 64 << 10);
}

test "tool trees: a tree of long paths is given up on within the memory it is given" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 14 directories of 240 bytes, hard links of one file in the last: paths of 3.4 KB.
    var dir = try tmp.dir.createDirPathOpen(io, "cache/t/v/n", .{});
    defer dir.close(io);
    var depth: usize = 0;
    var cur = dir;
    while (depth < 14) : (depth += 1) {
        const name = try std.fmt.allocPrint(arena, "{d:0>2}{s}", .{ depth, &pad_d });
        const next = try cur.createDirPathOpen(io, name, .{});
        if (depth > 0) cur.close(io);
        cur = next;
    }
    defer cur.close(io);
    try cur.writeFile(io, .{ .sub_path = "f0", .data = "x" });
    for (1..5200) |i| {
        const name = try std.fmt.allocPrintSentinel(arena, "f{d}", .{i}, 0);
        try std.testing.expectEqual(
            linux.E.SUCCESS,
            linux.errno(linux.linkat(cur.handle, "f0", cur.handle, name, 0)),
        );
    }
    try tmp.dir.createDirPath(io, "lists");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // Memory for 40 MiB and no more: what the walk keeps for 5,200 such paths is about 50 MB.
    const buf = try std.testing.allocator.alloc(u8, 40 << 20);
    defer std.testing.allocator.free(buf);
    var fba: std.heap.FixedBufferAllocator = .init(buf);
    const v = try check(
        arena,
        fba.allocator(),
        io,
        try std.fmt.allocPrint(arena, "{s}/cache", .{root}),
        try std.fmt.allocPrint(arena, "{s}/lists", .{root}),
        "/t",
        .{},
        null,
    );
    try std.testing.expectEqualStrings("", v.env);
}

test "tool trees: a file a shared mapping still writes is read again, not trusted from a list" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const tree = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel });
    // A page of the file, written through a mapping that outlives its descriptor.
    const path = "cache/" ++ tree_rel ++ "/mapped";
    try tmp.dir.writeFile(io, .{ .sub_path = path, .data = &page });
    const fd = try std.fmt.allocPrintSentinel(arena, "{s}/mapped", .{tree}, 0);
    const opened = linux.open(fd, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(opened) == .SUCCESS);
    const opened_fd = std.math.cast(linux.fd_t, opened).?;
    const prot: linux.PROT = .{ .READ = true, .WRITE = true };
    const map = linux.mmap(null, 4096, prot, .{ .TYPE = .SHARED }, opened_fd, 0);
    try std.testing.expect(linux.errno(map) == .SUCCESS);
    _ = linux.close(opened_fd);
    defer _ = linux.munmap(@ptrFromInt(map), 4096);
    const bytes: [*]u8 = @ptrFromInt(map);
    bytes[0] = 'a';
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    // The page is dirty and mapped writable: this write sets neither ctime nor mtime.
    bytes[1] = 'b';
    const v = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(v.env, try shellDigest(arena, tree));
}

test "tool trees: a lease is believed only where a writable mapping was seen to refuse it" {
    try std.testing.expect(leasesSeeMappings(0xef53));
    try std.testing.expect(leasesSeeMappings(0x01021994));
    const overlayfs = 0x794c7630;
    try std.testing.expect(!leasesSeeMappings(overlayfs));
    try std.testing.expect(!leasesSeeMappings(0));
}

test "tool trees: a plant of names does not cost the trees that were checked before" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const first = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(first.env, tree_rel);
    for (0..1100) |i| {
        try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "cache/p{d:0>4}", .{i}));
    }
    const v = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(v.env, tree_rel);
    try expectIn(v.env, "node/22.0.0/x64");
}

test "tool trees: a link, a mode or an empty directory is in the second digest and not the first" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const base = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const dir = "cache/" ++ tree_rel;
    // A link moved to another file of the tree.
    try tmp.dir.deleteFile(io, dir ++ "/zig-link");
    try tmp.dir.symLink(io, "a/x", dir ++ "/zig-link", .{});
    const moved = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(base.env, moved.env);
    try std.testing.expect(!std.mem.eql(u8, base.full, moved.full));
    // A mode.
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const zig = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/zig", .{ root, dir }, 0);
    _ = linux.chmod(zig, 0o4755);
    const mode = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(base.env, mode.env);
    try std.testing.expect(!std.mem.eql(u8, moved.full, mode.full));
    // A directory.
    try tmp.dir.createDirPath(io, dir ++ "/another-empty");
    const dirs = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(base.env, dirs.env);
    try std.testing.expect(!std.mem.eql(u8, mode.full, dirs.full));
    // And the same tree twice gives the same.
    const again = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(dirs.full, again.full);
}

test "tool trees: a link that can lead out of the tree leaves the tree out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    try tmp.dir.createDirPath(io, "cache/zig/0.17.0/.evil");
    try tmp.dir.writeFile(io, .{ .sub_path = "cache/zig/0.17.0/.evil/gcc", .data = "evil" });
    try tmp.dir.symLink(io, "../../../.evil/gcc", "cache/" ++ tree_rel ++ "/lib/gcc", .{});
    const v = try checkWith(arena, f, .{}, null);
    try std.testing.expect(std.mem.indexOf(u8, v.env, tree_rel) == null);
    try expectIn(v.env, "node/22.0.0/x64");
    try expectIn(v.note, "a link leaves the tree");
    try std.testing.expect(!leavesTree("./a/b", "../c"));
    try std.testing.expect(leavesTree("./b", "../c"));
    try std.testing.expect(leavesTree("./a/b", "/etc/passwd"));
    try std.testing.expect(leavesTree("./a/b", "../a/./c/.."));
    try std.testing.expect(leavesTree("./a/b", "c/../d"));
    try std.testing.expect(!leavesTree("./a/b", "../a/c"));
    try std.testing.expect(leavesTree("./a/b", "../../c"));
}

test "tool trees: one tree over a limit of its own costs that tree and no other" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // Zig's tree reads 11 bytes in its first file, node's tree 5.
    const v = try checkWith(arena, f, .{ .tree_read_bytes = 6 }, null);
    try expectIn(v.env, "node/22.0.0/x64");
    try std.testing.expect(std.mem.indexOf(u8, v.env, tree_rel) == null);
    try expectIn(v.note, "left out 1: " ++ tree_rel ++ " (too many bytes to read)");
    try std.testing.expect(std.mem.indexOf(u8, v.note, "stopped") == null);
    const entries = try checkWith(arena, f, .{ .tree_entries = 3 }, null);
    try expectIn(entries.env, "node/22.0.0/x64");
    try expectIn(entries.note, "too many entries");
    const paths = try checkWith(arena, f, .{ .tree_path_bytes = 10 }, null);
    try expectIn(paths.note, "too many bytes of paths");
}

test "tool trees: checks together hold what the process allows and give it back" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    var budget: hash_files.Budget = .{};
    try std.testing.expectEqual(@as(u64, 0), budget.held.load(.acquire));
    // Other checks hold nearly all of it: this tree does not fit.
    _ = budget.held.fetchAdd(1000, .acq_rel);
    _ = budget.checks.fetchAdd(1000, .acq_rel);
    const v = try checkWith(arena, f, .{ .memory = 2000, .budget = &budget }, null);
    _ = budget.held.fetchSub(1000, .acq_rel);
    _ = budget.checks.fetchSub(1000, .acq_rel);
    try expectIn(v.note, "too much memory in use");
    try std.testing.expectEqual(@as(u64, 0), budget.held.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), budget.checks.load(.acquire));
    // `hashFiles()` calls hold far past the checks' limit: they take nothing from the checks.
    _ = budget.held.fetchAdd(1 << 30, .acq_rel);
    const calls = try checkWith(arena, f, .{ .budget = &budget }, null);
    _ = budget.held.fetchSub(1 << 30, .acq_rel);
    try expectIn(calls.env, tree_rel);
    try std.testing.expect(std.mem.indexOf(u8, calls.note, "too much memory") == null);
    const fits = try checkWith(arena, f, .{ .budget = &budget }, null);
    try expectIn(fits.env, tree_rel);
    try std.testing.expectEqual(@as(u64, 0), budget.held.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), budget.checks.load(.acquire));
}

test "tool trees: lists are not written past what is read, and leftovers and empty directories go" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    // A half-written list a runner left long ago, and one being written now.
    const dead = "lists/node/22.0.0/x64.stat.0123456789abcdef";
    const live = "lists/node/22.0.0/x64.stat.fedcba9876543210";
    try tmp.dir.writeFile(io, .{ .sub_path = dead, .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = live, .data = "x" });
    const dead_path = try std.fmt.allocPrint(arena, "{s}/node/22.0.0/x64.stat.0123456789abcdef", .{
        f.lists,
    });
    const old = try std.process.run(arena, io, .{
        .argv = &.{ "touch", "-d", "2 hours ago", dead_path },
    });
    try std.testing.expect(old.term == .exited and old.term.exited == 0);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, dead, .{}));
    try tmp.dir.access(io, live, .{});
    // A tree that is gone takes its directories with it, when nothing else is in them.
    try tmp.dir.deleteTree(io, "cache/node");
    try tmp.dir.deleteFile(io, live);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "lists/node", .{}));
}

test "tool trees: a writer opening a leased file does not end the process" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = "x" });
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const path = try std.fmt.allocPrintSentinel(a.allocator(), "{s}/f", .{
        try tmp.dir.realPathFileAlloc(io, ".", a.allocator()),
    }, 0);
    const held_fd = std.math.cast(linux.fd_t, linux.open(path, .{ .ACCMODE = .RDONLY }, 0)).?;
    defer _ = linux.close(held_fd);
    // What `hashFile` does with the file it reads.
    _ = linux.fcntl(held_fd, linux.F.SETSIG, @backingInt(linux.SIG.URG));
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.fcntl(held_fd, linux.F.SETLEASE, linux.F.RDLCK)),
    );
    // A writer that would wait for the lease to be let go gets an error instead, and the signal
    // of the break is one a process survives.
    const w = linux.open(path, .{ .ACCMODE = .WRONLY, .NONBLOCK = true }, 0);
    try std.testing.expectEqual(linux.E.AGAIN, linux.errno(w));
    _ = linux.fcntl(held_fd, linux.F.SETLEASE, linux.F.UNLCK);
}

test "tool trees: a check leaves SIGIO as it found it, for std.Io's cancels" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    var before: linux.Sigaction = undefined;
    _ = linux.sigaction(linux.SIG.IO, null, &before);
    _ = try checkWith(arena, f, .{}, null);
    var after: linux.Sigaction = undefined;
    _ = linux.sigaction(linux.SIG.IO, null, &after);
    try std.testing.expectEqual(before.handler.handler, after.handler.handler);
    try std.testing.expect(after.handler.handler != linux.SIG.IGN);
}

test "tool trees: a link through a link that goes up leaves the tree, whatever its text counts" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    try tmp.dir.createDirPath(io, "cache/zig/0.17.0/.evil");
    try tmp.dir.writeFile(io, .{ .sub_path = "cache/zig/0.17.0/.evil/gcc", .data = "evil" });
    // Inside the tree both stay: `lib/d` is the tree's own top, and the text of `gcc` goes up
    // two, which is one more than the tree has above `lib/d`, so it leaves the tree.
    try tmp.dir.symLink(io, "..", "cache/" ++ tree_rel ++ "/lib/d", .{});
    try tmp.dir.symLink(io, "lib/d/../../.evil/gcc", "cache/" ++ tree_rel ++ "/gcc", .{});
    const v = try checkWith(arena, f, .{}, null);
    try std.testing.expect(std.mem.indexOf(u8, v.env, tree_rel) == null);
    try expectIn(v.env, "node/22.0.0/x64");
}

test "tool trees: trees a job made after the tool cannot spend the budget the tool needs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    // Six trees, small until a check has listed them, that sort before the tool's.
    for (0..6) |i| {
        const p = try std.fmt.allocPrint(arena, "cache/0/0/t{d}", .{i});
        try tmp.dir.createDirPath(io, p);
        const file = try std.fmt.allocPrint(arena, "{s}/f", .{p});
        try tmp.dir.writeFile(io, .{ .sub_path = file, .data = "x" });
    }
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    // Then each grows to more than a tree may read, together more than the check may.
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for (0..6) |i| {
        const file = try std.fmt.allocPrint(arena, "{s}/cache/0/0/t{d}/f", .{ root, i });
        const argv: []const []const u8 = &.{ "truncate", "-s", "2M", file };
        const grown = try std.process.run(arena, io, .{ .argv = argv });
        try std.testing.expect(grown.term == .exited and grown.term.exited == 0);
    }
    const tight: Limits = .{ .racy_s = 0, .read_bytes = 3 << 20, .tree_read_bytes = 1 << 20 };
    const v = try checkWith(arena, f, tight, null);
    try expectIn(v.env, tree_rel);
    try expectIn(v.env, "node/22.0.0/x64");
}

test "tool trees: trees a job made fill the environment after the tool, not before it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    // 480 trees with names of 100 bytes, which sort between the two the tool cache had.
    for (0..480) |i| {
        const name = try std.fmt.allocPrint(arena, "cache/p/v/{d:0>4}{s}", .{ i, &pad_n });
        try tmp.dir.createDirPath(io, name);
    }
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const v = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(v.env, tree_rel);
    try expectIn(v.env, "node/22.0.0/x64");
    // The trees that did not fit are counted, though the note stops naming them.
    const lines = std.mem.count(u8, v.env, "\n") + 1;
    const want = try std.fmt.allocPrint(arena, "; left out {d}: ", .{482 - lines});
    try expectIn(v.note, want);
}

test "tool trees: a cancel that lands in the lists' upkeep is there for what runs next" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const arena_state = struct {
        fn run(path: []const u8, cancelled: *bool) void {
            const io = std.testing.io;
            // Not a point of cancellation: the cancel is waiting when this ends.
            const until = nowMs(io) + 200;
            while (nowMs(io) < until) {}
            var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer a.deinit();
            keepList(a.allocator(), io, path, "x\n");
            io.sleep(.fromSeconds(30), .awake) catch {
                cancelled.* = true;
            };
        }
    };
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(std.testing.io, ".", &buf);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sub/list", .{buf[0..n]});
    defer std.testing.allocator.free(path);
    var cancelled = false;
    var task = try std.testing.io.concurrent(arena_state.run, .{ path, &cancelled });
    task.cancel(std.testing.io);
    try std.testing.expect(cancelled);
}

test "tool trees: calls that overlap share a walk, and any answer is a walk's own" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const fresh = try checkWith(arena, f, .{}, null);
    var flights: Flights = .{};
    defer flights.list.deinit(std.heap.smp_allocator);
    const Caller = struct {
        fn run(fl: *Flights, ff: Fixture, ar: *std.heap.ArenaAllocator, out: *Verdict, ok: *bool) void {
            // Each caller its own arena (one is not shared between threads); the test frees them.
            const v = checkOnce(fl, ar.allocator(), std.heap.smp_allocator, std.testing.io, ff.cache, ff.lists, "/t", null) catch return;
            out.* = v;
            ok.* = true;
        }
    };
    var verdicts: [6]Verdict = undefined;
    var oks: [6]bool = @splat(false);
    var arenas: [6]std.heap.ArenaAllocator = @splat(.init(std.heap.page_allocator));
    defer for (&arenas) |*x| x.deinit();
    var threads: [6]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Caller.run, .{ &flights, f, &arenas[i], &verdicts[i], &oks[i] });
    for (threads) |t| t.join();
    for (verdicts, oks) |v, ok| {
        try std.testing.expect(ok);
        try std.testing.expectEqualStrings(fresh.env, v.env);
        try std.testing.expectEqualStrings(fresh.full, v.full);
    }
    try std.testing.expect(flights.walks >= 1 and flights.walks <= 6);
    // Nothing is kept once the last caller is gone.
    try std.testing.expectEqual(@as(usize, 0), flights.list.items.len);
}

test "tool trees: a change after an answer is in the next answer, whatever the tree's times say" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const tree = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel });
    var flights: Flights = .{};
    defer flights.list.deinit(std.heap.smp_allocator);
    const gpa = std.testing.allocator;
    var last = try checkOnce(&flights, arena, gpa, io, f.cache, f.lists, "/t", null);
    // A file's content (the directory's mtime does not move), a mode, a new file, a link.
    for ([_][]const u8{
        "printf 'changed\\n' > zig",
        "chmod 4755 zig",
        "printf new > added",
        "ln -s ../../x zig-link2",
    }) |edit| {
        const run = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", try std.fmt.allocPrint(arena, "cd \"$0\" && {s}", .{edit}), tree } });
        try std.testing.expect(run.term == .exited and run.term.exited == 0);
        const now = try checkOnce(&flights, arena, gpa, io, f.cache, f.lists, "/t", null);
        const walked = try checkWith(arena, f, .{}, null);
        try std.testing.expectEqualStrings(walked.env, now.env);
        try std.testing.expectEqualStrings(walked.full, now.full);
        try std.testing.expect(!std.mem.eql(u8, last.env, now.env) or !std.mem.eql(u8, last.full, now.full));
        last = now;
    }
}
